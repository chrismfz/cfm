// Package outbound implements cfm's Outbound Abuse Sentinel.
//
// Phase 1 is observe-only: it reads NFLOG events for new outbound connections
// produced by the cfm_outbound_observe nft chain, classifies each event by
// destination port group (SMTP / SCAN / HTTP / DNS), maintains per-uid sliding
// window counters, and emits a forensic warning to cfm.smtp.log plus an admin
// notification when a uid crosses a configured threshold. Nothing here drops,
// throttles or suspends — those actions belong to phase 2 (enforcer).
package outbound

import (
	"sync"
	"time"
)

// Signal identifies which class of outbound traffic a counter tracks.
type Signal string

const (
	SignalSMTP    Signal = "smtp"     // outbound 25/465/587 (mail flood)
	SignalSCAN    Signal = "scan"     // outbound 22/23/3389 (brute-force / scanner)
	SignalHTTP    Signal = "http"     // outbound 80/443/8080/8443 (POST flood / botnet C2)
	SignalDNS     Signal = "dns"      // outbound UDP 53 (amplification participant)
	SignalUNIQDST Signal = "uniq_dst" // unique destination IPs across all ports (horizontal scan)
)

// AllSignals is iteration order for analyzer ticks and reset.
var AllSignals = []Signal{SignalSMTP, SignalSCAN, SignalHTTP, SignalDNS, SignalUNIQDST}

// Thresholds returns the configured per-window threshold for a signal.
// Returns 0 (disabled) for unknown signals.
func Thresholds(cfg Runtime) map[Signal]int {
	return map[Signal]int{
		SignalSMTP:    cfg.SMTPPerWindow,
		SignalSCAN:    cfg.UniqueDstPerWindow, // scan reuses uniq-dst threshold; flagged separately
		SignalHTTP:    cfg.HTTPPerWindow,
		SignalDNS:     cfg.DNSPerWindow,
		SignalUNIQDST: cfg.UniqueDstPerWindow,
	}
}

// Runtime is the resolved, validated config the analyzer/collector consume.
// It is independent of config.OutboundConfig so test code can build one
// directly without parsing.
type Runtime struct {
	Window              time.Duration
	SMTPPerWindow       int
	UniqueDstPerWindow  int
	HTTPPerWindow       int
	DNSPerWindow        int
	DedupCooldown       time.Duration
	QueueSampleLimit    int
	NotifySeverity      string
	SMTPPorts           map[uint16]struct{}
	ScanPorts           map[uint16]struct{}
	HTTPPorts           map[uint16]struct{}
	AllowUIDs           map[uint32]struct{}
	AllowGIDs           map[uint32]struct{}
	Enrich              bool
}

// Event is one classified outbound connection observation.
type Event struct {
	When    time.Time
	UID     uint32
	GID     uint32
	IPVer   int
	SrcIP   [16]byte
	DstIP   [16]byte
	SPort   uint16
	DPort   uint16
	IsUDP   bool
	Signal  Signal
}

// Verdict is what the analyzer hands to the alerter when a threshold is
// crossed and dedup permits emission. Counts are at the moment of the trip.
type Verdict struct {
	When        time.Time
	UID         uint32
	GID         uint32
	Signal      Signal
	Count       int
	Threshold   int
	Window      time.Duration
	UniqueDsts  int      // distinct destination IPs in this window for this uid (any signal)
	SamplePeers []string // up to 5 recent dst:port hits for forensics
}

// uidState tracks per-uid sliding-window data for every signal.
type uidState struct {
	gid uint32
	// per-signal ring of timestamps (oldest -> newest); we use a slice and
	// expire from the head on every push. Capacity is bounded by threshold*2
	// so a runaway abuser doesn't grow the slice unboundedly: we cap at the
	// largest plausible threshold and drop excess from the head.
	hits map[Signal][]time.Time

	// distinct destination IPs in window (string keys keep IPv4/IPv6 uniform).
	dstWindow map[string]time.Time

	// ring of recent peers for forensics (most recent at end).
	peers []string

	// last verdict emission per signal — used for dedup.
	lastEmit map[Signal]time.Time
}

func newUIDState() *uidState {
	return &uidState{
		hits:      make(map[Signal][]time.Time, len(AllSignals)),
		dstWindow: make(map[string]time.Time, 32),
		peers:     make([]string, 0, 16),
		lastEmit:  make(map[Signal]time.Time, len(AllSignals)),
	}
}

// Analyzer maintains sliding-window counters across all observed uids and
// produces verdicts when thresholds trip.
type Analyzer struct {
	cfg        Runtime
	thresholds map[Signal]int
	mu         sync.Mutex
	uids       map[uint32]*uidState
}

// NewAnalyzer constructs an analyzer bound to a runtime config.
func NewAnalyzer(cfg Runtime) *Analyzer {
	return &Analyzer{
		cfg:        cfg,
		thresholds: Thresholds(cfg),
		uids:       make(map[uint32]*uidState),
	}
}

// Observe records one event and returns a Verdict if it crosses a threshold
// AND the per-uid+signal dedup cooldown has elapsed. nil otherwise.
//
// Concurrency: safe for concurrent callers (single mutex; analyzer is not
// expected to be a hot path — outbound NFLOG is gated to ct state new on a
// small set of ports).
func (a *Analyzer) Observe(ev Event) *Verdict {
	if a == nil || ev.Signal == "" {
		return nil
	}
	thr := a.thresholds[ev.Signal]
	if thr <= 0 {
		// Signal not configured — record nothing, emit nothing.
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	st, ok := a.uids[ev.UID]
	if !ok {
		st = newUIDState()
		st.gid = ev.GID
		a.uids[ev.UID] = st
	}
	st.gid = ev.GID // keep latest gid known for this uid

	cutoff := ev.When.Add(-a.cfg.Window)

	// Append to per-signal window and drop expired entries from the head.
	hits := append(st.hits[ev.Signal], ev.When)
	for len(hits) > 0 && hits[0].Before(cutoff) {
		hits = hits[1:]
	}
	// Bound memory: keep at most 2*thr + 8 (safe slack). If we exceed, the
	// uid is plainly tripping anyway and older entries don't add information.
	if cap(hits) > 0 && len(hits) > 2*thr+8 {
		hits = hits[len(hits)-(2*thr+8):]
	}
	st.hits[ev.Signal] = hits

	// Maintain per-uid distinct destination set across ALL signals.
	dstKey := ipKey(ev.IPVer, ev.DstIP)
	st.dstWindow[dstKey] = ev.When
	for k, t := range st.dstWindow {
		if t.Before(cutoff) {
			delete(st.dstWindow, k)
		}
	}

	// Maintain rolling peer sample (most recent N).
	peer := dstKey + ":" + portString(ev.DPort)
	st.peers = append(st.peers, peer)
	const peerCap = 16
	if len(st.peers) > peerCap {
		st.peers = st.peers[len(st.peers)-peerCap:]
	}

	// Threshold check for this signal.
	count := len(hits)
	uniq := len(st.dstWindow)

	// Special-case UNIQDST: that signal is driven by uniq, not by len(hits).
	tripped := false
	tripCount := count
	switch ev.Signal {
	case SignalUNIQDST:
		tripCount = uniq
		tripped = uniq >= a.cfg.UniqueDstPerWindow
	default:
		tripped = count >= thr
	}
	if !tripped {
		// Even if THIS signal didn't trip, a horizontal scan might still trip
		// UNIQDST as a side effect (a SCAN/SMTP burst across many destinations).
		// Check uniq separately — distinct dst threshold uses UNIQDST cooldown.
		if uniq >= a.cfg.UniqueDstPerWindow && a.dedupOK(st, SignalUNIQDST, ev.When) {
			st.lastEmit[SignalUNIQDST] = ev.When
			return a.makeVerdict(ev, SignalUNIQDST, uniq, a.cfg.UniqueDstPerWindow, st, uniq)
		}
		return nil
	}

	if !a.dedupOK(st, ev.Signal, ev.When) {
		return nil
	}
	st.lastEmit[ev.Signal] = ev.When

	return a.makeVerdict(ev, ev.Signal, tripCount, thr, st, uniq)
}

func (a *Analyzer) dedupOK(st *uidState, sig Signal, now time.Time) bool {
	last, ok := st.lastEmit[sig]
	if !ok {
		return true
	}
	return now.Sub(last) >= a.cfg.DedupCooldown
}

func (a *Analyzer) makeVerdict(ev Event, sig Signal, count, thr int, st *uidState, uniq int) *Verdict {
	limit := a.cfg.QueueSampleLimit
	if limit <= 0 || limit > len(st.peers) {
		limit = len(st.peers)
	}
	peers := append([]string(nil), st.peers[len(st.peers)-limit:]...)
	return &Verdict{
		When:        ev.When,
		UID:         ev.UID,
		GID:         st.gid,
		Signal:      sig,
		Count:       count,
		Threshold:   thr,
		Window:      a.cfg.Window,
		UniqueDsts:  uniq,
		SamplePeers: peers,
	}
}

// IsAllowed reports whether the analyzer should skip a uid+gid combo entirely.
// Root (uid=0) is always exempt: kernel-originated packets, cfm itself, and
// system services would otherwise dominate the signal.
func (a *Analyzer) IsAllowed(uid, gid uint32) bool {
	if uid == 0 {
		return true
	}
	if _, ok := a.cfg.AllowUIDs[uid]; ok {
		return true
	}
	if _, ok := a.cfg.AllowGIDs[gid]; ok {
		return true
	}
	return false
}

func ipKey(ipver int, b [16]byte) string {
	if ipver == 4 {
		return string(b[12:16])
	}
	return string(b[:])
}

func portString(p uint16) string {
	// Tiny non-allocating-ish hot-path helper; kept here so analyzer.go has
	// no fmt import.
	if p == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = byte('0' + p%10)
		p /= 10
	}
	return string(buf[i:])
}
