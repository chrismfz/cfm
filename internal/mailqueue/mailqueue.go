// Package mailqueue builds and holds an MTA-agnostic mail-queue report — the
// structured `exim -bp` / `postqueue -p` view: how many messages are queued/
// frozen/deferred, their age distribution, the top sender/recipient domains, the
// oldest messages, and the top deferral/freeze reasons.
//
// Sourcing is detector-published, NOT per-request: the active queue detector
// (exim_queues / postfix_queues) already polls the MTA, so it builds the report
// once per cycle from output it already has and Publish()es it here; the API,
// CLI and WebUI all read the last-published report with zero extra exec. This
// package owns the shared types + the pure parsers (no exec, unit-tested); the
// MTA-specific commands live in the detectors.
package mailqueue

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxParseMsgs         = 20000 // hard cap on messages parsed from a queue listing
	maxRcptDomainsPerMsg = 8     // distinct recipient domains retained per message
	DefaultTop           = 10
)

// Report is the MTA-agnostic queue snapshot published by the active detector.
type Report struct {
	MTA        string         `json:"mta"` // exim | postfix
	MeasuredAt time.Time      `json:"measured_at"`
	Total      int            `json:"total"`    // authoritative count (exim -bpc / postqueue count)
	Parsed     int            `json:"parsed"`   // messages parsed from the listing (<= maxParseMsgs)
	Frozen     int            `json:"frozen"`   // exim frozen / postfix hold
	Deferred   int            `json:"deferred"` // non-frozen, older than 1h (stuck but retrying)
	Truncated  bool           `json:"truncated"`
	AgeBuckets map[string]int `json:"age_buckets"` // <10m,10m-1h,1h-6h,6h-1d,>1d

	TopSenderDomains    []DomCount    `json:"top_sender_domains"`
	TopRecipientDomains []DomCount    `json:"top_recipient_domains"`
	Oldest              []QueuedMsg   `json:"oldest"`
	DeferReasons        []DeferReason `json:"defer_reasons"` // top normalized deferral/freeze reasons (may be nil)
}

// QueuedMsg is one parsed queue entry (aggregates + a bounded oldest-N sample
// are returned, not the whole queue).
type QueuedMsg struct {
	AgeSec      int64    `json:"age_sec"`
	SizeBytes   int64    `json:"size_bytes"`
	ID          string   `json:"id"`
	Sender      string   `json:"sender"`
	Frozen      bool     `json:"frozen"`
	Recipients  int      `json:"recipients"`
	rcptDomains []string // deduped, capped; aggregated then dropped from JSON
}

// DomCount is a domain with its message count.
type DomCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// DeferReason is one normalized deferral/freeze reason with its frequency.
type DeferReason struct {
	Reason   string `json:"reason"`   // normalized (variable bits stripped)
	Category string `json:"category"` // deferred | failed | frozen
	Count    int    `json:"count"`
	Sample   string `json:"sample"` // one representative raw reason
}

// ── published store ─────────────────────────────────────────────────────────

var (
	mu     sync.RWMutex
	latest *Report
)

// Publish records the newest report (detector calls this each cycle).
func Publish(r Report) {
	if r.MeasuredAt.IsZero() {
		r.MeasuredAt = time.Now()
	}
	mu.Lock()
	latest = &r
	mu.Unlock()
}

// Latest returns the last-published report, ok=false when none yet (no queue
// detector enabled, or first cycle hasn't run).
func Latest() (Report, bool) {
	mu.RLock()
	defer mu.RUnlock()
	if latest == nil {
		return Report{}, false
	}
	return *latest, true
}

// TestOnlyReset clears the store (package-global; tests share it).
func TestOnlyReset() {
	mu.Lock()
	latest = nil
	mu.Unlock()
}

// ── exim `-bp` → Report (pure) ───────────────────────────────────────────────

// BuildEximReport parses `exim -bp` output into an aggregated Report. total is
// the authoritative count from `exim -bpc` (0 → fall back to the parsed count).
// top bounds the returned domain lists and oldest-N sample.
func BuildEximReport(bpOutput string, total, top int) Report {
	if top <= 0 {
		top = DefaultTop
	}
	msgs, truncated := parseBP(bpOutput)

	r := Report{
		MTA:        "exim",
		Parsed:     len(msgs),
		Truncated:  truncated,
		AgeBuckets: map[string]int{"<10m": 0, "10m-1h": 0, "1h-6h": 0, "6h-1d": 0, ">1d": 0},
	}
	senderDom := map[string]int{}
	recipDom := map[string]int{}
	for _, m := range msgs {
		if m.Frozen {
			r.Frozen++
		} else if m.AgeSec >= 3600 {
			r.Deferred++
		}
		bucketAge(r.AgeBuckets, m.AgeSec)
		if d := domainOf(m.Sender); d != "" {
			senderDom[d]++
		}
		for _, d := range m.rcptDomains {
			recipDom[d]++
		}
	}
	r.Total = len(msgs)
	if total > 0 {
		r.Total = total
	}
	r.TopSenderDomains = topDomains(senderDom, top)
	r.TopRecipientDomains = topDomains(recipDom, top)
	r.Oldest = oldestN(msgs, top)
	return r
}

// parseBP parses `exim -bp` output. Format per message:
//
//	<age> <size> <id> <sender@dom>
//	          recipient@dom          (indented; one or more)
//	*** frozen ***                   (only for frozen messages)
func parseBP(out string) (msgs []QueuedMsg, truncated bool) {
	var cur *QueuedMsg
	flush := func() {
		if cur != nil {
			msgs = append(msgs, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "*** frozen ***") {
			if cur != nil {
				cur.Frozen = true
			}
			continue
		}
		if m, ok := parseHeaderLine(line); ok {
			if len(msgs) >= maxParseMsgs {
				truncated = true
				break
			}
			flush()
			cur = &m
			continue
		}
		if cur != nil && strings.TrimSpace(line) != "" && strings.Contains(line, "@") {
			cur.Recipients++
			if d := domainOf(strings.Trim(strings.TrimSpace(line), "<>")); d != "" {
				addDomainCapped(cur, d)
			}
		}
	}
	flush()
	return msgs, truncated
}

func parseHeaderLine(line string) (QueuedMsg, bool) {
	f := strings.Fields(line)
	if len(f) < 4 {
		return QueuedMsg{}, false
	}
	age, ok := parseAge(f[0])
	if !ok {
		return QueuedMsg{}, false
	}
	size, ok := parseSize(f[1])
	if !ok {
		return QueuedMsg{}, false
	}
	sender := ""
	if i := strings.IndexByte(line, '<'); i >= 0 {
		if j := strings.IndexByte(line[i:], '>'); j >= 0 {
			sender = line[i+1 : i+j]
		}
	}
	return QueuedMsg{AgeSec: age, SizeBytes: size, ID: f[2], Sender: sender}, true
}

func parseAge(s string) (int64, bool) {
	if len(s) < 2 {
		return 0, false
	}
	num, err := strconv.ParseFloat(s[:len(s)-1], 64)
	if err != nil {
		return 0, false
	}
	switch s[len(s)-1] {
	case 's':
		return int64(num), true
	case 'm':
		return int64(num * 60), true
	case 'h':
		return int64(num * 3600), true
	case 'd':
		return int64(num * 86400), true
	case 'w':
		return int64(num * 604800), true
	}
	return 0, false
}

func parseSize(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	mult := float64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult, s = 1024, s[:len(s)-1]
	case 'M', 'm':
		mult, s = 1024*1024, s[:len(s)-1]
	case 'G', 'g':
		mult, s = 1024*1024*1024, s[:len(s)-1]
	}
	num, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return int64(num * mult), true
}

func bucketAge(b map[string]int, age int64) {
	switch {
	case age < 600:
		b["<10m"]++
	case age < 3600:
		b["10m-1h"]++
	case age < 6*3600:
		b["1h-6h"]++
	case age < 86400:
		b["6h-1d"]++
	default:
		b[">1d"]++
	}
}

func addDomainCapped(m *QueuedMsg, d string) {
	if len(m.rcptDomains) >= maxRcptDomainsPerMsg {
		return
	}
	for _, e := range m.rcptDomains {
		if e == d {
			return
		}
	}
	m.rcptDomains = append(m.rcptDomains, d)
}

func domainOf(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

func topDomains(m map[string]int, top int) []DomCount {
	out := make([]DomCount, 0, len(m))
	for d, c := range m {
		out = append(out, DomCount{Domain: d, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain < out[j].Domain
	})
	if len(out) > top {
		out = out[:top]
	}
	return out
}

func oldestN(msgs []QueuedMsg, n int) []QueuedMsg {
	cp := make([]QueuedMsg, len(msgs))
	copy(cp, msgs)
	sort.Slice(cp, func(i, j int) bool { return cp[i].AgeSec > cp[j].AgeSec })
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}
