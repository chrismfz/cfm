// internal/webdetector/engine.go
package webdetector

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

// LogRec is one TSV log line parsed.
type LogRec struct {
	TS      float64
	IP      string
	Host    string
	Method  string
	URI     string
	Proto   string
	Status  int
	Bytes   int64
	RT, URT float64
	UA      string
	Ref     string
}

// parseTSV parses the TSV log format used by access_cfm_tsv.log.
// ts ip host method uri proto status bytes rt urt ref ua
func parseTSV(line string) (LogRec, bool) {
	f := strings.SplitN(line, "\t", 12)
	if len(f) < 12 {
		return LogRec{}, false
	}
	ts, _ := strconv.ParseFloat(f[0], 64)
	st, _ := strconv.Atoi(f[6])
	by, _ := strconv.ParseInt(f[7], 10, 64)

	rt, _ := strconv.ParseFloat(zero(f[8]), 64)
	// If Apache wrote microseconds via %D, normalize to seconds.
	if rt > 10000 {
		rt = rt / 1_000_000.0
	}
	ut, _ := strconv.ParseFloat(zero(f[9]), 64)

	return LogRec{
		TS:     ts,
		IP:     f[1],
		Host:   strings.ToLower(f[2]),
		Method: strings.ToLower(f[3]),
		URI:    strings.ToLower(f[4]),
		Proto:  strings.ToLower(f[5]),
		Status: st,
		Bytes:  by,
		RT:     rt,
		URT:    ut,
		UA:     strings.ToLower(f[11]),
		Ref:    strings.ToLower(f[10]),
	}, true
}

func zero(s string) string {
	if s == "" || s == "-" {
		return "0"
	}
	return s
}

// isBotUA κάνει ένα απλό substring-based detection για bot-like UAs.
// Το χρησιμοποιούμε και στο short drilldown και στο short snapshot (MiniMetrics).
func isBotUA(ua string) bool {
	sub := []string{
		"bot", "spider", "crawl", "scanner",
		"ahrefs", "semrush",
		"python-requests", "curl", "wget",
		"headless", "puppeteer",
	}
	l := strings.ToLower(ua)
	for _, s := range sub {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

type bucketSW struct {
	from, to time.Time
	total    int

	c2xx int
	c3xx int
	c4xx int
	c5xx int
	c401 int
	c403 int
	c404 int
	c500 int
	c502 int
	c503 int
	c504 int
	c499 int

	// Method mix
	cGET   int
	cPOST  int
	cHEAD  int
	cOTHER int

	sumRT    float64
	sumBytes int64

	ips map[string]int

	// Keep a few representative raw lines per IP for alert samples.
	// (We store the first line seen per IP per bucket.)
	ipSample map[string]string

	ips403     map[string]int
	ips404     map[string]int
	ipsAgent   map[string]int
	ipsMalPath map[string]int
	ipsMalRule map[string]map[int]int // ip -> ruleIndex -> count

	ips403WAF map[string]int // WAF-origin 403s (from OpenResty cfm_waf.lua via observe)

	// Challenge paths counters (for "challenge-only" actions)
	ipsChalPath map[string]int
	ipsChalRule map[string]map[int]int // ip -> ruleIndex -> count

	// Lightweight per-IP counters for challenge thresholds
	ips4xx       map[string]int
	ips5xx       map[string]int
	ipsPOST      map[string]int
	ipsNoUA      map[string]int
	ipsHTTP10    map[string]int
	ipsMalformed map[string]int                 // 400+414+431 per IP
	ipsUniqUA    map[string]map[uint64]struct{} // UA churn: ip -> set(hash(ua))

	// 40x combo support (403+404) for IP-level detectors
	ips40x     map[string]int
	ip40xPaths map[string]map[uint64]struct{}

	// NEW: unique signals (memory-safe via hash sets with cap)
	ipUniqPaths map[string]map[uint64]struct{} // ip -> set(hash(path))
	ipUniqHosts map[string]map[uint64]struct{} // ip -> set(hash(host))

	uas   map[string]int
	refs  map[string]int
	paths map[string]int

	// subnet behavioral aggregation (IPv4 /24 etc)
	subnetReqs      map[string]int                 // subnet -> req count
	subnetIPs       map[string]map[string]struct{} // subnet -> distinct IPs
	subnetUniqPaths map[string]map[uint64]struct{} // subnet -> uniq paths
	subnetUniqHosts map[string]map[uint64]struct{} // subnet -> uniq hosts
	subnetHostReqs  map[string]map[string]int      // subnet -> host -> req count

}

type hostState struct {
	buckets []bucketSW
	samples *core.SampleRing
}

// ShortRow is the short-window row for webtop.
type ShortRow struct {
	Host         string   `json:"host"`
	RPS          float64  `json:"rps"`
	R2xx         float64  `json:"rps_2xx"`
	R3xx         float64  `json:"rps_3xx"`
	R4xx         float64  `json:"rps_4xx"`
	R5xx         float64  `json:"rps_5xx"`
	R401         float64  `json:"rps_401"`
	R403         float64  `json:"rps_403"`
	R404         float64  `json:"rps_404"`
	R499         float64  `json:"rps_499"`
	UniqueIPs    int      `json:"unique_ips"`
	ErrRatio     float64  `json:"err_ratio"`
	Auth401Ratio float64  `json:"auth401_ratio"`
	ProcAvgSec   float64  `json:"proc_avg_sec"`
	Score        float64  `json:"score"`
	Reasons      []string `json:"reasons"`
	BytesRPS     float64  `json:"bytes_rps"`

	BotRatio      float64 `json:"bot_ratio"`
	UADiversity   float64 `json:"ua_diversity"`
	PathDiversity float64 `json:"path_diversity"`
	PostRatio     float64 `json:"post_ratio"`
}

// TopKV for drilldown views.
type TopKV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// HostDetail is the drill-down view for a single host over the short window.
type HostDetail struct {
	Host          string  `json:"host"`
	WindowSec     float64 `json:"window_sec"`
	TotalReq      int     `json:"total_req"`
	DirectPct     float64 `json:"direct_pct"`
	BotPct        float64 `json:"bot_pct"`
	PathDiversity float64 `json:"path_diversity"`
	UniquePaths   int     `json:"unique_paths"`
	UADiversity   float64 `json:"ua_diversity"`
	UniqueUAs     int     `json:"unique_uas"`
	PostRatio     float64 `json:"post_ratio"`
	ProcAvgSec    float64 `json:"proc_avg_sec"`

	// Short-window scoring for this vhost
	ShortScore   float64  `json:"short_score"`
	ShortReasons []string `json:"short_reasons"`

	TopIPs         []TopKV             `json:"top_ips"`
	TopAgents      []TopKV             `json:"top_agents"`
	TopReferrers   []TopKV             `json:"top_referrers"`
	TopPaths       []TopKV             `json:"top_paths"`
	EnrichedTopIPs []map[string]string `json:"enriched_top_ips,omitempty"`

	// Feature dump (για ML / debug)
	MedianPerIPRPS float64 `json:"median_per_ip_rps"`
	BytesRPS       float64 `json:"bytes_rps"`
	HotIPs         int     `json:"hot_ips"`
	FailureIndex   float64 `json:"failure_index"`
	UAEntropy      float64 `json:"ua_entropy"`
	PathEntropy    float64 `json:"path_entropy"`
	IPSkew         float64 `json:"ip_skew"`
}

// HotIPRow είναι global aggregated view per IP.
type HotIPRow struct {
	IP     string `json:"ip"`
	Req    int    `json:"req"`
	Vhosts int    `json:"vhosts"`

	PTR     string `json:"ptr,omitempty"`
	ASN     string `json:"asn,omitempty"`
	ASNName string `json:"asn_name,omitempty"`
	Country string `json:"country,omitempty"`
}

// IPDetail είναι short-window drilldown για ένα IP.
type IPDetail struct {
	IP        string  `json:"ip"`
	WindowSec float64 `json:"window_sec"`
	Req       int     `json:"req"`
	Vhosts    int     `json:"vhosts"`

	// per-vhost breakdown
	Hosts []TopKV `json:"hosts"`

	// απλό rate
	RPS float64 `json:"rps"`

	// 🔥 Long-window (EMA) view
	LongHorizonSec float64  `json:"long_horizon_sec,omitempty"`
	LongReq        int      `json:"long_req,omitempty"`
	LongVhosts     int      `json:"long_vhosts,omitempty"`
	LongRPS        float64  `json:"long_rps,omitempty"`
	LongScore      float64  `json:"long_score,omitempty"`
	LongReasons    []string `json:"long_reasons,omitempty"`

	// enrichment
	PTR     string `json:"ptr,omitempty"`
	ASN     string `json:"asn,omitempty"`
	ASNName string `json:"asn_name,omitempty"`
	Country string `json:"country,omitempty"`
}

// IPSignals είναι το "full" IP-level row με score & προτάσεις.
type IPSignals struct {
	IP      string   `json:"ip"`
	Req     int      `json:"req"`
	Vhosts  int      `json:"vhosts"`
	RPS     float64  `json:"rps"`
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons,omitempty"`

	PTR     string `json:"ptr,omitempty"`
	ASN     string `json:"asn,omitempty"`
	ASNName string `json:"asn_name,omitempty"`
	Country string `json:"country,omitempty"`

	Proposals []IPActionProposal `json:"proposals,omitempty"`
}

type IPActionProposal struct {
	Action     string  `json:"action"`                // "block", "notify", "watch", ...
	Reason     string  `json:"reason"`                // π.χ. "ip_score_high"
	Score      float64 `json:"score"`                 // το score που οδήγησε στην πρόταση
	TTLSeconds int     `json:"ttl_seconds,omitempty"` // (CLI compatibility; unused for now)
}

// ipLongAgg κρατά “μαλακά” averages για το long window.
type ipLongAgg struct {
	Req    float64
	Vhosts float64
	RPS    float64
}

// ipLongMem είναι το global IP long-window state.
type ipLongMem struct {
	mu         sync.RWMutex
	stats      map[string]*ipLongAgg
	lastUpdate time.Time
}

// Engine is the main web detector instance.
type Engine struct {
	cfg      Config
	src      core.LineSource
	state    *core.State
	stateKey string

	adapter  LogFormatAdapter
	malRules []malRule

	chalRules   []chalRule
	nginxBridge *NginxBridge // nil if OpenRestyMode disabled
	manualChal  manualChalState

	// bypassFunc: covers IGNORE_IPS / IGNORE_NETS — skip emit entirely for these IPs.
	// Set once at startup via SetBypassFunc (no lock needed).
	bypassFunc func(string) bool

	// chalExcludeFunc: covers ASN/UA/PTR challenge-exclude rules.
	// Signature mirrors ChallengeExclude.Match but returns only (action, matched).
	// Set once at startup via SetChalExcludeFunc (no lock needed).
	chalExcludeFunc func(ip, host, ua, asn, ptr, rule string) (string, bool)

	mu    sync.RWMutex
	hosts map[string]*hostState

	longwin *LongWindow
	scorer  Scorer
	enr     *enrich.Enricher

	lastFeed time.Time  // last time we fed long-window
	ipLong   *ipLongMem // long-window IP aggregates (EMA)

	// Emit rate-limit so we don't spam blocker every tick.
	emitMu     sync.Mutex
	ipLastEmit map[string]time.Time

	// Challenge emit cooldown separate from blocks
	ipLastChalEmit map[string]time.Time

	// Subnet challenge emit cooldown
	subnetLastChalEmit map[string]time.Time

	// last context for an IP that matched a challenge rule (host/uri/pattern)
	chalLast map[string]chalCtx

	// VHOST under-attack state (auto suspicious)
	vhostMu          sync.Mutex
	vhostUnderAttack map[string]bool
	vhostLastChange  map[string]time.Time

	// NEW: vhost uniqpaths state (phase 1) to avoid log spam + hysteresis
	vhostUniqPathsActive     map[string]bool
	vhostUniqPathsLastChange map[string]time.Time

	// --- ingest progress / stall logging (for "silent stops") ---
	progMu            sync.Mutex
	lastParsedAt      time.Time
	lastProgressLogAt time.Time
	parsedSinceLog    int64

	// --- periodic pruning of unbounded emit/cooldown maps ---
	lastEmitPrune time.Time

	// Challenge API state (vhost/ip/events)
	chalAPI         *ChallengeAPIStore
	chalOnce        sync.Once
	chalExpiredSeen map[string]time.Time

	challengeExcludes *excludeStore
	wafExcludes       *excludeStore
	trafficRules      *trafficRuleStore
	history           *HistoryStore
}

type malRule struct {
	sub   string // already lowercased
	count int
}

// NewEngine creates a webdetector Engine. It does NOT start any goroutines.
func NewEngine(cfg Config) *Engine {
	cfg.FillDefaults()

	e := &Engine{
		cfg:     cfg,
		hosts:   make(map[string]*hostState),
		scorer:  DefaultScorer(),
		longwin: NewLongWindow(cfg.LongHorizon(), cfg.Window, DefaultScorer()),
		//chris//
		adapter: NewAutoDetectAdapter(),

		ipLong: &ipLongMem{
			stats: make(map[string]*ipLongAgg),
		},
		ipLastEmit: make(map[string]time.Time),
	}

	// Challenge API store (ring buffer events + vhost/ip state)
	e.chalAPI = NewChallengeAPIStore(50000)
	e.chalExpiredSeen = make(map[string]time.Time)
	e.challengeExcludes = newExcludeStore(cfg.ChallengeExcludeStorePath)
	e.wafExcludes = newExcludeStore(cfg.WAFExcludeStorePath)
	e.trafficRules = newTrafficRuleStore(cfg.TrafficRulesStorePath)
	// manual from api webtop challenge add//
	e.manualChal.init()

	// enable openresty mode//
	if cfg.OpenRestyMode {
		e.nginxBridge = NewNginxBridge(cfg.OpenRestySock, cfg.OpenRestyToken, cfg.ChallengePathsTTL, cfg.OpenRestyOkIPTTL)
		e.nginxBridge.IsWAFExcluded = e.isWAFExcluded
		e.nginxBridge.HasWAFExcludes = e.WAFExcludeHasAny
		e.nginxBridge.ListWAFExcludes = e.WAFExcludeList
		e.nginxBridge.RuleDecision = e.TrafficRuleSimulate
		e.nginxBridge.ListTrafficRules = e.TrafficRuleList
	}
	// Compile MALPATH rules. Supports "N:substring" override syntax.
	e.malRules = compileMalRules(cfg.MalPathList, cfg.MalPathCount)

	// Compile CHALLENGE rules (paths). Supports "N:substring" override syntax.
	if cfg.ChallengePathsEnabled {
		e.chalRules = compileChalRules(cfg.ChallengePathsList, cfg.ChallengePathsCount)
	}

	e.ipLastChalEmit = make(map[string]time.Time)
	e.subnetLastChalEmit = make(map[string]time.Time)
	e.chalLast = make(map[string]chalCtx)

	e.vhostUnderAttack = make(map[string]bool)
	e.vhostLastChange = make(map[string]time.Time)

	e.vhostUniqPathsActive = make(map[string]bool)
	e.vhostUniqPathsLastChange = make(map[string]time.Time)

	if cfg.HistoryEnabled {
		if hs, err := NewHistoryStore(cfg.HistoryDBPath, cfg.HistoryRetentionDays, cfg.HistoryPruneEvery); err != nil {
			logging.Logf("[webdetector][history] disabled (init failed): %v", err)
		} else {
			e.history = hs
			logging.Logf("[webdetector][history] enabled sqlite db=%s retention_days=%d prune_every=%s", cfg.HistoryDBPath, cfg.HistoryRetentionDays, cfg.HistoryPruneEvery)
		}
	}

	// Enrichment is optional.
	if cfg.UseEnrich {
		dirs := cfg.EnrichDirs
		if len(dirs) == 0 {
			dirs = []string{"/var/lib/cfm/maxmind", "/etc/cfm"}
		}
		if enr, err := enrich.New(dirs...); err == nil {
			e.enr = enr
			logging.Logf("[webdetector] enrichment enabled (dirs=%v)", dirs)
		} else {
			logging.Logf("[webdetector] enrichment init failed: %v", err)
		}
	}

	return e
}

func subnetKeyV4(ip string, prefix int) string {
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	if prefix <= 0 || prefix > 32 {
		prefix = 24
	}
	mask := net.CIDRMask(prefix, 32)
	netIP := v4.Mask(mask)
	return fmt.Sprintf("%s/%d", netIP.String(), prefix)
}

func addStringToSetWithCap(m map[string]map[string]struct{}, key, val string, capN int) {
	if key == "" || val == "" {
		return
	}
	if capN <= 0 {
		capN = 1024
	}
	set := m[key]
	if set == nil {
		set = make(map[string]struct{}, 8)
		m[key] = set
	}
	if len(set) >= capN {
		return
	}
	set[val] = struct{}{}
}

// ChallengeAPI returns the in-memory store used by the challenge JSON API.
func (e *Engine) ChallengeAPI() *ChallengeAPIStore {
	return e.chalAPI
}

// RecordChallengeSolved updates the store when a challenge is solved.
func (e *Engine) RecordChallengeSolved(ip, host, uri string, diff int, ms int64) {
	if e == nil || e.chalAPI == nil {
		return
	}
	e.chalAPI.RecordSolved(ip, host, uri, diff, ms)
	e.appendHistory(HistoryEvent{TsUnix: time.Now().Unix(), Type: "challenge_solved", Host: host, IP: ip, Payload: map[string]interface{}{"uri": uri, "diff": diff, "ms": ms}})
}

// RecordIPChallenge updates the store when we emit a challenge for an IP.
func (e *Engine) RecordIPChallenge(ip, host, rule, uri, method string, status int, ttl time.Duration) {
	if e == nil || e.chalAPI == nil {
		return
	}
	e.chalAPI.RecordIPChallenge(ip, host, rule, uri, method, status, ttl)
	e.appendHistory(HistoryEvent{TsUnix: time.Now().Unix(), Type: "challenge_issued", Host: host, IP: ip, Reason: rule, TTLSec: int(ttl / time.Second), Status: status, Payload: map[string]interface{}{"uri": uri, "method": method, "expires_at": time.Now().Add(ttl).Unix()}})
}

// RecordVhostAuto records auto_on/auto_off for vhosts (and current metrics).
func (e *Engine) RecordVhostAuto(host string, active bool, row SuspiciousRow, on, off float64, hold time.Duration) {
	if e == nil || e.chalAPI == nil {
		return
	}
	e.chalAPI.RecordVhostAuto(host, active, row, on, off, hold)
	typ := "challenge_vhost_auto_off"
	if active {
		typ = "challenge_vhost_auto_on"
	}
	e.appendHistory(HistoryEvent{TsUnix: time.Now().Unix(), Type: typ, Host: host, Mode: "auto", Score: row.Score, UniqIP: row.UniqueIPs, RPS: row.RPS, Reason: strings.Join(row.Reasons, ",")})
}

func (e *Engine) appendHistory(ev HistoryEvent) {
	if e == nil || e.history == nil {
		return
	}
	e.history.Append(ev)
}

// RecordWAFTrigger persists a WAF trigger event emitted by OpenResty/Lua bridge
// so UI/CLI analytics can include logonly/challenge/block triggers from cfm.waf.log.
func (e *Engine) RecordWAFTrigger(ip, host, uri, method, action, reason string, ttl time.Duration, asn uint, asnName, country string) {
	if e == nil {
		return
	}
	host = cleanHost(host)
	method = strings.ToLower(strings.TrimSpace(method))
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		action = "triggered"
	}
	e.appendHistory(HistoryEvent{
		TsUnix: time.Now().Unix(),
		Type:   "waf_trigger",
		Host:   host,
		IP:     strings.TrimSpace(ip),
		Reason: strings.TrimSpace(reason),
		Mode:   action,
		TTLSec: int(ttl / time.Second),
		Payload: map[string]interface{}{
			"uri":      uri,
			"method":   method,
			"action":   action,
			"asn":      asn,
			"asn_name": strings.TrimSpace(asnName),
			"country":  strings.TrimSpace(country),
		},
	})
}

func (e *Engine) expireOldChallenges() {
	if e == nil || e.history == nil || e.chalAPI == nil {
		return
	}
	now := time.Now()
	for _, st := range e.chalAPI.ListIPs("", "challenge", 2000) {
		if st.ExpiresAt.IsZero() || st.ExpiresAt.After(now) {
			continue
		}
		key := st.IP + "|" + cleanHost(st.Host)
		if ts, ok := e.chalExpiredSeen[key]; ok && ts.Equal(st.ExpiresAt) {
			continue
		}
		e.chalExpiredSeen[key] = st.ExpiresAt
		e.history.Append(HistoryEvent{
			TsUnix: now.Unix(),
			Type:   "challenge_expired_unsolved",
			Host:   st.Host,
			IP:     st.IP,
			Reason: st.Rule,
			Payload: map[string]interface{}{
				"expires_at": st.ExpiresAt.Unix(),
			},
		})
	}
}

// --- integration with detectors framework ---

func (e *Engine) SetSource(src core.LineSource)       { e.src = src }
func (e *Engine) SetState(st *core.State, key string) { e.state = st; e.stateKey = key }
func (e *Engine) Every() time.Duration                { return e.cfg.Every }

// Enricher returns the optional MaxMind/DNS enricher instance (may be nil).
func (e *Engine) Enricher() *enrich.Enricher { return e.enr }

// NginxBridge returns the bridge instance (may be nil).
func (e *Engine) NginxBridge() *NginxBridge { return e.nginxBridge }

// Name implements core.PeriodicDetector.
func (e *Engine) Name() string {
	return "webdetector"
}

// sourceLabel returns the real ingest source for logs/debug messages.
// In file mode we show LogPath, in folder mode we show LogDir (+ glob).
func (e *Engine) sourceLabel() string {
	mode := strings.ToLower(strings.TrimSpace(e.cfg.Mode))
	switch mode {
	case "folder":
		dir := strings.TrimSpace(e.cfg.LogDir)
		if dir == "" {
			dir = "(unset)"
		}
		glob := strings.TrimSpace(e.cfg.Glob)
		if glob != "" {
			return fmt.Sprintf("%s (glob=%s recursive=%v)", dir, glob, e.cfg.Recursive)
		}
		return fmt.Sprintf("%s (recursive=%v)", dir, e.cfg.Recursive)
	default:
		p := strings.TrimSpace(e.cfg.LogPath)
		if p == "" {
			p = "(unset)"
		}
		return p
	}
}

func (e *Engine) ApplyPosition(p core.Position) {
	if ft, ok := e.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
}
func (e *Engine) Position() core.Position {
	if e.src == nil {
		return core.Position{}
	}
	off, ino, ts := e.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

// RunOnce reads new log lines, updates short-window state, and periodically
// feeds the long-window ring. It does NOT currently emit Alerts (L7 autotune),
// only maintains data for webtop/HTTP API.
func (e *Engine) RunOnce(ctx context.Context, out chan<- core.Alert) error {

	if e.src == nil {
		return nil
	}

	// resume pos
	if e.state != nil && e.stateKey != "" {
		if p, ok := e.state.Get(e.stateKey); ok {
			e.ApplyPosition(p)
		}
	}

	if err := e.src.Open(); err != nil {
		// This can happen during log rotation/atomic writes. We keep the periodic
		// loop alive, but log enough context to diagnose "stuck" behavior.
		logging.Logf("[webdetector] tail open failed: %v (mode=%s source=%q)",
			err, e.cfg.Mode, e.sourceLabel())
		return fmt.Errorf("webdetector: tail open failed: %w", err)

	}
	defer e.src.Close()

	now := time.Now()
	for {
		line, err := e.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			off, ino, ts := e.src.Position()
			logging.Logf("[webdetector] tail read failed: %v (off=%d ino=%d ts=%d mode=%s source=%q)",
				err, off, ino, ts, e.cfg.Mode, e.sourceLabel())
			return fmt.Errorf("webdetector: tail read failed: %w", err)
		}
		//chris//
		//rec, ok := parseTSV(line)
		rec, ok := e.adapter.Parse(line)
		if !ok {
			continue
		}

		// progress marker: we successfully parsed a record
		e.progMu.Lock()
		e.lastParsedAt = time.Now()
		e.parsedSinceLog++
		e.progMu.Unlock()

		e.ingest(rec, line)
	}

	// Ensure buckets age out even when there are no new log lines.
	// (Without this, snapshots can look "stuck" until traffic resumes.)
	now = time.Now()
	e.pruneShort(now)

	// Prune unbounded emit/cooldown maps periodically.
	// Rate-limited to once per long-horizon interval to keep cost negligible.
	horizon := e.cfg.LongHorizon()
	if horizon <= 0 {
		horizon = 20 * time.Minute
	}
	if e.lastEmitPrune.IsZero() || now.Sub(e.lastEmitPrune) >= horizon {
		e.pruneEmitMaps(now)
		e.lastEmitPrune = now
	}

	// Feed long-window approx once per short-window horizon.
	if e.lastFeed.IsZero() || now.Sub(e.lastFeed) >= e.cfg.Window {
		snap := e.snapshotMini(now)
		e.longwin.Tick(now, snap)
		e.updateIPLong(now) //  update EMA-based IP long view
		e.lastFeed = now
	}

	// Emit challenge-worthy IP alerts (before blocks)
	e.emitIPChallenges(now, out)

	// Emit block-worthy IP alerts (picked up by autosink blocker).
	e.emitIPBlocks(now, out)
	e.expireOldChallenges()

	// save pos
	if e.state != nil && e.stateKey != "" {
		e.state.Put(e.stateKey, e.Position())
	}

	// Long-window heartbeat: once per long horizon (e.g. 20m) log either:
	// - progress: last parsed timestamp + count since last log
	// - stall: no parsed lines for >= long horizon
	e.logIngestHeartbeat(now)

	return nil
}

// logIngestHeartbeat emits a low-noise progress/stall log line at long-window cadence.
// This helps diagnose "silent stop" scenarios (tail stuck, goroutine hung, file rotated, etc.)
// without spamming every tick.
func (e *Engine) logIngestHeartbeat(now time.Time) {
	horizon := e.cfg.LongHorizon()
	if horizon <= 0 {
		return
	}

	e.progMu.Lock()
	defer e.progMu.Unlock()

	// throttle to once per horizon
	if !e.lastProgressLogAt.IsZero() && now.Sub(e.lastProgressLogAt) < horizon {
		return
	}
	e.lastProgressLogAt = now

	// If we never parsed anything, treat as stall-ish but explicit.
	if e.lastParsedAt.IsZero() {
		logging.Logf("[webdetector][stall] no parsed lines yet (horizon=%s mode=%s source=%q)",
			horizon, e.cfg.Mode, e.sourceLabel())
		e.parsedSinceLog = 0
		return
	}

	idle := now.Sub(e.lastParsedAt)
	if idle >= horizon {
		logging.Logf("[webdetector][stall] no parsed lines for %s (last=%s horizon=%s mode=%s source=%q)",
			idle.Truncate(time.Second), e.lastParsedAt.UTC().Format(time.RFC3339), horizon, e.cfg.Mode, e.sourceLabel())
		e.parsedSinceLog = 0
		return
	}

	// normal progress log
	logging.Logf("[webdetector][progress] parsed=%d last=%s idle=%s horizon=%s mode=%s source=%q",
		e.parsedSinceLog,
		e.lastParsedAt.UTC().Format(time.RFC3339),
		idle.Truncate(time.Second),
		horizon,
		e.cfg.Mode,
		e.sourceLabel(),
	)
	e.parsedSinceLog = 0
}

// ingest updates per-host buckets with one log record.
func (e *Engine) ingest(rec LogRec, rawLine string) {
	host := strings.ToLower(strings.TrimSpace(rec.Host))
	if host == "" {
		return
	}

	t := tsToTime(rec.TS)
	e.mu.Lock()
	defer e.mu.Unlock()

	hs := e.hosts[host]
	if hs == nil {
		hs = &hostState{
			buckets: make([]bucketSW, 0, 16),
			samples: core.NewSampleRing(e.cfg.SampleLimit),
		}
		e.hosts[host] = hs
	}

	// Append sample line (for debugging / future ML).
	hs.samples.Add(host, rawLine)

	bDur := e.cfg.Every
	if bDur <= 0 {
		bDur = 5 * time.Second
	}

	// rotate/prune old buckets
	cutoff := t.Add(-e.cfg.Window)
	i := 0
	for ; i < len(hs.buckets); i++ {
		if hs.buckets[i].to.After(cutoff) {
			break
		}
	}
	if i > 0 {
		hs.buckets = append([]bucketSW(nil), hs.buckets[i:]...)
	}

	// ensure current bucket
	var b *bucketSW
	if len(hs.buckets) == 0 {
		start := t.Truncate(bDur)
		hs.buckets = append(hs.buckets, newBucketSW(start, bDur))
		b = &hs.buckets[0]
	} else {
		last := &hs.buckets[len(hs.buckets)-1]
		if !t.Before(last.to) {
			start := t.Truncate(bDur)
			hs.buckets = append(hs.buckets, newBucketSW(start, bDur))
			b = &hs.buckets[len(hs.buckets)-1]
		} else {
			b = last
		}
	}

	// aggregate stats
	b.total++
	switch rec.Status / 100 {
	case 2:
		b.c2xx++
	case 3:
		b.c3xx++
	case 4:
		b.c4xx++
		switch rec.Status {
		case 401:
			b.c401++
		case 403:
			b.c403++
		case 404:
			b.c404++
		}
	case 5:
		b.c5xx++
		switch rec.Status {
		case 500:
			b.c500++
		case 502:
			b.c502++
		case 503:
			b.c503++
		case 504:
			b.c504++
		}
	}

	if rec.Status == 499 {
		b.c499++
	}

	// Method mix
	switch rec.Method {
	case "get":
		b.cGET++
	case "post":
		b.cPOST++
	case "head":
		b.cHEAD++
	default:
		b.cOTHER++
	}

	if b.ips == nil {
		b.ips = make(map[string]int)
	}
	if rec.IP != "" {
		b.ips[rec.IP]++

		if b.ipSample == nil {
			b.ipSample = make(map[string]string)
		}
		if _, ok := b.ipSample[rec.IP]; !ok {
			b.ipSample[rec.IP] = rawLine
		}
	}

	// Per-IP error thresholds (optional)
	if rec.IP != "" {
		if rec.Status == 403 && e.cfg.IP403Count > 0 {
			if b.ips403 == nil {
				b.ips403 = make(map[string]int)
			}
			b.ips403[rec.IP]++
		}
		if rec.Status == 404 && e.cfg.IP404Count > 0 {
			if b.ips404 == nil {
				b.ips404 = make(map[string]int)
			}
			b.ips404[rec.IP]++
		}
		if len(e.cfg.AgentList) > 0 && e.cfg.AgentCount > 0 && rec.UA != "" {
			if uaMatchAny(rec.UA, e.cfg.AgentList) {
				if b.ipsAgent == nil {
					b.ipsAgent = make(map[string]int)
				}
				b.ipsAgent[rec.IP]++
			}
		}
	}

	// Malicious path probe thresholds (optional)
	if rec.IP != "" && e.cfg.MalPathCount > 0 && len(e.cfg.MalPathList) > 0 {
		// p is already normalized below; but we can safely use rec.URI too (lowercased).
		// We'll count based on the normalized path (no query string).
	}

	if b.uas == nil {
		b.uas = make(map[string]int)
	}
	if rec.UA != "" {
		b.uas[rec.UA]++
	}

	if b.refs == nil {
		b.refs = make(map[string]int)
	}
	ref := rec.Ref
	if ref == "" || ref == "-" {
		ref = "(direct)"
	}
	b.refs[ref]++

	if b.paths == nil {
		b.paths = make(map[string]int)
	}
	p := rec.URI
	if p == "" || p == "-" {
		p = "/"
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	b.paths[p]++

	// ------------------------------------------------------------
	// NEW: unique-based challenge signals (phase 1)
	// ------------------------------------------------------------
	if rec.IP != "" {
		// Unique paths per IP (sneaky scraper)

		// Unique paths per IP (sneaky scraper)
		// IMPORTANT: count path-only (no query) and ignore static assets
		// to avoid false positives on WP admin / heavy asset pages.
		if e.cfg.ChallengeIPUniqPathsEnabled && e.cfg.ChallengeIPUniqPathsMin > 0 {
			if !isStaticAssetPath(p) {
				if b.ipUniqPaths == nil {
					b.ipUniqPaths = make(map[string]map[uint64]struct{})
				}
				addHashToSetWithCap(b.ipUniqPaths, rec.IP, hash64(p), e.cfg.ChallengeIPUniqPathsCap)
			}
		}

		// Unique hosts per IP (scanner / vhost enumeration)
		if e.cfg.ChallengeIPUniqHostsEnabled && e.cfg.ChallengeIPUniqHostsMin > 0 {
			if b.ipUniqHosts == nil {
				b.ipUniqHosts = make(map[string]map[uint64]struct{})
			}
			addHashToSetWithCap(b.ipUniqHosts, rec.IP, hash64(host), e.cfg.ChallengeIPUniqHostsCap)
		}
	}

	// ------------------------------------------------------------
	// NEW: subnet-based challenge signals
	// ------------------------------------------------------------
	if e.cfg.ChallengeSubnetEnabled && rec.IP != "" {
		sub := subnetKeyV4(rec.IP, e.cfg.ChallengeSubnetPrefixV4)
		if sub != "" {
			if b.subnetReqs == nil {
				b.subnetReqs = make(map[string]int)
			}
			b.subnetReqs[sub]++

			if b.subnetIPs == nil {
				b.subnetIPs = make(map[string]map[string]struct{})
			}
			addStringToSetWithCap(b.subnetIPs, sub, rec.IP, e.cfg.ChallengeSubnetCap)

			if !isStaticAssetPath(p) {
				if b.subnetUniqPaths == nil {
					b.subnetUniqPaths = make(map[string]map[uint64]struct{})
				}
				addHashToSetWithCap(b.subnetUniqPaths, sub, hash64(p), e.cfg.ChallengeSubnetCap)
			}

			if host != "" {
				if b.subnetUniqHosts == nil {
					b.subnetUniqHosts = make(map[string]map[uint64]struct{})
				}
				addHashToSetWithCap(b.subnetUniqHosts, sub, hash64(host), e.cfg.ChallengeSubnetCap)

				if b.subnetHostReqs == nil {
					b.subnetHostReqs = make(map[string]map[string]int)
				}
				hm := b.subnetHostReqs[sub]
				if hm == nil {
					hm = make(map[string]int)
					b.subnetHostReqs[sub] = hm
				}
				hm[host]++
			}
		}
	}

	// Per-IP challenge counters (only allocate maps if a related threshold is enabled)
	if rec.IP != "" {
		// status class counters
		if (e.cfg.ChallengeIP4xxRPSMin > 0 || e.cfg.ChallengeIPErrRatioMin > 0) && rec.Status/100 == 4 {
			if b.ips4xx == nil {
				b.ips4xx = make(map[string]int)
			}
			b.ips4xx[rec.IP]++
			e.chalLast[rec.IP] = chalCtx{Host: rec.Host, URI: p, Method: rec.Method, Status: rec.Status, UA: rec.UA, Sub: "4xx", TS: rec.TS}
		}
		if (e.cfg.ChallengeIP5xxRPSMin > 0 || e.cfg.ChallengeIPErrRatioMin > 0) && rec.Status/100 == 5 {
			if b.ips5xx == nil {
				b.ips5xx = make(map[string]int)
			}
			b.ips5xx[rec.IP]++
			e.chalLast[rec.IP] = chalCtx{Host: rec.Host, URI: p, Method: rec.Method, Status: rec.Status, UA: rec.UA, Sub: "5xx", TS: rec.TS}
		}

		// method ratio
		if e.cfg.ChallengeIPPostRatioMin > 0 && rec.Method == "post" {
			if b.ipsPOST == nil {
				b.ipsPOST = make(map[string]int)
			}
			b.ipsPOST[rec.IP]++
			e.chalLast[rec.IP] = chalCtx{Host: rec.Host, URI: p, Method: rec.Method, Status: rec.Status, UA: rec.UA, Sub: "post", TS: rec.TS}
		}

		// empty UA
		if e.cfg.ChallengeIPNoUAMin > 0 {
			if rec.UA == "" || rec.UA == "-" {
				if !isMachineStyleEndpointGo(p) {
					if b.ipsNoUA == nil {
						b.ipsNoUA = make(map[string]int)
					}
					b.ipsNoUA[rec.IP]++
					e.chalLast[rec.IP] = chalCtx{
						Host:   rec.Host,
						URI:    p,
						Method: rec.Method,
						UA:     rec.UA,
						Status: rec.Status,
						Sub:    "no_ua",
						TS:     rec.TS,
					}
				}
			}
		}

		// malformed request burst: 400 Bad Request + 414 URI Too Long + 431 Headers Too Large
		if e.cfg.ChallengeIPMalformedMin > 0 &&
			(rec.Status == 400 || rec.Status == 414 || rec.Status == 431) {
			if b.ipsMalformed == nil {
				b.ipsMalformed = make(map[string]int)
			}
			b.ipsMalformed[rec.IP]++
			e.chalLast[rec.IP] = chalCtx{Host: rec.Host, URI: p, Method: rec.Method, Status: rec.Status, UA: rec.UA, Sub: "malformed", TS: rec.TS}
		}

		// UA churn: too many distinct User-Agents from the same IP
		if e.cfg.ChallengeIPUniqUAMin > 0 && rec.UA != "" && rec.UA != "-" {
			if b.ipsUniqUA == nil {
				b.ipsUniqUA = make(map[string]map[uint64]struct{})
			}
			addHashToSetWithCap(b.ipsUniqUA, rec.IP, hash64(rec.UA), e.cfg.ChallengeIPUniqUACap)
		}
	}

	// Challenge-only rule checks (paths)
	e.trackChallengePaths(rec, p, b)

	// Now that we have normalized path `p`, count malicious probes per IP.
	if rec.IP != "" && e.cfg.MalPathCount > 0 && len(e.cfg.MalPathList) > 0 {

		if rec.IP != "" && len(e.malRules) > 0 {
			pl := strings.ToLower(p)
			for ridx, r := range e.malRules {
				if r.sub != "" && strings.Contains(pl, r.sub) {
					if b.ipsMalPath == nil {
						b.ipsMalPath = make(map[string]int)
					}
					b.ipsMalPath[rec.IP]++ // total MALPATH hits (for stats)

					if b.ipsMalRule == nil {
						b.ipsMalRule = make(map[string]map[int]int)
					}
					m := b.ipsMalRule[rec.IP]
					if m == nil {
						m = make(map[int]int)
						b.ipsMalRule[rec.IP] = m
					}
					m[ridx]++
					break // count only the first matching rule per request (prevents double-count inflation)
				}
			}
		}

	}

	// 40x combo counters (403+404) per IP, with optional ignore prefixes + unique-path gating.
	if rec.IP != "" && e.cfg.IP40xComboCount > 0 && (rec.Status == 403 || rec.Status == 404) {
		if !hasAnyPrefix(p, e.cfg.Ignore40xPrefixes) {
			if b.ips40x == nil {
				b.ips40x = make(map[string]int)
			}
			b.ips40x[rec.IP]++

			if e.cfg.IP40xComboUniquePaths > 0 {
				if b.ip40xPaths == nil {
					b.ip40xPaths = make(map[string]map[uint64]struct{})
				}
				set := b.ip40xPaths[rec.IP]
				if set == nil {
					set = make(map[uint64]struct{})
					b.ip40xPaths[rec.IP] = set
				}
				set[hash64(p)] = struct{}{}
			}
		}
	}

	b.sumRT += rec.RT
	b.sumBytes += rec.Bytes

}

func newBucketSW(start time.Time, dur time.Duration) bucketSW {
	return bucketSW{
		from:     start,
		to:       start.Add(dur),
		ips:      make(map[string]int),
		ipSample: make(map[string]string),
		uas:      make(map[string]int),
		refs:     make(map[string]int),
		paths:    make(map[string]int),
	}
}

func tsToTime(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * float64(time.Second))
	return time.Unix(sec, nsec)
}

// pruneShort prunes per-host buckets older than the configured short window,
// even when there is no new traffic (so the view stays "live").
func (e *Engine) pruneShort(now time.Time) {
	win := e.cfg.Window
	if win <= 0 {
		return
	}
	cutoff := now.Add(-win)

	e.mu.Lock()
	defer e.mu.Unlock()

	for host, hs := range e.hosts {
		if hs == nil || len(hs.buckets) == 0 {
			delete(e.hosts, host)
			continue
		}
		i := 0
		for ; i < len(hs.buckets); i++ {
			if hs.buckets[i].to.After(cutoff) {
				break
			}
		}
		if i > 0 {
			hs.buckets = hs.buckets[i:]
		}
		if len(hs.buckets) == 0 {
			delete(e.hosts, host)
		}
	}
}

// pruneEmitMaps removes stale entries from all per-IP and per-subnet cooldown
// maps that would otherwise grow indefinitely on servers under sustained attack.
//
// Called from RunOnce at most once per long-horizon interval (~20 min default).
// The cutoff is 2× the long horizon — conservative enough to avoid evicting
// entries that are still within an active cooldown window.
func (e *Engine) pruneEmitMaps(now time.Time) {
	horizon := e.cfg.LongHorizon()
	if horizon <= 0 {
		horizon = 20 * time.Minute
	}
	cutoff := now.Add(-2 * horizon)
	longCutoff := now.Add(-horizon)

	// --- ipLastEmit, ipLastChalEmit, subnetLastChalEmit (under emitMu) ---
	e.emitMu.Lock()
	for ip, t := range e.ipLastEmit {
		if t.Before(cutoff) {
			delete(e.ipLastEmit, ip)
		}
	}
	if e.ipLastChalEmit != nil {
		for ip, t := range e.ipLastChalEmit {
			if t.Before(cutoff) {
				delete(e.ipLastChalEmit, ip)
			}
		}
	}
	if e.subnetLastChalEmit != nil {
		for subnet, t := range e.subnetLastChalEmit {
			if t.Before(cutoff) {
				delete(e.subnetLastChalEmit, subnet)
			}
		}
	}
	e.emitMu.Unlock()

	// --- chalLast (under e.mu write lock) ---
	// chalCtx holds the last matched host/uri/pattern per IP.
	// Safe to evict once the IP hasn't triggered a challenge in one long horizon.
	e.mu.Lock()
	if e.chalLast != nil {
		// chalCtx doesn't carry a timestamp, so we use ipLastChalEmit as proxy.
		// If no emit exists (already pruned above), the ctx is also stale.
		e.emitMu.Lock()
		for ip := range e.chalLast {
			if _, active := e.ipLastChalEmit[ip]; !active {
				delete(e.chalLast, ip)
			}
		}
		e.emitMu.Unlock()
	}
	e.mu.Unlock()

	// --- ipLong.stats (under ipLong.mu) ---
	// IPs that haven't appeared in the short window for a full long horizon
	// will have alpha≈1 on next update anyway — safe to evict early.
	if e.ipLong != nil {
		e.ipLong.mu.Lock()
		if e.ipLong.stats != nil && !e.ipLong.lastUpdate.IsZero() {
			for ip := range e.ipLong.stats {
				// Evict if we'd never see this IP in a fresh updateIPLong call,
				// i.e. it's not in any current short-window bucket.
				// Simple proxy: evict if not in ipLastEmit and not in ipLastChalEmit.
				e.emitMu.Lock()
				_, inEmit := e.ipLastEmit[ip]
				_, inChal := e.ipLastChalEmit[ip]
				e.emitMu.Unlock()
				if !inEmit && !inChal {
					delete(e.ipLong.stats, ip)
				}
			}
		}
		e.ipLong.mu.Unlock()
	}

	// --- chalExpiredSeen (direct field, under emitMu for safety) ---
	e.emitMu.Lock()
	if e.chalExpiredSeen != nil {
		for key, t := range e.chalExpiredSeen {
			if t.Before(longCutoff) {
				delete(e.chalExpiredSeen, key)
			}
		}
	}
	e.emitMu.Unlock()
}

// snapshotMiniLocked builds MiniMetrics per host from current short-window buckets.
// Προϋποθέτει ότι ο caller κρατά ήδη e.mu.RLock ή Lock.
func (e *Engine) snapshotMiniLocked(now time.Time) map[string]MiniMetrics {
	out := make(map[string]MiniMetrics, len(e.hosts))
	for host, hs := range e.hosts {
		if len(hs.buckets) == 0 {
			continue
		}

		var tot, c2, c3, c4, c5, c401, c403, c404, c499 int
		var c500, c502, c503, c504 int
		var sumRT float64
		var sumBytes int64
		ipCounts := map[string]int{}
		// για diversity / bot signals / methods
		uaCounts := map[string]int{}
		pathsUnion := map[string]struct{}{}
		var cGET, cPOST, cHEAD, cOTHER int

		first := hs.buckets[0].from
		last := hs.buckets[len(hs.buckets)-1].to
		winSec := last.Sub(first).Seconds()
		if winSec <= 0 {
			winSec = e.cfg.Window.Seconds()
		}
		if winSec <= 0 {
			winSec = 1
		}

		for i := range hs.buckets {
			b := &hs.buckets[i]
			tot += b.total
			c2 += b.c2xx
			c3 += b.c3xx
			c4 += b.c4xx
			c5 += b.c5xx
			c401 += b.c401
			c403 += b.c403
			c404 += b.c404
			c499 += b.c499
			c500 += b.c500
			c502 += b.c502
			c503 += b.c503
			c504 += b.c504
			sumRT += b.sumRT
			sumBytes += b.sumBytes
			for ip, n := range b.ips {
				ipCounts[ip] += n
			}
			for ua, n := range b.uas {
				uaCounts[ua] += n
			}
			for p := range b.paths {
				pathsUnion[p] = struct{}{}
			}
			cGET += b.cGET
			cPOST += b.cPOST
			cHEAD += b.cHEAD
			cOTHER += b.cOTHER
		}

		if tot == 0 {
			continue
		}

		m := MiniMetrics{}
		m.RPSTotal = float64(tot) / winSec
		m.RPS2xx = float64(c2) / winSec
		m.RPS3xx = float64(c3) / winSec
		m.RPS4xx = float64(c4) / winSec
		m.RPS5xx = float64(c5) / winSec
		m.RPS401 = float64(c401) / winSec
		m.RPS403 = float64(c403) / winSec
		m.RPS404 = float64(c404) / winSec
		m.RPS499 = float64(c499) / winSec

		// 50x breakdown (χωρίς 504, που το κρατάμε ξεχωριστά)
		c50x := c500 + c502 + c503
		m.RPS50x = float64(c50x) / winSec
		m.RPS504 = float64(c504) / winSec

		m.ErrRatio = float64(c4+c5+c499) / float64(tot)
		if m.ErrRatio < 0 {
			m.ErrRatio = 0
		}
		if m.ErrRatio > 1 {
			m.ErrRatio = 1
		}

		m.Auth401Ratio = float64(c401) / float64(tot)

		// bytes/sec
		if winSec > 0 {
			m.BytesRPS = float64(sumBytes) / winSec
		}

		// median per-IP RPS (approx)
		if len(ipCounts) > 0 {
			m.UniqueIPs = len(ipCounts)
			vals := make([]float64, 0, len(ipCounts))

			// μετράμε και “ζεστές” IPs
			hotCount := 0
			const hotRPS = 1.0 // TODO: κάν’ το tunable αν θέλεις

			for _, cnt := range ipCounts {
				rps := float64(cnt) / winSec
				vals = append(vals, rps)
				if rps >= hotRPS {
					hotCount++
				}
			}
			sort.Float64s(vals)
			m.MedianPerIPRPS = vals[len(vals)/2]
			m.HotIPs = hotCount
		}

		// UA diversity + bot ratio
		uniqueUAs := len(uaCounts)
		if uniqueUAs > 0 {
			m.UADiversity = float64(uniqueUAs) / maxf(float64(tot), 1)
		}
		var botHits int
		for ua, cnt := range uaCounts {
			if isBotUA(ua) {
				botHits += cnt
			}
		}
		if tot > 0 {
			m.BotRatio = float64(botHits) / float64(tot)
		}

		// Path diversity
		uniquePaths := len(pathsUnion)
		if uniquePaths > 0 {
			m.PathDiversity = float64(uniquePaths) / maxf(float64(tot), 1)
		}

		// POST ratio (method mix)
		if tot > 0 {
			m.PostRatio = float64(cPOST) / float64(tot)
		}

		out[host] = m
	}
	return out
}

// snapshotMini είναι safe wrapper για callers που δεν κρατούν το mutex.
func (e *Engine) snapshotMini(now time.Time) map[string]MiniMetrics {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.snapshotMiniLocked(now)
}

// updateIPLong ανανεώνει το EMA-based long window για IPs,
// βασισμένο στο τρέχον short-window state.
func (e *Engine) updateIPLong(now time.Time) {
	if e.ipLong == nil {
		return
	}

	// 1) Φτιάχνουμε ένα short snapshot per IP (χωρίς enrichment).
	type aggShort struct {
		req    int
		vhosts map[string]struct{}
	}

	stats := make(map[string]*aggShort)

	e.mu.RLock()
	func() {
		defer e.mu.RUnlock()
		for host, hs := range e.hosts {
			if hs == nil {
				continue
			}
			for i := range hs.buckets {
				b := &hs.buckets[i]
				for ip, n := range b.ips {
					a := stats[ip]
					if a == nil {
						a = &aggShort{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					a.req += n
					a.vhosts[host] = struct{}{}
				}
			}
		}
	}()

	if len(stats) == 0 {
		return
	}

	winSec := e.cfg.Window.Seconds()
	if winSec <= 0 {
		winSec = 60
	}

	// 2) Υπολογίζουμε alpha σε σχέση με το long horizon.
	e.ipLong.mu.Lock()
	defer e.ipLong.mu.Unlock()

	if e.ipLong.stats == nil {
		e.ipLong.stats = make(map[string]*ipLongAgg)
	}

	var alpha float64
	if e.ipLong.lastUpdate.IsZero() {
		alpha = 1.0
	} else {
		horizon := e.cfg.LongHorizon()
		if horizon <= 0 {
			horizon = 10 * e.cfg.Window
		}
		delta := now.Sub(e.ipLong.lastUpdate)
		alpha = delta.Seconds() / horizon.Seconds()
		if alpha > 1 {
			alpha = 1
		} else if alpha < 0 {
			alpha = 0
		}
	}

	for ip, a := range stats {
		rps := float64(a.req) / winSec
		vhosts := float64(len(a.vhosts))
		req := float64(a.req)

		agg := e.ipLong.stats[ip]
		if agg == nil || alpha >= 1.0 || e.ipLong.lastUpdate.IsZero() {
			// πρώτη φορά ή μεγάλο gap → γράψε κατευθείαν
			if agg == nil {
				agg = &ipLongAgg{}
				e.ipLong.stats[ip] = agg
			}
			agg.Req = req
			agg.Vhosts = vhosts
			agg.RPS = rps
			continue
		}

		// EMA: new = (1-alpha)*old + alpha*current
		oneMinus := 1.0 - alpha
		agg.Req = oneMinus*agg.Req + alpha*req
		agg.Vhosts = oneMinus*agg.Vhosts + alpha*vhosts
		agg.RPS = oneMinus*agg.RPS + alpha*rps
	}

	e.ipLong.lastUpdate = now
}

// TopShort returns short-window stats + score for all hosts, sorted by RPS.
func (e *Engine) TopShort(limit int) []ShortRow {

	now := time.Now()

	e.mu.RLock()
	defer e.mu.RUnlock()
	snap := e.snapshotMiniLocked(now)

	rows := make([]ShortRow, 0, len(snap))
	for host, m := range snap {
		sig := Signals{
			RPS:  m.RPSTotal,
			R3xx: m.RPS3xx,
			R4xx: m.RPS4xx,
			R5xx: m.RPS5xx,

			R401: m.RPS401,
			R403: m.RPS403,
			R404: m.RPS404,

			R50x: m.RPS50x,
			R504: m.RPS504,

			ErrRatio:      m.ErrRatio,
			Auth401Ratio:  m.Auth401Ratio,
			UniqueIPs:     m.UniqueIPs,
			MedianPerIP:   m.MedianPerIPRPS,
			BytesRPS:      m.BytesRPS,
			HotIPs:        m.HotIPs,
			BotRatio:      m.BotRatio,
			PathDiversity: m.PathDiversity,
			UADiversity:   m.UADiversity,
			PostRatio:     m.PostRatio,
		}
		res := e.scorer.Score(sig)

		// derive proc avg sec from mini (we stored total RT / total req inside buckets)
		// we don't keep sumRT in MiniMetrics; approximate by using last bucket set:
		procAvg := 0.0
		if hs := e.hosts[host]; hs != nil && len(hs.buckets) > 0 {
			var sumRT float64
			var tot int
			for i := range hs.buckets {
				sumRT += hs.buckets[i].sumRT
				tot += hs.buckets[i].total
			}
			if tot > 0 {
				procAvg = sumRT / float64(tot)
			}
		}

		rows = append(rows, ShortRow{
			Host: host,
			RPS:  m.RPSTotal,
			R2xx: m.RPS2xx,
			R3xx: m.RPS3xx,
			R4xx: m.RPS4xx,
			R5xx: m.RPS5xx,

			R401: m.RPS401,
			R403: m.RPS403,
			R404: m.RPS404,
			R499: m.RPS499,

			UniqueIPs:     m.UniqueIPs,
			ErrRatio:      m.ErrRatio,
			Auth401Ratio:  m.Auth401Ratio,
			ProcAvgSec:    procAvg,
			Score:         res.Score,
			Reasons:       res.Reasons,
			BytesRPS:      m.BytesRPS,
			BotRatio:      m.BotRatio,
			UADiversity:   m.UADiversity,
			PathDiversity: m.PathDiversity,
			PostRatio:     m.PostRatio,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].RPS == rows[j].RPS {
			return rows[i].Host < rows[j].Host
		}
		return rows[i].RPS > rows[j].RPS
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// HostDetail returns top IPs/Agents/Referrers/Paths for a host in the short window.
func (e *Engine) HostDetail(host string, topN int) HostDetail {
	e.mu.RLock()
	defer e.mu.RUnlock()

	hs := e.hosts[host]
	if hs == nil {
		return HostDetail{Host: host, WindowSec: e.cfg.Window.Seconds()}
	}

	if len(hs.buckets) == 0 {
		return HostDetail{Host: host, WindowSec: e.cfg.Window.Seconds()}
	}

	var tot, direct int

	// status counters για scoring
	var c2, c3, c4, c5, c401, c403, c404, c499 int
	var sumBytes int64

	ipc := map[string]int{}
	uac := map[string]int{}
	rfc := map[string]int{}
	ptc := map[string]int{}
	var sumRT float64
	var postCount int

	first := hs.buckets[0].from
	last := hs.buckets[len(hs.buckets)-1].to
	winSec := last.Sub(first).Seconds()
	if winSec <= 0 {
		winSec = e.cfg.Window.Seconds()
	}
	if winSec <= 0 {
		winSec = 1
	}

	for i := range hs.buckets {
		b := &hs.buckets[i]
		tot += b.total
		sumRT += b.sumRT
		sumBytes += b.sumBytes

		c2 += b.c2xx
		c3 += b.c3xx
		c4 += b.c4xx
		c5 += b.c5xx
		c401 += b.c401
		c403 += b.c403
		c404 += b.c404
		c499 += b.c499

		for k, v := range b.ips {
			ipc[k] += v
		}
		for k, v := range b.uas {
			uac[k] += v
		}
		for k, v := range b.refs {
			rfc[k] += v
			if k == "(direct)" {
				direct += v
			}
		}
		for k, v := range b.paths {
			ptc[k] += v
		}
		postCount += b.cPOST
	}

	// --- Short-window scoring για αυτό το host ---
	// UniqueIPs + median per-IP RPS + hot IPs
	var uniqueIPs int
	var medianPerIP, bytesRPS float64
	var hotIPs int

	if len(ipc) > 0 {
		uniqueIPs = len(ipc)
		vals := make([]float64, 0, len(ipc))
		const hotRPS = 1.0
		for _, cnt := range ipc {
			rps := float64(cnt) / winSec
			vals = append(vals, rps)
			if rps >= hotRPS {
				hotIPs++
			}
		}
		sort.Float64s(vals)
		medianPerIP = vals[len(vals)/2]
	}
	if winSec > 0 {
		bytesRPS = float64(sumBytes) / winSec
	}

	// υπολογισμός diversity & ratios
	uniquePaths := len(ptc)
	uniqueUAs := len(uac)
	pathDiv := float64(uniquePaths) / maxf(float64(tot), 1)
	uaDiv := float64(uniqueUAs) / maxf(float64(tot), 1)
	postRatio := float64(postCount) / maxf(float64(tot), 1)

	// bot ratio από UAs (όπως και παραπάνω helper)
	var botHits int
	for ua, cnt := range uac {
		if isBotUA(ua) {
			botHits += cnt
		}
	}
	botRatio := 0.0
	if tot > 0 {
		botRatio = float64(botHits) / float64(tot)
	}

	// Failure index ~ πόσο “αποτυγχάνει” η κίνηση
	failureIndex := 0.0
	if tot > 0 {
		failureIndex = float64(c4+c5+c401) / float64(tot)
	}

	// UA entropy (0–1, normalized)
	uaEntropy := entropyFromCounts(uac, tot)

	// Path entropy (0–1, normalized)
	pathEntropy := entropyFromCounts(ptc, tot)

	// IP skew = max_per_ip / mean_per_ip (>=1)
	ipSkew := 0.0
	if len(ipc) > 0 {
		maxCnt := 0
		for _, cnt := range ipc {
			if cnt > maxCnt {
				maxCnt = cnt
			}
		}
		mean := float64(tot) / float64(len(ipc))
		if mean > 0 {
			ipSkew = float64(maxCnt) / mean
		}
	}

	mini := MiniMetrics{
		RPSTotal:       float64(tot) / winSec,
		RPS2xx:         float64(c2) / winSec,
		RPS3xx:         float64(c3) / winSec,
		RPS4xx:         float64(c4) / winSec,
		RPS5xx:         float64(c5) / winSec,
		RPS401:         float64(c401) / winSec,
		RPS403:         float64(c403) / winSec,
		RPS404:         float64(c404) / winSec,
		RPS499:         float64(c499) / winSec,
		ErrRatio:       float64(c4+c5+c499) / maxf(float64(tot), 1),
		Auth401Ratio:   float64(c401) / maxf(float64(tot), 1),
		UniqueIPs:      uniqueIPs,
		MedianPerIPRPS: medianPerIP,
		BytesRPS:       bytesRPS,
		HotIPs:         hotIPs,
		BotRatio:       botRatio,
		PathDiversity:  pathDiv,
		UADiversity:    uaDiv,
		PostRatio:      postRatio,
	}

	sig := Signals{
		RPS:  mini.RPSTotal,
		R3xx: mini.RPS3xx,
		R4xx: mini.RPS4xx,
		R5xx: mini.RPS5xx,
		R401: mini.RPS401,
		R403: mini.RPS403,
		R404: mini.RPS404,
		// R50x / R504 παραμένουν 0 στο short
		ErrRatio:      mini.ErrRatio,
		Auth401Ratio:  mini.Auth401Ratio,
		UniqueIPs:     mini.UniqueIPs,
		MedianPerIP:   mini.MedianPerIPRPS,
		BytesRPS:      mini.BytesRPS,
		HotIPs:        mini.HotIPs,
		BotRatio:      mini.BotRatio,
		PathDiversity: mini.PathDiversity,
		UADiversity:   mini.UADiversity,
		PostRatio:     mini.PostRatio,
	}
	res := e.scorer.Score(sig)

	top := func(m map[string]int) []TopKV {
		out := make([]TopKV, 0, len(m))
		for k, v := range m {
			out = append(out, TopKV{Key: k, Count: v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
		if topN > 0 && len(out) > topN {
			out = out[:topN]
		}
		return out
	}

	props := HostDetail{
		Host:       host,
		WindowSec:  winSec,
		TotalReq:   tot,
		DirectPct:  pct(direct, tot),
		ProcAvgSec: 0,

		PathDiversity: pathDiv,
		UniquePaths:   uniquePaths,
		UADiversity:   uaDiv,
		UniqueUAs:     uniqueUAs,
		PostRatio:     postRatio,

		// Score / reasons
		ShortScore:   res.Score,
		ShortReasons: res.Reasons,

		// Feature dump
		MedianPerIPRPS: medianPerIP,
		BytesRPS:       bytesRPS,
		HotIPs:         hotIPs,
		FailureIndex:   failureIndex,
		UAEntropy:      uaEntropy,
		PathEntropy:    pathEntropy,
		IPSkew:         ipSkew,

		// Top lists
		TopIPs:       top(ipc),
		TopAgents:    top(uac),
		TopReferrers: top(rfc),
		TopPaths:     top(ptc),
	}

	if tot > 0 {
		props.ProcAvgSec = sumRT / float64(tot)
	}

	// Bot% σε μορφή % για CLI
	props.BotPct = pct(botHits, tot)

	// Enrich top IPs via MaxMind if enabled.
	if e.enr != nil && len(props.TopIPs) > 0 {
		enriched := make([]map[string]string, 0, len(props.TopIPs))
		for _, kv := range props.TopIPs {
			ipStr := kv.Key
			if net.ParseIP(ipStr) == nil {
				continue
			}
			info := map[string]string{
				"ip":    ipStr,
				"count": strconv.Itoa(kv.Count),
			}
			enriched = append(enriched, info)

			// Enricher.Lookup returns a value struct (no nil check needed)
			geo := e.enr.Lookup(ipStr)
			if geo.PTR != "" {
				info["ptr"] = geo.PTR
			}
			if geo.ASN != 0 {
				info["asn"] = strconv.FormatUint(uint64(geo.ASN), 10)
			}
			if geo.ASNName != "" {
				info["asn_name"] = geo.ASNName
			}
			if geo.Country != "" {
				info["country"] = geo.Country

			}
		}
		if len(enriched) > 0 {
			props.EnrichedTopIPs = enriched
		}
	}

	return props
}

func pct(a, b int) float64 {
	if b <= 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// entropyFromCounts υπολογίζει normalized entropy [0,1] πάνω σε counts.
func entropyFromCounts(m map[string]int, total int) float64 {
	if total <= 0 || len(m) == 0 {
		return 0
	}
	var h float64
	t := float64(total)
	for _, c := range m {
		if c <= 0 {
			continue
		}
		p := float64(c) / t
		h += -p * math.Log2(p)
	}
	maxH := math.Log2(float64(len(m)))
	if maxH <= 0 {
		return 0
	}
	return h / maxH
}

// Marshalable helper for debugging.
func (e *Engine) DebugDump() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	b, _ := json.MarshalIndent(e.TopShort(0), "", "  ")
	return string(b)
}

// isLocalInterfaceIP returns true if ip is assigned to any local interface.
func isLocalInterfaceIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		_, n, err := net.ParseCIDR(a.String())
		if err != nil || n == nil {
			continue
		}
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// scoreIPSimple: basic heuristic score για IPs.
// Χρησιμοποιεί μόνο RPS, total requests και πόσα vhosts χτυπάει.
func scoreIPSimple(rps float64, req int, vhosts int) (float64, []string) {
	score := 0.0
	reasons := []string{}

	// RPS contribution
	if rps >= 5 {
		score += 0.6
		reasons = append(reasons, "hi_rps")
	} else if rps >= 1 {
		score += 0.4
		reasons = append(reasons, "med_rps")
	} else if rps >= 0.1 {
		score += 0.2
		reasons = append(reasons, "low_rps")
	}

	// Vhost diversity contribution
	if vhosts >= 10 {
		score += 0.3
		reasons = append(reasons, "many_vhosts")
	} else if vhosts >= 3 {
		score += 0.2
		reasons = append(reasons, "multi_vhosts")
	}

	// Slow-but-persistent crawler hint (δεν αυξάνει score, απλά reason)
	if req >= 200 && rps < 0.1 {
		reasons = append(reasons, "slow_crawler_like")
	}

	if score > 1 {
		score = 1
	}
	return score, reasons
}

func proposeIPActions(row IPSignals) []IPActionProposal {
	// Hard triggers (404/403/agent floods) should always propose a block.
	for _, r := range row.Reasons {
		switch {
		case strings.HasPrefix(r, "404_flood"):
			return []IPActionProposal{{Action: "block", Reason: "web_404_flood", Score: row.Score}}
		case strings.HasPrefix(r, "403_flood"):
			return []IPActionProposal{{Action: "block", Reason: "web_403_flood", Score: row.Score}}
		case strings.HasPrefix(r, "403waf_flood"):
			return []IPActionProposal{{Action: "block", Reason: "web_403waf_flood", Score: row.Score}}
		case strings.HasPrefix(r, "agent_flood"):
			return []IPActionProposal{{Action: "block", Reason: "web_agent_flood", Score: row.Score}}
		case strings.HasPrefix(r, "malpath_flood"):
			return []IPActionProposal{{Action: "block", Reason: "web_malpath_flood", Score: row.Score}}
		case strings.HasPrefix(r, "40x_combo"):
			return []IPActionProposal{{Action: "block", Reason: "web_40x_combo", Score: row.Score}}
		}
	}

	s := row.Score
	out := []IPActionProposal{}

	switch {
	case s >= 0.90:
		out = append(out, IPActionProposal{
			Action: "block",
			Reason: "ip_score_high",
			Score:  s,
		})
	case s >= 0.70:
		out = append(out, IPActionProposal{
			Action: "notify",
			Reason: "ip_score_elevated",
			Score:  s,
		})
	case s >= 0.50:
		out = append(out, IPActionProposal{
			Action: "watch",
			Reason: "ip_score_borderline",
			Score:  s,
		})
	}
	return out
}

// IPShort παράγει full IP signals (με score & proposals) από το short-window state.
func (e *Engine) IPShort(limit int) []IPSignals {
	e.mu.RLock()
	defer e.mu.RUnlock()

	type agg struct {
		req     int
		vhosts  map[string]struct{}
		c403    int
		c403WAF int
		c404    int
		cAgent  int
		cMal    int
		mal     map[int]int
		c40x    int
		p40x    map[uint64]struct{}
	}

	stats := make(map[string]*agg)

	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		for i := range hs.buckets {
			b := &hs.buckets[i]
			for ip, n := range b.ips {
				a := stats[ip]
				if a == nil {
					a = &agg{
						vhosts: make(map[string]struct{}),
					}
					stats[ip] = a
				}
				a.req += n
				a.vhosts[host] = struct{}{}
			}

			// Per-IP threshold counters (evaluated over the same short WINDOW)
			if b.ips403 != nil {
				for ip, n := range b.ips403 {
					a := stats[ip]
					if a == nil {
						a = &agg{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					a.c403 += n
				}
			}

			if b.ips403WAF != nil {
				for ip, n := range b.ips403WAF {
					a := stats[ip]
					if a == nil {
						a = &agg{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					a.c403WAF += n
				}
			}

			if b.ips404 != nil {
				for ip, n := range b.ips404 {
					a := stats[ip]
					if a == nil {
						a = &agg{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					a.c404 += n
				}
			}
			if b.ipsAgent != nil {
				for ip, n := range b.ipsAgent {
					a := stats[ip]
					if a == nil {
						a = &agg{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					a.cAgent += n
				}
			}

			if b.ipsMalPath != nil {
				for ip, n := range b.ipsMalPath {
					a := stats[ip]
					if a == nil {
						a = &agg{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					a.cMal += n
				}
			}

			if b.ipsMalRule != nil {
				for ip, mm := range b.ipsMalRule {
					a := stats[ip]
					if a == nil {
						a = &agg{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					if a.mal == nil {
						a.mal = make(map[int]int)
					}
					for ridx, n := range mm {
						a.mal[ridx] += n
					}
				}
			}

			if b.ips40x != nil {
				for ip, n := range b.ips40x {
					a := stats[ip]
					if a == nil {
						a = &agg{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					a.c40x += n
				}
			}
			if b.ip40xPaths != nil {
				for ip, set := range b.ip40xPaths {
					a := stats[ip]
					if a == nil {
						a = &agg{vhosts: make(map[string]struct{})}
						stats[ip] = a
					}
					if a.p40x == nil {
						a.p40x = make(map[uint64]struct{})
					}
					for h := range set {
						a.p40x[h] = struct{}{}
					}
				}
			}

		}
	}

	winSec := e.cfg.Window.Seconds()
	if winSec <= 0 {
		winSec = 60
	}

	rows := make([]IPSignals, 0, len(stats))
	for ip, a := range stats {
		rps := float64(a.req) / winSec
		vhosts := len(a.vhosts)

		score, reasons := scoreIPSimple(rps, a.req, vhosts)

		// Per-IP flood triggers (same WINDOW)
		hard := false
		if e.cfg.IP404Count > 0 && a.c404 >= e.cfg.IP404Count {
			hard = true
			reasons = append(reasons, fmt.Sprintf("404_flood(%d/%d)", a.c404, e.cfg.IP404Count))
		}
		if e.cfg.IP403Count > 0 && a.c403 >= e.cfg.IP403Count {
			hard = true
			reasons = append(reasons, fmt.Sprintf("403_flood(%d/%d)", a.c403, e.cfg.IP403Count))
		}

		if e.cfg.IP403WAFCount > 0 && a.c403WAF >= e.cfg.IP403WAFCount {
			hard = true
			reasons = append(reasons, fmt.Sprintf("403waf_flood(%d/%d)", a.c403WAF, e.cfg.IP403WAFCount))
		}

		if e.cfg.AgentCount > 0 && a.cAgent >= e.cfg.AgentCount {
			hard = true
			reasons = append(reasons, fmt.Sprintf("agent_flood(%d/%d)", a.cAgent, e.cfg.AgentCount))
		}

		// Per-rule MALPATH thresholds (supports "N:pattern")
		if a.mal != nil && len(e.malRules) > 0 {
			for ridx, n := range a.mal {
				if ridx >= 0 && ridx < len(e.malRules) {
					thr := e.malRules[ridx].count
					if thr > 0 && n >= thr {
						hard = true
						reasons = append(reasons, fmt.Sprintf("malpath(%d/%d:%s)", n, thr, e.malRules[ridx].sub))
						break
					}
				}
			}
		}

		// Global MALPATH threshold (legacy/default)
		if !hard && e.cfg.MalPathCount > 0 && a.cMal >= e.cfg.MalPathCount {
			hard = true
			reasons = append(reasons, fmt.Sprintf("malpath_flood(%d/%d)", a.cMal, e.cfg.MalPathCount))
		}

		// 40x combo (403+404) with unique-path gating (safer)
		if e.cfg.IP40xComboCount > 0 && a.c40x >= e.cfg.IP40xComboCount {
			uniq := 0
			if a.p40x != nil {
				uniq = len(a.p40x)
			}
			if e.cfg.IP40xComboUniquePaths <= 0 || uniq >= e.cfg.IP40xComboUniquePaths {
				hard = true
				reasons = append(reasons,
					fmt.Sprintf("40x_combo(%d/%d paths=%d/%d)", a.c40x, e.cfg.IP40xComboCount, uniq, e.cfg.IP40xComboUniquePaths),
				)
			}
		}

		if hard && score < 1.0 {
			score = 1.0
		}

		rows = append(rows, IPSignals{
			IP:      ip,
			Req:     a.req,
			Vhosts:  vhosts,
			RPS:     rps,
			Score:   score,
			Reasons: reasons,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score == rows[j].Score {
			return rows[i].RPS > rows[j].RPS
		}
		return rows[i].Score > rows[j].Score
	})

	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	// 🔥 Enrichment + proposals ΜΟΝΟ για τις top-N
	for i := range rows {
		rows[i].Proposals = proposeIPActions(rows[i])

		if e.enr == nil {
			continue
		}

		ip := rows[i].IP
		if net.ParseIP(ip) == nil {
			continue
		}

		geo := e.enr.Lookup(ip)
		if geo.PTR != "" {
			rows[i].PTR = geo.PTR
		}
		if geo.ASN != 0 {
			rows[i].ASN = strconv.FormatUint(uint64(geo.ASN), 10)
		}
		if geo.ASNName != "" {
			rows[i].ASNName = geo.ASNName
		}
		if geo.Country != "" {
			rows[i].Country = geo.Country
		}
	}

	return rows

}

// HotIPs υπολογίζει global "ζεστά" IPs από το short-window state.
// Τώρα βασίζεται πάνω στο IPShort και επιστρέφει μόνο το "παλιό" view για συμβατότητα.
func (e *Engine) HotIPs(limit int) []HotIPRow {
	sigs := e.IPShort(limit)
	rows := make([]HotIPRow, 0, len(sigs))
	for _, s := range sigs {
		rows = append(rows, HotIPRow{
			IP:      s.IP,
			Req:     s.Req,
			Vhosts:  s.Vhosts,
			PTR:     s.PTR,
			ASN:     s.ASN,
			ASNName: s.ASNName,
			Country: s.Country,
		})
	}
	return rows
}

// IPDetail σκανάρει το short-window state και κάνει drilldown για ένα IP.
func (e *Engine) IPDetail(ip string) IPDetail {
	e.mu.RLock()
	defer e.mu.RUnlock()

	d := IPDetail{
		IP:        ip,
		WindowSec: e.cfg.Window.Seconds(),
	}

	if net.ParseIP(ip) == nil {
		return d
	}

	hostCounts := make(map[string]int)
	var firstSet bool
	var first, last time.Time

	for host, hs := range e.hosts {
		if hs == nil || len(hs.buckets) == 0 {
			continue
		}
		for i := range hs.buckets {
			b := &hs.buckets[i]
			n, ok := b.ips[ip]
			if !ok || n == 0 {
				continue
			}
			hostCounts[host] += n
			d.Req += n

			if !firstSet {
				first = b.from
				last = b.to
				firstSet = true
			} else {
				if b.from.Before(first) {
					first = b.from
				}
				if b.to.After(last) {
					last = b.to
				}
			}
		}
	}

	d.Vhosts = len(hostCounts)

	if firstSet {
		winSec := last.Sub(first).Seconds()
		if winSec <= 0 {
			winSec = d.WindowSec
		}
		if winSec <= 0 {
			winSec = 1
		}
		d.RPS = float64(d.Req) / winSec
	}

	if len(hostCounts) > 0 {
		hosts := make([]TopKV, 0, len(hostCounts))
		for h, c := range hostCounts {
			hosts = append(hosts, TopKV{Key: h, Count: c})
		}
		sort.Slice(hosts, func(i, j int) bool {
			return hosts[i].Count > hosts[j].Count
		})
		d.Hosts = hosts
	}

	// enrichment
	if e.enr != nil {
		geo := e.enr.Lookup(ip)
		if geo.PTR != "" {
			d.PTR = geo.PTR
		}
		if geo.ASN != 0 {
			d.ASN = strconv.FormatUint(uint64(geo.ASN), 10)
		}
		if geo.ASNName != "" {
			d.ASNName = geo.ASNName
		}
		if geo.Country != "" {
			d.Country = geo.Country
		}
	}

	// attach long-window EMA view
	if snap, ok := e.ipLongOne(ip); ok {
		d.LongHorizonSec = e.cfg.LongHorizon().Seconds()
		d.LongReq = snap.Req
		d.LongVhosts = snap.Vhosts
		d.LongRPS = snap.RPS
		d.LongScore = snap.Score
		d.LongReasons = snap.Reasons
	}

	return d
}

// IPLong επιστρέφει EMA-based long-window IP view με score & proposals.
func (e *Engine) IPLong(limit int) []IPSignals {
	if e.ipLong == nil {
		return nil
	}

	e.ipLong.mu.RLock()
	defer e.ipLong.mu.RUnlock()

	rows := make([]IPSignals, 0, len(e.ipLong.stats))
	for ip, agg := range e.ipLong.stats {
		req := int(agg.Req + 0.5)
		vhosts := int(agg.Vhosts + 0.5)
		rps := agg.RPS

		if req <= 0 {
			continue
		}

		score, reasons := scoreIPSimple(rps, req, vhosts)

		rows = append(rows, IPSignals{
			IP:      ip,
			Req:     req,
			Vhosts:  vhosts,
			RPS:     rps,
			Score:   score,
			Reasons: reasons,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Score == rows[j].Score {
			return rows[i].RPS > rows[j].RPS
		}
		return rows[i].Score > rows[j].Score
	})

	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	// Enrichment + proposals για τις top-N
	for i := range rows {
		rows[i].Proposals = proposeIPActions(rows[i])

		if e.enr == nil {
			continue
		}

		ip := rows[i].IP
		if net.ParseIP(ip) == nil {
			continue
		}

		geo := e.enr.Lookup(ip)
		if geo.PTR != "" {
			rows[i].PTR = geo.PTR
		}
		if geo.ASN != 0 {
			rows[i].ASN = strconv.FormatUint(uint64(geo.ASN), 10)
		}
		if geo.ASNName != "" {
			rows[i].ASNName = geo.ASNName
		}
		if geo.Country != "" {
			rows[i].Country = geo.Country
		}
	}

	return rows
}

type ipLongSnapshot struct {
	Req     int
	Vhosts  int
	RPS     float64
	Score   float64
	Reasons []string
}

// ipLongOne επιστρέφει ένα EMA-based long snapshot για συγκεκριμένη IP.
func (e *Engine) ipLongOne(ip string) (ipLongSnapshot, bool) {
	if e.ipLong == nil {
		return ipLongSnapshot{}, false
	}

	e.ipLong.mu.RLock()
	defer e.ipLong.mu.RUnlock()

	agg, ok := e.ipLong.stats[ip]
	if !ok || agg == nil {
		return ipLongSnapshot{}, false
	}

	req := int(agg.Req + 0.5)
	vhosts := int(agg.Vhosts + 0.5)
	rps := agg.RPS

	if req <= 0 {
		return ipLongSnapshot{}, false
	}

	score, reasons := scoreIPSimple(rps, req, vhosts)

	return ipLongSnapshot{
		Req:     req,
		Vhosts:  vhosts,
		RPS:     rps,
		Score:   score,
		Reasons: reasons,
	}, true
}

func uaMatchAny(ua string, subs []string) bool {
	u := strings.ToLower(ua)
	for _, s := range subs {
		if s != "" && strings.Contains(u, s) {
			return true
		}
	}
	return false
}

func pathMatchAny(path string, subs []string) bool {
	p := strings.ToLower(path)
	for _, s := range subs {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		// If config entry doesn't start with '/', allow matching filenames too.
		// This makes "wso.php" match "/wp-content/uploads/wso.php".
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

// InjectObserved injects a synthetically-observed request outcome into the
// short-window state. Called via OnObserve hook when OpenResty/cfm_waf.lua
// reports a WAF-terminated request (e.g. 403) that never reached upstream and
// therefore never appeared in the access log.
//
// Thread-safe. Non-blocking.
func (e *Engine) InjectObserved(ip, host, uri, method string, status int, reason string) {
	if ip == "" {
		return
	}
	// Normalize just like ingest() does
	if host == "" {
		host = "_waf" // sentinel vhost for WAF hits with no host header
	}
	host = strings.ToLower(host)
	if uri == "" {
		uri = "/"
	}
	p := uri
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if e.isWAFExcluded(host, p) {
		return
	}
	method = strings.ToLower(method)

	now := time.Now()
	rawLine := fmt.Sprintf("[WAF403] ip=%s host=%s method=%s uri=%s reason=%s", ip, host, method, uri, reason)
	e.appendHistory(HistoryEvent{TsUnix: now.Unix(), Type: "waf_observe", Host: host, IP: ip, Reason: reason, Status: status, Payload: map[string]interface{}{"uri": uri, "method": method}})

	rec := LogRec{
		TS:     float64(now.UnixNano()) / 1e9,
		IP:     ip,
		Host:   host,
		Method: method,
		URI:    p,
		Status: status,
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	hs := e.hosts[host]
	if hs == nil {
		hs = &hostState{
			buckets: make([]bucketSW, 0, 8),
			samples: core.NewSampleRing(e.cfg.SampleLimit),
		}
		e.hosts[host] = hs
	}
	hs.samples.Add(host, rawLine)

	bDur := e.cfg.Every
	if bDur <= 0 {
		bDur = 5 * time.Second
	}
	t := tsToTime(rec.TS)

	// prune stale buckets
	cutoff := t.Add(-e.cfg.Window)
	i := 0
	for ; i < len(hs.buckets); i++ {
		if hs.buckets[i].to.After(cutoff) {
			break
		}
	}
	if i > 0 {
		hs.buckets = append([]bucketSW(nil), hs.buckets[i:]...)
	}

	var b *bucketSW
	if len(hs.buckets) == 0 {
		start := t.Truncate(bDur)
		hs.buckets = append(hs.buckets, newBucketSW(start, bDur))
		b = &hs.buckets[0]
	} else {
		last := &hs.buckets[len(hs.buckets)-1]
		if !t.Before(last.to) {
			start := t.Truncate(bDur)
			hs.buckets = append(hs.buckets, newBucketSW(start, bDur))
			b = &hs.buckets[len(hs.buckets)-1]
		} else {
			b = last
		}
	}

	// Count in overall totals (so host appears in snapshots/webtop)
	b.total++
	b.c4xx++
	b.c403++

	if b.ips == nil {
		b.ips = make(map[string]int)
	}
	b.ips[ip]++
	if b.ipSample == nil {
		b.ipSample = make(map[string]string)
	}
	if _, ok := b.ipSample[ip]; !ok {
		b.ipSample[ip] = rawLine
	}

	// WAF-specific 403 counter (separate threshold + kind)
	if status == 403 && e.cfg.IP403WAFCount > 0 {
		if b.ips403WAF == nil {
			b.ips403WAF = make(map[string]int)
		}
		b.ips403WAF[ip]++
	}

	// Also feed into the combined 40x combo counter if enabled
	if e.cfg.IP40xComboCount > 0 && !hasAnyPrefix(p, e.cfg.Ignore40xPrefixes) {
		if b.ips40x == nil {
			b.ips40x = make(map[string]int)
		}
		b.ips40x[ip]++
		if e.cfg.IP40xComboUniquePaths > 0 {
			if b.ip40xPaths == nil {
				b.ip40xPaths = make(map[string]map[uint64]struct{})
			}
			set := b.ip40xPaths[ip]
			if set == nil {
				set = make(map[uint64]struct{})
				b.ip40xPaths[ip] = set
			}
			set[hash64(p)] = struct{}{}
		}
	}
}

// emitIPBlocks emits core.Alert for IPs that should be blocked (per IPShort proposals).
// This is meant to be consumed by the existing autosink blocker pipeline.
func (e *Engine) emitIPBlocks(now time.Time, out chan<- core.Alert) {
	if out == nil {
		return
	}

	// how many candidates to consider per tick
	const topN = 50

	// rate-limit per IP
	const cooldown = 30 * time.Second

	// how many sample lines to attach
	const maxSamples = 8

	rows := e.IPShort(topN)
	if len(rows) == 0 {
		return
	}

	for _, row := range rows {
		// find "block" proposal
		blockReason := ""
		wantBlock := false
		for _, p := range row.Proposals {
			if p.Action == "block" {
				wantBlock = true
				blockReason = p.Reason
				break
			}
		}
		if !wantBlock {
			continue
		}

		// classify (so you can instantly see WHY it blocked)
		kind := "WEB/ABUSE"
		class := "abuse"
		limit := ""
		for _, r := range row.Reasons {
			switch {
			case strings.HasPrefix(r, "404_flood"):
				kind = "WEB/404"
				class = "404_flood"
				limit = r
			case strings.HasPrefix(r, "403_flood"):
				kind = "WEB/403"
				class = "403_flood"
				limit = r
			case strings.HasPrefix(r, "403waf_flood"):
				kind = "WEB/403WAF"
				class = "403waf_flood"
				limit = r
			case strings.HasPrefix(r, "agent_flood"):
				kind = "WEB/BOT"
				class = "agent_flood"
				limit = r
			case strings.HasPrefix(r, "malpath_flood"):
				kind = "WEB/MALPATH"
				class = "malpath_flood"
				limit = r
			case strings.HasPrefix(r, "40x_combo"):
				kind = "WEB/40X"
				class = "40x_combo"
				limit = r
			}
			if limit != "" {
				break
			}
		}
		if class == "abuse" && strings.HasPrefix(blockReason, "ip_score") {
			kind = "WEB/RPS"
			class = "score_high"
		}

		ip := net.ParseIP(row.IP)
		if ip == nil {
			continue
		}

		// don't block ourselves (any local interface address)
		if isLocalInterfaceIP(ip) {
			continue
		}

		// avoid blocking private/loopback/link-local (defensive)
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}

		// avoid blocking private/loopback/link-local (defensive)
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}

		// cooldown check
		skip := func() bool {
			e.emitMu.Lock()
			defer e.emitMu.Unlock()
			last, ok := e.ipLastEmit[row.IP]
			if ok && now.Sub(last) < cooldown {
				return true
			}
			e.ipLastEmit[row.IP] = now
			return false
		}()
		if skip {
			e.appendHistory(HistoryEvent{TsUnix: now.Unix(), Type: "block_trigger", IP: row.IP, Reason: blockReason, Score: row.Score, RPS: row.RPS, Payload: map[string]interface{}{"reasons": strings.Join(row.Reasons, ","), "outcome": "suppressed_by_cooldown", "req": row.Req, "vhosts": row.Vhosts}})
			continue
		}

		e.appendHistory(HistoryEvent{TsUnix: now.Unix(), Type: "block_trigger", IP: row.IP, Reason: blockReason, Score: row.Score, RPS: row.RPS, Payload: map[string]interface{}{"reasons": strings.Join(row.Reasons, ","), "outcome": "block", "req": row.Req, "vhosts": row.Vhosts}})
		e.appendHistory(HistoryEvent{TsUnix: now.Unix(), Type: "suspicious_snapshot", IP: row.IP, Reason: strings.Join(row.Reasons, ","), Score: row.Score, RPS: row.RPS, Payload: map[string]interface{}{"req": row.Req, "vhosts": row.Vhosts}})

		samples := e.ipSamples(row.IP, maxSamples)

		// IMPORTANT:
		// If your autosink blocker expects a different Kind, change this:

		extra := map[string]string{
			"detector": "webdetector",
			"ip":       row.IP,
			"class":    class,
			"score":    fmt.Sprintf("%.2f", row.Score),
			"rps":      fmt.Sprintf("%.3f", row.RPS),
			"vhosts":   strconv.Itoa(row.Vhosts),
			"req":      strconv.Itoa(row.Req),
			"reason":   strings.Join(row.Reasons, ","),
			"action":   "block",
		}
		if limit != "" {
			extra["limit"] = limit
		} else if blockReason != "" {
			extra["limit"] = blockReason
		} // e.g. "web_ip" or "webdetector.ip"
		a := core.Alert{
			When:    now,
			Kind:    core.AlertKind(kind),
			Key:     row.IP,
			Count:   row.Req,
			Samples: samples,
			Extra:   extra,
		}

		// non-blocking send: if channel is full, skip
		select {
		case out <- a:
		default:
		}
	}
}

// ipSamples collects representative raw log lines for an IP from the short-window buckets.
func (e *Engine) ipSamples(ip string, max int) []string {
	if max <= 0 {
		return nil
	}
	out := make([]string, 0, max)
	seen := make(map[string]struct{}, max)

	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, hs := range e.hosts {
		if hs == nil {
			continue
		}
		for i := range hs.buckets {
			b := &hs.buckets[i]
			if b.ipSample == nil {
				continue
			}
			s, ok := b.ipSample[ip]
			if !ok || s == "" {
				continue
			}
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
			if len(out) >= max {
				return out
			}
		}
	}
	return out
}

// 40x combo helpers
func hash64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

func addHashToSetWithCap(m map[string]map[uint64]struct{}, key string, h uint64, capN int) {
	if key == "" || h == 0 {
		return
	}
	if capN <= 0 {
		capN = 512
	}
	set := m[key]
	if set == nil {
		set = make(map[uint64]struct{}, 8)
		m[key] = set
	}
	// cap reached? stop tracking new uniques (count is already ">= cap")
	if len(set) >= capN {
		return
	}
	set[h] = struct{}{}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// isStaticAssetPath returns true for common static asset URLs that should not
// contribute to "unique paths" counters (prevents WP admin false positives).
// Input MUST be the normalized path (no query string).
func isStaticAssetPath(p string) bool {
	if p == "" || p == "-" {
		return false
	}
	// Extension-based ignore (last path segment only)
	seg := p
	if i := strings.LastIndexByte(seg, '/'); i >= 0 && i+1 < len(seg) {
		seg = seg[i+1:]
	}
	// strip any accidental query (defensive)
	if i := strings.IndexByte(seg, '?'); i >= 0 {
		seg = seg[:i]
	}
	if j := strings.LastIndexByte(seg, '.'); j >= 0 && j+1 < len(seg) {
		ext := seg[j+1:]
		switch ext {
		case "css", "js", "mjs", "map",
			"png", "jpg", "jpeg", "gif", "webp", "ico", "svg",
			"woff", "woff2", "ttf", "eot", "otf",
			"mp4", "webm", "mp3", "wav",
			"pdf", "txt", "xml", "json":
			return true
		}
	}
	return false
}

func compileMalRules(list []string, def int) []malRule {
	if def <= 0 {
		def = 1
	}
	rules := make([]malRule, 0, len(list))
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		c := def
		// Allow "N:pattern"
		if i := strings.IndexByte(s, ':'); i > 0 {
			if n, err := strconv.Atoi(strings.TrimSpace(s[:i])); err == nil {
				c = n
				s = strings.TrimSpace(s[i+1:])
			}
		}
		if s == "" || c <= 0 {
			continue
		}
		rules = append(rules, malRule{sub: strings.ToLower(s), count: c})
	}
	return rules
}

// SetBypassFunc wires an IP-level predicate (IGNORE_IPS / IGNORE_NETS).
// Must be called before RunOnce.
func (e *Engine) SetBypassFunc(fn func(string) bool) {
	e.bypassFunc = fn
}

// SetChalExcludeFunc wires the challenge-exclude callback (ASN/UA/PTR rules).
// The function receives enriched asn/ptr (engine does the lookup) and returns
// (action, matched).  Must be called before RunOnce.
func (e *Engine) SetChalExcludeFunc(fn func(ip, host, ua, asn, ptr, rule string) (string, bool)) {
	e.chalExcludeFunc = fn
}

// isBypassed reports whether ip is in the global IGNORE_IPS / IGNORE_NETS list.
func (e *Engine) isBypassed(ip string) bool {
	return e.bypassFunc != nil && e.bypassFunc(ip)
}

// isExcluded runs the challenge-exclude rules for ip.
// It resolves ASN / PTR via the engine's enricher if available.
// ua is best-effort (callers pass "" when unknown; ua=* rules still match).
func (e *Engine) isExcluded(ip, host, ua, rule string) bool {
	if e.challengeExcludes != nil && e.challengeExcludes.MatchHost(host) {
		//logging.Logf("[challenge][debug] exclude_store_match ip=%s host=%s ua=%q rule=%s", ip, host, ua, rule)
		return true
	}
	if e.chalExcludeFunc == nil {
		//logging.Logf("[challenge][debug] exclude_no_func ip=%s host=%s ua=%q rule=%s", ip, host, ua, rule)
		return false
	}
	asn, ptr := "", ""
	if e.enr != nil {
		r := e.enr.Lookup(ip)
		if r.ASN > 0 {
			asn = fmt.Sprintf("AS%d", r.ASN)
		}
		ptr = r.PTR
	}
	_, matched := e.chalExcludeFunc(ip, host, ua, asn, ptr, rule)
	//logging.Logf("[challenge][debug] isExcluded ip=%s host=%s ua=%q rule=%s asn=%q ptr=%q matched=%v", ip, host, ua, rule, asn, ptr, matched)
	return matched
}

func (e *Engine) ChallengeExcludeAdd(typ, value string) bool {
	if e == nil || e.challengeExcludes == nil {
		return false
	}
	return e.challengeExcludes.Add(typ, value)
}

func (e *Engine) ChallengeExcludeRemove(typ, value string) bool {
	if e == nil || e.challengeExcludes == nil {
		return false
	}
	return e.challengeExcludes.Remove(typ, value)
}

func (e *Engine) ChallengeExcludeList() []excludeEntry {
	if e == nil || e.challengeExcludes == nil {
		return nil
	}
	return e.challengeExcludes.List()
}

func (e *Engine) WAFExcludeAdd(typ, value string) bool {
	if e == nil || e.wafExcludes == nil {
		return false
	}
	return e.wafExcludes.Add(typ, value)
}

func (e *Engine) WAFExcludeRemove(typ, value string) bool {
	if e == nil || e.wafExcludes == nil {
		return false
	}
	return e.wafExcludes.Remove(typ, value)
}

func (e *Engine) WAFExcludeList() []excludeEntry {
	if e == nil || e.wafExcludes == nil {
		return nil
	}
	return e.wafExcludes.List()
}

func (e *Engine) isWAFExcluded(host, path string) bool {
	if e == nil || e.wafExcludes == nil {
		return false
	}
	if e.wafExcludes.MatchHost(host) {
		return true
	}
	if e.wafExcludes.MatchPath(path) {
		return true
	}
	return false
}

func (e *Engine) WAFExcludeHasAny() bool {
	if e == nil || e.wafExcludes == nil {
		return false
	}
	return len(e.wafExcludes.List()) > 0
}

func (e *Engine) TrafficRuleAdd(rule TrafficRule) (TrafficRule, error) {
	if e == nil || e.trafficRules == nil {
		return TrafficRule{}, fmt.Errorf("traffic rules store unavailable")
	}
	return e.trafficRules.Add(rule)
}

func (e *Engine) TrafficRuleUpdate(id string, rule TrafficRule) (TrafficRule, error) {
	if e == nil || e.trafficRules == nil {
		return TrafficRule{}, fmt.Errorf("traffic rules store unavailable")
	}
	return e.trafficRules.Update(id, rule)
}

func (e *Engine) TrafficRuleRemove(id string) bool {
	if e == nil || e.trafficRules == nil {
		return false
	}
	return e.trafficRules.Remove(id)
}

func (e *Engine) TrafficRuleGet(id string) (TrafficRule, bool) {
	if e == nil || e.trafficRules == nil {
		return TrafficRule{}, false
	}
	return e.trafficRules.Get(id)
}

func (e *Engine) TrafficRuleList() []TrafficRule {
	if e == nil || e.trafficRules == nil {
		return nil
	}
	return e.trafficRules.List()
}

func (e *Engine) TrafficRuleSimulate(in TrafficRuleEvalInput) TrafficRuleEvalResult {
	if e == nil || e.trafficRules == nil {
		return TrafficRuleEvalResult{Matched: false}
	}
	if strings.TrimSpace(in.Country) == "" && strings.TrimSpace(in.IP) != "" && e.enr != nil {
		if geo := e.enr.Lookup(strings.TrimSpace(in.IP)); strings.TrimSpace(geo.Country) != "" {
			in.Country = geo.Country
		}
	}
	return e.trafficRules.Simulate(in)
}
