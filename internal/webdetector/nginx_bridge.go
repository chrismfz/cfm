// internal/webdetector/nginx_bridge.go
//
// NginxBridge is the Go side of the cfm ↔ OpenResty integration.
//
// When OpenRestyMode is enabled in config, cfm pushes decisions to a
// small unix-socket HTTP server that OpenResty Lua polls per-request.
//
// Two decision types:
//   - Per-IP:    challenge / block / clear  (from existing IP rules)
//   - Per-vhost: challenge / clear          (from CHALLENGE_VHOST + CHALLENGE_SUSPICIOUS_VHOST_SCORE)
//
// Wire format (all JSON):
//
//   POST /nginx/ip          { "ip":"1.2.3.4", "action":"challenge|block", "ttl_sec":600 }
//   POST /nginx/ip/clear    { "ip":"1.2.3.4" }
//   POST /nginx/vhost       { "host":"example.com", "action":"challenge", "ttl_sec":600 }
//   POST /nginx/vhost/clear { "host":"example.com" }
//   GET  /nginx/status      → NginxBridgeStatus (for cfm status / debug)
//
// Lua polls these from the shared-dict server (cfm_decisions.lua) which
// subscribes to the same socket.

package webdetector

import (
	"bufio"
	"bytes"
	"cfm/internal/clam"
	"cfm/internal/enrich"
	"cfm/internal/logging"
	"cfm/internal/sslcollector"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── Config fields (add these to webdetector.Config) ──────────────────────────
//
//   OpenRestyMode  bool          // OPENRESTY_MODE = 1
//   OpenRestySock  string        // OPENRESTY_SOCK  = /var/run/cfm_nginx.sock
//   OpenRestyToken string        // OPENRESTY_TOKEN = sometoken
//
// Already done in webdetector_config.go; referenced here for clarity.

// ── NginxBridge ───────────────────────────────────────────────────────────────

// NginxBridge is the push client that cfm uses to notify OpenResty.
// It is safe for concurrent use.
type NginxBridge struct {
	cfg    bridgeCfg
	client *http.Client
	// started bool

	mu             sync.RWMutex
	ipState        map[string]bridgeIPEntry    // ip   → current decision
	vhState        map[string]bridgeVhostEntry // host → current decision
	okState        map[okStateKey]time.Time    // (ip,host,scope) → solved-ok expiry (bypasses matching vhost challenge)
	bypassFunc     func(string) bool           // set once at startup; no lock needed (written before serving starts)
	hostBypassFunc func(string) bool           // host-level permanent allow (CHALLENGE_HOST_BYPASS); same write-once guarantee
	stats          bridgeStatsState

	// decisionSem caps concurrent in-flight handleDecision goroutines.
	// Without it, the http.Server is goroutine-per-connection with no
	// upper bound; under attack or a thundering-herd burst it can spawn
	// thousands of goroutines and exhaust memory. When the semaphore is
	// saturated, the handler returns an immediate fail-open allow/allow
	// decision (matching the Lua-side fail_open default) and increments
	// stats.shedCount so the operator can see when it's tripping.
	// Sized at 8 * runtime.NumCPU() in NewNginxBridge.
	decisionSem chan struct{}

	// OnTrigger is called when an external push (e.g. cfm_waf.lua) sets a new
	// IP decision via POST /nginx/ip. The hook receives the IP, action
	// ("challenge"|"block"), reason (e.g. "WAF_XSS"), and TTL so the caller
	// can log to cfm.challenges.log with enrichment. Optional metadata
	// Set via SetTriggerHook. Called without b.mu held.
	//
	// `sample` mirrors nginxIPMsg.Sample — when true, the ua/referer/contentType
	// strings are populated from the request and the consumer should write a
	// richer line to cfm.waf.sampled.log. Non-sampled triggers pass empty
	// strings for those three fields.
	OnTrigger func(ip, action, reason string, ttl time.Duration, host, uri, method string, wafRuleID int, sample bool, ua, referer, contentType string)

	// OnWAFStats is called once per row of the snapshot pushed by Lua.
	// Each call carries an absolute count for the (hour_unix, host) tuple;
	// the persister must use UPSERT semantics — repeated calls for the same
	// (hour, host) overwrite. Set via SetWAFStatsHook. Called without b.mu
	// held; dispatched async.
	OnWAFStats func(hourUnix int64, host string, count int)

	// OnObserve is called when OpenResty (or others) reports an observed request outcome.
	// Typical use: WAF returns 403, but we want webdetector to "see" that 403 and escalate.
	// Called without b.mu held.
	OnObserve func(ip, host, uri, method string, status int, reason string)

	// IsWAFExcluded is queried by Lua via /nginx/waf/excluded for per-request
	// pre-WAF bypass checks based on dynamic exclude rules.
	IsWAFExcluded func(host, uri string) bool

	// HasWAFExcludes reports whether any dynamic WAF exclude rules exist.
	HasWAFExcludes func() bool

	// ListWAFExcludes returns current dynamic WAF exclude entries.
	ListWAFExcludes func() []excludeEntry

	// RuleDecision evaluates dynamic traffic rules for the current request
	// shape (host/ip/ua/path/method/country) and returns the matched action.
	RuleDecision func(TrafficRuleEvalInput) TrafficRuleEvalResult

	// ListTrafficRules returns normalized, ordered traffic rules used for
	// local snapshot enforcement in OpenResty Lua.
	ListTrafficRules func() []TrafficRule

	// Clam
	clamMgr      clam.Enqueuer
	clamPending  string
	clamInfected string

	// enricher maxmind
	// LookupCachedOrAsync is used on the request hot path so a cold IP's
	// PTR/mmdb lookup never blocks the decision response (deferred to a
	// background goroutine that warms the cache for next time). Lookup
	// remains for non-hot-path callers (admin/analysis).
	enr interface {
		Lookup(string) enrich.Result
		LookupCachedOrAsync(string) enrich.Result
	}

	// Asynchronous hook dispatcher. OnTrigger / OnObserve callbacks do
	// SQLite writes (history_store.Append) and disk logging which can
	// exceed the Lua-side decision_timeout_ms. They are dispatched onto
	// hookCh and processed by a single drainer goroutine so that the
	// bridge HTTP handlers never block on them. Buffered + drop-on-full
	// — under scanner floods we'd rather lose a few audit rows than
	// push backpressure into the enforcement path.
	hookCh      chan func()
	hookDropped atomic.Int64
	hookStopped atomic.Bool
}

func (b *NginxBridge) SetEnricher(e *enrich.Enricher) { b.enr = e }

// refreshSkew is the minimum remaining time before we bother to re-push
// an already-active decision (to avoid log spam / needless socket traffic).
// We only refresh when an entry is close to expiring.
const refreshSkew = 30 * time.Second

var nginxUploadAllowedDirs = []string{
	"/tmp",
	"/var/tmp",
	"/usr/local/openresty/nginx/client_body_temp",
}

type bridgeCfg struct {
	Enabled    bool
	SockPath   string
	Token      string
	DefaultTTL time.Duration
	OkIPTTL    time.Duration // if 0 -> cookie-only (no IP ok-state)
	Trace      bool
}

type statusCaptureWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCaptureWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

type bridgeIPEntry struct {
	Action  string // "challenge" | "block" | "logonly"
	Expires time.Time
	Reason  string
}

type bridgeVhostEntry struct {
	Action  string // "challenge"
	Expires time.Time
	Reason  string
}

type bridgeStatsState struct {
	mu sync.Mutex

	pushes     int64
	errors     int64
	lastError  string
	lastPushAt time.Time

	totalDurations     []time.Duration
	queueWaitDurations []time.Duration
	stageADurations    []time.Duration
	stageBDurations    []time.Duration
	stageCDurations    []time.Duration
	timeoutByMinute    map[int64]int64
	// shedCount is incremented every time handleDecision returns an immediate
	// fail-open response because the decision-handler concurrency semaphore
	// was saturated. Surfaced as BridgeStats.Timing.SheddedCount so the
	// operator can see when the bridge is actively shedding under burst
	// load (vs. mysterious silence). A nonzero value means the bridge is
	// protecting itself from goroutine explosion — not necessarily an
	// error, but worth attention if it grows fast.
	shedCount int64
}

// BridgeStats is exported for cfm status / JSON API.
type BridgeStats struct {
	Pushes     int64     `json:"pushes"`
	Errors     int64     `json:"errors"`
	LastError  string    `json:"last_error,omitempty"`
	LastPushAt time.Time `json:"last_push_at,omitempty"`

	ActiveIPs    int `json:"active_ips"`
	ActiveVhosts int `json:"active_vhosts"`

	Timing BridgeTimingStats `json:"timing"`
}

type BridgeTimingStats struct {
	TotalP50Ms      int64 `json:"total_p50_ms"`
	TotalP95Ms      int64 `json:"total_p95_ms"`
	TotalP99Ms      int64 `json:"total_p99_ms"`
	QueueWaitP95Ms  int64 `json:"queue_wait_p95_ms"`
	StageAAvgMs     int64 `json:"stage_a_avg_ms"`
	StageBAvgMs     int64 `json:"stage_b_avg_ms"`
	StageCAvgMs     int64 `json:"stage_c_avg_ms"`
	TimeoutPerMin   int64 `json:"timeout_count_last_minute"`
	TimeoutCurrMin  int64 `json:"timeout_count_current_minute"`
	SamplesTotal    int64 `json:"samples_total"`
	QueueSamples    int64 `json:"queue_wait_samples"`
	// SheddedCount: total decision requests that were fail-open shed
	// because the handler concurrency semaphore was saturated. See
	// bridgeStatsState.shedCount for context. Cumulative since process
	// start; resets only on bridge restart.
	SheddedCount int64 `json:"shedded_count"`
}

// NginxBridgeStatus is what GET /nginx/status returns.
type NginxBridgeStatus struct {
	Enabled      bool        `json:"enabled"`
	SockPath     string      `json:"sock_path"`
	ActiveIPs    []string    `json:"active_ips"`
	ActiveVhosts []string    `json:"active_vhosts"`
	Stats        BridgeStats `json:"stats"`
}

// Snapshot payload for Lua local enforcement.
type nginxSnapshotResp struct {
	IPs         []nginxSnapshotIP    `json:"ips"`
	Vhosts      []nginxSnapshotVhost `json:"vhosts"`
	Rules       []TrafficRule        `json:"rules"`
	WAFExcludes []excludeEntry       `json:"waf_excludes"`
	Version     string               `json:"version"`
	TSUnix      int64                `json:"ts_unix"`
}

type nginxSnapshotIP struct {
	IP     string `json:"ip"`
	Action string `json:"action"`
}

type nginxSnapshotVhost struct {
	Host   string `json:"host"`
	Action string `json:"action"`
}

func snapshotVersion(ips []nginxSnapshotIP, vhosts []nginxSnapshotVhost, rules []TrafficRule, wafExcludes []excludeEntry) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(struct {
		IPs         []nginxSnapshotIP    `json:"ips"`
		Vhosts      []nginxSnapshotVhost `json:"vhosts"`
		Rules       []TrafficRule        `json:"rules"`
		WAFExcludes []excludeEntry       `json:"waf_excludes"`
	}{
		IPs:         ips,
		Vhosts:      vhosts,
		Rules:       rules,
		WAFExcludes: wafExcludes,
	})
	return hex.EncodeToString(h.Sum(nil))
}

// ── Wire types (shared with Lua via JSON) ─────────────────────────────────────

type nginxIPMsg struct {
	IP     string `json:"ip"`
	Action string `json:"action"` // "challenge" | "block"
	TTLSec int    `json:"ttl_sec"`
	Reason string `json:"reason,omitempty"`

	Host   string `json:"host,omitempty"`
	URI    string `json:"uri,omitempty"` // prefer request_uri (includes query)
	Method string `json:"method,omitempty"`

	// WAFRuleID is the cfm_waf RULE_IDS numeric handle for the rule that
	// produced this trigger (e.g. 101 = rule_traversal, 320 = rule_rce).
	// Optional — older Lua clients won't send it; 0 means "unknown".
	// Distinct from the decision-engine rule_id field returned in
	// /nginx/decision (that one is for TrafficRuleEvalInput rules).
	WAFRuleID int `json:"waf_rule_id,omitempty"`

	// Sampled-hit-log fields. Present only when Lua decided to sample this
	// trigger (CFM_WAF_SAMPLE_RATE). Used to write the richer
	// cfm.waf.sampled.log entry without bloating every trigger push.
	Sample      bool   `json:"sample,omitempty"`
	UA          string `json:"ua,omitempty"`
	Referer     string `json:"referer,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// nginxWAFStatsMsg is the snapshot pushed by Lua's maybe_flush_waf_insp.
// Each row is an absolute count for the (hour_unix, host) tuple — Go upserts
// idempotently, so repeated pushes for the same hour are safe.
type nginxWAFStatsMsg struct {
	Rows []nginxWAFStatsRow `json:"rows"`
}

type nginxWAFStatsRow struct {
	HourUnix int64  `json:"hour_unix"`
	Host     string `json:"host"`
	Count    int    `json:"count"`
}

type nginxIPClearMsg struct {
	IP string `json:"ip"`
}

type nginxVhostMsg struct {
	Host   string `json:"host"`
	Action string `json:"action"` // "challenge"
	TTLSec int    `json:"ttl_sec"`
	Reason string `json:"reason,omitempty"`
}

type nginxVhostClearMsg struct {
	Host string `json:"host"`
}

type nginxOKTouchMsg struct {
	IP     string `json:"ip"`
	Host   string `json:"host"`
	Scope  string `json:"scope"`
	TTLSec int    `json:"ttl_sec"`
}

type okStateKey struct {
	IP    string
	Host  string
	Scope string
}

// Observation from OpenResty/WAF: "I returned status X for this request"
// POST /nginx/observe
// { "ip":"1.2.3.4", "host":"example.com", "uri":"/x?y=1", "method":"get", "status":403, "reason":"PAY_SHELL" }
type nginxObserveMsg struct {
	IP     string `json:"ip"`
	Host   string `json:"host,omitempty"`
	URI    string `json:"uri,omitempty"` // request_uri preferred (includes query)
	Method string `json:"method,omitempty"`
	Status int    `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// NEW: SetBypassFunc wires a predicate that permanently allows an IP regardless
// of any ipState / vhState entry. Use for IGNORE_IPS / IGNORE_NETS.
// Must be called before ServeDecisions() starts.
func (b *NginxBridge) SetBypassFunc(fn func(string) bool) {
	if b == nil {
		return
	}
	b.bypassFunc = fn
}

// SetHostBypassFunc wires a host predicate that permanently allows any host
// that matches, regardless of any vhState / ipState entry.
// Designed for CHALLENGE_HOST_BYPASS (e.g. cpanel.*, webmail.*, whm.*).
// Must be called before ServeDecisions() starts.
func (b *NginxBridge) SetHostBypassFunc(fn func(string) bool) {
	if b == nil {
		return
	}
	b.hostBypassFunc = fn
}

// BypassIPTemp extends okState for one IP so that vhost-wide challenge is
// bypassed for at least ttl. Used for ASN/UA chalExclude in vhost mode.
// Does NOT push to Lua (okState is checked in-process in handleDecision).
func (b *NginxBridge) BypassIPTemp(ip string, ttl time.Duration) {
	b.BypassIPScopeTemp(ip, "", "web", ttl)
}

// BypassIPScopeTemp extends okState for one (ip,host,scope) tuple so only the
// matching scope/host request bypasses challenge.
func (b *NginxBridge) BypassIPScopeTemp(ip, host, scope string, ttl time.Duration) {
	if b == nil || !b.cfg.Enabled {
		return
	}
	ip = strings.TrimSpace(ip)
	host = normalizeHost(host)
	scope = strings.TrimSpace(scope)
	if ip == "" || host == "" || scope == "" {
		return
	}
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}
	exp := time.Now().Add(ttl)
	k := okStateKey{IP: ip, Host: host, Scope: scope}

	b.mu.Lock()
	cur, ok := b.okState[k]
	if !ok || exp.After(cur) {
		b.okState[k] = exp
	}
	b.mu.Unlock()
}

// Clam Manager
func (b *NginxBridge) SetClamManager(m clam.Enqueuer, pendingDir, infectedDir string) {
	if b == nil {
		return
	}
	b.clamMgr = m
	b.clamPending = pendingDir
	b.clamInfected = infectedDir
	if pendingDir != "" {
		_ = os.MkdirAll(pendingDir, 0o700)
	}
	if infectedDir != "" {
		_ = os.MkdirAll(infectedDir, 0o700)
	}
}

type nginxUploadMsg struct {
	IP            string `json:"ip"`
	Host          string `json:"host,omitempty"`
	URI           string `json:"uri,omitempty"`
	Method        string `json:"method,omitempty"`
	Filename      string `json:"filename,omitempty"`
	BodyFile      string `json:"body_file"`
	Reason        string `json:"reason,omitempty"`
	AlreadyCopied bool   `json:"already_copied,omitempty"`
}

func (b *NginxBridge) handleUpload(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024)

	var msg nginxUploadMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	ip := strings.TrimSpace(msg.IP)
	host := normalizeHost(msg.Host)
	uri := strings.TrimSpace(msg.URI)
	bodyFile := strings.TrimSpace(msg.BodyFile)
	reason := strings.TrimSpace(msg.Reason)
	filename := strings.TrimSpace(msg.Filename)

	logging.LogfCLAM("[upload] ip=%s host=%s uri=%s filename=%q reason=%s",
		ip, host, uri, filename, reason)

	if bodyFile == "" || b.clamMgr == nil || !b.clamMgr.Enabled() {
		w.WriteHeader(http.StatusOK)
		return
	}

	srcPath, ok := validateUploadSourcePath(bodyFile, msg.AlreadyCopied, b.clamPending)
	if !ok {
		w.WriteHeader(http.StatusOK)
		return
	}

	fi, err := os.Stat(srcPath)
	if err != nil || fi.IsDir() || fi.Size() == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}

	var scanPath string
	var tempOwned bool

	if msg.AlreadyCopied {
		scanPath = srcPath
		tempOwned = true
	} else {

		safeIP := sanitizeForFilename(ip)
		dst := filepath.Join(b.clamPending,
			fmt.Sprintf("upload_%d_%s", time.Now().UnixNano(), safeIP))

		if err := copyFile(srcPath, dst); err != nil {
			logging.LogfCLAM("[upload] copy_failed src=%q err=%v", srcPath, err)
			w.WriteHeader(http.StatusOK)
			return
		}
		scanPath = dst
		tempOwned = true
	}

	label := "UPLOAD"
	if reason != "" {
		label += ":" + reason
	}
	if filename != "" {
		label += ":" + filename
	}

	enqueued := b.clamMgr.Enqueue(clam.Job{
		Path:        scanPath,
		IP:          ip,
		Host:        host,
		URI:         uri,
		FileName:    filename,
		Reason:      label,
		TempCopy:    true,
		InfectedDir: b.clamInfected,
	})

	if !enqueued && tempOwned && scanPath != "" {
		_ = os.Remove(scanPath)
		logging.LogfCLAM("[upload] enqueue dropped path=%s ip=%s host=%s", scanPath, ip, host)
	}

	w.WriteHeader(http.StatusOK)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err != nil {
		_ = os.Remove(dst)
		return err
	}
	return cerr
}

func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown"
	}
	return out
}

func validateUploadSourcePath(bodyFile string, alreadyCopied bool, clamPending string) (string, bool) {
	bodyFile = strings.TrimSpace(bodyFile)
	if bodyFile == "" || !filepath.IsAbs(bodyFile) {
		return "", false
	}
	srcPath, err := filepath.Abs(filepath.Clean(bodyFile))
	if err != nil {
		return "", false
	}
	if alreadyCopied {
		return validatePathWithinDir(srcPath, clamPending)
	}
	for _, base := range nginxUploadAllowedDirs {
		if p, ok := validatePathWithinDir(srcPath, base); ok {
			return p, true
		}
	}
	return "", false
}

func validatePathWithinDir(path, base string) (string, bool) {
	base = strings.TrimSpace(base)
	if base == "" {
		return "", false
	}
	safeBase, err := filepath.Abs(filepath.Clean(base))
	if err != nil {
		return "", false
	}
	// Resolve symlinks on the base so the prefix check is against the real dir.
	if real, rerr := filepath.EvalSymlinks(safeBase); rerr == nil {
		safeBase = real
	}

	path = strings.TrimSpace(path)
	if path == "" {
		return "", false
	}
	pathAbs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", false
	}
	// Resolve symlinks on the target path. A symlink inside the allowed dir
	// that points outside it will produce a realPath outside the prefix and
	// be rejected. If the path doesn't exist (or can't be resolved) reject it.
	realPath, err := filepath.EvalSymlinks(pathAbs)
	if err != nil {
		return "", false
	}
	if realPath == safeBase {
		return "", false
	}
	prefix := safeBase + string(os.PathSeparator)
	if !strings.HasPrefix(realPath, prefix) {
		return "", false
	}
	return realPath, true
}

// ── Constructor ───────────────────────────────────────────────────────────────

// NewNginxBridge creates a bridge. If cfg.Enabled is false all methods are no-ops.
func NewNginxBridge(sockPath, token string, defaultTTL, okIPTTL time.Duration) *NginxBridge {
	if defaultTTL <= 0 {
		defaultTTL = 10 * time.Minute
	}

	// okIPTTL: default 1 minute if not specified (caller may pass 0 for cookie-only)
	if okIPTTL < 0 {
		okIPTTL = 0
	}

	b := &NginxBridge{
		cfg: bridgeCfg{
			Enabled:    sockPath != "",
			SockPath:   sockPath,
			Token:      token,
			DefaultTTL: defaultTTL,
			OkIPTTL:    okIPTTL,
		},
		ipState: make(map[string]bridgeIPEntry),
		vhState: make(map[string]bridgeVhostEntry),
		okState: make(map[okStateKey]time.Time),
		stats: bridgeStatsState{
			timeoutByMinute: make(map[int64]int64),
		},
		decisionSem: make(chan struct{}, decisionConcurrencyCap()),
	}

	if b.cfg.Enabled {
		// Unix-socket HTTP client — no DNS, no TCP, very fast
		b.client = &http.Client{
			Timeout: 200 * time.Millisecond,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
				},
				DisableKeepAlives: false,
				MaxIdleConns:      4,
			},
		}
	}

	return b
}

// ── Public API (called from challenge_rules.go / engine.go) ──────────────────

// ChallengeIP tells OpenResty to intercept and challenge this IP.
// Safe to call even if OpenResty is not running (fails silently, logs warn).
func (b *NginxBridge) ChallengeIP(ip string, ttl time.Duration) {
	if !b.cfg.Enabled {
		return
	}
	// ── NEW: honour static bypass (IGNORE_IPS / IGNORE_NETS) ──────────────────
	if b.bypassFunc != nil && b.bypassFunc(ip) {
		return
	}
	// ──────────────────────────────────────────────────────────────────────────

	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}

	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "challenge", Expires: time.Now().Add(ttl)}
	b.mu.Unlock()

	b.post("/nginx/ip", nginxIPMsg{IP: ip, Action: "challenge", TTLSec: int(ttl.Seconds())})
}

// BlockIP tells OpenResty to hard-block this IP (return 403, no challenge).
func (b *NginxBridge) BlockIP(ip string, ttl time.Duration) {
	if !b.cfg.Enabled {
		return
	}

	if b.bypassFunc != nil && b.bypassFunc(ip) {
		return
	}

	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}

	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "block", Expires: time.Now().Add(ttl)}
	b.mu.Unlock()

	b.post("/nginx/ip", nginxIPMsg{IP: ip, Action: "block", TTLSec: int(ttl.Seconds())})
}

// ClearIP removes any active challenge/block for this IP (e.g. after PoW solved).
// GetReason returns the stored reason for the active challenge/block on an IP.
// Returns "" if the IP has no active entry or no reason was recorded.
// Call this BEFORE ClearIP (e.g. inside a solved hook) to capture the WAF/detector reason.
// SetTriggerHook registers a callback that fires whenever an external push
// (POST /nginx/ip) sets a new IP decision. Use this to log WAF trigger events
// to cfm.challenges.log with enrichment from the webdetector engine.
func (b *NginxBridge) SetTriggerHook(fn func(ip, action, reason string, ttl time.Duration, host, uri, method string, wafRuleID int, sample bool, ua, referer, contentType string)) {
	if b == nil {
		return
	}
	b.OnTrigger = fn
}

// SetObserveHook registers a callback for observation events (WAF 403, etc).
func (b *NginxBridge) SetObserveHook(fn func(ip, host, uri, method string, status int, reason string)) {
	if b == nil {
		return
	}
	b.OnObserve = fn
}

// SetWAFStatsHook registers a callback that fires once per row of the
// snapshot pushed by Lua. Rows carry absolute counts per (hour, host); the
// consumer should UPSERT into a sparse table.
func (b *NginxBridge) SetWAFStatsHook(fn func(hourUnix int64, host string, count int)) {
	if b == nil {
		return
	}
	b.OnWAFStats = fn
}

// hookQueueSize is the buffer depth for the async hook dispatcher. Sized so
// that a short scanner burst (a few thousand WAF triggers/sec for a second
// or two) can be absorbed without dropping; sustained overload will drop
// the overflow and count it in hookDropped.
const hookQueueSize = 4096

// startHookDispatcher spawns the single drainer goroutine that runs
// OnTrigger / OnObserve callbacks off the HTTP handler path. Returns a
// channel that closes when the drainer has exited after hookCh is closed.
func (b *NginxBridge) startHookDispatcher() <-chan struct{} {
	if b.hookCh == nil {
		b.hookCh = make(chan func(), hookQueueSize)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for fn := range b.hookCh {
			// A panicking hook must not kill the drainer; the bridge would
			// then silently stop dispatching every subsequent event.
			func() {
				defer func() {
					if r := recover(); r != nil {
						logging.Logf("[nginx_bridge] hook panic: %v", r)
					}
				}()
				fn()
			}()
		}
	}()
	return done
}

// dispatchHook schedules fn to run on the drainer goroutine. If the hook
// queue is full (rare — scanner flood) the event is dropped and a warn is
// logged at a throttled cadence. If the dispatcher is not running (tests,
// pre-Serve, post-shutdown) fn is executed inline so callers never silently
// lose events in the default case.
func (b *NginxBridge) dispatchHook(fn func()) {
	if b == nil || fn == nil {
		return
	}
	if b.hookStopped.Load() || b.hookCh == nil {
		fn()
		return
	}
	select {
	case b.hookCh <- fn:
	default:
		n := b.hookDropped.Add(1)
		// Log the first drop and then every 1000th — a noisy attacker
		// shouldn't be able to flood our own error log.
		if n == 1 || n%1000 == 0 {
			logging.Logf("[nginx_bridge] hook queue full; dropped %d events (buffer=%d)", n, cap(b.hookCh))
		}
	}
}

// HookDroppedCount returns the cumulative number of hook events dropped
// because the dispatcher queue was full. Exposed for status/telemetry.
func (b *NginxBridge) HookDroppedCount() int64 {
	if b == nil {
		return 0
	}
	return b.hookDropped.Load()
}

func (b *NginxBridge) GetReason(ip string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ipState[ip].Reason
}

// Also adds the IP to the solved-ok set so it bypasses vhost-wide challenge
// for the next 60 minutes — matching the solved cookie TTL.
func (b *NginxBridge) ClearIP(ip string) {
	b.ClearIPScoped(ip, "", "web")
}

// ClearIPScoped removes ipState and records a solved-ok state only for the
// provided host/scope.
func (b *NginxBridge) ClearIPScoped(ip, host, scope string) {
	if !b.cfg.Enabled {
		return
	}
	ip = strings.TrimSpace(ip)
	host = normalizeHost(host)
	scope = strings.TrimSpace(scope)

	b.mu.Lock()
	delete(b.ipState, ip)
	if b.cfg.OkIPTTL > 0 {
		if ip != "" && host != "" && scope != "" {
			b.okState[okStateKey{IP: ip, Host: host, Scope: scope}] = time.Now().Add(b.cfg.OkIPTTL)
		}
	} else {
		for k := range b.okState {
			if k.IP == ip {
				delete(b.okState, k)
			}
		}
	}
	b.mu.Unlock()

	b.post("/nginx/ip/clear", nginxIPClearMsg{IP: ip})
}

// vhostVariantsForBridge returns the exact host variants we want to mirror
// into the OpenResty bridge.
//
// Rules:
//   - bare apex host:       example.com     -> [example.com, www.example.com]
//   - already-www host:     www.example.com -> [www.example.com]
//   - wildcard host:        *.example.com   -> [*.example.com]
//   - empty/invalid host:   -> nil
//
// We intentionally do NOT expand to *.example.com because that would also
// catch api.example.com, cdn.example.com, etc.
func vhostVariantsForBridge(host string) []string {
	host = normalizeHost(host)
	if host == "" {
		return nil
	}

	if strings.HasPrefix(host, "*.") {
		return []string{host}
	}

	// prefix-label wildcard: "cpanel.*" — store as-is, no www expansion
	if strings.HasSuffix(host, ".*") {
		return []string{host}
	}

	if strings.HasPrefix(host, "www.") {
		return []string{host}
	}

	return []string{
		host,
		"www." + host,
	}
}

// ChallengeVhost puts an entire vhost into challenge mode.
// Every request to that vhost will be challenged regardless of IP.
// Called when CHALLENGE_VHOST fires or CHALLENGE_SUSPICIOUS_VHOST_SCORE turns on.
func (b *NginxBridge) ChallengeVhost(host string, ttl time.Duration) {
	b.ChallengeVhostWithReason(host, ttl, "")
}

// ChallengeVhostWithReason puts an entire vhost into challenge mode and
// records/logs the source reason when available.
func (b *NginxBridge) ChallengeVhostWithReason(host string, ttl time.Duration, reason string) {
	if !b.cfg.Enabled {
		return
	}
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}

	hosts := vhostVariantsForBridge(host)
	if len(hosts) == 0 {
		return
	}

	now := time.Now()
	exp := now.Add(ttl)
	reason = strings.TrimSpace(reason)

	for _, host := range hosts {
		needPush := false
		logEnter := false
		entryReason := reason

		b.mu.Lock()
		cur, ok := b.vhState[host]
		// Only push/log on state transition, or when we're close to expiry.
		if !ok || cur.Action != "challenge" || cur.Expires.Before(now) {
			b.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: exp, Reason: entryReason}
			needPush = true
			logEnter = true
		} else {
			// Keep it sticky without spamming: extend locally, push only near expiry.
			if exp.After(cur.Expires) {
				if entryReason == "" {
					entryReason = cur.Reason
				}
				b.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: exp, Reason: entryReason}
			}
			if cur.Expires.Sub(now) < refreshSkew {
				needPush = true
			}
		}
		b.mu.Unlock()

		if needPush {
			b.post("/nginx/vhost", nginxVhostMsg{
				Host:   host,
				Action: "challenge",
				TTLSec: int(ttl.Seconds()),
				Reason: entryReason,
			})
		}
		if logEnter {
			if entryReason != "" {
				logging.Logf("[nginx_bridge] vhost_challenge host=%s ttl=%s reason=%s", host, ttl, entryReason)
			} else {
				logging.Logf("[nginx_bridge] vhost_challenge host=%s ttl=%s", host, ttl)
			}
		}
	}
}

// ClearVhost removes vhost-wide challenge mode.
// Called when CHALLENGE_SUSPICIOUS_VHOST_SCORE score drops below ScoreOff.
func (b *NginxBridge) ClearVhost(host string) {
	if !b.cfg.Enabled {
		return
	}

	hosts := vhostVariantsForBridge(host)
	if len(hosts) == 0 {
		return
	}

	for _, host := range hosts {
		wasSet := false

		b.mu.Lock()
		if _, ok := b.vhState[host]; ok {
			wasSet = true
			delete(b.vhState, host)
		}
		b.mu.Unlock()

		if wasSet {
			b.post("/nginx/vhost/clear", nginxVhostClearMsg{Host: host})
			logging.Logf("[nginx_bridge] vhost_clear host=%s", host)
		}
	}
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if h == "" {
		return ""
	}
	if hh, _, err := net.SplitHostPort(h); err == nil && hh != "" {
		h = hh
	}
	return h
}

// Status returns a snapshot for debugging / cfm status output.
func (b *NginxBridge) Status() NginxBridgeStatus {
	if !b.cfg.Enabled {
		return NginxBridgeStatus{Enabled: false}
	}

	b.mu.RLock()
	ips := make([]string, 0, len(b.ipState))
	vhs := make([]string, 0, len(b.vhState))
	now := time.Now()
	for ip, e := range b.ipState {
		if e.Expires.After(now) {
			ips = append(ips, ip)
		}
	}
	for h, e := range b.vhState {
		if e.Expires.After(now) {
			vhs = append(vhs, h)
		}
	}
	b.mu.RUnlock()

	st := b.snapshotBridgeStats(len(ips), len(vhs))

	return NginxBridgeStatus{
		Enabled:      true,
		SockPath:     b.cfg.SockPath,
		ActiveIPs:    ips,
		ActiveVhosts: vhs,
		Stats:        st,
	}
}

func (b *NginxBridge) snapshotBridgeStats(activeIPs, activeVhosts int) BridgeStats {
	b.stats.mu.Lock()
	defer b.stats.mu.Unlock()
	nowMin := time.Now().UTC().Unix() / 60
	lastMin := nowMin - 1

	return BridgeStats{
		Pushes:       b.stats.pushes,
		Errors:       b.stats.errors,
		LastError:    b.stats.lastError,
		LastPushAt:   b.stats.lastPushAt,
		ActiveIPs:    activeIPs,
		ActiveVhosts: activeVhosts,
		Timing: BridgeTimingStats{
			TotalP50Ms:     percentileDurationMsLocked(b.stats.totalDurations, 0.50),
			TotalP95Ms:     percentileDurationMsLocked(b.stats.totalDurations, 0.95),
			TotalP99Ms:     percentileDurationMsLocked(b.stats.totalDurations, 0.99),
			QueueWaitP95Ms: percentileDurationMsLocked(b.stats.queueWaitDurations, 0.95),
			StageAAvgMs:    avgDurationMsLocked(b.stats.stageADurations),
			StageBAvgMs:    avgDurationMsLocked(b.stats.stageBDurations),
			StageCAvgMs:    avgDurationMsLocked(b.stats.stageCDurations),
			TimeoutPerMin:  b.stats.timeoutByMinute[lastMin],
			TimeoutCurrMin: b.stats.timeoutByMinute[nowMin],
			SamplesTotal:   int64(len(b.stats.totalDurations)),
			QueueSamples:   int64(len(b.stats.queueWaitDurations)),
			SheddedCount:   b.stats.shedCount,
		},
	}
}

const bridgeTimingWindowSamples = 4096

func appendDurationSample(dst []time.Duration, d time.Duration) []time.Duration {
	dst = append(dst, d)
	if len(dst) > bridgeTimingWindowSamples {
		copy(dst, dst[len(dst)-bridgeTimingWindowSamples:])
		dst = dst[:bridgeTimingWindowSamples]
	}
	return dst
}

func avgDurationMsLocked(samples []time.Duration) int64 {
	if len(samples) == 0 {
		return 0
	}
	var sum int64
	for _, s := range samples {
		sum += s.Milliseconds()
	}
	return sum / int64(len(samples))
}

func percentileDurationMsLocked(samples []time.Duration, p float64) int64 {
	if len(samples) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), samples...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := int(float64(len(cp)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx].Milliseconds()
}

// RunExpireLoop cleans up expired local state.
// Call as: go bridge.RunExpireLoop(ctx)
func (b *NginxBridge) RunExpireLoop(ctx context.Context) {
	if !b.cfg.Enabled {
		return
	}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			b.mu.Lock()
			for ip, e := range b.ipState {
				if e.Expires.Before(now) {
					delete(b.ipState, ip)
				}
			}
			for h, e := range b.vhState {
				if e.Expires.Before(now) {
					delete(b.vhState, h)
				}
			}
			for ip, exp := range b.okState {
				if exp.Before(now) {
					delete(b.okState, ip)
				}
			}
			b.mu.Unlock()
		}
	}
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (b *NginxBridge) post(path string, payload interface{}) {
	body, err := json.Marshal(payload)
	if err != nil {
		b.recordErr(fmt.Sprintf("marshal %s: %v", path, err))
		return
	}

	req, err := http.NewRequest(http.MethodPost, "http://unix"+path, bytes.NewReader(body))
	if err != nil {
		b.recordErr(fmt.Sprintf("newreq %s: %v", path, err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if b.cfg.Token != "" {
		req.Header.Set("X-CFM-Token", b.cfg.Token)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		// Socket not yet up, or OpenResty restarting — warn but don't crash.
		b.recordErr(fmt.Sprintf("post %s: %v", path, err))
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		b.recordErr(fmt.Sprintf("post %s: http %d", path, resp.StatusCode))
		return
	}

	b.stats.mu.Lock()
	b.stats.pushes++
	b.stats.lastPushAt = time.Now()
	b.stats.mu.Unlock()
}

func (b *NginxBridge) recordErr(msg string) {
	logging.Logf("[nginx_bridge] WARN: %s", msg)
	b.stats.mu.Lock()
	b.stats.errors++
	b.stats.lastError = msg
	b.stats.mu.Unlock()
}

// ── ServeHTTP: the unix-socket server that Lua reads from ─────────────────────
//
// This is the *server* side — OpenResty Lua connects here to get the current
// decision state. Run as: go bridge.ServeDecisions(ctx)

// slowHandlerThreshold is the "anything above this is worth investigating"
// bar for bridge HTTP handlers. Under normal conditions all handlers finish
// in well under a millisecond (pure in-memory state mutation + async hook
// dispatch); anything over this threshold suggests GC pressure, mutex
// contention, or a regression in a handler. Logged once per offending call
// with the method+path so the culprit is unambiguous.
const slowHandlerThreshold = 30 * time.Millisecond

// instrument wraps an http.HandlerFunc with a wall-clock timer and emits a
// warn-level log line when the handler exceeds slowHandlerThreshold. This
// is the diagnostic hook for "why is the Lua client still timing out?" —
// it tells us which bridge endpoint is actually slow instead of speculating.
func (b *NginxBridge) instrument(name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		enqueueAt := start
		if hdr := strings.TrimSpace(r.Header.Get("X-CFM-Enqueued-At")); hdr != "" {
			if unixNano, err := strconv.ParseInt(hdr, 10, 64); err == nil && unixNano > 0 {
				enqueueAt = time.Unix(0, unixNano)
			}
		}
		stageA := time.Since(start)
		sw := &statusCaptureWriter{ResponseWriter: w, status: http.StatusOK}
		stageBStart := time.Now()
		h(sw, r)
		stageB := time.Since(stageBStart)
		dur := time.Since(start)
		stageC := dur - stageA - stageB
		if stageC < 0 {
			stageC = 0
		}
		queueWait := start.Sub(enqueueAt)
		if queueWait < 0 {
			queueWait = 0
		}
		b.recordTiming(stageA, stageB, stageC, dur, queueWait, errors.Is(r.Context().Err(), context.DeadlineExceeded))
		if dur >= slowHandlerThreshold {
			logging.Logf("[nginx_bridge] slow handler %s %s took %s", r.Method, name, dur)
		}
		if !b.cfg.Trace {
			return
		}
		reqID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if reqID == "" {
			reqID = fmt.Sprintf("bridge-%d", start.UnixNano())
		}
		host := strings.TrimSpace(r.Host)
		uri := r.URL.RequestURI()
		action := "ok"
		if sw.status >= 400 {
			action = "error"
		}
		// handleDecision sets X-CFM-Bridge-Shed=1 on its concurrency-cap shed
		// path so [bridge_trace] lines are greppable: action=shed cleanly
		// distinguishes "we returned allow under load" from a normal allow.
		if sw.Header().Get("X-CFM-Bridge-Shed") == "1" {
			action = "shed"
		}
		errClass := ""
		if errors.Is(r.Context().Err(), context.Canceled) {
			errClass = "context_canceled"
		} else if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			errClass = "timeout"
		} else if sw.status == http.StatusBadRequest {
			errClass = "json_error"
		} else if sw.status == http.StatusServiceUnavailable {
			errClass = "queue_overflow"
		}
		logging.LogfSOCKET("[bridge_trace] timestamp=%s request_id=%s remote_addr=%q host=%q uri=%q method=%s action=%s duration_ms=%d status_code=%d error_class=%s stage_a_ms=%d stage_b_ms=%d stage_c_ms=%d queue_wait_ms=%d auth_header=%s",
			start.UTC().Format(time.RFC3339Nano), reqID, strings.TrimSpace(r.RemoteAddr), host, uri, r.Method, action, dur.Milliseconds(), sw.status, errClass, stageA.Milliseconds(), stageB.Milliseconds(), stageC.Milliseconds(), queueWait.Milliseconds(), "[REDACTED]")
	}
}

func (b *NginxBridge) recordTiming(stageA, stageB, stageC, total, queueWait time.Duration, timedOut bool) {
	b.stats.mu.Lock()
	defer b.stats.mu.Unlock()
	b.stats.stageADurations = appendDurationSample(b.stats.stageADurations, stageA)
	b.stats.stageBDurations = appendDurationSample(b.stats.stageBDurations, stageB)
	b.stats.stageCDurations = appendDurationSample(b.stats.stageCDurations, stageC)
	b.stats.totalDurations = appendDurationSample(b.stats.totalDurations, total)
	if queueWait > 0 {
		b.stats.queueWaitDurations = appendDurationSample(b.stats.queueWaitDurations, queueWait)
	}
	nowMin := time.Now().UTC().Unix() / 60
	for k := range b.stats.timeoutByMinute {
		if k < nowMin-10 {
			delete(b.stats.timeoutByMinute, k)
		}
	}
	if timedOut {
		b.stats.timeoutByMinute[nowMin]++
	}
}

// ServeDecisions starts a unix-socket HTTP server that Lua queries.
// It serves a simple decision API:
//
//	GET /nginx/decision?ip=1.2.3.4&host=example.com
//	→ { "ip_action": "challenge|block|allow", "vhost_action": "challenge|allow" }
//
//	GET /nginx/status
//	→ NginxBridgeStatus
func (b *NginxBridge) ServeDecisions(ctx context.Context) error {
	if !b.cfg.Enabled {
		return nil
	}

	sockPath := b.cfg.SockPath
	if dir := filepath.Dir(sockPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o750)
		if gid := sslcollector.CfmGroupID(); gid > 0 {
			_ = os.Chown(dir, 0, gid)
		}
	}
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("nginx_bridge listen %s: %w", sockPath, err)
	}
	// root:cfm 0660 — allows OpenResty workers (cfm group) to connect.
	_ = os.Chmod(sockPath, 0o660)
	if gid := sslcollector.CfmGroupID(); gid > 0 {
		_ = os.Chown(sockPath, 0, gid)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/nginx/decision", b.instrument("/nginx/decision", b.handleDecision))
	mux.HandleFunc("/nginx/ip", b.instrument("/nginx/ip", b.handleIPPush))
	mux.HandleFunc("/nginx/ip/clear", b.instrument("/nginx/ip/clear", b.handleIPClear))
	mux.HandleFunc("/nginx/vhost", b.instrument("/nginx/vhost", b.handleVhostPush))
	mux.HandleFunc("/nginx/vhost/clear", b.instrument("/nginx/vhost/clear", b.handleVhostClear))
	mux.HandleFunc("/nginx/ok/touch", b.instrument("/nginx/ok/touch", b.handleOKTouch))
	mux.HandleFunc("/nginx/observe", b.instrument("/nginx/observe", b.handleObserve))
	mux.HandleFunc("/nginx/waf/excluded", b.instrument("/nginx/waf/excluded", b.handleWAFExcluded))
	mux.HandleFunc("/nginx/waf/excluded/meta", b.instrument("/nginx/waf/excluded/meta", b.handleWAFExcludedMeta))
	mux.HandleFunc("/nginx/waf/excludes", b.instrument("/nginx/waf/excludes", b.handleWAFExcludes))
	mux.HandleFunc("/nginx/waf/stats", b.instrument("/nginx/waf/stats", b.handleWAFStats))
	mux.HandleFunc("/nginx/snapshot", b.instrument("/nginx/snapshot", b.handleSnapshot))
	mux.HandleFunc("/nginx/status", b.instrument("/nginx/status", b.handleStatus))
	mux.HandleFunc("/nginx/upload", b.instrument("/nginx/upload", b.handleUpload))
	mux.HandleFunc("/nginx/events/batch", b.instrument("/nginx/events/batch", b.handleEventsBatch))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}

	hookDone := b.startHookDispatcher()

	go func() {
		<-ctx.Done()
		ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx2)
		_ = os.Remove(sockPath)
		// HTTP handlers are done; safe to stop accepting new hook events
		// and let the drainer finish whatever it was mid-flight.
		b.hookStopped.Store(true)
		if b.hookCh != nil {
			close(b.hookCh)
			<-hookDone
		}
	}()

	logging.Logf("[nginx_bridge] decision server listening on unix:%s", sockPath)
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// decisionConcurrencyCap returns the size of the per-bridge decision-handler
// semaphore. Defaults to 8 × runtime.NumCPU() with a floor of 32 (so even on
// a 1-core test box / container the cap is a useful number, not 8). This is
// roomy enough that legitimate traffic from a busy host (a few hundred req/s)
// never trips it, but tight enough that a goroutine flood from a thundering
// herd or attack does get capped.
func decisionConcurrencyCap() int {
	n := runtime.NumCPU() * 8
	if n < 32 {
		n = 32
	}
	return n
}

// ── HTTP handlers (server side, called by Lua) ────────────────────────────────

// handleDecision: Lua asks "what do I do with this IP / vhost?"
// GET /nginx/decision?ip=1.2.3.4&host=example.com
func (b *NginxBridge) handleDecision(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Concurrency gate. If we're already at the cap of in-flight handlers,
	// shed by returning an immediate fail-open allow/allow response. Counts
	// in stats.shedCount so operators can see when this trips.
	//
	// CRITICAL: rule_action is set to "shed" in the response so cfm.lua's
	// decision cache filter (which only caches when ip_action+vhost_action
	// are both "allow" *and* rule_action is unset, see cfm.lua:675) skips
	// caching this entry. Without this, a 1-second saturation event would
	// cache "allow/allow" per-(IP,host,URL) for the full 90s
	// decision_cache_ttl_ms — turning a brief overload into 90 seconds of
	// degraded enforcement for affected requests. With rule_action set, each
	// shed forces the next request to retry the bridge fresh, so as soon
	// as the cap clears, normal enforcement resumes.
	//
	// Lua treats rule_action="shed" as fall-through-to-allow (cfm.lua only
	// hard-codes "block"/"challenge"/"throttle" at lines 1075/1084/1102),
	// so the user-visible behavior remains identical to a normal allow.
	//
	// Trade-off accepted: during shed, the handler does NOT consult ipState
	// (so a blocked IP slips through for that request), vhState, or run
	// traffic rules. For severe blocks, kernel-level nft rules drop the
	// packet before it reaches nginx — so the soft "block" leak is bounded
	// to web-only blocks during burst saturation. Operators should alert
	// on SheddedCount > 0 sustained — it indicates the bridge is overloaded
	// or its dependencies (geoip, rule engine) are stalled.
	select {
	case b.decisionSem <- struct{}{}:
		defer func() { <-b.decisionSem }()
	default:
		b.stats.mu.Lock()
		b.stats.shedCount++
		b.stats.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-CFM-Bridge-Shed", "1")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ip_action":    "allow",
			"vhost_action": "allow",
			"rule_action":  "shed",
		})
		return
	}

	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	uri := strings.TrimSpace(r.URL.Query().Get("uri"))
	// split path from query string — Lua sends request_uri which includes "?qs"
	var qs string
	if idx := strings.IndexByte(uri, '?'); idx >= 0 {
		qs = uri[idx+1:]
		uri = uri[:idx]
	}
	method := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("method")))
	ua := strings.TrimSpace(r.URL.Query().Get("ua"))
	country := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("country")))

	if country == "" && ip != "" && b.enr != nil {
		// LookupCachedOrAsync returns immediately: cache hit gives the real
		// CountryISO, cache miss returns "" and warms the cache async. We
		// trade off "first request from a fresh IP has no country" against
		// "every request blocks up to ~1s on PTR DNS + mmdb cold reads".
		// Subsequent requests from that IP (typically the next one, ms
		// later under load) will see the populated cache.
		if geo := b.enr.LookupCachedOrAsync(ip); geo.CountryISO != "" {
			country = geo.CountryISO // "GR" not "Greece"
		}
	}

	if hh, _, err := net.SplitHostPort(host); err == nil && hh != "" {
		host = hh
	}
	now := time.Now()

	// ── NEW: static bypass — always allow, ignores ipState/vhState entirely ──
	if b.bypassFunc != nil && b.bypassFunc(ip) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ip_action":    "allow",
			"vhost_action": "allow",
		})
		return
	}
	// ── NEW: host-level static bypass (CHALLENGE_HOST_BYPASS) ─────────────────
	// Wins over all ipState / vhState entries — cPanel/webmail/WHM must never
	// be challenged regardless of what the IP is doing on other vhosts.
	if b.hostBypassFunc != nil && b.hostBypassFunc(host) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"ip_action":    "allow",
			"vhost_action": "allow",
		})
		return
	}
	// ──────────────────────────────────────────────────────────────────────────

	ipAction := "allow"
	vhAction := "allow"

	b.mu.RLock()
	if e, ok := b.ipState[ip]; ok && e.Expires.After(now) {
		ipAction = e.Action
	}

	// vhost exact match first, else wildcard
	if h, ok := b.vhState[host]; ok && h.Expires.After(now) {
		vhAction = h.Action
	} else if host != "" {
		// wildcard match: "*.example.com" (suffix) or "cpanel.*" (prefix-label)
		for pat, e := range b.vhState {
			if !e.Expires.After(now) {
				continue
			}
			if len(pat) > 2 && pat[:2] == "*." {
				suf := pat[1:] // ".example.com"
				if len(host) > len(suf) && host[len(host)-len(suf):] == suf {
					vhAction = e.Action
					break
				}
			} else if strings.HasSuffix(pat, ".*") {
				base := pat[:len(pat)-2] // "cpanel"
				if base != "" && strings.HasPrefix(host, base+".") {
					vhAction = e.Action
					break
				}
			}
		}
	}

	scope := strings.TrimSpace(r.URL.Query().Get("scope"))
	if scope == "" {
		scope = "web"
	}
	// Solved-ok: IP passed PoW recently for same host/scope.
	if b.cfg.OkIPTTL > 0 {
		k := okStateKey{IP: ip, Host: host, Scope: scope}
		if exp, ok := b.okState[k]; ok && exp.After(now) {
			vhAction = "allow"
			ipAction = "allow"
		}
	}
	b.mu.RUnlock()

	resp := map[string]any{
		"ip_action":    ipAction, // "allow" | "challenge" | "block"
		"vhost_action": vhAction, // "allow" | "challenge"
	}
	if b.RuleDecision != nil {
		rr := b.RuleDecision(TrafficRuleEvalInput{
			Host:        host,
			IP:          ip,
			UA:          ua,
			Path:        uri,
			Method:      method,
			Country:     country,
			QueryString: qs,
		})
		if rr.Matched {
			resp["rule_action"] = rr.Action
			resp["rule_id"] = rr.Rule.ID
			if rr.Profile != "" {
				resp["throttle_profile"] = rr.Profile
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleIPPush: cfm (or external tool) pushes a new IP decision.
// Also called internally by ChallengeIP/BlockIP — but can be called
// directly by cfm's challenge_server.go sink as well.
func (b *NginxBridge) handleIPPush(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var msg nginxIPMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if msg.IP == "" || (msg.Action != "challenge" && msg.Action != "block" && msg.Action != "logonly") {
		http.Error(w, "bad fields", http.StatusBadRequest)
		return
	}

	ttl := time.Duration(msg.TTLSec) * time.Second
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}

	reason := strings.TrimSpace(msg.Reason)

	// normalize metadata (best-effort)
	msg.Host = normalizeHost(msg.Host)
	msg.URI = strings.TrimSpace(msg.URI)
	msg.Method = strings.ToLower(strings.TrimSpace(msg.Method))

	// logonly is a "dry-run audit" action:
	// - it should be logged (via OnTrigger hook)
	// - but it MUST NOT create an active IP decision in the bridge
	if msg.Action != "logonly" {
		b.mu.Lock()
		b.ipState[msg.IP] = bridgeIPEntry{
			Action:  msg.Action,
			Expires: time.Now().Add(ttl),
			Reason:  reason,
		}
		b.mu.Unlock()
	}

	// Fire the trigger hook when a reason is present (i.e. the push came from
	// cfm_waf.lua or another external caller that knows why it triggered).
	// Internal ChallengeIP/BlockIP calls from the Go engine don't set a reason
	// (they log via challenge_rules.go / RecordIPChallenge instead).
	// Dispatched async — hook writes to SQLite and disk, which must not be
	// allowed to exceed the Lua client's decision_timeout_ms.
	if reason != "" && b.OnTrigger != nil {
		ip, action, host, uri, method, wafRuleID := msg.IP, msg.Action, msg.Host, msg.URI, msg.Method, msg.WAFRuleID
		sample, ua, referer, ct := msg.Sample, msg.UA, msg.Referer, msg.ContentType
		b.dispatchHook(func() {
			b.OnTrigger(ip, action, reason, ttl, host, uri, method, wafRuleID, sample, ua, referer, ct)
		})
	}

	w.WriteHeader(http.StatusOK)
}

func (b *NginxBridge) handleIPClear(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var msg nginxIPClearMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	delete(b.ipState, msg.IP)
	b.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (b *NginxBridge) handleVhostPush(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var msg nginxVhostMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	msg.Host = strings.ToLower(strings.TrimSpace(msg.Host))
	if hh, _, err := net.SplitHostPort(msg.Host); err == nil && hh != "" {
		msg.Host = hh
	}
	if msg.Host == "" {
		http.Error(w, "bad fields", http.StatusBadRequest)
		return
	}

	ttl := time.Duration(msg.TTLSec) * time.Second
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}

	b.mu.Lock()
	b.vhState[msg.Host] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(ttl), Reason: strings.TrimSpace(msg.Reason)}
	b.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (b *NginxBridge) handleVhostClear(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var msg nginxVhostClearMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	delete(b.vhState, msg.Host)
	b.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// handleOKTouch: Lua tells us "this IP is active and has cfm_ok cookie, extend okState".
// POST /nginx/ok/touch { "ip":"1.2.3.4", "host":"example.com", "scope":"web", "ttl_sec":600 }
func (b *NginxBridge) handleOKTouch(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// If okState is disabled, no-op (still 200 so Lua doesn't spam logs)
	if b.cfg.OkIPTTL <= 0 {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "disabled": true})
		return
	}

	var msg nginxOKTouchMsg
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(msg.IP)
	host := normalizeHost(msg.Host)
	scope := strings.TrimSpace(msg.Scope)
	if ip == "" || host == "" || scope == "" {
		http.Error(w, "bad fields", http.StatusBadRequest)
		return
	}

	ttl := time.Duration(msg.TTLSec) * time.Second
	if ttl <= 0 {
		ttl = b.cfg.OkIPTTL
	}

	now := time.Now()
	exp := now.Add(ttl)

	b.mu.Lock()
	b.okState[okStateKey{IP: ip, Host: host, Scope: scope}] = exp
	b.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ttl_sec": int(ttl.Seconds())})
}

// handleObserve: OpenResty reports an observed request outcome (e.g. WAF returned 403).
// POST /nginx/observe { "ip":"1.2.3.4", "host":"a.com", "uri":"/x", "method":"get", "status":403, "reason":"PAY_XSS" }
func (b *NginxBridge) handleObserve(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}

	// Defensive: cap body size (avoid abuse over the socket)
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

	var msg nginxObserveMsg
	dec := json.NewDecoder(bufio.NewReader(r.Body))
	if err := dec.Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	ip := strings.TrimSpace(msg.IP)
	if ip == "" {
		http.Error(w, "bad fields", http.StatusBadRequest)
		return
	}

	host := normalizeHost(msg.Host)
	uri := strings.TrimSpace(msg.URI)
	method := strings.ToLower(strings.TrimSpace(msg.Method))
	status := msg.Status
	reason := strings.TrimSpace(msg.Reason)

	// Sanity: allow 100..599
	if status < 100 || status > 599 {
		status = 0
	}

	// Fire hook (do not block bridge). Dispatched async — InjectObserved
	// writes history rows and runs the ingest pipeline, either of which
	// can spike well past the Lua client's decision_timeout_ms.
	if b.OnObserve != nil {
		b.dispatchHook(func() {
			b.OnObserve(ip, host, uri, method, status, reason)
		})
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// handleEventsBatch receives queued Lua events in a single HTTP call.
//
// Lua's event flusher accumulates non-critical bridge events (observe, ok/touch,
// ip push) in a shared dict queue and flushes them as a JSON batch every
// CFM_EVENT_FLUSH_INTERVAL_SEC (default 1s). This handler processes all events
// in-process without N individual socket round-trips.
//
// Wire format:
//
//	POST /nginx/events/batch
//	{
//	  "events": [
//	    { "p": "/nginx/observe",  "b": "{\"ip\":\"1.2.3.4\",...}", "t": 1712345678.123 },
//	    { "p": "/nginx/ok/touch", "b": "{\"ip\":\"5.6.7.8\",\"ttl_sec\":1800}", "t": ... },
//	    ...
//	  ]
//	}
func (b *NginxBridge) handleEventsBatch(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}

	// Generous cap: 64 events × ~512 bytes ≈ 32KB typical; allow up to 256KB.
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)

	var batch struct {
		Events []struct {
			P string  `json:"p"` // original path: "/nginx/observe", "/nginx/ok/touch", "/nginx/ip"
			B string  `json:"b"` // original JSON payload (pre-encoded by Lua)
			T float64 `json:"t"` // enqueue timestamp (informational only)
		} `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	processed := 0
	now := time.Now()

	for _, ev := range batch.Events {
		path := strings.TrimSpace(ev.P)
		body := ev.B
		if path == "" || body == "" {
			continue
		}

		switch path {

		case "/nginx/observe":
			var msg nginxObserveMsg
			if err := json.Unmarshal([]byte(body), &msg); err != nil {
				continue
			}
			ip := strings.TrimSpace(msg.IP)
			host := normalizeHost(msg.Host)
			if ip == "" {
				continue
			}
			uri := strings.TrimSpace(msg.URI)
			method := strings.ToLower(strings.TrimSpace(msg.Method))
			status := msg.Status
			if status < 100 || status > 599 {
				status = 0
			}
			reason := strings.TrimSpace(msg.Reason)
			if b.OnObserve != nil {
				b.dispatchHook(func() {
					b.OnObserve(ip, host, uri, method, status, reason)
				})
			}
			processed++

		case "/nginx/ok/touch":
			if b.cfg.OkIPTTL <= 0 {
				processed++ // disabled; no-op but count as processed
				continue
			}
			var msg nginxOKTouchMsg
			if err := json.Unmarshal([]byte(body), &msg); err != nil {
				continue
			}
			ip := strings.TrimSpace(msg.IP)
			host := normalizeHost(msg.Host)
			scope := strings.TrimSpace(msg.Scope)
			if ip == "" || host == "" || scope == "" {
				continue
			}
			ttl := time.Duration(msg.TTLSec) * time.Second
			if ttl <= 0 {
				ttl = b.cfg.OkIPTTL
			}
			exp := now.Add(ttl)
			b.mu.Lock()
			b.okState[okStateKey{IP: ip, Host: host, Scope: scope}] = exp
			b.mu.Unlock()
			processed++

		case "/nginx/ip":
			var msg nginxIPMsg
			if err := json.Unmarshal([]byte(body), &msg); err != nil {
				continue
			}
			if msg.IP == "" || (msg.Action != "challenge" && msg.Action != "block" && msg.Action != "logonly") {
				continue
			}
			ttl := time.Duration(msg.TTLSec) * time.Second
			if ttl <= 0 {
				ttl = b.cfg.DefaultTTL
			}
			reason := strings.TrimSpace(msg.Reason)
			msg.Host = normalizeHost(msg.Host)
			msg.URI = strings.TrimSpace(msg.URI)
			msg.Method = strings.ToLower(strings.TrimSpace(msg.Method))

			if msg.Action != "logonly" {
				b.mu.Lock()
				b.ipState[msg.IP] = bridgeIPEntry{
					Action:  msg.Action,
					Expires: now.Add(ttl),
					Reason:  reason,
				}
				b.mu.Unlock()
			}
			if reason != "" && b.OnTrigger != nil {
				ip, action, host, uri, method, wafRuleID := msg.IP, msg.Action, msg.Host, msg.URI, msg.Method, msg.WAFRuleID
				sample, ua, referer, ct := msg.Sample, msg.UA, msg.Referer, msg.ContentType
				b.dispatchHook(func() {
					b.OnTrigger(ip, action, reason, ttl, host, uri, method, wafRuleID, sample, ua, referer, ct)
				})
			}
			processed++

		default:
			// Unknown event path — skip silently for forward compatibility.
			continue
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"processed": processed,
		"total":     len(batch.Events),
	})
}

func (b *NginxBridge) handleWAFExcluded(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	host := normalizeHost(r.URL.Query().Get("host"))
	uri := strings.TrimSpace(r.URL.Query().Get("uri"))
	excluded := false
	if b.IsWAFExcluded != nil {
		excluded = b.IsWAFExcluded(host, uri)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"excluded": excluded})
}

func (b *NginxBridge) handleWAFExcludedMeta(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	hasAny := false
	if b.HasWAFExcludes != nil {
		hasAny = b.HasWAFExcludes()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"has_any": hasAny})
}

func (b *NginxBridge) handleWAFExcludes(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	items := make([]excludeEntry, 0)
	if b.ListWAFExcludes != nil {
		for _, e := range b.ListWAFExcludes() {
			if strings.TrimSpace(e.Type) == "" || strings.TrimSpace(e.Value) == "" {
				continue
			}
			items = append(items, e)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"entries": items})
}

// handleWAFStats accepts the periodic snapshot pushed by Lua's
// maybe_flush_waf_insp. The body is {"rows":[{hour_unix, host, count}, ...]}
// with absolute counts per (hour, host); Go upserts each row idempotently.
//
// Set via b.OnWAFStats; if no consumer is wired the request is accepted
// silently to avoid Lua spamming retries during config reload.
func (b *NginxBridge) handleWAFStats(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var msg nginxWAFStatsMsg
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if b.OnWAFStats != nil && len(msg.Rows) > 0 {
		// Copy fields out of the request-scope slice; dispatch one hook per
		// row so each persistence call is independent.
		for _, r := range msg.Rows {
			hr, host, cnt := r.HourUnix, r.Host, r.Count
			b.dispatchHook(func() {
				b.OnWAFStats(hr, host, cnt)
			})
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (b *NginxBridge) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b.Status())
}

// handleSnapshot returns active ip/vhost actions and ordered traffic rules for
// local Lua-side enforcement. Intended for periodic refresh (not per-request).
func (b *NginxBridge) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now()
	resp := nginxSnapshotResp{
		IPs:         make([]nginxSnapshotIP, 0),
		Vhosts:      make([]nginxSnapshotVhost, 0),
		Rules:       make([]TrafficRule, 0),
		WAFExcludes: make([]excludeEntry, 0),
		TSUnix:      now.Unix(),
	}

	b.mu.RLock()
	for ip, e := range b.ipState {
		if e.Expires.After(now) {
			resp.IPs = append(resp.IPs, nginxSnapshotIP{
				IP:     ip,
				Action: e.Action,
			})
		}
	}
	for h, e := range b.vhState {
		if e.Expires.After(now) {
			resp.Vhosts = append(resp.Vhosts, nginxSnapshotVhost{
				Host:   h,
				Action: e.Action,
			})
		}
	}
	b.mu.RUnlock()

	if b.ListTrafficRules != nil {
		resp.Rules = b.ListTrafficRules()
	}
	if b.ListWAFExcludes != nil {
		resp.WAFExcludes = b.ListWAFExcludes()
	}
	sort.Slice(resp.IPs, func(i, j int) bool {
		if resp.IPs[i].IP != resp.IPs[j].IP {
			return resp.IPs[i].IP < resp.IPs[j].IP
		}
		return resp.IPs[i].Action < resp.IPs[j].Action
	})
	sort.Slice(resp.Vhosts, func(i, j int) bool {
		if resp.Vhosts[i].Host != resp.Vhosts[j].Host {
			return resp.Vhosts[i].Host < resp.Vhosts[j].Host
		}
		return resp.Vhosts[i].Action < resp.Vhosts[j].Action
	})
	sort.Slice(resp.WAFExcludes, func(i, j int) bool {
		if resp.WAFExcludes[i].Type != resp.WAFExcludes[j].Type {
			return resp.WAFExcludes[i].Type < resp.WAFExcludes[j].Type
		}
		return resp.WAFExcludes[i].Value < resp.WAFExcludes[j].Value
	})
	resp.Version = snapshotVersion(resp.IPs, resp.Vhosts, resp.Rules, resp.WAFExcludes)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (b *NginxBridge) checkToken(r *http.Request) bool {
	// Fail-closed: an empty token means misconfigured — reject all requests
	// rather than leaving the socket unauthenticated.
	if b.cfg.Token == "" {
		return false
	}
	return r.Header.Get("X-CFM-Token") == b.cfg.Token
}

// GetIPDecision returns the current action and reason for an IP from the
// in-process state. Used by the challenge server for post-intercept logging.
// Returns ("", "") if the IP has no active entry.
func (b *NginxBridge) GetIPDecision(ip string) (action, reason string) {
	if b == nil {
		return "", ""
	}
	b.mu.RLock()
	e, ok := b.ipState[ip]
	b.mu.RUnlock()
	if !ok || time.Now().After(e.Expires) {
		return "", ""
	}
	return e.Action, e.Reason
}
