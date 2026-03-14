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
	"cfm/internal/logging"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
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
	okState        map[string]time.Time        // ip   → solved-ok expiry (bypasses vhost challenge)
	bypassFunc     func(string) bool           // set once at startup; no lock needed (written before serving starts)
	hostBypassFunc func(string) bool           // host-level permanent allow (CHALLENGE_HOST_BYPASS); same write-once guarantee
	stats          BridgeStats

	// OnTrigger is called when an external push (e.g. cfm_waf.lua) sets a new
	// IP decision via POST /nginx/ip. The hook receives the IP, action
	// ("challenge"|"block"), reason (e.g. "WAF_XSS"), and TTL so the caller
	// can log to cfm.challenges.log with enrichment. Optional metadata
	// Set via SetTriggerHook. Called without b.mu held.
	OnTrigger func(ip, action, reason string, ttl time.Duration, host, uri, method string)

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
}

// refreshSkew is the minimum remaining time before we bother to re-push
// an already-active decision (to avoid log spam / needless socket traffic).
// We only refresh when an entry is close to expiring.
const refreshSkew = 30 * time.Second

type bridgeCfg struct {
	Enabled    bool
	SockPath   string
	Token      string
	DefaultTTL time.Duration
	OkIPTTL    time.Duration // if 0 -> cookie-only (no IP ok-state)
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

// BridgeStats is exported for cfm status / JSON API.
type BridgeStats struct {
	mu sync.Mutex

	Pushes     int64     `json:"pushes"`
	Errors     int64     `json:"errors"`
	LastError  string    `json:"last_error,omitempty"`
	LastPushAt time.Time `json:"last_push_at,omitempty"`

	ActiveIPs    int `json:"active_ips"`
	ActiveVhosts int `json:"active_vhosts"`
}

// NginxBridgeStatus is what GET /nginx/status returns.
type NginxBridgeStatus struct {
	Enabled      bool        `json:"enabled"`
	SockPath     string      `json:"sock_path"`
	ActiveIPs    []string    `json:"active_ips"`
	ActiveVhosts []string    `json:"active_vhosts"`
	Stats        BridgeStats `json:"stats"`
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
	TTLSec int    `json:"ttl_sec"`
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
	if b == nil || !b.cfg.Enabled {
		return
	}
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}
	exp := time.Now().Add(ttl)

	b.mu.Lock()
	cur, ok := b.okState[ip]
	if !ok || exp.After(cur) {
		b.okState[ip] = exp
	}
	b.mu.Unlock()
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
		okState: make(map[string]time.Time),
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
func (b *NginxBridge) SetTriggerHook(fn func(ip, action, reason string, ttl time.Duration, host, uri, method string)) {
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

func (b *NginxBridge) GetReason(ip string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ipState[ip].Reason
}

// Also adds the IP to the solved-ok set so it bypasses vhost-wide challenge
// for the next 60 minutes — matching the solved cookie TTL.
func (b *NginxBridge) ClearIP(ip string) {
	if !b.cfg.Enabled {
		return
	}

	b.mu.Lock()
	delete(b.ipState, ip)
	if b.cfg.OkIPTTL > 0 {
		b.okState[ip] = time.Now().Add(b.cfg.OkIPTTL)
	} else {
		delete(b.okState, ip)
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

	b.stats.mu.Lock()
	st := b.stats
	st.ActiveIPs = len(ips)
	st.ActiveVhosts = len(vhs)
	b.stats.mu.Unlock()

	return NginxBridgeStatus{
		Enabled:      true,
		SockPath:     b.cfg.SockPath,
		ActiveIPs:    ips,
		ActiveVhosts: vhs,
		Stats:        st,
	}
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
	b.stats.Pushes++
	b.stats.LastPushAt = time.Now()
	b.stats.mu.Unlock()
}

func (b *NginxBridge) recordErr(msg string) {
	logging.Logf("[nginx_bridge] WARN: %s", msg)
	b.stats.mu.Lock()
	b.stats.Errors++
	b.stats.LastError = msg
	b.stats.mu.Unlock()
}

// ── ServeHTTP: the unix-socket server that Lua reads from ─────────────────────
//
// This is the *server* side — OpenResty Lua connects here to get the current
// decision state. Run as: go bridge.ServeDecisions(ctx)

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
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("nginx_bridge listen %s: %w", sockPath, err)
	}
	// allow www-data (OpenResty) to connect
	_ = os.Chmod(sockPath, 0o660)

	mux := http.NewServeMux()
	mux.HandleFunc("/nginx/decision", b.handleDecision)
	mux.HandleFunc("/nginx/ip", b.handleIPPush)
	mux.HandleFunc("/nginx/ip/clear", b.handleIPClear)
	mux.HandleFunc("/nginx/vhost", b.handleVhostPush)
	mux.HandleFunc("/nginx/vhost/clear", b.handleVhostClear)
	mux.HandleFunc("/nginx/ok/touch", b.handleOKTouch)
	mux.HandleFunc("/nginx/observe", b.handleObserve)
	mux.HandleFunc("/nginx/waf/excluded", b.handleWAFExcluded)
	mux.HandleFunc("/nginx/waf/excluded/meta", b.handleWAFExcludedMeta)
	mux.HandleFunc("/nginx/waf/excludes", b.handleWAFExcludes)
	mux.HandleFunc("/nginx/status", b.handleStatus)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}

	go func() {
		<-ctx.Done()
		ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx2)
		_ = os.Remove(sockPath)
	}()

	logging.Logf("[nginx_bridge] decision server listening on unix:%s", sockPath)
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ── HTTP handlers (server side, called by Lua) ────────────────────────────────

// handleDecision: Lua asks "what do I do with this IP / vhost?"
// GET /nginx/decision?ip=1.2.3.4&host=example.com
func (b *NginxBridge) handleDecision(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
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
		// wildcard match: keys like "*.example.com"
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
			}
		}
	}

	// Solved-ok: IP passed PoW recently — bypass vhost-wide challenge.
	if b.cfg.OkIPTTL > 0 {
		if exp, ok := b.okState[ip]; ok && exp.After(now) {
			vhAction = "allow"
			ipAction = "allow"
		}
	}
	b.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"ip_action":    ipAction, // "allow" | "challenge" | "block"
		"vhost_action": vhAction, // "allow" | "challenge"
	})
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
	if reason != "" && b.OnTrigger != nil {
		b.OnTrigger(msg.IP, msg.Action, reason, ttl, msg.Host, msg.URI, msg.Method)
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
// POST /nginx/ok/touch { "ip":"1.2.3.4", "ttl_sec":600 }
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
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(msg.IP)
	if ip == "" {
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
	b.okState[ip] = exp
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

	// Fire hook (do not block bridge). The hook must be fast / non-blocking.
	if b.OnObserve != nil {
		b.OnObserve(ip, host, uri, method, status, reason)
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
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
	type item struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	items := make([]item, 0)
	if b.ListWAFExcludes != nil {
		for _, e := range b.ListWAFExcludes() {
			if strings.TrimSpace(e.Type) == "" || strings.TrimSpace(e.Value) == "" {
				continue
			}
			items = append(items, item{Type: e.Type, Value: e.Value})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"entries": items})
}

func (b *NginxBridge) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(b.Status())
}

func (b *NginxBridge) checkToken(r *http.Request) bool {
	if b.cfg.Token == "" {
		return true
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
