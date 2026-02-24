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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
	"strings"
	"cfm/internal/logging"
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
//        started bool

	mu      sync.RWMutex
	ipState map[string]bridgeIPEntry    // ip   → current decision
	vhState map[string]bridgeVhostEntry // host → current decision
	okState map[string]time.Time        // ip   → solved-ok expiry (bypasses vhost challenge)

	stats BridgeStats
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
	Action  string    // "challenge" | "block"
	Expires time.Time
}

type bridgeVhostEntry struct {
	Action  string    // "challenge"
	Expires time.Time
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
	Enabled      bool              `json:"enabled"`
	SockPath     string            `json:"sock_path"`
	ActiveIPs    []string          `json:"active_ips"`
	ActiveVhosts []string          `json:"active_vhosts"`
	Stats        BridgeStats       `json:"stats"`
}

// ── Wire types (shared with Lua via JSON) ─────────────────────────────────────

type nginxIPMsg struct {
	IP     string `json:"ip"`
	Action string `json:"action"`  // "challenge" | "block"
	TTLSec int    `json:"ttl_sec"`
}

type nginxIPClearMsg struct {
	IP string `json:"ip"`
}

type nginxVhostMsg struct {
	Host   string `json:"host"`
	Action string `json:"action"`  // "challenge"
	TTLSec int    `json:"ttl_sec"`
}

type nginxVhostClearMsg struct {
	Host string `json:"host"`
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
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}

	b.mu.Lock()
	b.ipState[ip] = bridgeIPEntry{Action: "block", Expires: time.Now().Add(ttl)}
	b.mu.Unlock()

	b.post("/nginx/ip", nginxIPMsg{IP: ip, Action: "block", TTLSec: int(ttl.Seconds())})
}

// ClearIP removes any active challenge/block for this IP (e.g. after PoW solved).
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

// ChallengeVhost puts an entire vhost into challenge mode.
// Every request to that vhost will be challenged regardless of IP.
// Called when CHALLENGE_VHOST fires or CHALLENGE_SUSPICIOUS_VHOST_SCORE turns on.
func (b *NginxBridge) ChallengeVhost(host string, ttl time.Duration) {
	if !b.cfg.Enabled {
		return
	}
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}

//b.mu.Lock()
//b.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(ttl)}
//b.mu.Unlock()
//b.post("/nginx/vhost", nginxVhostMsg{Host: host, Action: "challenge", TTLSec: int(ttl.Seconds())})
//logging.Logf("[nginx_bridge] vhost_challenge host=%s ttl=%s", host, ttl)


    host = normalizeHost(host)
    if host == "" { return }

    now := time.Now()
    exp := now.Add(ttl)

    needPush := false
    logEnter := false

    b.mu.Lock()
    cur, ok := b.vhState[host]
    // Only push/log on state transition, or when we're close to expiry.
    if !ok || cur.Action != "challenge" || cur.Expires.Before(now) {
        b.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: exp}
        needPush = true
        logEnter = true
    } else {
        // Keep it sticky without spamming: extend locally, push only near expiry.
        if exp.After(cur.Expires) {
            b.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: exp}
        }
        if cur.Expires.Sub(now) < refreshSkew {
            needPush = true
        }
    }
    b.mu.Unlock()

    if needPush {
        b.post("/nginx/vhost", nginxVhostMsg{Host: host, Action: "challenge", TTLSec: int(ttl.Seconds())})
    }
    if logEnter {
        logging.Logf("[nginx_bridge] vhost_challenge host=%s ttl=%s", host, ttl)
    }


}

// ClearVhost removes vhost-wide challenge mode.
// Called when CHALLENGE_SUSPICIOUS_VHOST_SCORE score drops below ScoreOff.
func (b *NginxBridge) ClearVhost(host string) {
	if !b.cfg.Enabled {
		return
	}

    host = normalizeHost(host)
    if host == "" { return }

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

func normalizeHost(h string) string {
    h = strings.TrimSpace(strings.ToLower(h))
    if h == "" { return "" }
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
//   GET /nginx/decision?ip=1.2.3.4&host=example.com
//   → { "ip_action": "challenge|block|allow", "vhost_action": "challenge|allow" }
//
//   GET /nginx/status
//   → NginxBridgeStatus
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
	mux.HandleFunc("/nginx/decision",   b.handleDecision)
	mux.HandleFunc("/nginx/ip",         b.handleIPPush)
	mux.HandleFunc("/nginx/ip/clear",   b.handleIPClear)
	mux.HandleFunc("/nginx/vhost",      b.handleVhostPush)
	mux.HandleFunc("/nginx/vhost/clear", b.handleVhostClear)
	mux.HandleFunc("/nginx/status",     b.handleStatus)

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

    ip   := strings.TrimSpace(r.URL.Query().Get("ip"))
    host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
    if hh, _, err := net.SplitHostPort(host); err == nil && hh != "" {
        host = hh
    }
	now  := time.Now()

	ipAction   := "allow"
	vhAction   := "allow"

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
		}
	}
	b.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"ip_action":   ipAction,   // "allow" | "challenge" | "block"
		"vhost_action": vhAction,  // "allow" | "challenge"
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
	if msg.IP == "" || (msg.Action != "challenge" && msg.Action != "block") {
		http.Error(w, "bad fields", http.StatusBadRequest)
		return
	}
	ttl := time.Duration(msg.TTLSec) * time.Second
	if ttl <= 0 {
		ttl = b.cfg.DefaultTTL
	}

	b.mu.Lock()
	b.ipState[msg.IP] = bridgeIPEntry{Action: msg.Action, Expires: time.Now().Add(ttl)}
	b.mu.Unlock()

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
	b.vhState[msg.Host] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(ttl)}
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
