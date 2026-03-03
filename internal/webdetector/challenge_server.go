package webdetector

import (
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"cfm/internal/sslcollector"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"os"
	"sync"
)

const (
	verifyPath    = "/__cfm_verify" // new preferred endpoint
	verifyPathOld = "/verify"       // legacy (keep during rollout)
)

type ChallengeServer struct {
	httpSrv  *http.Server
	httpsSrv *http.Server

	httpLn  net.Listener
	httpsLn net.Listener

	ssl    *sslcollector.Collector
	fw     firewall.Backend
	bridge *NginxBridge // OpenResty mode: ClearIP after solve

	cookieLife time.Duration // solved cookie lifetime (cfm_ok) and OK TTL

	// Tracks all goroutines started by Start(), including Serve() loops and the
	// ctx-cancel shutdown goroutine. Used on hot-reload to avoid port bind races.
	wg sync.WaitGroup

	// Self-protection: in-process rate limiting (per source IP) to reduce CPU
	// burn from spammers hitting / and especially /verify.
	rlMu     sync.Mutex
	rlByIP   map[string]*ipRateState
	rlLastGC time.Time

	// Optional: escalate self-protection bans into firewall blocks (local nft set with timeout).
	// Disabled by default to avoid surprises; enable later via config/plumbing if desired.
	rlFwEnabled   bool
	rlFwTTLPage   time.Duration
	rlFwTTLVerify time.Duration

	// Separate access log for per-request challenge HTTP lines ([challenge_http] ...).
	accessLogPath string
	accessLog     *challengeAccessLogger

	// Abuse blocking (many 4xx/5xx on non-verify paths inside challenge server)
	abuseEnabled  bool
	abuseWindow   time.Duration
	abuseBadN     int
	abuseBlockTTL time.Duration
	abuseCooldown time.Duration

	abuseMu   sync.Mutex
	abuseByIP map[string]*abuseState

	// Optional global ignore (wired by detectors layer, from [global] IGNORE_IPS/IGNORE_NETS).
	// If matched, challenge server will "auto-solve" (set cfm_ok + release) and redirect.
	ignoreFn  func(ipStr string) bool
	ignoreLog bool
}

type abuseState struct {
	winStart     time.Time
	badCount     int
	lastSeen     time.Time
	cooldownTill time.Time
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

// challengeAccessLogger writes [challenge_http] lines to a separate file.
// It opens lazily and falls back to logging.LogfCHALLENGES on failure.
type challengeAccessLogger struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

func newChallengeAccessLogger(path string) *challengeAccessLogger {
	p := strings.TrimSpace(path)
	if p == "" {
		return nil
	}
	return &challengeAccessLogger{path: p}
}
func (l *challengeAccessLogger) close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}

func (l *challengeAccessLogger) logf(format string, args ...any) {
	if l == nil || l.path == "" {
		logging.LogfCHALLENGES(format, args...)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.f == nil {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			logging.LogfCHALLENGES("[challenge_http] accesslog open failed: %s: %v", l.path, err)
			logging.LogfCHALLENGES(format, args...)
			return
		}
		l.f = f
	}

	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s "+format+"\n", append([]any{ts}, args...)...)
	_, _ = l.f.WriteString(line)
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (s *ChallengeServer) wrapAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		// log only verify + errors to keep noise low
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		if sw.status >= 400 || path == verifyPath || path == verifyPathOld {
			ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))
			if ip == "" {
				ip = strings.TrimSpace(r.Header.Get("X-Real-IP"))
			}
			if ip == "" {
				host, _, _ := net.SplitHostPort(r.RemoteAddr)
				if host != "" {
					ip = host
				} else {
					ip = r.RemoteAddr
				}
			}
			host := r.Host
			uri := path
			if r.URL.RawQuery != "" {
				uri += "?" + r.URL.RawQuery
			}
			if s.accessLog != nil {
				s.accessLog.logf("[challenge_http] ip=%s host=%s method=%s uri=%s status=%d bytes=%d ms=%d",
					ip, host, r.Method, uri, sw.status, sw.bytes, time.Since(start).Milliseconds(),
				)
			} else {
				logging.LogfCHALLENGES("[challenge_http] ip=%s host=%s method=%s uri=%s status=%d bytes=%d ms=%d",
					ip, host, r.Method, uri, sw.status, sw.bytes, time.Since(start).Milliseconds(),
				)
			}

			// Abuse blocking (many 4xx/5xx on non-verify paths)
			// Abuse blocking (many 4xx/5xx on non-verify paths)
			// IMPORTANT: do NOT feed self-protection 429s into abuseObserve(),
			// otherwise a verify-loop (cookie/domain mismatch) escalates into
			// challenge_abuse firewall blocks.
			if !(sw.status == http.StatusTooManyRequests && sw.Header().Get("Retry-After") != "") {
				s.abuseObserve(ip, host, uri, sw.status)
			}

		}
	})
}

// SetCookieLife configures how long the solved cookie should live.
// If <=0, a safe default is used.
func (s *ChallengeServer) SetCookieLife(d time.Duration) { s.cookieLife = d }

func (s *ChallengeServer) cookieTTL() time.Duration {
	if s.cookieLife > 0 {
		return s.cookieLife
	}
	return 60 * time.Minute
}

// SetNginxBridge wires the OpenResty bridge into the challenge server so that
// a successful PoW solve calls bridge.ClearIP(), letting Lua pass the IP through
// on the next request without querying the bridge again.
func (s *ChallengeServer) SetNginxBridge(b *NginxBridge) { s.bridge = b }

// SetAccessLogPath sets a separate file where [challenge_http] access lines will be written.
// If empty, access lines will continue to go to the main challenges log.
func (s *ChallengeServer) SetAccessLogPath(path string) { s.accessLogPath = strings.TrimSpace(path) }

// SetIPIgnore wires global ignore into challenge server (from [global] IGNORE_IPS/IGNORE_NETS).
// shouldIgnore must be fast and side-effect free.
func (s *ChallengeServer) SetIPIgnore(shouldIgnore func(string) bool, logIgnored bool) {
	s.ignoreFn = shouldIgnore
	s.ignoreLog = logIgnored
}

// SetAbuseConfig enables simple abuse blocking:
// if an IP causes >=badN requests with status>=400 (excluding verify endpoints)
// within "window", we add a firewall block with TTL "blockTTL", and we won't
// re-block the same IP until "cooldown" passes.
func (s *ChallengeServer) SetAbuseConfig(enabled bool, window time.Duration, badN int, blockTTL, cooldown time.Duration) {
	s.abuseEnabled = enabled
	if window > 0 {
		s.abuseWindow = window
	}
	if badN > 0 {
		s.abuseBadN = badN
	}
	if blockTTL > 0 {
		s.abuseBlockTTL = blockTTL
	}
	if cooldown > 0 {
		s.abuseCooldown = cooldown
	}
}

// Optional interface: only nft backend implements this.
type challengeRedirector interface {
	EnsureChallengeRedirect(httpListen, httpsListen string) error
}

func maybeListenV6LoopbackFromV4Loopback(addr string) (string, bool) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", false
	}
	if strings.TrimSpace(h) != "127.0.0.1" {
		return "", false
	}
	// build "[::1]:port"
	return net.JoinHostPort("::1", p), true
}

// Optional: cooldown-bypass set (recommended to avoid loops).
type challengeOKer interface {
	AddChallengeOK(ip net.IP, ttl *time.Duration) error
	RemoveChallengeOK(ip net.IP) error
}

const (
	maxVerifyBodyBytes  = 1 << 10 // 1KB
	maxUALen            = 256
	maxHostLen          = 253
	maxNextLen          = 2048
	maxHeaderBytesTight = 16 << 10 // 16KB (challenge server only)

	// ---- challenge server self-protection ----
	// /verify is the expensive endpoint (token + PoW verify). Keep it tight.
	rlVerifyWindow = 15 * time.Second
	rlVerifyBurst  = 30
	rlBanVerify    = 5 * time.Second

	// Challenge page (/) can be a bit looser.
	rlPageWindow = 15 * time.Second
	rlPageBurst  = 60
	rlBanPage    = 5 * time.Second

	rlGCInterval = 30 * time.Second
	rlStateTTL   = 10 * time.Minute
)

// ChallengeSolvedHook lets the detectors layer log solved/expired in a unified way.
// It is optional; if unset, ChallengeServer will log a minimal solved line.
type ChallengeSolvedHook func(ip, host, uri string, diff int, ms int64)

var challengeSolvedHook ChallengeSolvedHook

// SetChallengeSolvedHook installs a callback invoked after a successful solve.
func SetChallengeSolvedHook(h ChallengeSolvedHook) { challengeSolvedHook = h }

// ChallengeAbuseHook lets the detectors layer route challenge-server abuse
// into the unified sink (API/firewall/notifier), while the challenge server
// still keeps its own high-signal log line.
//
// If unset, ChallengeServer will fall back to direct firewall blocking.
type ChallengeAbuseHook func(ip, host, uri string, status int, badN int, window, blockTTL, cooldown time.Duration)

var challengeAbuseHook ChallengeAbuseHook

// SetChallengeAbuseHook installs a callback invoked when the challenge server
// detects abuse (many 4xx/5xx on non-verify paths within a window).
func SetChallengeAbuseHook(h ChallengeAbuseHook) { challengeAbuseHook = h }

func NewChallengeServer(ssl *sslcollector.Collector, fw firewall.Backend) *ChallengeServer {
	return &ChallengeServer{
		ssl: ssl,
		fw:  fw,

		rlByIP:   make(map[string]*ipRateState),
		rlLastGC: time.Now().UTC(),

		// firewall escalation defaults: OFF
		rlFwEnabled:   false,
		rlFwTTLPage:   2 * time.Minute,
		rlFwTTLVerify: 10 * time.Minute,
	}
}

func (s *ChallengeServer) Start(ctx context.Context, httpAddr, httpsAddr string) error {
	if s.accessLog == nil && strings.TrimSpace(s.accessLogPath) != "" {
		s.accessLog = newChallengeAccessLogger(s.accessLogPath)
	}

	if s.abuseByIP == nil {
		s.abuseByIP = make(map[string]*abuseState)
	}

	mux := http.NewServeMux()

	// Ensure nft NAT redirect rules exist (only if challenge listeners are set)
	if s.fw != nil {
		// Allow nft backend to emit rule-install debug lines into the same log file.
		if ls, ok := any(s.fw).(interface {
			SetChallengeLogger(func(format string, args ...any))
		}); ok {
			ls.SetChallengeLogger(logging.LogfCHALLENGES)
		}

		if cr, ok := any(s.fw).(challengeRedirector); ok {
			if err := cr.EnsureChallengeRedirect(httpAddr, httpsAddr); err != nil {
				// IMPORTANT: do NOT swallow; this is exactly how we ended up with DNAT but missing reset rules.
				logging.LogfCHALLENGES(
					"[challenge] nft ensure redirect FAILED http=%s https=%s err=%v",
					httpAddr, httpsAddr, err,
				)
				return fmt.Errorf("EnsureChallengeRedirect: %w", err)
			} else {
				// Optional: one-line confirmation (useful during debugging)
				logging.LogfCHALLENGES(
					"[challenge] nft ensure redirect OK http=%s https=%s",
					httpAddr, httpsAddr,
				)
			}
		}
	}

	// basic endpoints
	// --- VERIFY endpoint ---
	// JS will POST here with ?next=... and cookie set.
	verifyHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Global ignore: auto-solve + release (no rate-limit, no pow/token).
		// This prevents false-positive abuse blocks on trusted/internal networks.
		if ip := clientIP(r); ip != nil && s.shouldIgnoreIP(ip) {
			host := cleanHost(r.Host)
			next := r.URL.Query().Get("next")
			if next == "" {
				next = "/"
			}
			if !strings.HasPrefix(next, "/") {
				next = "/"
			}
			if len(next) > maxNextLen {
				next = "/"
			}
			s.autoSolveAndRelease(w, r, ip, host, next, "verify")
			return
		}

		// Self-protection: reject abusive IPs early (before reading body / verifying).
		if ip := clientIP(r); ip != nil {
			if ok, retry, bannedNow := s.rlAllow(ip.String(), rlKindVerify); !ok {
				if bannedNow {
					s.rlLogAbuse(r, ip.String(), rlKindVerify, retry)
					s.rlFirewallBlock(ip, rlKindVerify)
				}
				s.rlReject(w, retry)
				return
			}
		}

		// Hard cap body even though we don't use it (abuse / slowloris-ish clients)
		r.Body = http.MaxBytesReader(w, r.Body, maxVerifyBodyBytes)
		// Drain/close (some clients send junk; prevent resource pinning)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()

		// Header / Host / UA sanity (defense-in-depth)
		if !basicHeaderSanity(w, r) {
			return
		}
		if isWeirdUA(r.UserAgent()) {
			// Optional: you can also add a short penalty here (block/extend challenge)
			http.Error(w, "bad ua", http.StatusForbidden)
			return
		}

		verifyStart := time.Now()
		host := cleanHost(r.Host)

		ip := clientIP(r)
		ipStr := ""
		if ip == nil {
			http.Error(w, "bad client ip", http.StatusBadRequest)
			return
		}

		ipStr = ip.String()
		next := r.URL.Query().Get("next")
		if next == "" {
			next = "/"
		}
		// prevent open redirect
		if !strings.HasPrefix(next, "/") {
			next = "/"
		}

		if len(next) > maxNextLen {
			next = "/"
		}

		// Require cookie + HMAC token
		c, err := r.Cookie("cfm_chal")
		if err != nil || strings.TrimSpace(c.Value) == "" {
			http.Error(w, "missing cookie", http.StatusForbidden)
			return
		}

		// Expect token in header (sent by JS)
		tok := strings.TrimSpace(r.Header.Get("X-CFM-Token"))
		if tok == "" {
			http.Error(w, "missing token", http.StatusForbidden)
			return
		}
		if !verifyToken(tok, ip.String(), r.UserAgent(), c.Value) {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}

		// Require PoW too (token + cookie + PoW)
		powTok := strings.TrimSpace(r.Header.Get("X-CFM-Pow"))
		sol := strings.TrimSpace(r.Header.Get("X-CFM-Sol"))
		if powTok == "" || sol == "" {
			http.Error(w, "missing pow", http.StatusForbidden)
			return
		}

		cfg := defaultPowConfig()
		if !cfg.Enabled {
			http.Error(w, "pow disabled", http.StatusForbidden)
			return
		}

		// IMPORTANT: bind must be JS-reproducible => UA + cookie (no IP)
		bind := powBind(r.UserAgent(), c.Value)

		diff, nonce16, ok := verifyPowChallenge(powSecretKey(), powTok, bind, cfg, time.Now().UTC())
		if !ok || !verifyPowSolution(nonce16, bind, sol, diff) {
			http.Error(w, "bad pow", http.StatusForbidden)
			return
		}

		if challengeSolvedHook != nil {
			challengeSolvedHook(ipStr, host, next, diff, time.Since(verifyStart).Milliseconds())
		} else {
			logging.LogfCHALLENGES(
				"[challenge] ip=%s host=%s uri=%s result=solved ms=%d diff=%d",
				ip.String(),
				host,
				next,
				time.Since(verifyStart).Milliseconds(),
				diff,
			)
		}

		// Release:
		// 1) remove from nft challenge set (DNAT mode)
		if s.fw != nil {
			_ = s.fw.RemoveChallenge(ip)
			// 2) add cooldown OK (prevents immediate re-challenge loop)
			if oker, ok := any(s.fw).(challengeOKer); ok {
				ttl := s.cookieTTL()
				_ = oker.AddChallengeOK(ip, &ttl)
			}
		}

		// 3) OpenResty mode: clear IP from bridge so Lua passes it through.
		//    This is the primary release path when fw == nil (no DNAT).
		if s.bridge != nil {
			s.bridge.ClearIP(ipStr)
		}

		// 4) Set solved cookie so OpenResty can fast-path without re-query/cache loops.
		// Secure should follow the *original* scheme (OpenResty terminates TLS),
		// so trust X-Forwarded-Proto when present.
		xfProto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
		secure := (r.TLS != nil) || (xfProto == "https")

		// Random token is enough: unguessable => cannot be forged.
		// (Lua only checks presence; it doesn't validate, so don't use something guessable.)
		okVal := randomCookieValue()
		ttl := s.cookieTTL()
		http.SetCookie(w, &http.Cookie{
			Name:     "cfm_ok",
			Value:    okVal,
			Path:     "/",
			MaxAge:   int(ttl.Seconds()),
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})

		// Optional: expire the challenge cookie to reduce confusion/churn.
		http.SetCookie(w, &http.Cookie{
			Name:   "cfm_chal",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		// Give nft/conntrack a tiny moment; helps avoid browser redirect loops on keep-alives.
		time.Sleep(500 * time.Millisecond)

		// Redirect back to original path (relative redirect avoids scheme/host loops)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "close")

		// Safety: next is already forced to start with "/" above.
		http.Redirect(w, r, next, http.StatusSeeOther) // 303

	}

	// New endpoint + legacy alias.
	mux.HandleFunc(verifyPath, verifyHandler)
	mux.HandleFunc(verifyPathOld, verifyHandler)

	// --- CATCH-ALL: handle any path ---
	// Important: register after /hello,/healthz,/verify.

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		// Header / Host / UA sanity (defense-in-depth)
		if !basicHeaderSanity(w, r) {
			return
		}
		if isWeirdUA(r.UserAgent()) {
			http.Error(w, "bad ua", http.StatusForbidden)
			return
		}

		// Only GET/HEAD should ever get the challenge HTML.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// UX fix:
			// If a user is challenged while doing a POST (wp-admin save, login submit, etc),
			// returning 405 is confusing. Bounce them to the challenge page using GET.
			// We intentionally ONLY do this for POST (not OPTIONS) to avoid breaking
			// preflights or non-browser clients.
			if r.Method == http.MethodPost {
				next := r.URL.RequestURI()
				w.Header().Set("Cache-Control", "no-store")
				http.Redirect(w, r, "/?next="+url.QueryEscape(next), http.StatusSeeOther) // 303
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Avoid browsers hitting /favicon.ico etc causing token/cookie churn.
		// Always serve the challenge page from "/" only.
		if r.URL.Path != "/" {
			next := r.URL.RequestURI()
			w.Header().Set("Cache-Control", "no-store")

			http.Redirect(w, r, "/?next="+url.QueryEscape(next), http.StatusFound)
			return
		}
		// let existing endpoints win (ServeMux does this anyway)
		if r.URL.Path == "/hello" || r.URL.Path == "/healthz" || r.URL.Path == verifyPath || r.URL.Path == verifyPathOld {
			http.NotFound(w, r)
			return
		}

		ip := clientIP(r)
		if ip == nil {
			http.Error(w, "bad client ip", http.StatusBadRequest)
			return
		}

		// next (single parse + sanitize; reused below)
		next := r.URL.Query().Get("next")
		if next == "" {
			next = "/"
		}
		if !strings.HasPrefix(next, "/") {
			next = "/"
		}
		if len(next) > maxNextLen {
			next = "/"
		}

		// Global ignore: auto-solve + release (no challenge page, no abuse tracking).
		if s.shouldIgnoreIP(ip) {
			host := cleanHost(r.Host)
			s.autoSolveAndRelease(w, r, ip, host, next, "page")
			return
		}

		// Self-protection: rate limit challenge page requests per IP.
		if ok, retry, bannedNow := s.rlAllow(ip.String(), rlKindPage); !ok {
			if bannedNow {
				s.rlLogAbuse(r, ip.String(), rlKindPage, retry)
				s.rlFirewallBlock(ip, rlKindPage)
			}
			s.rlReject(w, retry)
			return
		}

		// If already solved (cookie present + token valid), release and redirect.
		next = r.URL.Query().Get("next")
		if next == "" {
			next = "/"
		}
		if !strings.HasPrefix(next, "/") {
			next = "/"
		}
		if len(next) > maxNextLen {
			next = "/"
		}

		// cookie challenge: set ONLY if missing (prevents token mismatch loops)
		cookieVal := ""
		if c, err := r.Cookie("cfm_chal"); err == nil && strings.TrimSpace(c.Value) != "" {
			cookieVal = c.Value
		} else {
			cookieVal = randomCookieValue()
			http.SetCookie(w, &http.Cookie{
				Name:     "cfm_chal",
				Value:    cookieVal,
				Path:     "/",
				MaxAge:   300,
				HttpOnly: false, // JS reads it
				Secure:   (r.TLS != nil),
				SameSite: http.SameSiteLaxMode,
			})
		}

		// Render challenge page (JS calls /verify with token)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		host := cleanHost(r.Host)

		// token binds to IP+UA+cookie
		//                tok := issueToken(ip.String(), r.UserAgent(), cookieVal)
		// challengeHTML placeholders are: host, token, next
		//                fmt.Fprintf(w, challengeHTML(), htmlEscape(host), htmlEscape(tok), htmlEscape(next))

		// token binds to IP+UA+cookie
		tok := issueToken(ip.String(), r.UserAgent(), cookieVal)

		// PoW challenge token (additive, but required at verify time)

		cfg := defaultPowConfig()
		powTok := ""

		if cfg.Enabled {
			nonce16 := make([]byte, 16)
			if _, err := rand.Read(nonce16); err == nil {
				// bind must be reproducible by JS => UA + cookie
				bind := powBind(r.UserAgent(), cookieVal)
				if pt, err := issuePowChallenge(powSecretKey(), time.Now().UTC(), cfg.Difficulty, nonce16, bind); err == nil {
					powTok = pt
				}
			}

		}

		if cfg.Enabled && powTok == "" {
			http.Error(w, "pow unavailable", http.StatusInternalServerError)
			return
		}

		// challengeHTML placeholders are: host, token, powTok, next, difficulty
		fmt.Fprintf(w, challengeHTML(),
			htmlEscape(host),
			strconv.Quote(tok),
			strconv.Quote(powTok),
			strconv.Quote(next),
			cfg.Difficulty,
		)

	})

	// ---------------- HTTP server ----------------
	if httpAddr != "" {
		ln, err := net.Listen("tcp", httpAddr)
		if err != nil {
			return fmt.Errorf("challenge http listen %s: %w", httpAddr, err)
		}
		s.httpLn = ln
		s.httpSrv = &http.Server{
			Addr: httpAddr,
			//Handler:           mux,
			Handler:           s.wrapAccessLog(mux),
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      20 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    maxHeaderBytesTight,
		}

		s.httpSrv.SetKeepAlivesEnabled(false)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			logging.Logf("[challenge] HTTP listening on %s", httpAddr)
			if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				logging.Logf("[challenge] HTTP serve error: %v", err)
			}
		}()

		// If user configured 127.0.0.1:PORT, also listen on [::1]:PORT for dual-stack DNAT.
		if v6addr, ok := maybeListenV6LoopbackFromV4Loopback(httpAddr); ok {
			if ln6, err := net.Listen("tcp", v6addr); err == nil {
				s.wg.Add(1)
				go func() {
					defer s.wg.Done()
					logging.Logf("[challenge] HTTP listening on %s", v6addr)
					if err := s.httpSrv.Serve(ln6); err != nil && err != http.ErrServerClosed {
						logging.Logf("[challenge] HTTP serve error (v6): %v", err)
					}
				}()
			} else {
				logging.Logf("[challenge] HTTP v6 loopback listen failed on %s: %v", v6addr, err)
			}
		}

	}

	// ---------------- HTTPS server ----------------
	if httpsAddr != "" {
		ln, err := net.Listen("tcp", httpsAddr)
		if err != nil {
			return fmt.Errorf("challenge https listen %s: %w", httpsAddr, err)
		}
		s.httpsLn = ln

		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if s.ssl == nil {
					return nil, fmt.Errorf("sslcollector not set")
				}
				// normalize servername
				name := strings.ToLower(strings.TrimSpace(chi.ServerName))
				name = strings.TrimSuffix(name, ".")
				if name == "" {
					// no SNI -> refuse (or later serve a default cert)
					return nil, fmt.Errorf("missing SNI")
				}
				return s.ssl.GetCertificate(chi) // you’ll implement/export this (see below)
			},
		}

		s.httpsSrv = &http.Server{
			Addr: httpsAddr,
			//Handler:           mux,
			Handler:           s.wrapAccessLog(mux),
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      20 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    maxHeaderBytesTight,
			TLSConfig:         tlsCfg,
		}

		s.httpsSrv.SetKeepAlivesEnabled(false)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			logging.Logf("[challenge] HTTPS listening on %s", httpsAddr)
			if err := s.httpsSrv.Serve(tls.NewListener(ln, tlsCfg)); err != nil && err != http.ErrServerClosed {
				logging.Logf("[challenge] HTTPS serve error: %v", err)
			}
		}()

		// If user configured 127.0.0.1:PORT, also listen on [::1]:PORT for dual-stack DNAT.
		if v6addr, ok := maybeListenV6LoopbackFromV4Loopback(httpsAddr); ok {
			if ln6, err := net.Listen("tcp", v6addr); err == nil {
				s.wg.Add(1)
				go func() {
					defer s.wg.Done()
					logging.Logf("[challenge] HTTPS listening on %s", v6addr)
					if err := s.httpsSrv.Serve(tls.NewListener(ln6, tlsCfg)); err != nil && err != http.ErrServerClosed {
						logging.Logf("[challenge] HTTPS serve error (v6): %v", err)
					}
				}()
			} else {
				logging.Logf("[challenge] HTTPS v6 loopback listen failed on %s: %v", v6addr, err)
			}
		}

	}

	// stop on ctx cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx2)

	}()

	return nil
}

func (s *ChallengeServer) Stop(ctx context.Context) error {
	var firstErr error

	if s.httpSrv != nil {
		if err := s.httpSrv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.httpsSrv != nil {
		if err := s.httpsSrv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if s.accessLog != nil {
		s.accessLog.close()
	}

	return firstErr
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		`&`, "&amp;",
		`<`, "&lt;",
		`>`, "&gt;",
		`"`, "&quot;",
		`'`, "&#39;",
	)
	return r.Replace(s)
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// ---------------- self-protection (in-process rate limit) ----------------

type ipRateState struct {
	winStart       time.Time
	count          int
	banUntil       time.Time
	lastSeen       time.Time
	fwBlockedUntil time.Time
}

const (
	rlKindPage = iota
	rlKindVerify
)

func (s *ChallengeServer) rlLogAbuse(r *http.Request, ip string, kind int, retry time.Duration) {
	k := "page"
	if kind == rlKindVerify {
		k = "verify"
	}

	ua := r.UserAgent()
	if len(ua) > 160 {
		ua = ua[:160] + "…"
	}

	host := r.Host
	if len(host) > 120 {
		host = host[:120] + "…"
	}

	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}
	if len(path) > 200 {
		path = path[:200] + "…"
	}

	// Log to challenge log (cfm.challenges.log) to keep it isolated from detector spam.
	logging.Logf(
		"[challenge server] selfprotect ip=%s kind=%s action=challenge_mem_ban retry=%s host=%s path=%s ua=%q",
		ip, k, retry, host, path, ua,
	)
}

// rlAllow returns whether the request should proceed and, if not, how long the
// client should wait before retrying.
func (s *ChallengeServer) rlAllow(ip string, kind int) (allowed bool, retry time.Duration, bannedNow bool) {
	now := time.Now().UTC()

	s.rlMu.Lock()
	defer s.rlMu.Unlock()

	if s.rlByIP == nil {
		s.rlByIP = make(map[string]*ipRateState)
	}

	// periodic GC
	if s.rlLastGC.IsZero() {
		s.rlLastGC = now
	}
	if now.Sub(s.rlLastGC) >= rlGCInterval {
		for k, st := range s.rlByIP {
			if now.Sub(st.lastSeen) > rlStateTTL {
				delete(s.rlByIP, k)
			}
		}
		s.rlLastGC = now
	}

	st := s.rlByIP[ip]
	if st == nil {
		st = &ipRateState{winStart: now, count: 0, lastSeen: now}
		s.rlByIP[ip] = st
	}
	st.lastSeen = now

	if now.Before(st.banUntil) {
		return false, st.banUntil.Sub(now), false
	}

	var win time.Duration
	var burst int
	var ban time.Duration
	if kind == rlKindVerify {
		win, burst, ban = rlVerifyWindow, rlVerifyBurst, rlBanVerify
	} else {
		win, burst, ban = rlPageWindow, rlPageBurst, rlBanPage
	}

	// reset window
	if now.Sub(st.winStart) >= win {
		st.winStart = now
		st.count = 0
	}

	st.count++
	if st.count > burst {
		st.banUntil = now.Add(ban)
		return false, ban, true
	}

	return true, 0, false
}

func (s *ChallengeServer) rlReject(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	http.Error(w, "rate limited", http.StatusTooManyRequests)
}

// rlFirewallBlock optionally escalates a self-protection ban into a local firewall block.
// This helps protect CPU by keeping future traffic from reaching userspace at all.
func (s *ChallengeServer) rlFirewallBlock(ip net.IP, kind int) {
	if !s.rlFwEnabled || s.fw == nil {
		return
	}

	// Pick TTL and comment by endpoint kind
	var ttl time.Duration
	comment := "cfm:challenge_selfprotect:page"
	if kind == rlKindVerify {
		ttl = s.rlFwTTLVerify
		comment = "cfm:challenge_selfprotect:verify"
	} else {
		ttl = s.rlFwTTLPage
	}

	// De-dupe: don't keep re-adding the same block every time we ban in memory.
	now := time.Now().UTC()
	ipStr := strings.TrimSpace(ip.String())

	s.rlMu.Lock()
	st := s.rlByIP[ipStr]
	if st == nil {
		st = &ipRateState{winStart: now, lastSeen: now}
		s.rlByIP[ipStr] = st
	}
	if !st.fwBlockedUntil.IsZero() && now.Before(st.fwBlockedUntil) {
		s.rlMu.Unlock()
		return
	}
	st.fwBlockedUntil = now.Add(ttl)
	s.rlMu.Unlock()

	_ = s.fw.AddBlock(ip, comment, &ttl)
}

// ---------------- helpers ----------------

// Wait blocks until all goroutines started by Start() have exited.
// Critical for hot-reload to avoid "address already in use" races.
func (s *ChallengeServer) Wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func cleanHost(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil && hh != "" {
		return hh
	}
	return h
}

func isVerifyPath(uri string) bool {
	// count as "verify" anything that starts with /__cfm_verify
	// (query string already included in uri variable)
	return strings.HasPrefix(uri, "/__cfm_verify")
}

// abuseObserve updates per-IP error counters and blocks via firewall if threshold exceeded.
func (s *ChallengeServer) abuseObserve(ipStr string, host, uri string, status int) {
	if !s.abuseEnabled || strings.TrimSpace(ipStr) == "" {
		return
	}

	// Global ignore: never count / block ignored IPs.
	if s.ignoreFn != nil && s.ignoreFn(strings.TrimSpace(ipStr)) {
		return
	}

	if status < 400 {
		return
	}
	// Don't count verify endpoint failures (avoid false positives on legit verify flows)
	if isVerifyPath(uri) {
		return
	}

	now := time.Now().UTC()
	ipStr = strings.TrimSpace(ipStr)

	s.abuseMu.Lock()
	st := s.abuseByIP[ipStr]
	if st == nil {
		st = &abuseState{winStart: now, lastSeen: now}
		s.abuseByIP[ipStr] = st
	}
	st.lastSeen = now

	// cooldown de-dupe
	if !st.cooldownTill.IsZero() && now.Before(st.cooldownTill) {
		s.abuseMu.Unlock()
		return
	}

	// reset window
	win := s.abuseWindow
	if win <= 0 {
		win = 10 * time.Second
	}
	if now.Sub(st.winStart) >= win {
		st.winStart = now
		st.badCount = 0
	}

	st.badCount++
	badN := s.abuseBadN
	if badN <= 0 {
		badN = 15
	}

	// cheap GC (keep map bounded)
	if len(s.abuseByIP) > 50000 {
		for k, v := range s.abuseByIP {
			if now.Sub(v.lastSeen) > 30*time.Minute {
				delete(s.abuseByIP, k)
			}
		}
	}

	if st.badCount < badN {
		s.abuseMu.Unlock()
		return
	}

	// trigger action
	ttl := s.abuseBlockTTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	cd := s.abuseCooldown
	if cd <= 0 {
		cd = 30 * time.Minute
	}
	st.cooldownTill = now.Add(cd)
	// reset counter after action (so we don't immediately re-trigger after cooldown ends)
	st.winStart = now
	st.badCount = 0
	s.abuseMu.Unlock()

	// Route to detectors sink if hook is installed.
	// This lets the unified sink push to API/Firewall/Notifier.
	if challengeAbuseHook != nil {
		challengeAbuseHook(ipStr, host, uri, status, badN, win, ttl, cd)
	} else {
		// Backwards-compatible fallback: direct firewall block.
		if s.fw != nil {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return
			}
			comment := "cfm:challenge_abuse"
			_ = s.fw.AddBlock(ip, comment, &ttl)
		}
	}

	// log to challenges log (high signal)
	logging.LogfCHALLENGES("[challenge_abuse] ip=%s host=%s bad>=%d window=%s status=%d uri=%s block_ttl=%s cooldown=%s",
		ipStr, host, badN, win.String(), status, uri, ttl.String(), cd.String(),
	)
}

// Cloudflare IP ranges (keep in sync with nginx trusted_proxies.conf).
// Source: https://www.cloudflare.com/ips/
var cloudflareNets []*net.IPNet
var cloudflareNetsOnce sync.Once

func initCloudflareNets() {
	cidrs := []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
		// IPv6
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil && n != nil {
			cloudflareNets = append(cloudflareNets, n)
		}
	}
}

func isCloudflareIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	cloudflareNetsOnce.Do(initCloudflareNets)
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isTrustedProxyPeer(peer net.IP) bool {
	if peer == nil {
		return false
	}
	if peer.IsLoopback() || peer.IsPrivate() || peer.IsLinkLocalUnicast() {
		return true
	}
	return isCloudflareIP(peer)
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(strings.TrimSpace(host))
	if peer == nil {
		return nil
	}

	// Trust proxy headers ONLY when the immediate peer is local/trusted
	// (OpenResty connects from 127.0.0.1 or private addr). In DNAT mode
	// peer is the real public client -> ignore spoofable headers.
	if isTrustedProxyPeer(peer) {
		// 1) Cloudflare real IP (if present)
		if h := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); h != "" {
			if ip := net.ParseIP(h); ip != nil {
				return ip
			}
		}
		// 2) X-Real-IP
		if h := strings.TrimSpace(r.Header.Get("X-Real-IP")); h != "" {
			if ip := net.ParseIP(h); ip != nil {
				return ip
			}
		}
		// 3) X-Forwarded-For: take first
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if len(parts) > 0 {
				first := strings.TrimSpace(parts[0])
				if ip := net.ParseIP(first); ip != nil {
					return ip
				}
			}
		}
	}

	return peer

}

func (s *ChallengeServer) shouldIgnoreIP(ip net.IP) bool {
	if ip == nil || s.ignoreFn == nil {
		return false
	}
	return s.ignoreFn(ip.String())
}

// autoSolveAndRelease:
// - removes challenge state (nft set) + adds OK cooldown (if supported)
// - clears bridge IP (OpenResty mode)
// - sets cfm_ok cookie
// - expires cfm_chal cookie (best-effort)
// - redirects to next
func (s *ChallengeServer) autoSolveAndRelease(w http.ResponseWriter, r *http.Request, ip net.IP, host, next, reason string) {
	ipStr := ""
	if ip != nil {
		ipStr = ip.String()
	}

	if s.ignoreLog {
		logging.LogfCHALLENGES("[challenge_ignore] ip=%s host=%s uri=%s reason=%s", ipStr, host, next, reason)
	}

	// Release from nft sets (DNAT mode)
	if s.fw != nil && ip != nil {
		_ = s.fw.RemoveChallenge(ip)
		if oker, ok := any(s.fw).(challengeOKer); ok {
			ttl := s.cookieTTL()
			_ = oker.AddChallengeOK(ip, &ttl)
		}
	}

	// OpenResty mode: clear IP from bridge (Lua pass-through)
	if s.bridge != nil && ipStr != "" {
		s.bridge.ClearIP(ipStr)
	}

	// Match secure flag to original scheme (OpenResty terminates TLS)
	xfProto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	secure := (r.TLS != nil) || (xfProto == "https")

	// Set solved cookie
	okVal := randomCookieValue()
	ttl := s.cookieTTL()
	http.SetCookie(w, &http.Cookie{
		Name:     "cfm_ok",
		Value:    okVal,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	// Expire challenge cookie (avoid churn)
	http.SetCookie(w, &http.Cookie{
		Name:   "cfm_chal",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "close")
	http.Redirect(w, r, next, http.StatusSeeOther) // 303
}

func basicHeaderSanity(w http.ResponseWriter, r *http.Request) bool {
	// Host sanity (prevents some oddballs; also avoids huge Host headers)
	host := r.Host
	if host == "" || len(host) > maxHostLen {
		http.Error(w, "bad host", http.StatusBadRequest)
		return false
	}
	// Optional: reject whitespace/control in Host
	for _, ch := range host {
		if ch <= 0x20 || ch == 0x7f {
			http.Error(w, "bad host", http.StatusBadRequest)
			return false
		}
	}
	// If you want: require SNI on HTTPS (most browsers do; stops random scanners)
	if r.TLS != nil && strings.TrimSpace(r.TLS.ServerName) == "" {
		http.Error(w, "missing sni", http.StatusBadRequest)
		return false
	}
	return true
}

func isWeirdUA(ua string) bool {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return true
	}
	if len(ua) > maxUALen {
		return true
	}
	if !utf8.ValidString(ua) {
		return true
	}
	// reject control chars / newlines (header smuggling-ish junk)
	for _, r := range ua {
		if r == '\r' || r == '\n' || r == 0 {
			return true
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	// very cheap heuristics: too repetitive, looks like binary, or obvious tools
	lower := strings.ToLower(ua)
	if strings.Contains(lower, "sqlmap") ||
		strings.Contains(lower, "nikto") ||
		strings.Contains(lower, "masscan") ||
		strings.Contains(lower, "nmap") {
		return true
	}
	// If it's insanely "dense" with punctuation, it's usually junk
	punct := 0
	for _, r := range ua {
		if strings.ContainsRune(`"'\<>[]{}()|;`, r) {
			punct++
		}
	}
	if punct >= 16 {
		return true
	}
	return false
}

func secretKey() []byte {
	// Set once in service env for stability across restarts:
	//   CFM_CHALLENGE_SECRET="random-long-string"
	s := strings.TrimSpace(os.Getenv("CFM_CHALLENGE_SECRET"))
	if s == "" {
		// fallback (works but not persistent across deployments)
		s = "cfm-default-secret-change-me"
	}
	return []byte(s)
}

func issueToken(ip, ua, cookieVal string) string {
	mac := hmac.New(sha256.New, secretKey())
	mac.Write([]byte(ip))
	mac.Write([]byte{0})
	mac.Write([]byte(ua))
	mac.Write([]byte{0})
	mac.Write([]byte(cookieVal))
	sum := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

func verifyToken(tok, ip, ua, cookieVal string) bool {
	want := issueToken(ip, ua, cookieVal)

	a, err1 := base64.RawURLEncoding.DecodeString(tok)
	b, err2 := base64.RawURLEncoding.DecodeString(want)
	if err1 != nil || err2 != nil {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// --- PoW helpers (additive to token/cookie) ---
// Important: bind must be reproducible by JS in the browser.
// Do NOT include client IP here (browser can't know it reliably behind NAT/LB).
func powSecretKey() []byte {
	// reuse the same secret as the token mechanism
	return secretKey()
}

func powBind(ua, cookieVal string) string {
	ua = strings.TrimSpace(ua)
	return ua + "|" + cookieVal
}

func randomCookieValue() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// last resort fallback
		h := sha256.Sum256([]byte(time.Now().UTC().String()))
		b = h[:]
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func challengeHTML() string {
	// placeholders: host, token, powTok, next, powDifficulty
	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Just a moment…</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:#0b1020;color:#e8eefc;display:flex;min-height:100vh;align-items:center;justify-content:center}
    .card{width:min(520px,92vw);background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:16px;padding:22px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
    .h{font-size:20px;font-weight:650;margin:0 0 10px}
    .p{opacity:.9;line-height:1.45;margin:0 0 14px}
    .muted{opacity:.7;font-size:13px}
    .spinner{width:34px;height:34px;border-radius:999px;border:3px solid rgba(255,255,255,.18);border-top-color:#fff;animation:spin 1s linear infinite;margin:14px 0}
    @keyframes spin{to{transform:rotate(360deg)}}
    code{background:rgba(255,255,255,.08);padding:.15rem .35rem;border-radius:8px}
  </style>
</head>
<body>
  <div class="card">
    <div class="h">Checking your browser…</div>
    <div class="p">We’re verifying your request before accessing <code>%s</code>.</div>
    <div class="spinner"></div>
    <div class="muted">This should take less than a second. If you’re stuck, enable JavaScript & cookies.</div>
  </div>

<script>
(function(){
  var token = %s;
  var powTok = %s;
  var next = %s;
  var difficulty = %d;

  // WebCrypto (crypto.subtle) requires a secure context in modern browsers.
  // If we were reached over plain HTTP, auto-upgrade to HTTPS to avoid
  // infinite reload loops (PoW would fail on insecure context).
  try {
    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
      var u = "https://" + window.location.host + window.location.pathname +
              window.location.search + window.location.hash;
      window.location.replace(u);
      return;
    }
  } catch (e) {
    var u2 = "https://" + window.location.host + window.location.pathname +
             window.location.search + window.location.hash;
    window.location.replace(u2);
    return;
  }

  function getCookie(name){
    var parts = ("; " + document.cookie).split("; " + name + "=");
    if (parts.length === 2) return decodeURIComponent(parts.pop().split(";").shift());
    return "";
  }

  function b64urlToBytes(s){
    s = (s || "").replace(/-/g,'+').replace(/_/g,'/');
    while (s.length %% 4) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function hasLeadingZeroBits(bytes, bits){
    if (bits <= 0) return true;
    var full = Math.floor(bits/8);
    var rem = bits %% 8;
    for (var i=0;i<full;i++) if (bytes[i] !== 0) return false;
    if (rem === 0) return true;
    var mask = 0xFF << (8 - rem);
    return (bytes[full] & mask) === 0;
  }

  async function sha256(u8){
    var buf = await crypto.subtle.digest('SHA-256', u8);
    return new Uint8Array(buf);
  }

  async function solvePow(){
    // token layout: ts(8) diff(2) nonce(16) mac(32) => nonce starts at offset 10
    var raw = b64urlToBytes(powTok);
    if (raw.length !== 58) throw new Error("bad pow token");
    var nonce = raw.slice(10, 26);

    // bind must match server powBind(): UA + "|" + cookie
    var ua = (navigator.userAgent || "").trim();

    var c = getCookie("cfm_chal");
    var bindStr = ua + "|" + c;

    var enc = new TextEncoder();
    var bindBytes = enc.encode(bindStr);

    // prefix = nonce || 0 || bind || 0
    var prefix = new Uint8Array(nonce.length + 1 + bindBytes.length + 1);
    prefix.set(nonce, 0);
    prefix[nonce.length] = 0;
    prefix.set(bindBytes, nonce.length + 1);
    prefix[prefix.length - 1] = 0;

    var i = 0;
    while (true){
      var solStr = String(i++);
      var solBytes = enc.encode(solStr);

      var msg = new Uint8Array(prefix.length + solBytes.length);
      msg.set(prefix, 0);
      msg.set(solBytes, prefix.length);

      var dig = await sha256(msg);
      if (hasLeadingZeroBits(dig, difficulty)) return solStr;

      if ((i %% 2000) === 0) await new Promise(function(r){ setTimeout(r, 0); });
    }
  }

  (async function(){
    try {
      var sol = await solvePow();

       fetch("/__cfm_verify?next="+encodeURIComponent(next), {
        method: "POST",
        headers: {
          "X-CFM-Token": token,
          "X-CFM-Pow": powTok,
          "X-CFM-Sol": sol,
        },
        credentials: "include"
      }).then(function(res){
        if (res.redirected) { window.location = res.url; return; }
        setTimeout(function(){ window.location = "/?next="+encodeURIComponent(next); }, 1200);
      }).catch(function(){
        setTimeout(function(){ location.reload(); }, 1200);
      });
    } catch(e) {
      setTimeout(function(){ location.reload(); }, 1200);
    }
  })();
})();
</script>

</body>
</html>`
}
