package webdetector

import (
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"cfm/internal/sslcollector"
	"cfm/internal/tlsfp"
	"cfm/internal/uaplausible"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
)

const (
	verifyPath    = "/__cfm_verify" // new preferred endpoint
	verifyPathOld = "/verify"       // legacy (keep during rollout)
	challengePath = "/__cfm_challenge"
)

var clearanceBridgeTokenPath = "/var/lib/cfm/lua/cfm_bridge_token.lua"

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

func normalizeChallengeNext(raw string) string {
	next := strings.TrimSpace(raw)
	if next == "" {
		return "/"
	}
	if len(next) > maxNextLen {
		return "/"
	}
	decodeOnce := func(in string) string {
		out, err := url.QueryUnescape(in)
		if err != nil {
			return in
		}
		return out
	}
	for i := 0; i < 4; i++ {
		if strings.HasPrefix(next, "%2f") || strings.HasPrefix(next, "%2F") {
			next = decodeOnce(next)
		}
		if !strings.HasPrefix(next, "/") {
			return "/"
		}
		u, err := url.ParseRequestURI(next)
		if err != nil {
			return "/"
		}
		if u.Path == challengePath {
			nested := strings.TrimSpace(u.Query().Get("next"))
			if nested == "" {
				return "/"
			}
			next = nested
			continue
		}
		nested := strings.TrimSpace(u.Query().Get("next"))
		if nested != "" && nestedChallengeTarget(nested) {
			q := u.Query()
			q.Del("next")
			u.RawQuery = q.Encode()
			next = u.RequestURI()
		}
		if len(next) > maxNextLen {
			return "/"
		}
		return next
	}
	return "/"
}

func nestedChallengeTarget(raw string) bool {
	v := strings.TrimSpace(raw)
	for i := 0; i < 4; i++ {
		if strings.HasPrefix(v, "%2f") || strings.HasPrefix(v, "%2F") {
			d, err := url.QueryUnescape(v)
			if err != nil {
				break
			}
			v = d
			continue
		}
		break
	}
	if !strings.HasPrefix(v, "/") {
		return false
	}
	u, err := url.ParseRequestURI(v)
	if err != nil {
		return true
	}
	return u.Path == challengePath
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

func truncateForLog(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
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
				s.accessLog.logf("[challenge_http] ip=%s host=%s method=%s uri=%s port=%d status=%d bytes=%d ms=%d",
					ip, host, r.Method, uri, localPort(r), sw.status, sw.bytes, time.Since(start).Milliseconds(),
				)
			} else {
				logging.LogfCHALLENGES("[challenge_http] ip=%s host=%s method=%s uri=%s port=%d status=%d bytes=%d ms=%d",
					ip, host, r.Method, uri, localPort(r), sw.status, sw.bytes, time.Since(start).Milliseconds(),
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

// ChallengeSolve describes one successful challenge solve. It is a struct rather
// than a positional argument list because the solve is the natural place to hang
// client-attestation signals, and every new signal would otherwise churn the
// hook signature and all its callers.
type ChallengeSolve struct {
	IP   string
	Host string
	URI  string
	Diff int
	// UA is the User-Agent that submitted the solve. Recorded because a solver
	// farm shows up as one exact UA string solving from many ASNs at once —
	// a correlation that is invisible without it.
	UA string
	// VerifyMS is how long the server spent processing the verify POST. It is
	// NOT how long the client took to solve — it never was, despite being
	// logged as a bare `ms=` since the challenge server was written.
	VerifyMS int64
	// SolveMS is the real client-side solve latency: wall-clock from PoW
	// issuance (read back out of the token) to the verify POST. -1 when the
	// issue timestamp is missing or implausible.
	//
	// This is the one PoW signal a native solver cannot fake without giving up
	// the speed advantage that makes it worth running. Note the per-solve value
	// is noisy — solve time is exponentially distributed, so a lucky honest
	// browser can land near zero. Judge it over a cluster, not a single event.
	//
	// It measures issue → submit, so it also contains HTML delivery, browser
	// startup, JS scheduling and the POST round trip. A datacenter client looks
	// faster than a mobile one for reasons unrelated to CPU; keep that in mind
	// before thresholding on it.
	//
	// Read it through SolveLatencyMS(), never directly: any value <= 0 means
	// unknown, so that a ChallengeSolve literal which omits the field cannot be
	// mistaken for an instantaneous — i.e. maximally suspicious — solve.
	SolveMS int64
	// UAImpossible is set when the submitted User-Agent contradicts itself (an
	// iPhone running desktop Blink, a Firefox carrying the Blink WebKit token).
	// UAReason names the rule(s). See internal/uaplausible — this says the UA is
	// a *lie*, not that it is old.
	UAImpossible bool
	UAReason     string
	// TLSFP is a short id for the client's TLS ClientHello, stamped by the edge
	// (configs/lua/cfm_tlsfp.lua) and parsed by internal/tlsfp. Empty when the
	// edge did not supply one — an older edge config, a plain-HTTP request, or
	// the legacy DNAT path where the daemon terminates TLS itself.
	//
	// This is the one signal on a solve the client does not author: its TLS
	// stack emits the handshake before any HTTP is sent. Log-first — nothing
	// scores on it yet, and the fingerprint↔UA mapping must be derived from
	// captured traffic rather than written from memory.
	TLSFP string
	// TLSRaw is the full tuple behind TLSFP, kept so it can be written once per
	// distinct fingerprint instead of on every solve.
	TLSRaw string
}

// TLSFingerprintOrDash renders TLSFP for a log line. Empty means "not
// available" — an older edge config, a plain-HTTP request, or the legacy DNAT
// path where no edge stamps the header — and "-" says so, where a bare %s would
// produce `tls_fp= ` and read as a parse failure. Both writers of the solve line
// go through this so the two can never disagree about what absence looks like.
func (s ChallengeSolve) TLSFingerprintOrDash() string {
	if s.TLSFP == "" {
		return "-"
	}
	return s.TLSFP
}

// SolveLatencyMS reports the real client-side solve latency and whether it is
// known. A sub-millisecond issue→submit gap cannot occur over HTTP, so treating
// 0 as unknown costs no real measurement and makes the struct's zero value safe.
func (s ChallengeSolve) SolveLatencyMS() (int64, bool) {
	if s.SolveMS <= 0 {
		return 0, false
	}
	return s.SolveMS, true
}

// ChallengeSolvedHook lets the detectors layer log solved/expired in a unified way.
// It is optional; if unset, ChallengeServer will log a minimal solved line.
// tlsFingerprintHeader is the request header the edge stamps with the client's
// TLS ClientHello summary. The edge clears any client-supplied value before
// setting its own — see configs/lua/cfm_tlsfp.lua and internal/tlsfp for the
// trust boundary that makes reading it safe while this stays log-only.
const tlsFingerprintHeader = "X-CFM-TLS"

// tlsPrints tracks which fingerprints have already been written out in full, so
// the tuple is logged once and each solve carries only the id.
var tlsPrints = tlsfp.NewRegistry(5000)

// tlsPrintsCapWarn fires the one-time notice that the fingerprint dictionary is
// full. Without it the cap would be silent, and a reader hunting the first_seen
// line for an id would conclude the daemon had lost it rather than that the
// dictionary stopped admitting entries.
var tlsPrintsCapWarn sync.Once

type ChallengeSolvedHook func(ChallengeSolve)

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

var (
	challengeTokenMu       sync.RWMutex
	challengeTokenOverride string
	challengeTokenWarnOnce sync.Once

	// Ephemeral per-process fallback key, generated once if no CHALLENGE_TOKEN
	// is configured.  Unpredictable, but challenge cookies don't survive restarts.
	challengeEphemeralKey     []byte
	challengeEphemeralKeyOnce sync.Once
)

// SetChallengeToken configures the token secret from detectors.conf
// ([webdetector] CHALLENGE_TOKEN).
func SetChallengeToken(token string) {
	challengeTokenMu.Lock()
	challengeTokenOverride = strings.TrimSpace(token)
	challengeTokenMu.Unlock()
}

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

func normalizeChallengeListenAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if p, err := strconv.Atoi(addr); err == nil && p > 0 && p <= 65535 {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
	}
	return addr
}

func (s *ChallengeServer) Start(ctx context.Context, httpAddr, httpsAddr string) error {
	httpAddr = normalizeChallengeListenAddress(httpAddr)
	httpsAddr = normalizeChallengeListenAddress(httpsAddr)
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
			}
			// EnsureChallengeRedirect returns nil for two opposite outcomes: it
			// installed the DNAT rules, or it found the redirect disabled
			// (OPENRESTY_MODE, where the edge decides in-path) and cleaned them
			// up instead. Reporting "OK" for both is how an operator ends up
			// believing DNAT is armed when it is not, in the one area whose own
			// code comment records having been burned before. Say which.
			armed := true
			if q, ok := any(s.fw).(interface{ ChallengeRedirectEnabled() bool }); ok {
				armed = q.ChallengeRedirectEnabled()
			}
			if armed {
				logging.LogfCHALLENGES(
					"[challenge] nft challenge DNAT armed: flagged clients are redirected to http=%s https=%s",
					httpAddr, httpsAddr,
				)
			} else {
				logging.LogfCHALLENGES(
					"[challenge] nft challenge DNAT disabled (edge decides in-path); any stale redirect rules cleaned up. Listeners http=%s https=%s still serve the edge's proxy_pass",
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
			host := trustedForwardedHost(r)
			next := normalizeChallengeNext(r.URL.Query().Get("next"))
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
		host := trustedForwardedHost(r)
		if host == "" {
			http.Error(w, "missing forwarded host", http.StatusBadRequest)
			return
		}
		if r.URL.Path == verifyPath || r.URL.Path == verifyPathOld || r.URL.Path == challengePath {
			if strings.HasPrefix(clearanceScope(r), "panel:") && normalizeForwardedPort(r.Header.Get("X-Forwarded-Port")) == "" {
				http.Error(w, "missing forwarded port", http.StatusBadRequest)
				return
			}
		}

		ip := clientIP(r)
		ipStr := ""
		if ip == nil {
			http.Error(w, "bad client ip", http.StatusBadRequest)
			return
		}

		ipStr = ip.String()
		next := normalizeChallengeNext(r.URL.Query().Get("next"))

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

		// One reading of the wall clock for both the freshness check and the
		// latency, so SolveMS can never exceed the TTL that was just enforced.
		verifyAt := time.Now().UTC()
		issuedAt, diff, nonce16, ok := verifyPowChallenge(powSecretKey(), powTok, bind, cfg, verifyAt)
		if !ok || !verifyPowSolution(nonce16, bind, sol, diff) {
			http.Error(w, "bad pow", http.StatusForbidden)
			return
		}

		ua := strings.TrimSpace(r.UserAgent())
		uaVerdict := uaplausible.Check(ua)
		fp, _ := tlsfp.Parse(r.Header.Get(tlsFingerprintHeader))
		solve := ChallengeSolve{
			IP:           ipStr,
			Host:         host,
			URI:          next,
			Diff:         diff,
			UA:           ua,
			VerifyMS:     time.Since(verifyStart).Milliseconds(),
			SolveMS:      powSolveLatencyMS(issuedAt, verifyAt, cfg.TTL),
			UAImpossible: uaVerdict.Impossible,
			UAReason:     uaVerdict.Reason(),
			TLSFP:        fp.ID,
			TLSRaw:       fp.Raw,
		}

		// One dictionary line per distinct fingerprint, so every solve can carry
		// the 8-character id instead of the full tuple. The UA rides along
		// because the whole point of the signal is the pairing: this is the
		// record that lets a fingerprint↔UA mapping be derived from real traffic
		// later rather than written from memory.
		if tlsPrints.FirstSeen(solve.TLSFP) {
			// trunc= is not decoration: a truncated list can be shared by two
			// different clients whose offers agree up to the bound, so the id is
			// weaker evidence and the line has to say which kind it is.
			logging.LogfCHALLENGES("[challenge] tls_fp=%s first_seen grease=%t trunc=%t ua=%q tls=%q",
				solve.TLSFP, fp.GREASE, fp.Truncated, solve.UA, solve.TLSRaw)
		} else if solve.TLSFP != "" && tlsPrints.Capped() {
			// No silent caps: say the dictionary stopped admitting entries, once,
			// rather than let a reader conclude the daemon lost a first_seen line.
			tlsPrintsCapWarn.Do(func() {
				logging.LogfCHALLENGES("[challenge] tls_fp dictionary full at %d entries; new fingerprints still log tls_fp= but get no first_seen line",
					tlsPrints.Len())
			})
		}

		publishChallengeSolveEvent(solve)

		if challengeSolvedHook != nil {
			challengeSolvedHook(solve)
		} else {
			logging.LogfCHALLENGES(
				"[challenge] ip=%s host=%s uri=%s result=solved ms=%d solve_ms=%d diff=%d tls_fp=%s",
				solve.IP,
				solve.Host,
				solve.URI,
				solve.VerifyMS,
				solve.SolveMS,
				solve.Diff,
				solve.TLSFingerprintOrDash(),
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
		secure := trustedForwardedProto(r) == "https"

		ttl := s.cookieTTL()
		scope := clearanceScope(r)
		exp := time.Now().UTC().Add(ttl)
		clearanceVal := issueClearanceToken(ipStr, host, scope, exp)
		http.SetCookie(w, &http.Cookie{
			Name:     "cfm_clearance",
			Value:    clearanceVal,
			Path:     "/",
			MaxAge:   int(ttl.Seconds()),
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
		logClearanceIssueTrace(r, host, scope, exp, true)

		// Transitional legacy solved marker (non-authoritative; kept for migration).
		okVal := randomCookieValue()
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

		// Carry the clearance across the apex↔www pair, once, before handing the
		// client back to its destination. Without this the origin's canonical
		// 301 lands the client on a host that has no clearance and it is
		// challenged again — a loop that a real user pays for and that
		// challenge_cookie_discard reads as a client discarding its cookie.
		// See clearance_handoff.go for why the cookie Domain attribute is not
		// the tool for this.
		//
		// Guarded three ways: the sibling must be a real apex↔www counterpart,
		// CFM must serve it under exactly that name (a wildcard certificate is
		// not evidence the vhost answers), and the request being handled must
		// not itself be a handoff — that last one is what makes the flow
		// terminate rather than bounce between the two hosts forever.
		if sib := clearanceSibling(host); sib != "" && s.ssl.HasExactHost(sib) && r.URL.Path != clearanceHandoffPath {
			if tok := issueHandoffToken(ipStr, sib, scope, time.Now().UTC().Add(handoffTokenTTL)); tok != "" {
				http.Redirect(w, r, handoffRedirectURL(sib, tok, next), http.StatusSeeOther)
				return
			}
		}

		// Safety: next is already forced to start with "/" above.
		http.Redirect(w, r, next, http.StatusSeeOther) // 303

	}

	// clearanceHandoffHandler is the second half of the apex↔www carry. It
	// grants the clearance the sibling host already earned and forwards on.
	//
	// It never issues a handoff of its own — that is the loop guard, and it is
	// structural rather than a counter.
	//
	// Every failure path still forwards to `next` without a cookie: a bad,
	// expired or replayed-from-elsewhere token must leave the client in the
	// ordinary challenge flow, never at a dead end. A handoff that does not
	// work costs one extra redirect; a handoff that 403s costs a visitor.
	clearanceHandoffHandler := func(w http.ResponseWriter, r *http.Request) {
		if !basicHeaderSanity(w, r) {
			return
		}
		host := cleanHost(r.Host)
		scope := clearanceScope(r)
		next := safeHandoffNext(r.URL.Query().Get("next"))

		w.Header().Set("Cache-Control", "no-store")

		ip := clientIP(r)
		if ip == nil {
			// No usable client address: forward, do not grant. The token is
			// address-bound, so there is nothing to verify against.
			http.Redirect(w, r, next, http.StatusSeeOther)
			return
		}
		ipStr := ip.String()

		if verifyHandoffToken(r.URL.Query().Get("t"), ipStr, host, scope, time.Now().UTC()) {
			ttl := s.cookieTTL()
			exp := time.Now().UTC().Add(ttl)
			http.SetCookie(w, &http.Cookie{
				Name:     "cfm_clearance",
				Value:    issueClearanceToken(ipStr, host, scope, exp),
				Path:     "/",
				MaxAge:   int(ttl.Seconds()),
				HttpOnly: true,
				Secure:   trustedForwardedProto(r) == "https",
				SameSite: http.SameSiteLaxMode,
			})
			logClearanceIssueTrace(r, host, scope, exp, true)
			logging.LogfCHALLENGES("[challenge] clearance handoff accepted ip=%s host=%s scope=%s", ipStr, host, scope)
		} else {
			logging.LogfCHALLENGES("[challenge] clearance handoff rejected ip=%s host=%s scope=%s (forwarding without clearance)", ipStr, host, scope)
		}

		http.Redirect(w, r, next, http.StatusSeeOther)
	}
	mux.HandleFunc(clearanceHandoffPath, clearanceHandoffHandler)

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
			// NOTE: this intentionally does not replay POST payloads; browser returns to
			// `next` as GET after verify. See CHALLENGE_POST_REPLAY_ACTIONS.md for
			// recommended ways to add resumable/replay behavior.
			// We intentionally ONLY do this for POST (not OPTIONS) to avoid breaking
			// preflights or non-browser clients.

			if r.Method == http.MethodPost {
				next := r.URL.RequestURI()

				postIP := clientIP(r)
				postIPStr := "-"
				if postIP != nil {
					postIPStr = postIP.String()
				}

				postAction, postReason := "", ""
				if s.bridge != nil {
					postAction, postReason = s.bridge.GetIPDecision(postIPStr)
				}
				if postReason == "" {
					postReason = postAction // fallback
				}

				logHost := truncateForLog(cleanHost(r.Host), 120)
				logPath := truncateForLog(r.URL.Path, 120)
				logURI := truncateForLog(next, 220)
				logCType := truncateForLog(strings.TrimSpace(r.Header.Get("Content-Type")), 80)

				logging.LogfCHALLENGES("[challenge] post-intercept ip=%s host=%s path=%s uri=%s uri_len=%d ctype=%q clen=%d reason=%s note=no_replay",
					postIPStr, logHost, logPath, logURI, len(next), logCType, r.ContentLength, postReason,
				)

				w.Header().Set("Cache-Control", "no-store")
				http.Redirect(w, r, challengePath+"?next="+url.QueryEscape(normalizeChallengeNext(next)), http.StatusSeeOther) // 303
				return
			}

			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Avoid browsers hitting /favicon.ico etc causing token/cookie churn.
		// Always serve the challenge page from canonical challenge paths only.
		if r.URL.Path != "/" && r.URL.Path != challengePath {
			next := r.URL.RequestURI()
			w.Header().Set("Cache-Control", "no-store")

			http.Redirect(w, r, challengePath+"?next="+url.QueryEscape(normalizeChallengeNext(next)), http.StatusFound)
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
		next := normalizeChallengeNext(r.URL.Query().Get("next"))

		// Global ignore: auto-solve + release (no challenge page, no abuse tracking).
		if s.shouldIgnoreIP(ip) {
			host := trustedForwardedHost(r)
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
		next = normalizeChallengeNext(r.URL.Query().Get("next"))

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
		// Prevent search engines from indexing the challenge page or following its links.
		// X-Robots-Tag is the authoritative signal; the meta tag below is belt-and-suspenders.
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		host := trustedForwardedHost(r)

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

		// challengeHTML placeholders are: host, token, powTok, next, difficulty.
		// host goes into <code>%s</code> via htmlEscape (covers &, <, >, ", '
		// — sufficient for HTML element-content placement). token/powTok/next
		// are emitted as JS string literals via jsStringLiteral, which post-
		// processes strconv.Quote to also escape <, >, &, U+2028, U+2029 so
		// they're safe inside <script>...</script>; see jsStringLiteral
		// docs for why strconv.Quote alone wasn't enough. next is also
		// normalized above ("/" prefix + max length cap). CodeQL #565
		// (real, fixed in jsStringLiteral) and #765 (FP, htmlEscape is
		// correct) at this call site, both 2026-05-09 triage.
		fmt.Fprintf(w, challengeHTML(),
			htmlEscape(host),
			jsStringLiteral(tok),
			jsStringLiteral(powTok),
			jsStringLiteral(next),
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

// jsStringLiteral returns a JavaScript string literal that is safe to embed
// inside an HTML <script> block. strconv.Quote alone is NOT safe for that
// context: it escapes \, ", control chars, and non-printables, but leaves
// <, >, &, and the JS-only line terminators U+2028 / U+2029 as-is. Inside
// <script>...</script>, the HTML parser still tokenises </script>
// regardless of JavaScript context, so an input value containing the
// literal sequence </script> would close the script tag early and let the
// remaining bytes execute as HTML — a reflected XSS via any tainted source
// that flows here (the ?next= query parameter is the documented vector;
// CodeQL #565 / 2026-05-09).
//
// Post-process the strconv.Quote output to escape those bytes via
// \uXXXX. The escape form is valid in JS string literals (and JSON) and
// does not change the runtime string value, only its source rendering —
// so the page-side JS sees the original characters once parsed.
func jsStringLiteral(s string) string {
	q := strconv.Quote(s)
	return jsHTMLEscapeReplacer.Replace(q)
}

var jsHTMLEscapeReplacer = strings.NewReplacer(
	"<", `\u003c`,
	">", `\u003e`,
	"&", `\u0026`,
	"\u2028", `\u2028`, // JS line separator: would terminate a string literal at runtime
	"\u2029", `\u2029`, // JS paragraph separator: same hazard
)

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
	secure := trustedForwardedProto(r) == "https"

	// Set signed clearance cookie (authoritative)
	ttl := s.cookieTTL()
	scope := clearanceScope(r)
	exp := time.Now().UTC().Add(ttl)
	clearanceVal := issueClearanceToken(ipStr, host, scope, exp)
	http.SetCookie(w, &http.Cookie{
		Name:     "cfm_clearance",
		Value:    clearanceVal,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	logClearanceIssueTrace(r, host, scope, exp, true)

	// Transitional legacy solved marker (non-authoritative; kept for migration).
	okVal := randomCookieValue()
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

func logClearanceIssueTrace(r *http.Request, host, scope string, exp time.Time, setCookie bool) {
	reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if reqID == "" {
		reqID = strings.TrimSpace(r.Header.Get("X-CFM-Request-ID"))
	}
	if reqID == "" {
		reqID = "-"
	}
	logging.LogfCHALLENGES("[clearance_trace] phase=verify_success req_id=%s host=%s scope=%s exp=%s set_cookie=%t",
		reqID, normalizeClearanceHost(host), scope, exp.Format(time.RFC3339), setCookie)
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
	// Preferred source: service env for stability across restarts:
	//   CFM_CHALLENGE_SECRET="random-long-string"
	if s := strings.TrimSpace(os.Getenv("CFM_CHALLENGE_SECRET")); s != "" {
		return []byte(s)
	}

	// Fallback source: detectors.conf [webdetector] CHALLENGE_TOKEN.
	challengeTokenMu.RLock()
	tok := challengeTokenOverride
	challengeTokenMu.RUnlock()
	if tok != "" {
		return []byte(tok)
	}

	// No configured secret: generate an ephemeral per-process key so the fallback
	// is at least unpredictable.  Challenge cookies will be invalid after a restart,
	// but there is no hardcoded literal that an attacker could exploit.
	challengeEphemeralKeyOnce.Do(func() {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			// rand.Read failure is extremely unlikely; use a fixed-length zeroed
			// slice rather than panicking — the warning below covers the risk.
			b = make([]byte, 32)
		}
		challengeEphemeralKey = b
	})
	challengeTokenWarnOnce.Do(func() {
		logging.LogfCHALLENGES("[challenge] WARNING: no CHALLENGE_TOKEN in detectors.conf and CFM_CHALLENGE_SECRET env not set; using ephemeral per-process secret (challenge cookies invalid after restart)")
	})
	return challengeEphemeralKey
}

var clearanceTokenWarnOnce sync.Once
var clearanceLuaReturnRe = regexp.MustCompile(`(?m)^\s*return\s+["']([^"']+)["']\s*$`)

func clearanceSecretKey() []byte {
	if tok, ok := readBridgeTokenSecret(clearanceBridgeTokenPath); ok {
		return []byte(tok)
	}
	if tok := strings.TrimSpace(os.Getenv("OPENRESTY_TOKEN")); tok != "" {
		return []byte(tok)
	}
	clearanceTokenWarnOnce.Do(func() {
		logging.LogfCHALLENGES("[challenge] ERROR: no canonical clearance secret available (missing bridge token file and OPENRESTY_TOKEN env); refusing to issue/validate cfm_clearance")
	})
	return nil
}

func readBridgeTokenSecret(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	m := clearanceLuaReturnRe.FindSubmatch(b)
	if len(m) < 2 {
		return "", false
	}
	tok := strings.TrimSpace(string(m[1]))
	if tok == "" {
		return "", false
	}
	return tok, true
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

type clearancePayload struct {
	V     string `json:"v"`
	Exp   int64  `json:"exp"`
	IP    string `json:"ip"`
	Host  string `json:"host"`
	Scope string `json:"scope"`
	Nonce string `json:"nonce"`
	HMAC  string `json:"hmac"`
}

func normalizeClearanceHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end > 0 {
			h = h[1:end]
		}
	} else if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else if strings.Count(h, ":") == 1 {
		if idx := strings.LastIndex(h, ":"); idx > 0 {
			h = h[:idx]
		}
	}
	return strings.TrimSuffix(h, ".")
}

func normalizeForwardedPort(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	var b strings.Builder
	for _, ch := range v {
		if ch >= '0' && ch <= '9' {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func trustedForwardedHost(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if h == "" {
		h = r.Host
	}
	return normalizeClearanceHost(h)
}

func trustedForwardedProto(r *http.Request) string {
	xfProto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if xfProto == "http" || xfProto == "https" {
		return xfProto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func clearanceScope(r *http.Request) string {
	p := normalizeForwardedPort(r.Header.Get("X-CFM-Panel-Port"))
	if p == "" {
		p = normalizeForwardedPort(r.Header.Get("X-Forwarded-Port"))
	}
	if p == "" || p == "80" || p == "443" {
		return "web"
	}
	return "panel:" + p
}

func issueClearanceToken(ip, host, scope string, exp time.Time) string {
	p := clearancePayload{V: "1", Exp: exp.Unix(), IP: ip, Host: normalizeClearanceHost(host), Scope: scope, Nonce: randomCookieValue()}
	payload := fmt.Sprintf("%s|%d|%s|%s|%s|%s", p.V, p.Exp, p.IP, p.Host, p.Scope, p.Nonce)
	key := clearanceSecretKey()
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	p.HMAC = hex.EncodeToString(mac.Sum(nil))
	b, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(b)
}

func verifyClearanceToken(tok, ip, host, scope string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil {
		return false
	}
	var p clearancePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return false
	}
	if p.V != "1" || p.Exp <= now.Unix() || strings.TrimSpace(p.Nonce) == "" {
		return false
	}
	if p.IP != ip || normalizeClearanceHost(p.Host) != normalizeClearanceHost(host) || p.Scope != scope {
		return false
	}
	payload := fmt.Sprintf("%s|%d|%s|%s|%s|%s", p.V, p.Exp, p.IP, normalizeClearanceHost(p.Host), p.Scope, p.Nonce)
	key := clearanceSecretKey()
	if len(key) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(p.HMAC)
	if err != nil || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
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
  <meta name="robots" content="noindex, nofollow" />
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
    <div class="muted">This should take a few seconds. If you’re stuck, enable JavaScript & cookies.</div>
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

func localPort(r *http.Request) int {
	if r == nil || r.Context() == nil {
		return 0
	}
	if v := r.Context().Value(http.LocalAddrContextKey); v != nil {
		if addr, ok := v.(net.Addr); ok {
			if ta, ok := addr.(*net.TCPAddr); ok {
				return ta.Port
			}
		}
	}
	return 0
}
