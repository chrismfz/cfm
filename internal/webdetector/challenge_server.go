package webdetector

import (
	"context"
	"crypto/tls"
	"io"
	"fmt"
	"net"
	"net/http"
	"net/url"
        "unicode/utf8"
	"strings"
	"time"

	"cfm/internal/logging"
	"cfm/internal/sslcollector"
	"cfm/internal/firewall"

        "crypto/hmac"
        "crypto/sha256"
        "encoding/base64"
        "os"
        "crypto/subtle"
	"crypto/rand"
	"sync"
	"cfm/internal/challengeid"

)

type ChallengeServer struct {
	httpSrv  *http.Server
	httpsSrv *http.Server

	httpLn  net.Listener
	httpsLn net.Listener

	ssl *sslcollector.Collector
	fw  firewall.Backend

        cidMu   sync.Mutex
        cidUsed map[string]time.Time // cid -> expiresAt (UTC)

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
        maxVerifyBodyBytes   = 1 << 10    // 1KB
        maxUALen             = 256
        maxHostLen           = 253
        maxNextLen           = 2048
        maxHeaderBytesTight  = 16 << 10   // 16KB (challenge server only)
)


func NewChallengeServer(ssl *sslcollector.Collector, fw firewall.Backend) *ChallengeServer {
        return &ChallengeServer{
                ssl:     ssl,
                fw:      fw,
                cidUsed: make(map[string]time.Time),
        }
}

func clampCID(s string) string {
        s = strings.TrimSpace(s)
        if len(s) < 8 || len(s) > 64 { // sanity
                return ""
        }
        return s
}

func (s *ChallengeServer) Start(ctx context.Context, httpAddr, httpsAddr string) error {
	mux := http.NewServeMux()

    // Ensure nft NAT redirect rules exist (only if challenge listeners are set)
        if s.fw != nil {
                if cr, ok := any(s.fw).(challengeRedirector); ok {
                        _ = cr.EnsureChallengeRedirect(httpAddr, httpsAddr)
                }
        }

	// basic endpoints
        // --- VERIFY endpoint ---
        // JS will POST here with ?next=... and cookie set.
        mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
                if r.Method != http.MethodPost {
                        w.WriteHeader(http.StatusMethodNotAllowed)
                        return
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
                if next == "" { next = "/" }
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




cid := clampCID(r.Header.Get("X-CFM-CID"))
if cid == "" {
        http.Error(w, "bad cid", http.StatusForbidden)
        return
}

        // IMPORTANT: cid must match what was issued for this IP by the sink/challengeid store
        if !challengeid.Global.Verify(ipStr, cid) {
                http.Error(w, "cid mismatch", http.StatusForbidden)
                return
        }

if !s.cidMarkOnce(cid, cfg.TTL) {
        http.Error(w, "reused cid", http.StatusForbidden)
        return
}


logging.LogfCHALLENGES(
        "[challenge] ip=%s host=%s uri=%s result=solved ms=%d diff=%d cid=%s",
        ip.String(),
        host,
        next,
        time.Since(verifyStart).Milliseconds(),
        diff,
        cid,
)


                // consume CID after a successful solve
                _ = challengeid.Global.Solved(ipStr, cid)

                // Release:
                // 1) remove from challenge set (so no more redirect)
                if s.fw != nil {
                        _ = s.fw.RemoveChallenge(ip)
                        // 2) add cooldown OK (prevents immediate re-challenge loop)
                        if oker, ok := any(s.fw).(challengeOKer); ok {
                                ttl := 60 * time.Minute
                                _ = oker.AddChallengeOK(ip, &ttl)
                        }
                }

                // Give nft/conntrack a tiny moment; helps avoid browser redirect loops on keep-alives.
                time.Sleep(400 * time.Millisecond)



// Redirect back to original path (relative redirect avoids scheme/host loops)
w.Header().Set("Cache-Control", "no-store")
w.Header().Set("Connection", "close")

// Safety: next is already forced to start with "/" above.
http.Redirect(w, r, next, http.StatusSeeOther) // 303



        })

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
                if r.URL.Path == "/hello" || r.URL.Path == "/healthz" || r.URL.Path == "/verify" {
                        http.NotFound(w, r)
                        return
                }

                ip := clientIP(r)
                if ip == nil {
                        http.Error(w, "bad client ip", http.StatusBadRequest)
                        return
                }

                ipStr := ip.String()
                // If already solved (cookie present + token valid), release and redirect.
                next := r.URL.Query().Get("next")
                if next == "" { next = "/" }
                if !strings.HasPrefix(next, "/") { next = "/" }
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
cid := ""

                // CID must already be issued by the sink for this IP
                if cfg.Enabled {
                        cid = clampCID(challengeid.Global.Get(ipStr))
                }

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

if cfg.Enabled && cid == "" {
        http.Error(w, "missing cid", http.StatusForbidden)
        return
}

if cfg.Enabled && powTok == "" {
        http.Error(w, "pow unavailable", http.StatusInternalServerError)
        return
}



// challengeHTML placeholders are: host, token, powTok, cid, next, difficulty
fmt.Fprintf(w, challengeHTML(),
        htmlEscape(host),
        htmlEscape(tok),
        htmlEscape(powTok),
        htmlEscape(cid),
        htmlEscape(next),
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
			Addr:              httpAddr,
			Handler:           mux,
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      20 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    maxHeaderBytesTight,
		}

                s.httpSrv.SetKeepAlivesEnabled(false)

		go func() {
			logging.Logf("[challenge] HTTP listening on %s", httpAddr)
			if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				logging.Logf("[challenge] HTTP serve error: %v", err)
			}
		}()

                // If user configured 127.0.0.1:PORT, also listen on [::1]:PORT for dual-stack DNAT.
                if v6addr, ok := maybeListenV6LoopbackFromV4Loopback(httpAddr); ok {
                        if ln6, err := net.Listen("tcp", v6addr); err == nil {
                                go func() {
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
			Addr:              httpsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 2 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      20 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    maxHeaderBytesTight,
			TLSConfig:         tlsCfg,
		}

                s.httpsSrv.SetKeepAlivesEnabled(false)

		go func() {
			logging.Logf("[challenge] HTTPS listening on %s", httpsAddr)
			if err := s.httpsSrv.Serve(tls.NewListener(ln, tlsCfg)); err != nil && err != http.ErrServerClosed {
				logging.Logf("[challenge] HTTPS serve error: %v", err)
			}
		}()

                // If user configured 127.0.0.1:PORT, also listen on [::1]:PORT for dual-stack DNAT.
                if v6addr, ok := maybeListenV6LoopbackFromV4Loopback(httpsAddr); ok {
                        if ln6, err := net.Listen("tcp", v6addr); err == nil {
                                go func() {
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
	go func() {
		<-ctx.Done()
		_ = s.Stop(context.Background())
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



// ---------------- helpers ----------------


// --- CID one-time use store (anti-replay for solved challenges) ---

func (s *ChallengeServer) cidCleanLocked(now time.Time) {
        for cid, exp := range s.cidUsed {
                if now.After(exp) {
                        delete(s.cidUsed, cid)
                }
        }
}

// cidMarkOnce returns true on first use; false if reused within ttl.
func (s *ChallengeServer) cidMarkOnce(cid string, ttl time.Duration) bool {
        cid = strings.TrimSpace(cid)
        if cid == "" {
                return false
        }

    // cheap sanity: base64url-ish size
    if len(cid) < 8 || len(cid) > 64 {
        return false
    }


        now := time.Now().UTC()
        if ttl <= 0 {
                ttl = 2 * time.Minute
        }

        s.cidMu.Lock()
        defer s.cidMu.Unlock()

        if s.cidUsed == nil {
                s.cidUsed = make(map[string]time.Time)
        }
        s.cidCleanLocked(now)

        if exp, ok := s.cidUsed[cid]; ok && now.Before(exp) {
                return false
        }

        s.cidUsed[cid] = now.Add(ttl)
        return true
}


func cleanHost(h string) string {
        if hh, _, err := net.SplitHostPort(h); err == nil && hh != "" {
                return hh
        }
        return h
}

func clientIP(r *http.Request) net.IP {
        host, _, err := net.SplitHostPort(r.RemoteAddr)
        if err != nil {
                // best-effort fallback
                host = r.RemoteAddr
        }
        ip := net.ParseIP(strings.TrimSpace(host))
        return ip
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
// placeholders: host, token, powTok, cid, next, powDifficulty
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
  var token = "%s";
  var powTok = "%s";
  var cid = "%s";
  var next = "%s";
  var difficulty = %d;

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

      fetch("/verify?next="+encodeURIComponent(next), {
        method: "POST",
        headers: {
          "X-CFM-Token": token,
          "X-CFM-Pow": powTok,
          "X-CFM-Sol": sol,
          "X-CFM-CID": cid
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
