package webdetector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
//	"errors"


)

type ChallengeServer struct {
	httpSrv  *http.Server
	httpsSrv *http.Server

	httpLn  net.Listener
	httpsLn net.Listener

	ssl *sslcollector.Collector
	fw  firewall.Backend

}


// Optional interface: only nft backend implements this.
type challengeRedirector interface {
        EnsureChallengeRedirect(httpListen, httpsListen string) error
}


// Optional: cooldown-bypass set (recommended to avoid loops).
type challengeOKer interface {
        AddChallengeOK(ip net.IP, ttl *time.Duration) error
        RemoveChallengeOK(ip net.IP) error
}



func NewChallengeServer(ssl *sslcollector.Collector, fw firewall.Backend) *ChallengeServer {
   return &ChallengeServer{ssl: ssl, fw: fw}
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

mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
    host := r.Host
    if h, _, err := net.SplitHostPort(host); err == nil {
        host = h
    }

    w.Header().Set("Content-Type", "text/html; charset=utf-8")

    // TLS details (only present on HTTPS)
    tlsBlock := ""
    if r.TLS != nil {
        cs := r.TLS

        // NOTE: PeerCertificates are *client* certs (mTLS). Most clients won't send any.
        // For "served server cert", look it up from sslcollector using SNI.
        served := "not_found"
        servedFP := ""
        servedNA := ""
        servedSrc := ""
        servedCertPath := ""
        servedKeyPath := ""

        if s.ssl != nil {
            name := cs.ServerName
            if name == "" {
                name = host
            }
            if e := s.ssl.EntryForHost(name); e != nil {
                served = "ok"
                servedFP = e.Fingerprint
                servedNA = e.NotAfter.Format(time.RFC3339)
                servedSrc = string(e.Source)
                servedCertPath = e.CertPath
                servedKeyPath = e.KeyPath
            }
        }


        tlsBlock = fmt.Sprintf(`
<h3>TLS</h3>
<ul>
<li>tls_version: %s</li>
<li>alpn: %s</li>
<li>cipher: %s (0x%04x)</li>
<li>sni: %s</li>
<li>server_name: %s</li>
<li>did_resume: %v</li>
<li>mutual_tls: %v</li>
<li>served: %s</li>
<li>served_fp: %s</li>
<li>served_not_after: %s</li>
<li>served_source: %s</li>
<li>served_cert_path: %s</li>
<li>served_key_path: %s</li>
</ul>`,
            htmlEscape(tlsVersionString(cs.Version)),
            htmlEscape(cs.NegotiatedProtocol),
            htmlEscape(tls.CipherSuiteName(cs.CipherSuite)),
            cs.CipherSuite,
            htmlEscape(cs.ServerName),
            htmlEscape(cs.ServerName),
            cs.DidResume,
            cs.HandshakeComplete && len(cs.VerifiedChains) > 0, // rough indicator
            htmlEscape(served),
            htmlEscape(servedFP),
            htmlEscape(servedNA),
            htmlEscape(servedSrc),
            htmlEscape(servedCertPath),
            htmlEscape(servedKeyPath),
        )
    }

    fmt.Fprintf(w,
        `<html><body style="font-family:sans-serif">
<h2>CFM challenge MVP</h2>
<p><b>OK</b></p>
<ul>
<li>proto: %s</li>
<li>host: %s</li>
<li>remote: %s</li>
<li>time: %s</li>
</ul>
%s
</body></html>`,
        htmlEscape(r.Proto),
        htmlEscape(host),
        htmlEscape(r.RemoteAddr),
        time.Now().Format(time.RFC3339),
        tlsBlock,
    )
})







	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ts": time.Now().Unix()})
	})




        // --- VERIFY endpoint ---
        // JS will POST here with ?next=... and cookie set.
        mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
                if r.Method != http.MethodPost {
                        w.WriteHeader(http.StatusMethodNotAllowed)
                        return
                }

                ip := clientIP(r)
                if ip == nil {
                        http.Error(w, "bad client ip", http.StatusBadRequest)
                        return
                }

                next := r.URL.Query().Get("next")
                if next == "" { next = "/" }
                // prevent open redirect
                if !strings.HasPrefix(next, "/") {
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

                // Redirect back to original host+path
                host := cleanHost(r.Host)
                scheme := "http"
                if r.TLS != nil {
                        scheme = "https"
                } else {
                        // if you always want https after solve, force it:
                       // scheme = "https"
                }
                target := scheme + "://" + host + next
                w.Header().Set("Cache-Control", "no-store")
                w.Header().Set("Connection", "close")
                http.Redirect(w, r, target, http.StatusFound)
        })

        // --- CATCH-ALL: handle any path ---
        // Important: register after /hello,/healthz,/verify.


        mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

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

                // If already solved (cookie present + token valid), release and redirect.
                next := r.URL.Query().Get("next")
                if next == "" { next = "/" }
                if !strings.HasPrefix(next, "/") { next = "/" }


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
                                MaxAge:   600,
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
                tok := issueToken(ip.String(), r.UserAgent(), cookieVal)

                // challengeHTML placeholders are: host, token, next
                fmt.Fprintf(w, challengeHTML(), htmlEscape(host), htmlEscape(tok), htmlEscape(next))

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
			MaxHeaderBytes:    1 << 20,
		}

                s.httpSrv.SetKeepAlivesEnabled(false)

		go func() {
			logging.Logf("[challenge] HTTP listening on %s", httpAddr)
			if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				logging.Logf("[challenge] HTTP serve error: %v", err)
			}
		}()
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
			MaxHeaderBytes:    1 << 20,
			TLSConfig:         tlsCfg,
		}

                s.httpsSrv.SetKeepAlivesEnabled(false)

		go func() {
			logging.Logf("[challenge] HTTPS listening on %s", httpsAddr)
			if err := s.httpsSrv.Serve(tls.NewListener(ln, tlsCfg)); err != nil && err != http.ErrServerClosed {
				logging.Logf("[challenge] HTTPS serve error: %v", err)
			}
		}()
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
        // placeholders: host, token, next
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
      var next = "%s";
      // POST /verify with token header; redirect handled by server.
      fetch("/verify?next="+encodeURIComponent(next), {
        method: "POST",
        headers: {"X-CFM-Token": token},
        credentials: "include"
      }).then(function(res){
        if (res.redirected) { window.location = res.url; return; }
        if (res.status >= 300 && res.status < 400) { return; }
        // fallback: try reloading original target after a moment
 setTimeout(function(){ window.location = "/?next="+encodeURIComponent(next); }, 1200);
      }).catch(function(){
 setTimeout(function(){ location.reload(); }, 1200);
      });
    })();
  </script>
</body>
</html>`
}
