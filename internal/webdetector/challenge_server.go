package webdetector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"cfm/internal/logging"
	"cfm/internal/sslcollector"

	"crypto/sha256"
	"encoding/hex"

)

type ChallengeServer struct {
	httpSrv  *http.Server
	httpsSrv *http.Server

	httpLn  net.Listener
	httpsLn net.Listener

	ssl *sslcollector.Collector
}

func NewChallengeServer(ssl *sslcollector.Collector) *ChallengeServer {
	return &ChallengeServer{ssl: ssl}
}

func (s *ChallengeServer) Start(ctx context.Context, httpAddr, httpsAddr string) error {
	mux := http.NewServeMux()

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

        // cert summary (leaf)
        certLine := "none"
        fpLine := ""
        if len(cs.PeerCertificates) > 0 {
            leaf := cs.PeerCertificates[0]
            certLine = fmt.Sprintf("subject=%s | issuer=%s | not_before=%s | not_after=%s",
                leaf.Subject.String(),
                leaf.Issuer.String(),
                leaf.NotBefore.Format(time.RFC3339),
                leaf.NotAfter.Format(time.RFC3339),
            )

            // SHA256 fingerprint
            sum := sha256.Sum256(leaf.Raw)
            fpLine = "sha256=" + strings.ToUpper(hex.EncodeToString(sum[:]))
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
<li>cert: %s</li>
<li>cert_fp: %s</li>
</ul>`,
            htmlEscape(tlsVersionString(cs.Version)),
            htmlEscape(cs.NegotiatedProtocol),
            htmlEscape(tls.CipherSuiteName(cs.CipherSuite)),
            cs.CipherSuite,
            htmlEscape(cs.ServerName),
            htmlEscape(cs.ServerName),
            cs.DidResume,
            cs.HandshakeComplete && len(cs.VerifiedChains) > 0, // rough indicator
            htmlEscape(certLine),
            htmlEscape(fpLine),
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
