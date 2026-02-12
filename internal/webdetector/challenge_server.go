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
		// strip port if present
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
</body></html>`,
			htmlEscape(r.Proto), htmlEscape(host), htmlEscape(r.RemoteAddr),
			time.Now().Format(time.RFC3339),
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
