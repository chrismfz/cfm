// Package sslcollector serves TLS certificate and private-key material to
// OpenResty/Angie workers via an authenticated unix socket so they can perform
// dynamic SNI-based certificate selection without the keys being world-readable.
//
// # Security model
//
// The socket is protected by a bearer token stored in
// /var/lib/cfm/lua/cfm_token.lua (mode 0640, root:cfm).  The only members of
// the cfm OS group are the nginx/OpenResty/Angie worker processes — no login
// shell, no other services.  Consequently any cfm-group principal is considered
// as trusted as a running nginx worker.
//
// Realistic attack paths that reach this socket therefore require either:
//   - Root access (which can read cert files directly from disk anyway), or
//   - A remote-code-execution vulnerability in the nginx worker itself.
//
// In both cases the socket does not materially increase the attacker's reach
// beyond what they already have.
//
// # Future hardening (tracked — not yet implemented)
//
//  1. SO_PEERCRED: replace the group-readable bearer token with kernel-verified
//     process credentials (UID/GID/PID).  This would restrict callers to the
//     exact nginx worker binary rather than any cfm-group process.  Note: it
//     does NOT improve security against a compromised nginx worker — the worker
//     already holds all cert+key pairs in memory — but it eliminates the
//     "another process obtains the token" vector entirely.
//     See: docs/ssl-collector.md
//
//  2. Encrypted offline snapshot: the on-disk snapshot
//     (/var/lib/cfm/sslcollector/dump.json, mode 0640) contains cert+key pairs
//     for all hosted domains.  Encrypting it with a key only available from the
//     running cfm daemon would prevent exfiltration of the file in isolation.
//     Controlled via SSLCOLLECTOR_OFFLINE_CACHE in cfm.conf.
//     See: docs/ssl-collector.md
package sslcollector

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type SockServerConfig struct {
	Enabled  bool
	SockPath string
	Token    string // required; empty disables auth (start is refused)
	SockGID  int    // if > 0, socket is chowned to root:SockGID after creation
	PEMTTL   time.Duration
	PEMMax   int
}

type pemCacheItem struct {
	certPEM  string
	keyPEM   string
	fp       string
	certMT   time.Time
	keyMT    time.Time
	cachedAt time.Time
}

type sockServer struct {
	col *Collector
	cfg SockServerConfig

	mu  sync.Mutex
	pem map[string]pemCacheItem
}

func (s *sockServer) authOK(r *http.Request) bool {
	g := r.Header.Get("X-SSLCollector-Token")
	if len(g) != len(s.cfg.Token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(g), []byte(s.cfg.Token)) == 1
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

func (s *sockServer) handleCert(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	host = strings.TrimSuffix(host, ".")
	if !validHost(host) {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}

	e := s.col.EntryForHost(host)
	if e == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// PEM cache hit?
	s.mu.Lock()
	if it, ok := s.pem[host]; ok {
		if it.fp == e.Fingerprint && it.certMT.Equal(e.CertMTime) && it.keyMT.Equal(e.KeyMTime) &&
			(s.cfg.PEMTTL <= 0 || time.Since(it.cachedAt) <= s.cfg.PEMTTL) {
			s.mu.Unlock()
			s.writeCertJSON(w, host, e, it.certPEM, it.keyPEM)
			return
		}
	}
	s.mu.Unlock()

	// Read PEM from disk (keys stay out of OpenResty FS perms)
	certPEM, err := os.ReadFile(e.CertPath)
	if err != nil {
		http.Error(w, "cert read error", http.StatusServiceUnavailable)
		return
	}
	keyPEM, err := os.ReadFile(e.KeyPath)
	if err != nil {
		http.Error(w, "key read error", http.StatusServiceUnavailable)
		return
	}

	// Update cache (simple eviction)
	s.mu.Lock()
	if s.cfg.PEMMax > 0 && len(s.pem) >= s.cfg.PEMMax {
		s.pem = map[string]pemCacheItem{}
	}
	s.pem[host] = pemCacheItem{
		certPEM:  string(certPEM),
		keyPEM:   string(keyPEM),
		fp:       e.Fingerprint,
		certMT:   e.CertMTime,
		keyMT:    e.KeyMTime,
		cachedAt: time.Now(),
	}
	s.mu.Unlock()

	s.writeCertJSON(w, host, e, string(certPEM), string(keyPEM))
}

func (s *sockServer) writeCertJSON(w http.ResponseWriter, host string, e *Entry, certPEM, keyPEM string) {
	out := map[string]any{
		"host":        host,
		"source":      e.Source,
		"cert_path":   e.CertPath,
		"key_path":    e.KeyPath,
		"not_after":   e.NotAfter.Format(time.RFC3339),
		"fingerprint": e.Fingerprint,
		"cert_pem":    certPEM,
		"key_pem":     keyPEM,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *sockServer) handleDumpAll(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, _, _, err := s.col.BuildDumpAllPayload()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

func (s *sockServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	st := s.col.Stats()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

func (s *sockServer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = s.col.Refresh(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (s *sockServer) handleDump(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	host = strings.TrimSuffix(host, ".")
	if !validHost(host) {
		http.Error(w, "bad host", http.StatusBadRequest)
		return
	}

	e := s.col.EntryForHost(host)
	if e == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(e)
}

// ServeSock starts an HTTP API on a unix socket for OpenResty.
// It stops when ctx is canceled.
//
// ServeSock refuses to start if cfg.Token is empty; every endpoint requires
// the X-SSLCollector-Token header to match the configured token.
func ServeSock(ctx context.Context, col *Collector, cfg SockServerConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if cfg.Token == "" {
		return errors.New("sslcollector: refusing to start socket server with empty token")
	}
	if cfg.SockPath == "" {
		cfg.SockPath = "/var/run/sslcollector.sock"
	}
	if cfg.PEMTTL == 0 {
		cfg.PEMTTL = 10 * time.Minute
	}
	if cfg.PEMMax == 0 {
		cfg.PEMMax = 50000
	}

	_ = os.Remove(cfg.SockPath)
	ln, err := net.Listen("unix", cfg.SockPath)
	if err != nil {
		return err
	}
	// F27: net.Listen("unix") defaults UnlinkOnClose=true, so ln.Close() unlinks
	// the path BY NAME. On a config-change restart the new server does
	// os.Remove+net.Listen to create a fresh inode at the same path; if the old
	// server's ctx-cancel Close() then runs, it unlink()s the NEW inode, leaving
	// the new server listening on an fd with no filesystem name (every worker
	// dial gets ENOENT). The os.Remove above already owns stale-file cleanup, and
	// disable/Stop remove the name explicitly, so Close() must not unlink.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = os.Chmod(cfg.SockPath, 0660)
	if cfg.SockGID > 0 {
		_ = os.Chown(cfg.SockPath, 0, cfg.SockGID)
	}

	s := &sockServer{
		col: col,
		cfg: cfg,
		pem: map[string]pemCacheItem{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/cert", s.handleCert)
	mux.HandleFunc("/stats", s.handleStats)
	mux.HandleFunc("/dumpall", s.handleDumpAll)
	mux.HandleFunc("/refresh", s.handleRefresh)
	mux.HandleFunc("/dump", s.handleDump)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      30 * time.Second, // /dumpall can serialize thousands of certs
		IdleTimeout:       10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = ln.Close()
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
