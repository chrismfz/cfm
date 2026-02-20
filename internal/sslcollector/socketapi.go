package sslcollector

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type SockServerConfig struct {
	Enabled bool
	SockPath string
	Token string        // optional, header: X-SSLCollector-Token
	PEMTTL time.Duration
	PEMMax int
}

type pemCacheItem struct {
	certPEM  string
	keyPEM   string
	fp       string
	certMT   time.Time
	keyMT    time.Time
	cachedAt time.Time
}

type dumpAllResponse struct {
    Version     string    `json:"version"`
    GeneratedAt time.Time `json:"generated_at"`
    Exact       []any     `json:"exact"`
    Wild        []any     `json:"wild"`
}

type sockServer struct {
	col *Collector
	cfg SockServerConfig

	mu  sync.Mutex
	pem map[string]pemCacheItem
}

func (s *sockServer) authOK(r *http.Request) bool {
	if s.cfg.Token == "" {
		return true
	}
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

    st := s.col.Stats()

    // Snapshot maps
    s.col.mu.RLock()
    exact := make(map[string]*Entry, len(s.col.exact))
    for k, v := range s.col.exact {
        exact[k] = v
    }
    wild := make(map[string]*Entry, len(s.col.wildSuffix))
    for k, v := range s.col.wildSuffix {
        wild[k] = v
    }
    s.col.mu.RUnlock()

    // Stable order
    exactKeys := make([]string, 0, len(exact))
    for k := range exact { exactKeys = append(exactKeys, k) }
    sort.Strings(exactKeys)

    wildKeys := make([]string, 0, len(wild))
    for k := range wild { wildKeys = append(wildKeys, k) }
    sort.Strings(wildKeys)

    // Read PEM once per unique entry (avoid duplicate disk reads)
    type pemPair struct{ cert, key string }
    pemByFP := map[string]pemPair{} // fingerprint -> pem

    getPEM := func(e *Entry) (string, string, bool) {
        if e == nil {
            return "", "", false
        }
        if pp, ok := pemByFP[e.Fingerprint]; ok {
            return pp.cert, pp.key, true
        }
        certPEM, err := os.ReadFile(e.CertPath)
        if err != nil { return "", "", false }
        keyPEM, err := os.ReadFile(e.KeyPath)
        if err != nil { return "", "", false }
        pemByFP[e.Fingerprint] = pemPair{cert: string(certPEM), key: string(keyPEM)}
        return pemByFP[e.Fingerprint].cert, pemByFP[e.Fingerprint].key, true
    }

    out := dumpAllResponse{
        Version:     st.Version,
        GeneratedAt: st.GeneratedAt,
        Exact:       make([]any, 0, len(exactKeys)),
        Wild:        make([]any, 0, len(wildKeys)),
    }

    for _, host := range exactKeys {
        e := exact[host]
        certPEM, keyPEM, ok := getPEM(e)
        if !ok { continue }
        out.Exact = append(out.Exact, map[string]any{
            "host":        host,
            "fingerprint": e.Fingerprint,
            "not_after":   e.NotAfter.Format(time.RFC3339),
            "cert_pem":    certPEM,
            "key_pem":     keyPEM,
        })
    }

    for _, suf := range wildKeys {
        e := wild[suf]
        certPEM, keyPEM, ok := getPEM(e)
        if !ok { continue }
        out.Wild = append(out.Wild, map[string]any{
            "suffix":      suf, // represents "*.suffix"
            "fingerprint": e.Fingerprint,
            "not_after":   e.NotAfter.Format(time.RFC3339),
            "cert_pem":    certPEM,
            "key_pem":     keyPEM,
        })
    }

    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(out)
}


func (s *sockServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
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

// ServeSock starts an HTTP API on a unix socket for OpenResty.
// It stops when ctx is canceled.
func ServeSock(ctx context.Context, col *Collector, cfg SockServerConfig) error {
	if !cfg.Enabled {
		return nil
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
	_ = os.Chmod(cfg.SockPath, 0660) // give group access (nginx/openresty group)

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

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
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
