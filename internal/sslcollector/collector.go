package sslcollector

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
)

type Collector struct {
	cfg Config

	// refreshedOnce flips to true after the first successful Refresh()
	// completes. Run() consults this to skip its own initial Refresh
	// when the daemon already kicked one off synchronously at startup
	// (eg in cmd/cfm/main.go's early-start block). Avoids a redundant
	// filesystem walk + identical snapshot write on every cfm boot.
	refreshedOnce atomic.Bool

	// refreshCallCount is incremented at the START of every Refresh().
	// Used by tests to assert the Run() dedup guard actually skips
	// the call rather than just relying on refreshedOnce being true
	// (which says nothing about whether Run did or didn't try). Not
	// load-bearing in production; an atomic.Int32 is cheap.
	refreshCallCount atomic.Int32

	// host index
	mu         sync.RWMutex
	exact      map[string]*Entry // host -> entry
	wildSuffix map[string]*Entry // suffix ("example.com") -> entry for "*.example.com"

	// known files + memo sigs (for cheap stat loop)
	filesMu    sync.RWMutex
	knownFiles map[string]struct{} // set of cert/key paths
	fileMemo   map[string]fileSig  // path -> last stat signature

	// tls cache
	cacheMu   sync.Mutex
	certCache map[string]cachedCert // normalized host -> cached cert
}

func New(cfg Config) *Collector {
	if cfg.CacheDir == "" {
		cfg.CacheDir = "/var/lib/cfm/sslcollector"
	}
	if cfg.StatEvery <= 0 {
		cfg.StatEvery = 60 * time.Second
	}
	if cfg.DiscoveryEvery <= 0 {
		cfg.DiscoveryEvery = 15 * time.Minute
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = 30 * time.Second
	}
	if cfg.MaxCertCache <= 0 {
		cfg.MaxCertCache = 20000
	}

	_ = os.MkdirAll(cfg.CacheDir, 0o700)

	return &Collector{
		cfg:        cfg,
		exact:      map[string]*Entry{},
		wildSuffix: map[string]*Entry{},
		knownFiles: map[string]struct{}{},
		fileMemo:   map[string]fileSig{},
		certCache:  map[string]cachedCert{},
	}
}

// GetCertificate is meant to be used directly as tls.Config.GetCertificate
func (c *Collector) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := normalizeHost(chi.ServerName)
	if host == "" {
		return nil, errors.New("missing sni")
	}

	e, ok := c.getEntryLocked(host)
	if !ok {
		return nil, errors.New("no cert for host")
	}

	// negative cache
	if until := time.Unix(e.negativeUntil.Load(), 0); until.After(time.Now()) {
		if s, _ := e.lastErr.Load().(string); s != "" {
			return nil, errors.New(s)
		}
		return nil, errors.New("temporarily unavailable")
	}

	// fast cache hit
	// ChainMTime is compared in addition to leaf+key mtimes so a
	// chain-only rotation (eg DA rewrites <domain>.cacert during an LE
	// intermediate transition) correctly invalidates this cache. Without
	// it, the Go TLS path keeps serving the cached *tls.Certificate
	// with the stale chain even after the next Refresh.
	c.cacheMu.Lock()
	cc, ok := c.certCache[host]
	c.cacheMu.Unlock()
	if ok && cc.fp == e.Fingerprint &&
		cc.certMTime.Equal(e.CertMTime) &&
		cc.keyMTime.Equal(e.KeyMTime) &&
		cc.chainMTime.Equal(e.ChainMTime) {
		return cc.cert, nil
	}

	// Load leaf+chain into a single PEM blob so tls.X509KeyPair builds
	// a Certificate with the intermediate chain attached. Bare
	// tls.LoadX509KeyPair(CertPath, KeyPath) would attach only the leaf
	// (DA's <domain>.cert is leaf-only) — browsers would see no path
	// to the trusted root.
	certPEM, err := assembleCertPEM(e.CertPath, e.ChainPath)
	if err != nil {
		e.lastErr.Store(err.Error())
		e.negativeUntil.Store(time.Now().Add(c.cfg.NegativeTTL).Unix())
		return nil, err
	}
	keyPEM, err := os.ReadFile(e.KeyPath)
	if err != nil {
		e.lastErr.Store(err.Error())
		e.negativeUntil.Store(time.Now().Add(c.cfg.NegativeTTL).Unix())
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		e.lastErr.Store(err.Error())
		e.negativeUntil.Store(time.Now().Add(c.cfg.NegativeTTL).Unix())
		return nil, err
	}
	e.lastErr.Store("")
	e.negativeUntil.Store(0)

	cc2 := cachedCert{
		cert:       &cert,
		certMTime:  e.CertMTime,
		keyMTime:   e.KeyMTime,
		chainMTime: e.ChainMTime,
		fp:         e.Fingerprint,
		loadedAt:   time.Now(),
	}

	c.cacheMu.Lock()
	// MVP eviction: if too big, clear all. (Later you can swap to LRU.)
	if len(c.certCache) > c.cfg.MaxCertCache {
		c.certCache = map[string]cachedCert{}
	}
	c.certCache[host] = cc2
	c.cacheMu.Unlock()

	return cc2.cert, nil
}

func expandGlob(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

var homeMountRe = regexp.MustCompile(`^home[0-9]*$`)

func expandHomeUserDirs(subdir string) []string {
	mounts, err := os.ReadDir("/")
	if err != nil {
		return nil
	}

	out := []string{}
	for _, m := range mounts {
		if !m.IsDir() || !homeMountRe.MatchString(m.Name()) {
			continue
		}
		out = append(out, expandGlob(filepath.Join("/", m.Name(), "*", subdir))...)
	}
	return out
}

// homeShallowWatchDirs returns the directories the watcher should watch
// one level deep (non-recursive): every /home* mount top (so brand-new
// user accounts — e.g. reseller-created — are detected the moment the
// home dir appears) and every existing /home*/<user> dir (so a later
// ssl/ dir or domains/<domain>/ssl.key for an existing user is detected).
//
// Recursive watches on entire home trees are deliberately avoided here:
// they would add an inotify watch per file/dir across every customer
// site. The watcher only escalates to a recursive watch when an actual
// cert directory (ssl/certs/letsencrypt) appears — see handleNewDir.
func homeShallowWatchDirs() []string {
	out := []string{}
	mounts, err := os.ReadDir("/")
	if err != nil {
		return out
	}
	for _, m := range mounts {
		if !m.IsDir() || !homeMountRe.MatchString(m.Name()) {
			continue
		}
		mountTop := filepath.Join("/", m.Name())
		out = append(out, mountTop)

		users, err := os.ReadDir(mountTop)
		if err != nil {
			continue
		}
		for _, u := range users {
			if u.IsDir() {
				out = append(out, filepath.Join(mountTop, u.Name()))
			}
		}
	}
	return out
}

func (c *Collector) Run(ctx context.Context) error {
	if !c.cfg.Enabled {
		return nil
	}

	// Skip the initial refresh when the daemon already invoked one
	// synchronously before launching this goroutine (the early-start
	// path in cmd/cfm/main.go does exactly this so the snapshot lands
	// on disk before any near-simultaneous edge reload). Without this
	// guard, every cfm start did the filesystem walk + snapshot write
	// twice — once at line ~480 of main.go and once here — which on
	// busy hosts is 1-2 seconds of redundant work plus a 17 MB
	// duplicate disk write.
	if !c.refreshedOnce.Load() {
		_ = c.Refresh(ctx)
	}

	// START WATCHER (NEW)
	roots := []string{
		"/etc/letsencrypt",
		"/var/cpanel/ssl",
		"/usr/local/directadmin",
		"/etc/ssl",
	}

	// targeted home scanning
	roots = append(roots, expandHomeUserDirs("ssl")...)
	roots = append(roots, expandHomeUserDirs("certs")...)
	roots = append(roots, expandHomeUserDirs("letsencrypt")...)

	w, err := NewWatcher(c, 2*time.Second)
	if err == nil {
		// Shallow (non-recursive) watch points so brand-new reseller
		// accounts and newly-created per-user ssl dirs are detected in
		// seconds instead of waiting for the DiscoveryEvery fallback.
		w.SetShallowRoots(homeShallowWatchDirs())
		_ = w.Start(ctx, roots)
	} else {
		logging.Logf("[sslcollector] watcher disabled: %v", err)
	}

	statTicker := time.NewTicker(c.cfg.StatEvery)
	defer statTicker.Stop()

	discoTicker := time.NewTicker(c.cfg.DiscoveryEvery)
	defer discoTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-statTicker.C:
			if c.anyKnownFileChanged() {
				_ = c.Refresh(ctx)
			}

		case <-discoTicker.C:
			_ = c.Refresh(ctx)
		}
	}
}

func (c *Collector) anyKnownFileChanged() bool {
	c.filesMu.RLock()
	paths := make([]string, 0, len(c.knownFiles))
	for p := range c.knownFiles {
		paths = append(paths, p)
	}
	c.filesMu.RUnlock()

	changed := false
	newMemo := make(map[string]fileSig, len(paths))

	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 {
			continue
		}
		sig := fileSig{mtime: st.ModTime(), size: st.Size()}
		newMemo[p] = sig

		c.filesMu.RLock()
		prev, ok := c.fileMemo[p]
		c.filesMu.RUnlock()

		if !ok || !prev.mtime.Equal(sig.mtime) || prev.size != sig.size {
			changed = true
		}
	}

	c.filesMu.Lock()
	for p, sig := range newMemo {
		c.fileMemo[p] = sig
	}
	c.filesMu.Unlock()

	return changed
}

func (c *Collector) getEntryLocked(host string) (*Entry, bool) {
	// exact first
	c.mu.RLock()
	if e, ok := c.exact[host]; ok {
		c.mu.RUnlock()
		return e, true
	}
	c.mu.RUnlock()

	// wildcard suffix: a.b.example.com -> try b.example.com then example.com (longest suffix wins)
	labels := strings.Split(host, ".")
	if len(labels) < 3 {
		return nil, false // wildcard cannot match apex or 1-level hosts
	}

	var best *Entry
	bestLen := 0

	for i := 1; i < len(labels)-1; i++ {
		suf := strings.Join(labels[i:], ".")
		c.mu.RLock()
		e, ok := c.wildSuffix[suf]
		c.mu.RUnlock()
		if ok {
			if l := len(suf); l > bestLen {
				best = e
				bestLen = l
			}
		}
	}
	if best != nil {
		return best, true
	}
	return nil, false
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimSuffix(h, ".")
	return h
}

func absClean(p string) string {
	if p == "" {
		return ""
	}
	ap, _ := filepath.Abs(p)
	return filepath.Clean(ap)
}

// EntryForHost returns the best matching entry for host (exact or wildcard).
func (c *Collector) EntryForHost(host string) *Entry {
	host = normalizeHost(host)
	if host == "" {
		return nil
	}
	e, ok := c.getEntryLocked(host)
	if !ok {
		return nil
	}
	return e
}
