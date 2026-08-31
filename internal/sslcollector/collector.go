package sslcollector

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
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

// homeMounts returns the absolute /home[0-9]* mount tops present on the
// host (/home, /home2, /home3, ...). This is the single source of truth
// for "which home mounts exist", shared by the watcher (homeShallowWatchDirs)
// and the scanner (discoverPairs -> scanHomeVirtualmin) so the watch set and
// the scan set can never disagree about which mounts to cover. A host that
// adds /home2 when /home fills must not become a discovery blind spot.
func homeMounts() []string {
	mounts, err := os.ReadDir("/")
	if err != nil {
		return nil
	}
	out := []string{}
	for _, m := range mounts {
		if !m.IsDir() {
			continue
		}
		top := filepath.Join("/", m.Name())
		if homeMountTopRE.MatchString(top) {
			out = append(out, top)
		}
	}
	return out
}

// homeShallowWatchDirs returns the directories the watcher should watch
// one level deep (non-recursive), backing exactly the home layout the
// scanner reads (Virtualmin: <home>/<user>/domains/<domain>/ssl.{key,cert}):
//
//   - every /home* mount top        → a brand-new user account (reseller-
//     created) fires a Create event the moment its home dir appears;
//   - every /home*/<user> dir        → a newly-created "domains" container
//     (first domain for that user) fires an event;
//   - every /home*/<user>/domains dir → a newly-created per-domain dir
//     fires an event, after which the ssl.key/ssl.cert file write inside it
//     is caught by the file-level isRelevant() filter.
//
// Recursive watches on entire home/web trees (public_html, wp-content,
// mail, ...) are deliberately avoided — they would add an inotify watch
// per file across every customer site. Renewals of already-discovered
// certs are covered by the 60s stat loop (knownFiles); the first-ever cert
// in a domain dir that predated startup is covered by the DiscoveryEvery
// rescan (now correct for all home mounts).
func homeShallowWatchDirs() []string {
	out := []string{}
	for _, mountTop := range homeMounts() {
		out = append(out, mountTop)

		users, err := os.ReadDir(mountTop)
		if err != nil {
			continue
		}
		for _, u := range users {
			if !u.IsDir() {
				continue
			}
			userDir := filepath.Join(mountTop, u.Name())
			out = append(out, userDir)

			// Watch the Virtualmin "domains" container so a NEW per-domain
			// dir (where ssl.key/ssl.cert live) fires a Create event.
			domainsDir := filepath.Join(userDir, "domains")
			if fi, err := os.Stat(domainsDir); err == nil && fi.IsDir() {
				out = append(out, domainsDir)
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

	// Mailcow is intentionally NOT a recursive root: acme/ and backups/ live
	// below its active store. mailcowActiveDirs adds only the store root and
	// immediate SNI host directories as shallow watches below.
	//
	// Per-user home cert material (Virtualmin: <home>/<user>/domains/
	// <domain>/ssl.{key,cert}) is covered by the SHALLOW watch points in
	// homeShallowWatchDirs() below, not by recursive roots here — watching
	// whole home trees would add an inotify watch per file across every
	// site. The previously-listed ~/ssl, ~/certs, ~/letsencrypt recursive
	// roots were removed: no scanner reads those paths (see discoverPairs),
	// so they only burned watches and fired no-op rescans.

	w, err := NewWatcher(c, 2*time.Second)
	if err == nil {
		// Shallow (non-recursive) watch points so brand-new reseller
		// accounts and newly-created per-user ssl dirs are detected in
		// seconds instead of waiting for the DiscoveryEvery fallback.
		shallowRoots := homeShallowWatchDirs()
		shallowRoots = append(shallowRoots, mailcowActiveDirs(defaultMailcowSSLRoot)...)
		w.SetShallowRoots(shallowRoots)
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
