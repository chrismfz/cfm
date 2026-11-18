package sslcollector

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"time"
)

// errKeyUnusable: buildEntry found no readable, non-empty key file.
var errKeyUnusable = errors.New("key file missing or empty")

// errNoPEMBlock: the cert file holds no PEM block.
var errNoPEMBlock = errors.New("cert file has no PEM block")

type Pair struct {
	Source    Source
	CertPath  string
	KeyPath   string
	ChainPath string
}

// discoverPairsHook replaces discoverPairs' result in Refresh. Tests only:
// the scanners read fixed system paths.
var discoverPairsHook func() []Pair

func (c *Collector) Refresh(ctx context.Context) error {
	c.refreshCallCount.Add(1)
	pairs := c.discoverPairs()
	if discoverPairsHook != nil {
		pairs = discoverPairsHook()
	}

	nextExact := map[string]*Entry{}
	nextWild := map[string]*Entry{}
	nextFiles := map[string]struct{}{}
	now := time.Now()

	prev := c.entriesByPair()
	seen := map[pairKey]bool{}
	failed := map[pairKey]bool{}

	add := func(e *Entry) {
		// track known files for stat loop.
		// ChainPath is included so the 60s statTicker -> anyKnownFileChanged
		// loop also detects chain-only rotations (eg DA rewriting
		// <domain>.cacert during an LE intermediate transition) when the
		// fsnotify watcher is unavailable. Without this entry, the only
		// fallback for chain-only changes is the 15-minute discoTicker.
		nextFiles[absClean(e.CertPath)] = struct{}{}
		nextFiles[absClean(e.KeyPath)] = struct{}{}
		if e.ChainPath != "" && e.ChainPath != e.CertPath {
			nextFiles[absClean(e.ChainPath)] = struct{}{}
		}

		for _, n := range e.Names {
			n = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(n, ".")))
			if n == "" {
				continue
			}

			// wildcard
			if strings.HasPrefix(n, "*.") {
				suf := normalizeHost(strings.TrimPrefix(n, "*."))
				if suf != "" {
					if old, ok := nextWild[suf]; !ok || betterEntry(e, old, now) {
						nextWild[suf] = e
					}
				}
				continue
			}

			host := normalizeHost(n)
			if host != "" {
				if old, ok := nextExact[host]; !ok || betterEntry(e, old, now) {
					nextExact[host] = e
				}
			}
		}
	}

	for _, p := range pairs {
		k := pairKeyOf(p.CertPath, p.KeyPath)
		seen[k] = true
		e, err := buildEntry(p, now)
		if err != nil {
			// A pair indexed before that fails now keeps its entry for a
			// while: see buildFailCarry.
			failed[k] = true
			old := prev[k]
			if old == nil || !c.carryOver(k, now) {
				continue
			}
			e = old
		}
		if len(e.Names) == 0 {
			continue
		}
		add(e)
	}

	// An indexed pair the scanners did not find this time, although its cert
	// file is still there, is carried the same way: most scanners skip an
	// empty cert file, which is what a truncate-then-write looks like for a
	// moment. A cert file that is gone (the account or domain removed) drops
	// the entry at once.
	for k, old := range prev {
		if seen[k] {
			continue
		}
		// Stat, not Lstat: a dangling symlink (an LE live/ link whose
		// archive was removed) is a removed cert, not one mid-rewrite.
		if _, err := os.Stat(old.CertPath); err != nil {
			continue
		}
		failed[k] = true
		if c.carryOver(k, now) && len(old.Names) > 0 {
			add(old)
		}
	}

	c.mu.Lock()
	c.exact = nextExact
	c.wildSuffix = nextWild
	c.mu.Unlock()
	c.forgetBuildFailures(failed)

	c.filesMu.Lock()
	c.knownFiles = nextFiles
	// keep memo map; it will be updated by stat loop
	c.filesMu.Unlock()

	// Persist the snapshot so workers (angie/openresty) can load it on
	// init_worker before the sslcollector socket is reachable. Best-effort:
	// errors are logged inside WriteSnapshot; do not propagate, since a
	// failed snapshot write must never break the running daemon. A
	// ReadOnly collector (the `cfm ssl` CLI) never writes it: the file is
	// the daemon's.
	if !c.cfg.ReadOnly {
		c.WriteSnapshot()
	}

	// Mark as refreshed so Run()'s startup path can skip its own
	// initial Refresh when the caller already invoked one
	// synchronously (eg the early-start path in cmd/cfm/main.go).
	c.refreshedOnce.Store(true)

	return nil
}

// buildFailCarry: how long an indexed pair that fails to build keeps its
// previous entry. A cert or key caught mid-rewrite when Refresh runs (a
// truncate-then-write, an empty key for a moment) used to leave the index at
// once. The payload is still complete without it, the edge REPLACES its store
// on a complete payload (sslcollector.lua ingest_dumpall), and the site served
// the default cert until the next Refresh. Carried, the entry stays in the
// payload: when its files can be read and hold PEM, they are sent; when they
// cannot or do not (empty, cut mid-write), getPEM skips it and the payload is
// incomplete, which the edge merges. A pair still failing after this long (a
// key that became a dangling symlink) leaves the index at the first Refresh
// past it.
const buildFailCarry = 10 * time.Minute

// pairKey identifies a cert/key pair across Refreshes.
type pairKey struct{ cert, key string }

func pairKeyOf(cert, key string) pairKey { return pairKey{absClean(cert), absClean(key)} }

// entriesByPair indexes the current entries by their cert/key pair.
func (c *Collector) entriesByPair() map[pairKey]*Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[pairKey]*Entry, len(c.exact)+len(c.wildSuffix))
	for _, m := range []map[string]*Entry{c.exact, c.wildSuffix} {
		for _, e := range m {
			if e != nil {
				out[pairKeyOf(e.CertPath, e.KeyPath)] = e
			}
		}
	}
	return out
}

// carryOver reports whether an indexed pair that failed to build at now may
// keep its previous entry: for buildFailCarry from its first failure.
func (c *Collector) carryOver(k pairKey, now time.Time) bool {
	c.carryMu.Lock()
	defer c.carryMu.Unlock()
	if c.buildFailSince == nil {
		c.buildFailSince = map[pairKey]time.Time{}
	}
	since, ok := c.buildFailSince[k]
	if !ok {
		c.buildFailSince[k] = now
		return true
	}
	return now.Sub(since) < buildFailCarry
}

// forgetBuildFailures drops the failure clock of every pair that did not fail
// in this Refresh (it built again, or is no longer discovered).
func (c *Collector) forgetBuildFailures(failed map[pairKey]bool) {
	c.carryMu.Lock()
	defer c.carryMu.Unlock()
	for k := range c.buildFailSince {
		if !failed[k] {
			delete(c.buildFailSince, k)
		}
	}
}

func buildEntry(p Pair, now time.Time) (*Entry, error) {
	// The key must be there too. Not every scanner checks it (the Virtualmin
	// ones glob for it, so a dangling ssl.key symlink matched), and an entry
	// whose key cannot be read is left out of every /dumpall payload, which
	// then says complete=false: the edge merges an incomplete payload instead
	// of replacing its store, so one such key stopped every worker on the
	// node from dropping a stale name (sslcollector.lua ingest_dumpall).
	if !fileOK(p.KeyPath) {
		return nil, errKeyUnusable
	}
	b, err := os.ReadFile(p.CertPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		// err is nil here (the read succeeded): returning it made Refresh
		// read Names off a nil entry and panic on any non-PEM cert file.
		return nil, errNoPEMBlock
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	names := []string{}
	if cn := cert.Subject.CommonName; cn != "" {
		names = append(names, cn)
	}
	names = append(names, cert.DNSNames...)
	names = uniqNamesKeepWild(names)

	stC, _ := os.Stat(p.CertPath)
	stK, _ := os.Stat(p.KeyPath)
	var stChain os.FileInfo
	if p.ChainPath != "" && p.ChainPath != p.CertPath {
		stChain, _ = os.Stat(p.ChainPath)
	}

	fp := sha256.Sum256(cert.Raw)

	e := &Entry{
		Source:      p.Source,
		Names:       names,
		CertPath:    p.CertPath,
		KeyPath:     p.KeyPath,
		ChainPath:   p.ChainPath,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		SelfSigned:  isSelfSigned(cert),
		Fingerprint: hex.EncodeToString(fp[:]),
		LastSeen:    now,
	}
	if stC != nil {
		e.CertMTime = stC.ModTime()
		e.CertSize = stC.Size()
	}
	if stK != nil {
		e.KeyMTime = stK.ModTime()
		e.KeySize = stK.Size()
	}
	if stChain != nil {
		e.ChainMTime = stChain.ModTime()
		e.ChainSize = stChain.Size()
	}
	return e, nil
}

func uniqNamesKeepWild(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, n := range in {
		n = strings.TrimSpace(strings.ToLower(strings.TrimSuffix(n, ".")))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func certValidityRank(e *Entry, now time.Time) int {
	if now.Before(e.NotBefore) {
		return 1 // not yet valid
	}
	if now.After(e.NotAfter) {
		return 0 // expired
	}
	return 2 // currently valid
}

func betterEntry(a, b *Entry, now time.Time) bool {
	if a == nil {
		return false
	}
	if b == nil {
		return true
	}

	// 1) Prefer certs that are valid now over not-yet-valid over expired.
	va, vb := certValidityRank(a, now), certValidityRank(b, now)
	if va != vb {
		return va > vb
	}

	// 2) Prefer non-self-signed over self-signed.
	if a.SelfSigned != b.SelfSigned {
		return !a.SelfSigned
	}

	// 3) Preserve source preference as primary policy.
	if prefer(a.Source, b.Source) != prefer(b.Source, a.Source) {
		return prefer(a.Source, b.Source)
	}

	// 4) Prefer longer remaining/newer expiry.
	if !a.NotAfter.Equal(b.NotAfter) {
		return a.NotAfter.After(b.NotAfter)
	}

	// 5) deterministic tie-breaker to avoid map-order surprises.
	if a.CertPath != b.CertPath {
		return a.CertPath < b.CertPath
	}
	return a.KeyPath < b.KeyPath
}

func isSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	// Fast check first, then cryptographic self-signature verification.
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

func prefer(a, b Source) bool {
	order := map[Source]int{
		SrcLetsEncrypt: 5,
		SrcCPanel:      4,
		SrcDirectAdmin: 4,
		SrcVirtualmin:  3,
		SrcWebmin:      3,
		SrcGeneric:     1,
	}
	return order[a] > order[b]
}
