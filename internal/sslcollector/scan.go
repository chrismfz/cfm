package sslcollector

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"time"
)

type Pair struct {
	Source    Source
	CertPath  string
	KeyPath   string
	ChainPath string
}

func (c *Collector) Refresh(ctx context.Context) error {
	c.refreshCallCount.Add(1)
	pairs := c.discoverPairs()

	nextExact := map[string]*Entry{}
	nextWild := map[string]*Entry{}
	nextFiles := map[string]struct{}{}
	now := time.Now()

	for _, p := range pairs {
		e, err := buildEntry(p, now)
		if err != nil || len(e.Names) == 0 {
			continue
		}

		// track known files for stat loop
		nextFiles[absClean(e.CertPath)] = struct{}{}
		nextFiles[absClean(e.KeyPath)] = struct{}{}

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

	c.mu.Lock()
	c.exact = nextExact
	c.wildSuffix = nextWild
	c.mu.Unlock()

	c.filesMu.Lock()
	c.knownFiles = nextFiles
	// keep memo map; it will be updated by stat loop
	c.filesMu.Unlock()

	// Persist the snapshot so workers (angie/openresty) can load it on
	// init_worker before the sslcollector socket is reachable. Best-effort:
	// errors are logged inside WriteSnapshot; do not propagate, since a
	// failed snapshot write must never break the running daemon.
	c.WriteSnapshot()

	// Mark as refreshed so Run()'s startup path can skip its own
	// initial Refresh when the caller already invoked one
	// synchronously (eg the early-start path in cmd/cfm/main.go).
	c.refreshedOnce.Store(true)

	return nil
}

func buildEntry(p Pair, now time.Time) (*Entry, error) {
	b, err := os.ReadFile(p.CertPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, err
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
