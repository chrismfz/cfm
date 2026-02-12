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
					if old, ok := nextWild[suf]; !ok || prefer(e.Source, old.Source) {
						nextWild[suf] = e
					}
				}
				continue
			}

			host := normalizeHost(n)
			if host != "" {
				if old, ok := nextExact[host]; !ok || prefer(e.Source, old.Source) {
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
		NotAfter:    cert.NotAfter,
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
