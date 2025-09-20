// cmd/cfm/dyndns.go
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"cfm/internal/firewall"
	"cfm/internal/firewall/nft"
	"github.com/miekg/dns"
)

// ─────────────────────────────────────────────────────────────────────────────
// Data model & helpers
// ─────────────────────────────────────────────────────────────────────────────

type dynRecord struct {
	Host        string
	LastV4      []string
	LastV6      []string
	NextRefresh time.Time
	Interval    time.Duration // optional override; 0 = use DNS TTL
}

// resolveWithTTL returns A and AAAA plus the minimum TTL seen (fallback defaultTTL if none).
func resolveWithTTL(ctx context.Context, host string, defaultTTL time.Duration) (v4, v6 []string, ttl time.Duration, err error) {
	ttl = defaultTTL

	c := new(dns.Client)
	cfg, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	if cfg == nil || len(cfg.Servers) == 0 {
		cfg = &dns.ClientConfig{Servers: []string{"1.1.1.1"}, Port: "53", Timeout: 2}
	}

	q := func(qtype uint16) ([]string, uint32, error) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		server := net.JoinHostPort(cfg.Servers[0], cfg.Port)
		r, _, e := c.ExchangeContext(ctx, m, server)
		if e != nil || r == nil || r.Rcode != dns.RcodeSuccess {
			return nil, 0, e
		}
		var out []string
		minTTL := uint32(0)
		for _, a := range r.Answer {
			switch rr := a.(type) {
			case *dns.A:
				if qtype == dns.TypeA {
					out = append(out, rr.A.String())
					if minTTL == 0 || rr.Hdr.Ttl < minTTL {
						minTTL = rr.Hdr.Ttl
					}
				}
			case *dns.AAAA:
				if qtype == dns.TypeAAAA {
					out = append(out, rr.AAAA.String())
					if minTTL == 0 || rr.Hdr.Ttl < minTTL {
						minTTL = rr.Hdr.Ttl
					}
				}
			}
		}
		return out, minTTL, nil
	}

	v4s, ttl4, err4 := q(dns.TypeA)
	v6s, ttl6, err6 := q(dns.TypeAAAA)

	if err4 != nil && err6 != nil {
		if err4 != nil {
			err = err4
		} else {
			err = err6
		}
		return
	}
	v4, v6 = v4s, v6s

	minTTL := ttl4
	if minTTL == 0 || (ttl6 != 0 && ttl6 < minTTL) {
		minTTL = ttl6
	}
	if minTTL > 0 {
		ttl = time.Duration(minTTL) * time.Second
	}

	// clamp for sanity
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	if ttl > 1*time.Hour {
		ttl = 1 * time.Hour
	}
	return
}

// equal string slices (as sets)
func eqStrSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]struct{}, len(a))
	for _, s := range a {
		m[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := m[s]; !ok {
			return false
		}
	}
	return true
}

func dedupStrings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	m := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// parse simple cfm.dyndns format: one hostname per line, with optional "interval=5m"
func parseDynDNS(b []byte) []struct {
	Host     string
	Interval time.Duration
} {
	var out []struct {
		Host     string
		Interval time.Duration
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host := strings.Fields(line)[0]
		var iv time.Duration
		for _, f := range strings.Fields(line)[1:] {
			if strings.HasPrefix(f, "interval=") {
				if d, err := time.ParseDuration(strings.TrimPrefix(f, "interval=")); err == nil {
					iv = d
				}
			}
		}
		out = append(out, struct {
			Host     string
			Interval time.Duration
		}{host, iv})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// DynDNSManager
// ─────────────────────────────────────────────────────────────────────────────

// Σημείωση: fwBackend και fileWatcher ορίζονται ήδη στο package main (όπως τα χρησιμοποιείς στη main.go).
type DynDNSManager struct {
	nb      *nft.Backend
	watcher *fileWatcher
	records map[string]*dynRecord // host -> rec
}

func NewDynDNSManager(be firewall.Backend, cfgDir string) *DynDNSManager {
	var w *fileWatcher
	if cfgDir != "" {
		w = newFileWatcher(filepath.Join(cfgDir, "cfm.dyndns"))
	}
	ddm := &DynDNSManager{
		watcher: w,
		records: map[string]*dynRecord{},
	}
	if nb, ok := be.(*nft.Backend); ok {
		ddm.nb = nb
	}
	return ddm
}

// FileChanged επιστρέφει true αν το cfm.dyndns άλλαξε και συγχρονίζει τα d.records (hosts & intervals).
func (d *DynDNSManager) FileChanged() bool {
	if d.watcher == nil {
		return false
	}
	b, ok := d.watcher.Changed()
	if !ok {
		return false
	}
	want := parseDynDNS(b)

	seen := map[string]struct{}{}
	for _, it := range want {
		h := strings.TrimSpace(it.Host)
		if h == "" {
			continue
		}
		seen[h] = struct{}{}
		if rec, ok := d.records[h]; ok {
			rec.Interval = it.Interval
		} else {
			d.records[h] = &dynRecord{Host: h, Interval: it.Interval}
		}
	}
	// drop removed hosts
	for h := range d.records {
		if _, ok := seen[h]; !ok {
			delete(d.records, h)
		}
	}
	return true
}

// LoadOnce κάνει initial resolve & apply ΟΛΩΝ των hosts (startup ή μετά από αλλαγή αρχείου).
func (d *DynDNSManager) LoadOnce(ctx context.Context) error {
	if d.nb == nil {
		return nil
	}
	now := time.Now()
	var allV4, allV6 []string
	changed := false

	for _, rec := range d.records {
		v4, v6, ttl, err := resolveWithTTL(ctx, rec.Host, 5*time.Minute)
		if err != nil {
			// μικρό backoff και κράτα ό,τι είχες
			rec.NextRefresh = now.Add(1 * time.Minute)
			continue
		}
		if !eqStrSet(rec.LastV4, v4) || !eqStrSet(rec.LastV6, v6) {
			rec.LastV4, rec.LastV6 = v4, v6
			changed = true
		}
		next := ttl
		if rec.Interval > 0 {
			next = rec.Interval
		}
		rec.NextRefresh = now.Add(next)

		allV4 = append(allV4, rec.LastV4...)
		allV6 = append(allV6, rec.LastV6...)
	}

	if !changed {
		return nil
	}
	allV4 = dedupStrings(allV4)
	allV6 = dedupStrings(allV6)

	if err := d.nb.ReplaceSetFlushAdd("allow_dyn_v4", allV4, nil); err != nil {
		return fmt.Errorf("dyndns apply v4: %w", err)
	}
	if err := d.nb.ReplaceSetFlushAdd("allow_dyn_v6", allV6, nil); err != nil {
		return fmt.Errorf("dyndns apply v6: %w", err)
	}
	if os.Getenv("CFM_DEBUG") != "" {
		fmt.Printf("[dyndns] updated hosts: v4=%d v6=%d\n", len(allV4), len(allV6))
	}
	return nil
}

// Tick εκτελεί refresh ανά TTL/interval, χωρίς να ξαναδιαβάσει το αρχείο.
func (d *DynDNSManager) Tick(ctx context.Context, now time.Time) {
	if d.nb == nil || len(d.records) == 0 {
		return
	}
	var allV4, allV6 []string
	changed := false

	for _, rec := range d.records {
		// όχι ώρα για refresh; κράτα τα παλιά
		if now.Before(rec.NextRefresh) {
			allV4 = append(allV4, rec.LastV4...)
			allV6 = append(allV6, rec.LastV6...)
			continue
		}
		// refresh
		v4, v6, ttl, err := resolveWithTTL(ctx, rec.Host, 5*time.Minute)
		if err != nil {
			rec.NextRefresh = now.Add(1 * time.Minute)
			allV4 = append(allV4, rec.LastV4...)
			allV6 = append(allV6, rec.LastV6...)
			continue
		}
		if !eqStrSet(rec.LastV4, v4) || !eqStrSet(rec.LastV6, v6) {
			rec.LastV4, rec.LastV6 = v4, v6
			changed = true
		}
		next := ttl
		if rec.Interval > 0 {
			next = rec.Interval
		}
		rec.NextRefresh = now.Add(next)

		allV4 = append(allV4, rec.LastV4...)
		allV6 = append(allV6, rec.LastV6...)
	}

	if !changed {
		return
	}
	allV4 = dedupStrings(allV4)
	allV6 = dedupStrings(allV6)
	_ = d.nb.ReplaceSetFlushAdd("allow_dyn_v4", allV4, nil)
	_ = d.nb.ReplaceSetFlushAdd("allow_dyn_v6", allV6, nil)
	if os.Getenv("CFM_DEBUG") != "" {
		fmt.Printf("[dyndns] updated hosts: v4=%d v6=%d\n", len(allV4), len(allV6))
	}
}
