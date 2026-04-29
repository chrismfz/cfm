// Package dyndns periodically resolves hostnames listed in cfm.dyndns and
// keeps the nftables allow_dyn_v4 / allow_dyn_v6 sets up-to-date.
//
// Usage in main:
//
//	ddm := dyndns.NewManager(be, cfgDir)
//	_ = ddm.FileChanged()
//	_ = ddm.LoadOnce(ctx)
//	// … inside the daemon tick loop:
//	if ddm.FileChanged() { _ = ddm.LoadOnce(ctx) }
//	ddm.Tick(ctx, time.Now())
package dyndns

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cfm/internal/filewatch"
	"cfm/internal/firewall"
	"cfm/internal/logging"

	"github.com/miekg/dns"
)

// ─────────────────────────────────────────────────────────────────────────────
// Internal data model
// ─────────────────────────────────────────────────────────────────────────────

type record struct {
	host        string
	lastV4      []string
	lastV6      []string
	nextRefresh time.Time
	interval    time.Duration // 0 = follow DNS TTL
}

// ─────────────────────────────────────────────────────────────────────────────
// Manager
// ─────────────────────────────────────────────────────────────────────────────

// Manager watches cfm.dyndns, resolves hostnames and pushes IPs into the
// nftables allow sets via firewall.Backend.
type Manager struct {
	be      firewall.Backend
	watcher *filewatch.Watcher
	records map[string]*record // host → record
}

// NewManager creates a Manager backed by be. If cfgDir is empty the watcher
// is disabled and no file is read (safe to call; all methods become no-ops).
func NewManager(be firewall.Backend, cfgDir string) *Manager {
	m := &Manager{records: make(map[string]*record)}

	if cfgDir != "" {
		m.watcher = filewatch.New(filepath.Join(cfgDir, "cfm.dyndns"))
	}
	m.be = be
	return m
}

// FileChanged returns true when cfm.dyndns has changed on disk and
// synchronises the internal host list accordingly (adds new hosts, removes
// deleted ones, updates per-host intervals).
func (m *Manager) FileChanged() bool {
	if m.watcher == nil {
		return false
	}
	b, ok := m.watcher.Changed()
	if !ok {
		return false
	}

	want := parseFile(b)
	seen := make(map[string]struct{}, len(want))

	var added, removed, updated int
	for _, it := range want {
		h := strings.TrimSpace(it.host)
		if h == "" {
			continue
		}
		seen[h] = struct{}{}
		if rec, exists := m.records[h]; exists {
			if rec.interval != it.interval {
				rec.interval = it.interval
				updated++
			}
		} else {
			m.records[h] = &record{host: h, interval: it.interval}
			added++
		}
	}
	// drop hosts that were removed from the file
	for h := range m.records {
		if _, ok := seen[h]; !ok {
			delete(m.records, h)
			removed++
		}
	}

	logging.Logf("[dyndns] cfm.dyndns reloaded: %d hosts tracked (added=%d removed=%d updated=%d)",
		len(m.records), added, removed, updated)
	return true
}

// LoadOnce resolves every tracked host and immediately pushes the full allow
// sets. Call this at startup and whenever FileChanged returns true.
func (m *Manager) LoadOnce(ctx context.Context) error {
	if m.be == nil {
		return nil
	}
	if len(m.records) == 0 {
		logging.Logf("[dyndns] LoadOnce: no hosts configured, skipping")
		return nil
	}

	logging.Logf("[dyndns] resolving %d host(s)...", len(m.records))

	now := time.Now()
	var allV4, allV6 []string
	changed := false

	for _, rec := range m.records {
		v4, v6, ttl, err := resolveWithTTL(ctx, rec.host, 5*time.Minute)
		if err != nil {
			logging.Logf("[dyndns] resolve error %s: %v (retry in 1m)", rec.host, err)
			rec.nextRefresh = now.Add(1 * time.Minute)
			continue
		}

		if !eqSet(rec.lastV4, v4) || !eqSet(rec.lastV6, v6) {
			logIPChange(rec.host, rec.lastV4, rec.lastV6, v4, v6)
			rec.lastV4, rec.lastV6 = v4, v6
			changed = true
		}

		next := ttl
		if rec.interval > 0 {
			next = rec.interval
		}
		rec.nextRefresh = now.Add(next)

		logging.Logf("[dyndns] %s → v4=%s v6=%s (next refresh in %s)",
			rec.host, joinOrNone(rec.lastV4), joinOrNone(rec.lastV6), next.Round(time.Second))

		allV4 = append(allV4, rec.lastV4...)
		allV6 = append(allV6, rec.lastV6...)
	}

	if !changed {
		logging.Logf("[dyndns] LoadOnce: all IPs unchanged, sets not updated")
		return nil
	}
	allV4 = dedup(allV4)
	allV6 = dedup(allV6)
	logging.Logf("[dyndns] applying sets: allow_dyn_v4=%d allow_dyn_v6=%d", len(allV4), len(allV6))
	return m.apply(allV4, allV6)
}

// Tick refreshes only the hosts whose TTL / interval has elapsed.
// Call this on every daemon tick; it is cheap when nothing is due.
func (m *Manager) Tick(ctx context.Context, now time.Time) {
	if m.be == nil || len(m.records) == 0 {
		return
	}
	var allV4, allV6 []string
	changed := false

	for _, rec := range m.records {
		if now.Before(rec.nextRefresh) {
			// not due yet — carry forward cached IPs
			allV4 = append(allV4, rec.lastV4...)
			allV6 = append(allV6, rec.lastV6...)
			continue
		}

		v4, v6, ttl, err := resolveWithTTL(ctx, rec.host, 5*time.Minute)
		if err != nil {
			logging.Logf("[dyndns] resolve error %s: %v (retry in 1m)", rec.host, err)
			rec.nextRefresh = now.Add(1 * time.Minute)
			allV4 = append(allV4, rec.lastV4...)
			allV6 = append(allV6, rec.lastV6...)
			continue
		}

		if !eqSet(rec.lastV4, v4) || !eqSet(rec.lastV6, v6) {
			logIPChange(rec.host, rec.lastV4, rec.lastV6, v4, v6)
			rec.lastV4, rec.lastV6 = v4, v6
			changed = true
		}

		next := ttl
		if rec.interval > 0 {
			next = rec.interval
		}
		rec.nextRefresh = now.Add(next)

		allV4 = append(allV4, rec.lastV4...)
		allV6 = append(allV6, rec.lastV6...)
	}

	if !changed {
		return
	}
	allV4 = dedup(allV4)
	allV6 = dedup(allV6)
	logging.Logf("[dyndns] sets updated after tick: allow_dyn_v4=%d allow_dyn_v6=%d", len(allV4), len(allV6))
	_ = m.apply(allV4, allV6)
}

// apply pushes v4/v6 slices into the nft allow_dyn sets.
func (m *Manager) apply(v4, v6 []string) error {
	if err := m.be.ReplaceSetFlushAdd("allow_dyn_v4", v4, nil); err != nil {
		return fmt.Errorf("dyndns apply v4: %w", err)
	}
	if err := m.be.ReplaceSetFlushAdd("allow_dyn_v6", v6, nil); err != nil {
		return fmt.Errorf("dyndns apply v6: %w", err)
	}
	if os.Getenv("CFM_DEBUG") != "" {
		fmt.Printf("[dyndns] updated sets: v4=%d v6=%d\n", len(v4), len(v6))
	}
	return nil
}

// logIPChange logs a human-readable diff when a host's resolved IPs change.
func logIPChange(host string, oldV4, oldV6, newV4, newV6 []string) {
	if !eqSet(oldV4, newV4) {
		logging.Logf("[dyndns] %s IPv4 changed: %s → %s",
			host, joinOrNone(oldV4), joinOrNone(newV4))
	}
	if !eqSet(oldV6, newV6) {
		logging.Logf("[dyndns] %s IPv6 changed: %s → %s",
			host, joinOrNone(oldV6), joinOrNone(newV6))
	}
}

func joinOrNone(ips []string) string {
	if len(ips) == 0 {
		return "(none)"
	}
	return strings.Join(ips, ", ")
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS resolution
// ─────────────────────────────────────────────────────────────────────────────

// resolveWithTTL queries A + AAAA for host and returns the minimum observed
// TTL clamped to [30s, 1h]. Falls back to defaultTTL when no records carry a
// TTL (e.g. local /etc/hosts).
func resolveWithTTL(ctx context.Context, host string, defaultTTL time.Duration) (v4, v6 []string, ttl time.Duration, err error) {
	ttl = defaultTTL

	c := new(dns.Client)
	cfg, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	if cfg == nil || len(cfg.Servers) == 0 {
		cfg = &dns.ClientConfig{Servers: []string{"1.1.1.1"}, Port: "53", Timeout: 2}
	}

	query := func(qtype uint16) ([]string, uint32, error) {
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

	v4s, ttl4, err4 := query(dns.TypeA)
	v6s, ttl6, err6 := query(dns.TypeAAAA)

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
	// clamp to sensible bounds
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}
	return
}

// ─────────────────────────────────────────────────────────────────────────────
// File parser
// ─────────────────────────────────────────────────────────────────────────────

type entry struct {
	host     string
	interval time.Duration
}

// parseFile parses cfm.dyndns: one hostname per line, optional "interval=5m".
// Lines starting with # and blank lines are ignored.
func parseFile(b []byte) []entry {
	var out []entry
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		e := entry{host: fields[0]}
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "interval=") {
				if d, err := time.ParseDuration(strings.TrimPrefix(f, "interval=")); err == nil {
					e.interval = d
				}
			}
		}
		out = append(out, e)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// String-slice helpers
// ─────────────────────────────────────────────────────────────────────────────

// eqSet reports whether a and b contain the same elements (order-independent).
func eqSet(a, b []string) bool {
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

// dedup returns a new slice with duplicate strings removed (order preserved).
func dedup(in []string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
