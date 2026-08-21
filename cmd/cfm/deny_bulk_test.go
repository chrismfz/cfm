package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"cfm/internal/allowlist"
)

type fakeBulkBlocker struct {
	calls  int
	got    []net.IP
	failed []net.IP
}

func (f *fakeBulkBlocker) AddManualBlocksBulk(ips []net.IP) ([]net.IP, error) {
	f.calls++
	f.got = append([]net.IP(nil), ips...)
	if len(f.failed) > 0 {
		return f.failed, fmt.Errorf("%d failed", len(f.failed))
	}
	return nil, nil
}

func permEntry(s string) allowlist.Entry {
	return allowlist.Entry{Kind: allowlist.KindIP, IP: net.ParseIP(s)}
}

func manyPermEntries(n int) []allowlist.Entry {
	out := make([]allowlist.Entry, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, permEntry(fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff)))
	}
	return out
}

func TestBulkPreapplyDenyHosts_BelowThresholdIsNoop(t *testing.T) {
	entries := manyPermEntries(denyBulkMinBatch - 1)
	seen := map[string]string{}
	f := &fakeBulkBlocker{}

	bulkPreapplyDenyHosts(entries, seen, f)

	if f.calls != 0 {
		t.Fatalf("below threshold must not call bulk, calls=%d", f.calls)
	}
	if len(seen) != 0 {
		t.Fatalf("below threshold must mark nothing seen, seen=%d", len(seen))
	}
}

func TestBulkPreapplyDenyHosts_SuccessMarksAllSeen(t *testing.T) {
	entries := manyPermEntries(denyBulkMinBatch)
	seen := map[string]string{}
	f := &fakeBulkBlocker{}

	bulkPreapplyDenyHosts(entries, seen, f)

	if f.calls != 1 {
		t.Fatalf("calls=%d, want 1", f.calls)
	}
	if len(f.got) != denyBulkMinBatch {
		t.Fatalf("bulk received %d IPs, want %d", len(f.got), denyBulkMinBatch)
	}
	if len(seen) != denyBulkMinBatch {
		t.Fatalf("seen=%d, want %d", len(seen), denyBulkMinBatch)
	}
	for _, e := range entries {
		if seen["ip|"+e.IP.String()] != "perm" {
			t.Fatalf("entry %s not marked seen perm", e.IP)
		}
	}
}

func TestBulkPreapplyDenyHosts_FailedStayUnseen(t *testing.T) {
	entries := manyPermEntries(denyBulkMinBatch)
	seen := map[string]string{}
	// Report the first two IPs as failed.
	f := &fakeBulkBlocker{failed: []net.IP{entries[0].IP, entries[1].IP}}

	bulkPreapplyDenyHosts(entries, seen, f)

	if _, ok := seen["ip|"+entries[0].IP.String()]; ok {
		t.Fatalf("failed IP %s must stay unseen", entries[0].IP)
	}
	if _, ok := seen["ip|"+entries[1].IP.String()]; ok {
		t.Fatalf("failed IP %s must stay unseen", entries[1].IP)
	}
	if seen["ip|"+entries[2].IP.String()] != "perm" {
		t.Fatalf("succeeded IP %s must be marked seen", entries[2].IP)
	}
	if len(seen) != denyBulkMinBatch-2 {
		t.Fatalf("seen=%d, want %d", len(seen), denyBulkMinBatch-2)
	}
}

func TestBulkPreapplyDenyHosts_SkipsNonHostAndSeen(t *testing.T) {
	ttl := time.Hour
	until := time.Now().Add(time.Hour)
	// A few more than the threshold so that excluding the already-seen one still
	// leaves enough permanent hosts to take the bulk path.
	nPerm := denyBulkMinBatch + 5
	entries := manyPermEntries(nPerm)
	// Add entries that must NOT reach the bulk path.
	entries = append(entries,
		allowlist.Entry{Kind: allowlist.KindCIDR, CIDR: "192.0.2.0/24"},
		allowlist.Entry{Kind: allowlist.KindIP, IP: net.ParseIP("203.0.113.7"), TTL: &ttl},
		allowlist.Entry{Kind: allowlist.KindIP, IP: net.ParseIP("203.0.113.8"), Until: &until},
		allowlist.Entry{Kind: allowlist.KindIP, IP: nil}, // malformed → left to per-IP path
	)
	seen := map[string]string{
		"ip|" + entries[0].IP.String(): "perm", // already seen → excluded from bulk
	}
	f := &fakeBulkBlocker{}

	bulkPreapplyDenyHosts(entries, seen, f)

	// bulk should get exactly the permanent hosts minus the already-seen one.
	if len(f.got) != nPerm-1 {
		t.Fatalf("bulk got %d IPs, want %d", len(f.got), nPerm-1)
	}
	for _, ip := range f.got {
		s := ip.String()
		if s == "192.0.2.0" || s == "203.0.113.7" || s == "203.0.113.8" || s == "<nil>" {
			t.Fatalf("bulk must not include non-permanent-host entry %s", s)
		}
	}
}
