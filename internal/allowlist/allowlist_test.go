package allowlist

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadEntriesFromFile_ResolvesHostnamesWithTTL(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "cfm.allow")
	if err := os.WriteFile(path, []byte("198.51.100.2 ttl=1m\nexample.test until=2030-01-02T03:04:05Z\nbad_host\n"), 0600); err != nil {
		t.Fatal(err)
	}

	entries, meta, err := ReadEntriesFromFile(context.Background(), path, ReadOptions{
		ResolveHostnames: true,
		LookupHost: func(_ context.Context, host string) ([]net.IP, error) {
			if host != "example.test" {
				return nil, nil
			}
			return []net.IP{net.ParseIP("203.0.113.9")}, nil
		},
	})
	if err != nil {
		t.Fatalf("read entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want=2", len(entries))
	}
	if got := entries[0].TTL; got == nil || *got != time.Minute {
		t.Fatalf("ttl=%v want=1m", got)
	}
	if got := entries[1].IP.String(); got != "203.0.113.9" {
		t.Fatalf("resolved ip=%q", got)
	}
	if len(meta) != 3 {
		t.Fatalf("meta=%d want=3", len(meta))
	}
	if meta[2].Note == "" {
		t.Fatalf("expected invalid hostname note")
	}
}

func TestBuildSnapshot_AggregatesSourcesAndInlineTokens(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "cfm.allow"), []byte("198.51.100.0/24\nallow.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "cfm.dyndns"), []byte("dyn.example\n"), 0600); err != nil {
		t.Fatal(err)
	}

	snap, err := BuildSnapshot(context.Background(), SnapshotOptions{
		Sources: []SnapshotSource{
			{Path: filepath.Join(tmp, "cfm.allow"), ResolveHostnames: true},
			{Path: filepath.Join(tmp, "cfm.dyndns"), ResolveHostnames: true},
		},
		ExtraTokens: []string{"api.example"},
		LookupHost: func(_ context.Context, host string) ([]net.IP, error) {
			switch host {
			case "allow.example":
				return []net.IP{net.ParseIP("203.0.113.7")}, nil
			case "dyn.example":
				return []net.IP{net.ParseIP("203.0.113.8")}, nil
			case "api.example":
				return []net.IP{net.ParseIP("203.0.113.9")}, nil
			default:
				return nil, nil
			}
		},
	})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	for _, ip := range []string{"203.0.113.7", "203.0.113.8", "203.0.113.9"} {
		if _, ok := snap.ExactIPs[ip]; !ok {
			t.Fatalf("missing ip %s", ip)
		}
	}
	if len(snap.CIDRNets) != 1 || snap.CIDRNets[0].String() != "198.51.100.0/24" {
		t.Fatalf("cidrs=%v", snap.CIDRNets)
	}
	if len(snap.Metadata) == 0 {
		t.Fatalf("expected metadata")
	}
}
