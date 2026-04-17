package webdetector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExcludeStore_ScopedHostMatch(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	scope := map[string]struct{}{"app.example.com": {}}
	if ok := s.Add("host", "app.example.com", scope); !ok {
		t.Fatalf("expected scoped add to succeed")
	}
	if !s.MatchChallenge("app.example.com") {
		t.Fatalf("expected host to match scoped entry")
	}
	if s.MatchChallenge("other.example.com") {
		t.Fatalf("did not expect host outside scope to match")
	}
}

func TestExcludeStore_ScopedPathMatchRequiresHostInScope(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	scope := map[string]struct{}{"www.example.com": {}}
	if ok := s.Add("path", "/wp-admin/*", scope); !ok {
		t.Fatalf("expected scoped path add to succeed")
	}
	if !s.MatchWAF("www.example.com", "/wp-admin/setup") {
		t.Fatalf("expected in-scope host/path to match")
	}
	if s.MatchWAF("other.example.com", "/wp-admin/setup") {
		t.Fatalf("did not expect path match for out-of-scope host")
	}
}

func TestExcludeStore_LoadLegacyEntriesAsGlobal(t *testing.T) {
	p := filepath.Join(t.TempDir(), "excludes.json")
	legacy := `[{"type":"path","value":"/legacy","created_at":"2026-01-01T00:00:00Z"}]`
	if err := os.WriteFile(p, []byte(legacy), 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}
	s := newExcludeStore(p)
	if !s.MatchWAF("any.example.com", "/legacy") {
		t.Fatalf("expected legacy entry without scope to be treated global")
	}
}

func TestExcludeStore_MatchWAFChecksHostAndPathRulesWithScope(t *testing.T) {
	s := newExcludeStore(filepath.Join(t.TempDir(), "excludes.json"))
	scope := map[string]struct{}{"tenant-a.example.com": {}}
	if ok := s.Add("path", "/wp-admin/*", scope); !ok {
		t.Fatalf("expected scoped path add to succeed")
	}
	if ok := s.Add("host", "tenant-a.example.com", scope); !ok {
		t.Fatalf("expected scoped host add to succeed")
	}
	if !s.MatchWAF("tenant-a.example.com", "/wp-admin/index.php") {
		t.Fatalf("expected in-scope host+path to match")
	}
	if s.MatchWAF("tenant-b.example.com", "/wp-admin/index.php") {
		t.Fatalf("expected out-of-scope tenant path to not match")
	}
	if s.MatchWAF("tenant-b.example.com", "/") {
		t.Fatalf("expected out-of-scope tenant host to not match")
	}
}
