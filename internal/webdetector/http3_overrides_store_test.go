package webdetector

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestHTTP3OverrideStore_AddRemoveList(t *testing.T) {
	dir := t.TempDir()
	s := newHTTP3OverrideStore(filepath.Join(dir, "http3.json"))

	if s.HasAny() {
		t.Fatal("fresh store should be empty")
	}

	if !s.Add("Example.com", nil) {
		t.Fatal("first add should succeed")
	}
	if s.Add("example.com", nil) {
		t.Fatal("duplicate add (case-insensitive) should fail")
	}
	if !s.HasAny() {
		t.Fatal("store should have entries after add")
	}

	if !s.IsEnabled("example.com") {
		t.Fatal("exact host lookup should match")
	}
	if !s.IsEnabled("EXAMPLE.COM") {
		t.Fatal("host lookup should be case-insensitive")
	}
	if !s.IsEnabled("example.com.") {
		t.Fatal("trailing dot should be normalized")
	}
	if s.IsEnabled("sub.example.com") {
		t.Fatal("exact entry should not match subdomain")
	}

	if !s.Remove("example.com", nil) {
		t.Fatal("remove should succeed")
	}
	if s.Remove("example.com", nil) {
		t.Fatal("double remove should fail")
	}
	if s.HasAny() {
		t.Fatal("store should be empty after remove")
	}
}

func TestHTTP3OverrideStore_Wildcard(t *testing.T) {
	dir := t.TempDir()
	s := newHTTP3OverrideStore(filepath.Join(dir, "http3.json"))

	if !s.Add("*.cdn.example.com", nil) {
		t.Fatal("wildcard add should succeed")
	}
	if !s.IsEnabled("static.cdn.example.com") {
		t.Fatal("wildcard should match one-level subdomain")
	}
	if !s.IsEnabled("img.cdn.example.com") {
		t.Fatal("wildcard should match arbitrary subdomain")
	}
	if s.IsEnabled("cdn.example.com") {
		t.Fatal("*.x should not match x itself")
	}
	if s.IsEnabled("other.example.com") {
		t.Fatal("wildcard should not match outside the suffix")
	}
}

func TestHTTP3OverrideStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "http3.json")

	s1 := newHTTP3OverrideStore(path)
	_ = s1.Add("foo.example.com", nil)
	_ = s1.Add("bar.example.com", nil)
	_ = s1.Add("*.cdn.example.com", nil)

	// New store from same file should load entries.
	s2 := newHTTP3OverrideStore(path)
	got := s2.Hosts()
	want := []string{"*.cdn.example.com", "bar.example.com", "foo.example.com"}
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("expected %d hosts after reload, got %d (%v)", len(want), len(got), got)
	}
	for i, h := range want {
		if got[i] != h {
			t.Errorf("hosts[%d]: want %q, got %q", i, h, got[i])
		}
	}
	if !s2.IsEnabled("foo.example.com") {
		t.Fatal("reloaded entry should match")
	}
	if !s2.IsEnabled("anything.cdn.example.com") {
		t.Fatal("reloaded wildcard should match")
	}
}

func TestHTTP3OverrideStore_NormalizationRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	s := newHTTP3OverrideStore(filepath.Join(dir, "http3.json"))

	if s.Add("", nil) {
		t.Error("empty host should be rejected")
	}
	if s.Add("   ", nil) {
		t.Error("whitespace-only host should be rejected")
	}
	if s.IsEnabled("") {
		t.Error("IsEnabled of empty host should be false")
	}
}

func TestHTTP3OverrideStore_MatchInfo(t *testing.T) {
	dir := t.TempDir()
	s := newHTTP3OverrideStore(filepath.Join(dir, "http3.json"))

	_ = s.Add("foo.example.com", nil)
	_ = s.Add("*.cdn.example.com", nil)

	// Exact match: matched, pattern == host, exact == true.
	matched, pattern, exact := s.MatchInfo("foo.example.com")
	if !matched || pattern != "foo.example.com" || !exact {
		t.Errorf("exact lookup: matched=%v pattern=%q exact=%v", matched, pattern, exact)
	}

	// Wildcard match: matched, pattern is the wildcard, exact == false.
	matched, pattern, exact = s.MatchInfo("static.cdn.example.com")
	if !matched || pattern != "*.cdn.example.com" || exact {
		t.Errorf("wildcard lookup: matched=%v pattern=%q exact=%v", matched, pattern, exact)
	}

	// CRITICAL: the bug we fixed — `foo.example.com` opt-in must NOT
	// match `sub.foo.example.com`. The Lua data path never honored that
	// suffix semantics; the UI must agree.
	matched, _, _ = s.MatchInfo("sub.foo.example.com")
	if matched {
		t.Error("exact opt-in for foo.example.com must NOT match sub.foo.example.com (suffix semantics is a bug)")
	}

	// No match.
	matched, pattern, exact = s.MatchInfo("other.example.com")
	if matched || pattern != "" || exact {
		t.Errorf("miss: matched=%v pattern=%q exact=%v", matched, pattern, exact)
	}
}

func TestHTTP3OverrideStore_AddRollbackOnSaveFailure(t *testing.T) {
	// Pointing the store at a directory that doesn't exist AND cannot be
	// created (parent is a regular file, not a directory) makes MkdirAll
	// fail, which makes saveLocked fail. The store must roll back the
	// in-memory insert so the daemon's view matches disk.
	dir := t.TempDir()
	// Create a regular file where the store wants to create a directory.
	blocker := filepath.Join(dir, "blocker")
	if err := writeFile(t, blocker, "x"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	storePath := filepath.Join(blocker, "subdir", "http3.json") // MkdirAll(blocker/subdir) will fail
	s := newHTTP3OverrideStore(storePath)

	if s.Add("example.com", nil) {
		t.Fatal("Add should report failure when persistence fails")
	}
	if s.IsEnabled("example.com") {
		t.Fatal("in-memory state should be rolled back when persistence fails")
	}
	if s.HasAny() {
		t.Fatal("store should be empty after rollback")
	}
}

func TestHTTP3OverrideStore_RemoveRollbackOnSaveFailure(t *testing.T) {
	// Mirrors AddRollbackOnSaveFailure's trick: use a path whose parent
	// MkdirAll cannot create (parent is a regular file). The Add path
	// will rollback the in-memory entry, so we have to populate the
	// store via a successful path first and then move the store's path
	// to an unwritable target. Simplest: construct the store with a
	// good path, Add successfully, then swap s.path to a guaranteed-bad
	// target before Remove. This is white-box but the alternative
	// (mocking the filesystem) adds far more surface for a single test.
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "http3.json")
	s := newHTTP3OverrideStore(goodPath)
	if !s.Add("example.com", nil) {
		t.Fatal("initial Add should succeed")
	}

	blocker := filepath.Join(dir, "blocker-file")
	if err := writeFile(t, blocker, "x"); err != nil {
		t.Fatalf("setup blocker: %v", err)
	}
	s.path = filepath.Join(blocker, "subdir", "http3.json") // MkdirAll(blocker/subdir) will fail

	if s.Remove("example.com", nil) {
		t.Fatal("Remove should report failure when persistence fails")
	}
	if !s.IsEnabled("example.com") {
		t.Fatal("in-memory state should be restored when persistence fails")
	}
}

// writeFile is a tiny test helper used by the rollback test.
func writeFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0o600)
}
