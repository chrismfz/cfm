package webdetector

import (
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
