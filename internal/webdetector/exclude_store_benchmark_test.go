package webdetector

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkExcludeStoreMatchWAFManyWildcards(b *testing.B) {
	store := newExcludeStore(filepath.Join(b.TempDir(), "excludes.json"))
	for i := 0; i < 1000; i++ {
		host := fmt.Sprintf("tenant-%04d.example.com", i)
		rule := fmt.Sprintf("/wp-admin/%04d/*", i)
		if !store.Add("path", rule, map[string]struct{}{host: {}}) {
			b.Fatalf("add failed for %s %s", host, rule)
		}
	}

	host := "tenant-0999.example.com"
	path := "/wp-admin/0999/index.php"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !store.MatchWAF(host, path) {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkLegacyExcludeLoopMatchWAFManyWildcards(b *testing.B) {
	entries := make([]excludeEntry, 0, 1000)
	for i := 0; i < 1000; i++ {
		host := fmt.Sprintf("tenant-%04d.example.com", i)
		rule := fmt.Sprintf("/wp-admin/%04d/*", i)
		entries = append(entries, excludeEntry{Type: "path", Value: rule, ScopeHosts: []string{host}})
	}

	host := "tenant-0999.example.com"
	path := "/wp-admin/0999/index.php"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !legacyMatchWAF(entries, host, path) {
			b.Fatal("expected match")
		}
	}
}

func legacyMatchWAF(entries []excludeEntry, host, path string) bool {
	for _, e := range entries {
		if !legacyHostInScope(host, e.ScopeHosts) {
			continue
		}
		switch e.Type {
		case "host":
			if legacyMatchExcludeValue(host, e.Value) {
				return true
			}
		case "path":
			if legacyMatchExcludeValue(path, e.Value) {
				return true
			}
		}
	}
	return false
}

func legacyHostInScope(host string, scopeHosts []string) bool {
	if len(scopeHosts) == 0 {
		return true
	}
	for _, scopeHost := range scopeHosts {
		ok, err := filepath.Match(scopeHost, host)
		if err == nil && ok {
			return true
		}
		if !strings.ContainsAny(scopeHost, "*?") && strings.EqualFold(scopeHost, host) {
			return true
		}
	}
	return false
}

func legacyMatchExcludeValue(value, rule string) bool {
	ok, err := filepath.Match(rule, value)
	if err == nil && ok {
		return true
	}
	if !strings.ContainsAny(rule, "*?") && strings.Contains(value, rule) {
		return true
	}
	return false
}
