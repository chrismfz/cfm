package webdetector

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkExcludeStoreMatchWAF(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			store := newExcludeStore(filepath.Join(b.TempDir(), "excludes.json"))
			for i := 0; i < n; i++ {
				hostRule := fmt.Sprintf("tenant-%04d-*.example.com", i)
				pathRule := fmt.Sprintf("/wp-admin/%04d/*/index.?hp", i)
				if !store.Add("path", pathRule, map[string]struct{}{hostRule: {}}) {
					b.Fatalf("add failed for %s %s", hostRule, pathRule)
				}
			}

			host := fmt.Sprintf("tenant-%04d-api.example.com", n-1)
			path := fmt.Sprintf("/wp-admin/%04d/a/index.php", n-1)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !store.MatchWAF(host, path) {
					b.Fatal("expected match")
				}
			}
		})
	}
}

func BenchmarkExcludeStoreMatchChallenge(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			store := newExcludeStore(filepath.Join(b.TempDir(), "challenge_excludes.json"))
			for i := 0; i < n; i++ {
				rule := fmt.Sprintf("*tenant-%04d*.example.com", i)
				if !store.Add("host", rule, nil) {
					b.Fatalf("add failed for %s", rule)
				}
			}

			host := fmt.Sprintf("edge-tenant-%04d-app.example.com", n-1)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !store.MatchChallenge(host) {
					b.Fatal("expected match")
				}
			}
		})
	}
}

func BenchmarkLegacyExcludeLoopMatchWAFManyWildcards(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			entries := make([]excludeEntry, 0, n)
			for i := 0; i < n; i++ {
				host := fmt.Sprintf("tenant-%04d-*.example.com", i)
				rule := fmt.Sprintf("/wp-admin/%04d/*/index.?hp", i)
				entries = append(entries, excludeEntry{Type: "path", Value: rule, ScopeHosts: []string{host}})
			}

			host := fmt.Sprintf("tenant-%04d-api.example.com", n-1)
			path := fmt.Sprintf("/wp-admin/%04d/a/index.php", n-1)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !legacyMatchWAF(entries, host, path) {
					b.Fatal("expected match")
				}
			}
		})
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
