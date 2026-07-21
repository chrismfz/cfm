package webdetector

import (
	"path/filepath"
	"strings"
	"testing"
)

// Every route the engine registers must sit under a prefix the shared
// apiserver proxies (SharedAPIPrefixes). The apiserver mounts the engine mux
// per-prefix, so a route under an uncovered prefix is registered but
// UNREACHABLE in production: the request falls through to the webui catch-all
// and the caller gets dashboard HTML instead of JSON. This shipped twice
// (/api/v1/http3/, then the whole /api/v1/clam/ group) before this test
// existed — a new top-level group now fails here until its prefix is added.
func TestRegisterHTTP_SharedPrefixCoverage(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(Config{
		TrafficRulesStorePath:     filepath.Join(dir, "r.json"),
		ChallengeExcludeStorePath: filepath.Join(dir, "c.json"),
		WAFExcludeStorePath:       filepath.Join(dir, "w.json"),
		ClamScanOverrideStorePath: filepath.Join(dir, "o.json"),
		ClamModeOverrideStorePath: filepath.Join(dir, "m.json"),
		ClamSigIgnoreStorePath:    filepath.Join(dir, "s.json"),
	})

	prefixes := SharedAPIPrefixes()
	if len(prefixes) == 0 {
		t.Fatal("SharedAPIPrefixes is empty")
	}
	for _, p := range prefixes {
		if !strings.HasPrefix(p, "/api/v1/") || !strings.HasSuffix(p, "/") {
			t.Fatalf("prefix %q must look like /api/v1/<group>/", p)
		}
	}

	routes := e.apiRoutes()
	if len(routes) == 0 {
		t.Fatal("apiRoutes is empty")
	}
	seen := map[string]bool{}
	for _, rt := range routes {
		if seen[rt.path] {
			t.Errorf("duplicate route %q", rt.path)
		}
		seen[rt.path] = true
		covered := false
		for _, p := range prefixes {
			if strings.HasPrefix(rt.path, p) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("route %q is NOT covered by any SharedAPIPrefixes entry — it will be unreachable through the shared apiserver (dashboard HTML instead of JSON). Add its /api/v1/<group>/ prefix to SharedAPIPrefixes.", rt.path)
		}
	}

	// And no prefix should be dead weight — every proxied prefix carries at
	// least one route, so a renamed group can't leave a stale mount behind.
	for _, p := range prefixes {
		used := false
		for _, rt := range routes {
			if strings.HasPrefix(rt.path, p) {
				used = true
				break
			}
		}
		if !used {
			t.Errorf("prefix %q has no routes — stale entry in SharedAPIPrefixes?", p)
		}
	}
}
