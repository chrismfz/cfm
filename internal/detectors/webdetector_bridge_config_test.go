package detectors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/sslcollector"
)

// The Site Cache gates published to the edge: SITE_CACHE is a kill switch that
// defaults ON (the per-vhost policy store is what arms a vhost), and
// MICRO_CACHE_ENFORCE is an opt-in that defaults OFF (an upgrade must never
// start caching HTML on its own — CLAUDE.md §6). A default flipped here would
// ship to every node that does not set the key.
func TestWebdetectorBridgeConfig_SiteCacheDefaults(t *testing.T) {
	cfg := webdetectorBridgeConfig(map[string]string{}, map[string]string{})
	if !cfg.SiteCache {
		t.Error("SITE_CACHE unset → SiteCache false; want true (kill switch, default on)")
	}
	if cfg.MicroCacheEnforce {
		t.Error("MICRO_CACHE_ENFORCE unset → MicroCacheEnforce true; want false (opt-in, default off)")
	}
	for _, c := range []struct {
		kv          map[string]string
		site, micro bool
	}{
		{map[string]string{"SITE_CACHE": "0"}, false, false},
		{map[string]string{"SITE_CACHE": "0 ; panic button"}, false, false},
		{map[string]string{"MICRO_CACHE_ENFORCE": "1"}, true, true},
		{map[string]string{"MICRO_CACHE_ENFORCE": "1 # after burn-in"}, true, true},
		{map[string]string{"SITE_CACHE": "0", "MICRO_CACHE_ENFORCE": "1"}, false, true},
	} {
		got := webdetectorBridgeConfig(map[string]string{}, c.kv)
		if got.SiteCache != c.site || got.MicroCacheEnforce != c.micro {
			t.Errorf("%v → site_cache=%v micro_cache_enforce=%v, want %v/%v", c.kv, got.SiteCache, got.MicroCacheEnforce, c.site, c.micro)
		}
	}
}

// The reference detectors.conf (what a fresh install ships) states both knobs
// explicitly at their defaults, and the file the daemon renders from it carries
// them to the edge as such.
func TestReferenceDetectorsConf_SiteCacheKnobs(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "detectors.conf")
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Fatalf("ReadSectionsFile(%s): %v", path, err)
	}
	wd, ok := secs.ByName["webdetector"]
	if !ok {
		t.Fatal("[webdetector] section missing from the reference detectors.conf")
	}
	// Written explicitly: an absurd fallback proves the value parsed.
	if !kvBool(wd, "SITE_CACHE", false) {
		t.Error("reference detectors.conf: SITE_CACHE is not written as 1")
	}
	if kvBool(wd, "MICRO_CACHE_ENFORCE", true) {
		t.Error("reference detectors.conf: MICRO_CACHE_ENFORCE is not written as 0")
	}
	cfg := webdetectorBridgeConfig(secs.Global, wd)
	if !cfg.SiteCache || cfg.MicroCacheEnforce {
		t.Fatalf("reference detectors.conf → site_cache=%v micro_cache_enforce=%v, want true/false", cfg.SiteCache, cfg.MicroCacheEnforce)
	}
	out := filepath.Join(t.TempDir(), "cfm_bridge_config.lua")
	if err := sslcollector.WriteWebdetectorBridgeConfig(out, cfg, 0); err != nil {
		t.Fatalf("WriteWebdetectorBridgeConfig: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"site_cache = true,", "micro_cache_enforce = false,"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("rendered cfm_bridge_config.lua lacks %q:\n%s", want, b)
		}
	}
}
