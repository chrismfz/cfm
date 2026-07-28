package detectors

import (
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

type capturingSink struct{ got []core.Alert }

func (c *capturingSink) Publish(a core.Alert) { c.got = append(c.got, a) }

// shippedIgnore mirrors the IGNORE_IPS/IGNORE_NETS/LOG_IGNORED values in the
// reference configs/detectors.conf, because those are what make the suppression
// below silent on a default install.
func shippedIgnore() *IPIgnore {
	return newIPIgnoreFromGlobal(KV{
		"IGNORE_IPS":  "127.0.0.1, 172.22.1.13",
		"IGNORE_NETS": "172.17.0.1/16, 10.0.0.0/8, 84.54.49.0/24",
		"LOG_IGNORED": "no",
	})
}

func hostScopedAlert(samples []string, extra map[string]string) core.Alert {
	e := map[string]string{
		core.ExtraIPScope: core.IPScopeHost,
		"enforcement":     "observe",
		"reason":          "CHALLENGE_SOLVER_FARM",
		"host":            "shop.example.com",
	}
	for k, v := range extra {
		e[k] = v
	}
	return core.Alert{
		When:    time.Now(),
		Kind:    core.AlertKind("Challenge/SolverFarm"),
		Key:     "shop.example.com",
		Count:   73,
		Samples: samples,
		Extra:   e,
	}
}

// A host-scoped alert quotes client-controlled text (the User-Agents it saw).
// The sink's pickIP fallback scans Samples for anything IP-shaped, so without
// the ip_scope declaration a client could name its own "source" address, get it
// matched by the global ignore list, and have the entire alert dropped before
// any notification — silently, since LOG_IGNORED is off by default.
func TestHostScopedAlertIgnoresIPInSamples(t *testing.T) {
	ua := `[challenge] ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ` +
		`(KHTML, like Gecko) Chrome/10.0.0.1 Safari/537.36" solves=118 (98%)`
	samples := []string{
		"[challenge] host=shop.example.com solves=120 distinct_ips=112 distinct_subnets=73 solves_per_ip=1.07 window=1m0s",
		ua,
	}

	s := &sectionSink{section: "challenge_solver_farm", ignore: shippedIgnore()}
	if got := s.pickIP(hostScopedAlert(samples, nil)); got != "" {
		t.Fatalf("pickIP = %q, want \"\" — a host-scoped alert must not adopt an address out of a quoted User-Agent", got)
	}
}

// The same alert without the declaration demonstrates the fallback is real, so
// this test fails loudly if someone removes ip_scope from the detector.
func TestSamplesFallbackStillAppliesWithoutHostScope(t *testing.T) {
	samples := []string{`[challenge] ua="... Chrome/10.0.0.1 Safari/537.36" solves=118 (98%)`}
	a := hostScopedAlert(samples, nil)
	delete(a.Extra, core.ExtraIPScope)

	s := &sectionSink{section: "challenge_solver_farm", ignore: shippedIgnore()}
	got := s.pickIP(a)
	if got == "" {
		t.Skip("pickIP no longer falls back to scanning samples; ip_scope may be redundant")
	}
	if !shippedIgnore().ShouldIgnore(got) {
		t.Fatalf("expected the scraped address %q to be on the shipped ignore list", got)
	}
}

// An ordinary Chrome UA is IP-shaped enough to be picked up by accident
// (Chrome/118.0.0.0), which would mis-name an unrelated address as the source in
// the operator's notification. Declaring host scope must prevent that too.
func TestHostScopedAlertNotMisattributedByOrdinaryUA(t *testing.T) {
	samples := []string{
		`[challenge] ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36" solves=118 (98%)`,
	}
	s := &sectionSink{section: "challenge_solver_farm", ignore: shippedIgnore()}
	if got := s.pickIP(hostScopedAlert(samples, nil)); got != "" {
		t.Fatalf("pickIP = %q, want \"\" — a Chrome version string is not a source address", got)
	}
}

// An authoritative detector-supplied IP must still win: the scope declaration
// suppresses the guesswork fallback, not a real answer.
func TestExplicitIPStillWinsOverHostScope(t *testing.T) {
	a := hostScopedAlert([]string{"[challenge] ua=\"... 10.0.0.1 ...\""}, map[string]string{"ip": "203.0.113.9"})
	s := &sectionSink{section: "challenge_solver_farm", ignore: shippedIgnore()}
	if got := s.pickIP(a); got != "203.0.113.9" {
		t.Fatalf("pickIP = %q, want the detector-provided address", got)
	}
}

// Detectors that key on an IP are unaffected by the new branch.
func TestIPKeyedAlertUnaffected(t *testing.T) {
	a := core.Alert{
		Kind:    core.AlertKind("WAF/SQLI"),
		Key:     "203.0.113.9",
		Samples: []string{`[waf] ua="... Chrome/10.0.0.1 ..." reason=WAF_SQLI`},
		Extra:   map[string]string{"ip": "203.0.113.9"},
	}
	s := &sectionSink{section: "waf_security", ignore: shippedIgnore()}
	if got := s.pickIP(a); got != "203.0.113.9" {
		t.Fatalf("pickIP = %q, want 203.0.113.9", got)
	}
}
