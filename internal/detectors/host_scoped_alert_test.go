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

// Control case: the same alert WITHOUT the declaration shows the fallback is
// real and that the address it scrapes really is on the shipped ignore list —
// i.e. that ip_scope is load-bearing, not decoration. It does not (and cannot)
// guard the detector's own use of ip_scope; TestAlertDeclaresHostScope in
// package solverfarm does that.
func TestSamplesFallbackStillAppliesWithoutHostScope(t *testing.T) {
	samples := []string{`[challenge] ua="... Chrome/10.0.0.1 Safari/537.36" solves=118 (98%)`}
	a := hostScopedAlert(samples, nil)
	delete(a.Extra, core.ExtraIPScope)

	s := &sectionSink{section: "challenge_solver_farm", ignore: shippedIgnore()}
	got := s.pickIP(a)
	if got == "" {
		t.Fatal("pickIP no longer scans samples for an address — this control test is obsolete, delete it (and reassess whether ip_scope is still needed)")
	}
	if !shippedIgnore().ShouldIgnore(got) {
		t.Fatalf("expected the scraped address %q to be on the shipped ignore list", got)
	}
}

// A whitespace or capitalisation slip must not quietly re-enable the fallback.
func TestHostScopeMatchIsLenientAboutFormatting(t *testing.T) {
	for _, v := range []string{"host", " host", "Host", "HOST "} {
		a := hostScopedAlert([]string{`[challenge] ua="... Chrome/10.0.0.1 ..."`}, map[string]string{core.ExtraIPScope: v})
		s := &sectionSink{section: "challenge_solver_farm", ignore: shippedIgnore()}
		if got := s.pickIP(a); got != "" {
			t.Errorf("ip_scope=%q: pickIP = %q, want \"\"", v, got)
		}
	}
}

// End-to-end through Publish, which is where the property actually lives: with
// no BLOCK policy the sink must notify and hand the alert to the inner sink with
// the vhost intact. Before the fix, pickIP would have scraped 10.0.0.1 out of
// the quoted UA, matched the shipped IGNORE_NETS, and returned at the
// ignored_global_ip branch — no inner Publish, no notification.
func TestHostScopedAlertSurvivesPublish(t *testing.T) {
	inner := &capturingSink{}
	s := &sectionSink{
		section: "challenge_solver_farm",
		pol:     blockPolicy{Mode: "no"},
		inner:   inner,
		ignore:  shippedIgnore(),
	}
	samples := []string{
		"[challenge] host=shop.example.com solves=120 distinct_ips=112 distinct_subnets=73 solves_per_ip=1.07 window=1m0s",
		`[challenge] ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/10.0.0.1 Safari/537.36" solves=118 (98%)`,
	}
	s.Publish(hostScopedAlert(samples, nil))

	if len(inner.got) != 1 {
		t.Fatalf("inner sink received %d alerts, want 1 — the alert was dropped before reaching it", len(inner.got))
	}
	out := inner.got[0]
	if out.Key != "shop.example.com" {
		t.Errorf("Key = %q, want the vhost preserved (decorateIP would have replaced it with the scraped address)", out.Key)
	}
	if got := out.Extra["reason"]; got == "ignored_global_ip" {
		t.Error("alert was routed through the global-ignore drop")
	}
	if _, ok := out.Extra["src_ip"]; ok {
		t.Errorf("src_ip = %q, want it unset for a host-scoped finding", out.Extra["src_ip"])
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

// Detectors that key on an IP are unaffected by the new branch. Note the Extra
// map deliberately carries no "ip": that makes resolution fall PAST the new
// branch to the Key, which is the path this test exists to cover. An alert
// carrying Extra["ip"] would return at step 0 and never reach it.
func TestIPKeyedAlertUnaffected(t *testing.T) {
	a := core.Alert{
		Kind:    core.AlertKind("WAF/SQLI"),
		Key:     "203.0.113.9",
		Samples: []string{`[waf] ua="... Chrome/10.0.0.1 ..." reason=WAF_SQLI`},
		Extra:   map[string]string{"reason": "WAF_SQLI"},
	}
	s := &sectionSink{section: "waf_security", ignore: shippedIgnore()}
	if got := s.pickIP(a); got != "203.0.113.9" {
		t.Fatalf("pickIP = %q, want the Key address 203.0.113.9", got)
	}
}

// A nil Extra map must not panic and must still resolve from the Key.
func TestNilExtraResolvesFromKey(t *testing.T) {
	a := core.Alert{Kind: core.AlertKind("WAF/SQLI"), Key: "203.0.113.9"}
	s := &sectionSink{section: "waf_security", ignore: shippedIgnore()}
	if got := s.pickIP(a); got != "203.0.113.9" {
		t.Fatalf("pickIP = %q, want 203.0.113.9", got)
	}
}
