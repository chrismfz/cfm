package detectors

import (
	"strings"
	"testing"

	"cfm/internal/webdetector"
)

// TestWAFSecurityFamilyCoverage asserts the waf_security detector maps EVERY
// WAF reason-family from the code registry — so adding a new WAF family can
// never leave it silently unconfigurable — and that the ON-by-default set is
// exactly the families that have an edge-`block` rule (the only ones that can
// autoblock in Phase 1), plus WAF_BACKDOOR armed for a future promotion, minus
// WAF_TRAVERSAL, whose block rule (101) landed 2026-09-05 and is held through
// its burn-in (see waf_security_register.go).
func TestWAFSecurityFamilyCoverage(t *testing.T) {
	fams := webdetector.WAFReasonFamilies()
	if len(fams) < 20 {
		t.Fatalf("registry returned only %d families — WAFReasonFamilies broken?", len(fams))
	}

	// Every registry family must be covered by the threshold map.
	cov := wafSecurityFamilies(KV{})
	for _, f := range fams {
		if _, ok := cov[f]; !ok {
			t.Errorf("family %s from the registry is not covered by wafSecurityFamilies", f)
		}
	}

	// Every family with an edge-block rule must default ON; a family without one
	// (except the armed WAF_BACKDOOR) must default 0. WAF_WEBSHELL is armed by
	// default as of 2026-07-18 (edge-block rule 413) — it follows the normal rule
	// like WAF_CVE — after the operator confirmed it runs cleanly fleet-wide.
	for _, f := range fams {
		def := cov[f]
		block := webdetector.WAFFamilyHasBlockRule(f)
		_, held := heldAutoblockFamilies[f]
		switch {
		case held:
			// A held family has an edge-block rule (otherwise the hold is
			// meaningless) but is deliberately kept at 0 through its burn-in.
			if !block {
				t.Errorf("%s is in heldAutoblockFamilies but has no edge-block rule — drop the hold", f)
			}
			if def != 0 {
				t.Errorf("%s is held through burn-in but defaults to %d, want 0", f, def)
			}
		case block && def != 1:
			t.Errorf("%s has an edge-block rule but defaults to %d, want 1", f, def)
		case !block && f != "WAF_BACKDOOR" && def != 0:
			t.Errorf("%s has no edge-block rule but defaults to %d, want 0", f, def)
		}
	}
	if cov["WAF_BACKDOOR"] != 1 {
		t.Errorf("WAF_BACKDOOR should be armed to 1, got %d", cov["WAF_BACKDOOR"])
	}
	// The rendered detectors.conf template is derived from the same defaults:
	// every armed family appears as "1", every held one as "0", and a family
	// that is 0 only because it has no block rule is not listed at all.
	tmpl := wafSecurityDefaultsTemplate()
	for _, f := range fams {
		key := strings.TrimPrefix(f, "WAF_")
		_, held := heldAutoblockFamilies[f]
		got, listed := tmpl[key]
		switch {
		case cov[f] == 1 && got != "1":
			t.Errorf("template: armed family %s should render as 1, got %q (listed=%v)", f, got, listed)
		case held && got != "0":
			t.Errorf("template: held family %s should render as 0, got %q", f, got)
		case cov[f] == 0 && !held && listed:
			t.Errorf("template: inert family %s should not be listed, got %q", f, got)
		}
	}
	for _, scalar := range []string{"ENABLED", "EVERY", "WINDOW", "DRY_RUN", "BLOCK"} {
		if _, ok := tmpl[scalar]; !ok {
			t.Errorf("template: scalar %s missing", scalar)
		}
	}

	// The hold is a conscious, dated decision: WAF_TRAVERSAL (rule 101, block
	// since 2026-09-05) is the one family held today. Arming it is a deletion
	// from heldAutoblockFamilies — and this assertion.
	if _, held := heldAutoblockFamilies["WAF_TRAVERSAL"]; !held {
		t.Errorf("WAF_TRAVERSAL is no longer held — if that is deliberate, update the reference detectors.conf, CLAUDE.md §6 and this test")
	}
	// WAF_WEBSHELL and WAF_CVE both have edge-block rules (413 / 10001) — assert it,
	// so if someone later removes them this test's premise is rechecked.
	if !webdetector.WAFFamilyHasBlockRule("WAF_WEBSHELL") {
		t.Errorf("expected WAF_WEBSHELL to have an edge-block rule (413)")
	}
	if !webdetector.WAFFamilyHasBlockRule("WAF_CVE") {
		t.Errorf("expected WAF_CVE to have an edge-block rule (10001)")
	}
	// WAF_CVE is armed by default (operator wants CVE hits to ban + notify); a
	// low-confidence CVE rule is held per-rule with RULE_<id>=0, not by un-arming
	// the family.
	if cov["WAF_CVE"] != 1 {
		t.Errorf("WAF_CVE has an edge-block rule (10001) but defaults to %d, want 1", cov["WAF_CVE"])
	}
	// WAF_WEBSHELL is armed by default as of 2026-07-18 (edge-block rule 413).
	if cov["WAF_WEBSHELL"] != 1 {
		t.Errorf("WAF_WEBSHELL has an edge-block rule (413) but defaults to %d, want 1", cov["WAF_WEBSHELL"])
	}

	// Sanity: the armed block-tier families are exactly what we expect today.
	for _, f := range []string{"WAF_SQLI", "WAF_RCE", "WAF_UPLOAD_FNAME", "WAF_UPLOAD_CONTENT", "WAF_WEBSHELL", "WAF_CVE"} {
		if !webdetector.WAFFamilyHasBlockRule(f) {
			t.Errorf("expected %s to have an edge-block rule", f)
		}
	}

	// Config overrides are honored, and the key is the family name minus WAF_.
	over := wafSecurityFamilies(KV{"SQLI": "0", "WEBSHELL": "3", "TRAVERSAL": "1"})
	if over["WAF_SQLI"] != 0 {
		t.Errorf("SQLI=0 override not applied: got %d", over["WAF_SQLI"])
	}
	if over["WAF_TRAVERSAL"] != 1 {
		t.Errorf("TRAVERSAL=1 must arm the held family: got %d", over["WAF_TRAVERSAL"])
	}
	if over["WAF_WEBSHELL"] != 3 {
		t.Errorf("WEBSHELL=3 override not applied: got %d", over["WAF_WEBSHELL"])
	}
}
