package detectors

import (
	"testing"

	"cfm/internal/webdetector"
)

// TestWAFSecurityFamilyCoverage asserts the waf_security detector maps EVERY
// WAF reason-family from the code registry — so adding a new WAF family can
// never leave it silently unconfigurable — and that the ON-by-default set is
// exactly the families that have an edge-`block` rule (the only ones that can
// autoblock in Phase 1), plus WAF_BACKDOOR armed for a future promotion.
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
		switch {
		case block && def != 1:
			t.Errorf("%s has an edge-block rule but defaults to %d, want 1", f, def)
		case !block && f != "WAF_BACKDOOR" && def != 0:
			t.Errorf("%s has no edge-block rule but defaults to %d, want 0", f, def)
		}
	}
	if cov["WAF_BACKDOOR"] != 1 {
		t.Errorf("WAF_BACKDOOR should be armed to 1, got %d", cov["WAF_BACKDOOR"])
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
	over := wafSecurityFamilies(KV{"SQLI": "0", "WEBSHELL": "3"})
	if over["WAF_SQLI"] != 0 {
		t.Errorf("SQLI=0 override not applied: got %d", over["WAF_SQLI"])
	}
	if over["WAF_WEBSHELL"] != 3 {
		t.Errorf("WEBSHELL=3 override not applied: got %d", over["WAF_WEBSHELL"])
	}
}
