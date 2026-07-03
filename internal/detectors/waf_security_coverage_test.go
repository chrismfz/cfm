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
	// (except the armed WAF_BACKDOOR) must default 0. WAF_WEBSHELL is the one
	// deliberate exception: it has an edge-block rule (413) but is intentionally
	// left un-armed (default 0) pending a burn-in — see wafSecurityFamilies.
	for _, f := range fams {
		def := cov[f]
		block := webdetector.WAFFamilyHasBlockRule(f)
		switch {
		case f == "WAF_WEBSHELL":
			if def != 0 {
				t.Errorf("WAF_WEBSHELL is intentionally un-armed but defaults to %d, want 0", def)
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
	// WAF_WEBSHELL now has an edge-block rule (413) — assert it, so if someone
	// later removes 413 this test's premise is rechecked.
	if !webdetector.WAFFamilyHasBlockRule("WAF_WEBSHELL") {
		t.Errorf("expected WAF_WEBSHELL to have an edge-block rule (413)")
	}

	// Sanity: the four block-tier families are exactly what we expect today.
	for _, f := range []string{"WAF_SQLI", "WAF_RCE", "WAF_UPLOAD_FNAME", "WAF_UPLOAD_CONTENT"} {
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
