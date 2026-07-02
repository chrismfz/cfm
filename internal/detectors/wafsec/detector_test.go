package wafsec

import (
	"context"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

// drain runs one RunOnce tick and returns the alerts it emitted.
func drain(t *testing.T, d *Detector) []core.Alert {
	t.Helper()
	out := make(chan core.Alert, 256)
	if err := d.RunOnce(context.Background(), out); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	close(out)
	var got []core.Alert
	for a := range out {
		got = append(got, a)
	}
	return got
}

func ev(ip, reason, ruleID string) core.InputEvent {
	return core.InputEvent{
		When: time.Now(), Source: "waf", Reason: reason, Signal: ruleID,
		Scope: "example.gr", SrcIP: ip, Method: "post", Path: "/wp-login.php",
	}
}

func TestBlockTierFamilyFiresOnFirstHit(t *testing.T) {
	d := New(Config{Families: map[string]int{"WAF_SQLI": 1}})
	d.Enqueue(ev("203.0.113.7", "WAF_SQLI:UNION_SELECT", "301"))
	got := drain(t, d)
	if len(got) != 1 {
		t.Fatalf("want 1 alert, got %d", len(got))
	}
	a := got[0]
	if a.Kind != core.AlertKind("WAF/SQLI") {
		t.Errorf("Kind = %q, want WAF/SQLI", a.Kind)
	}
	if a.Key != "203.0.113.7" || a.Extra["ip"] != "203.0.113.7" {
		t.Errorf("IP not carried: key=%q extra.ip=%q", a.Key, a.Extra["ip"])
	}
	if a.Extra["family"] != "WAF_SQLI" || a.Extra["rule_id"] != "301" {
		t.Errorf("attribution wrong: family=%q rule_id=%q", a.Extra["family"], a.Extra["rule_id"])
	}
	if a.Extra["reason"] != "WAF_SQLI:UNION_SELECT" {
		t.Errorf("raw reason lost: %q", a.Extra["reason"])
	}
	if _, ok := a.Extra["enforcement"]; ok {
		t.Errorf("non-dryrun alert must not set enforcement (got %q) — it should block", a.Extra["enforcement"])
	}
}

func TestDisabledFamilyNeverFires(t *testing.T) {
	// BAD_UA absent/0 = edge-only; many hits, zero alerts.
	d := New(Config{Families: map[string]int{"WAF_SQLI": 1, "WAF_BAD_UA": 0}})
	for i := 0; i < 50; i++ {
		d.Enqueue(ev("198.51.100.9", "WAF_BAD_UA:UA_FAKE", "201"))
	}
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("disabled family fired %d alerts", len(got))
	}
}

func TestAccumulateFamilyFiresAtThreshold(t *testing.T) {
	d := New(Config{Families: map[string]int{"WAF_WEBSHELL": 3}})
	ip := "203.0.113.20"
	d.Enqueue(ev(ip, "WAF_WEBSHELL:PROBE", "410"))
	d.Enqueue(ev(ip, "WAF_WEBSHELL:PROBE", "410"))
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("fired before threshold: %d", len(got))
	}
	d.Enqueue(ev(ip, "WAF_WEBSHELL:PROBE", "410"))
	if got := drain(t, d); len(got) != 1 {
		t.Fatalf("want 1 alert at threshold 3, got %d", len(got))
	}
	// Further hits in the same window must not re-emit.
	d.Enqueue(ev(ip, "WAF_WEBSHELL:PROBE", "410"))
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("re-emitted after firing: %d", len(got))
	}
}

func TestPerRuleOverrideWins(t *testing.T) {
	// Family SQLI=1, but rule 301 overridden to 0 → that rule never blocks,
	// while another SQLI rule (309) still does.
	d := New(Config{
		Families:      map[string]int{"WAF_SQLI": 1},
		RuleOverrides: map[string]int{"301": 0},
	})
	d.Enqueue(ev("203.0.113.30", "WAF_SQLI:UNION_SELECT", "301"))
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("RULE_301=0 override should suppress, got %d alerts", len(got))
	}
	d.Enqueue(ev("203.0.113.31", "WAF_SQLI:SLEEP", "309")) // same family, no override
	if got := drain(t, d); len(got) != 1 {
		t.Fatalf("non-overridden SQLI rule should still fire, got %d", len(got))
	}
}

func TestPerRuleOverrideEnablesDisabledFamily(t *testing.T) {
	// Family BAD_UA=0 (off), but a single rule id is opted-in via override.
	d := New(Config{
		Families:      map[string]int{"WAF_BAD_UA": 0},
		RuleOverrides: map[string]int{"201": 1},
	})
	d.Enqueue(ev("203.0.113.40", "WAF_BAD_UA:UA_FAKE", "201"))
	if got := drain(t, d); len(got) != 1 {
		t.Fatalf("per-rule opt-in should fire even with family=0, got %d", len(got))
	}
}

func TestDryRunMarksEnforcement(t *testing.T) {
	d := New(Config{Families: map[string]int{"WAF_RCE": 1}, DryRun: true})
	d.Enqueue(ev("203.0.113.50", "WAF_RCE:CMD", "320"))
	got := drain(t, d)
	if len(got) != 1 || got[0].Extra["enforcement"] != "dryrun" {
		t.Fatalf("dry-run alert must carry enforcement=dryrun, got %+v", got)
	}
}

func TestAllowListSuppresses(t *testing.T) {
	d := New(Config{Families: map[string]int{"WAF_SQLI": 1}, AllowIPs: []string{"203.0.113.7"}, AllowNets: []string{"10.0.0.0/8"}})
	d.Enqueue(ev("203.0.113.7", "WAF_SQLI:x", "301")) // exact allow ip
	d.Enqueue(ev("10.1.2.3", "WAF_SQLI:x", "301"))    // allow net
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("allow-listed IPs fired %d alerts", len(got))
	}
}

func TestFamilyOf(t *testing.T) {
	cases := map[string]string{
		"WAF_SQLI:UNION_SELECT":     "WAF_SQLI",
		"WAF_RCE":                   "WAF_RCE",
		"  WAF_BACKDOOR:B64 ":       "WAF_BACKDOOR",
		"":                          "",
	}
	for in, want := range cases {
		if got := familyOf(in); got != want {
			t.Errorf("familyOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmptyReasonAndIPSkipped(t *testing.T) {
	d := New(Config{Families: map[string]int{"WAF_SQLI": 1}})
	d.Enqueue(ev("", "WAF_SQLI:x", "301"))  // no IP
	d.Enqueue(ev("203.0.113.9", "", "301")) // no reason/family
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("empty ip/reason should be skipped, got %d", len(got))
	}
}
