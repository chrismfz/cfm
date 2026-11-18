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

// TestCVEFromReason covers the WAF_CVE reason -> display-CVE mapping used to
// label the autoblock notification (WAF/CVE-2025-34085) and the cve Extra field.
func TestCVEFromReason(t *testing.T) {
	cases := []struct{ reason, want string }{
		{"WAF_CVE:CVE_2025_34085:SIMPLE_FILE_LIST:RENAME_TO_PHP", "CVE-2025-34085"},
		{"WAF_CVE:CVE_2020_36847:SIMPLE_FILE_LIST:UPLOAD_PHP", "CVE-2020-36847"},
		{"WAF_CVE:LOG4SHELL:NESTED", ""}, // no CVE_* token -> fall back to plain family
		{"WAF_SQLI:UNION_SELECT", ""},    // non-CVE family
		{"WAF_CVE", ""},                  // family only, no segments
	}
	for _, c := range cases {
		if got := cveFromReason(c.reason); got != c.want {
			t.Errorf("cveFromReason(%q) = %q, want %q", c.reason, got, c.want)
		}
	}
}

// A RULE_<id> override above 1 counts that rule's own hits: the family's
// other rules must not fill it.
func TestRuleOverrideAboveOneCountsOnlyItsRule(t *testing.T) {
	d := New(Config{
		Families:      map[string]int{"WAF_RCE": 5},
		RuleOverrides: map[string]int{"329": 2},
	})
	ip := "203.0.113.20"
	for i := 0; i < 3; i++ {
		d.Enqueue(ev(ip, "WAF_RCE:CMD", "320")) // family-threshold hits (3 < 5)
	}
	d.Enqueue(ev(ip, "WAF_RCE:SHELL", "329")) // first 329 hit: 1 < 2
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("one 329 hit plus other family hits fired %d alerts; want 0", len(got))
	}
	d.Enqueue(ev(ip, "WAF_RCE:SHELL", "329"))
	got := drain(t, d)
	if len(got) != 1 || got[0].Extra["rule_id"] != "329" || got[0].Count != 2 {
		t.Fatalf("second 329 hit: got %+v, want one alert for rule 329 with count 2", got)
	}
	// The family's own count is untouched by 329's hits: 3 so far, fires at 5.
	d.Enqueue(ev(ip, "WAF_RCE:CMD", "320"))
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("family fired at 4 hits: %d alerts", len(got))
	}
}

// Once the family has banned an IP this window, a per-rule counter tripping
// for the same IP does not alert again.
func TestRuleScopedTripAfterFamilyBanIsQuiet(t *testing.T) {
	d := New(Config{
		Families:      map[string]int{"WAF_RCE": 1},
		RuleOverrides: map[string]int{"329": 2},
	})
	ip := "203.0.113.21"
	d.Enqueue(ev(ip, "WAF_RCE:CMD", "320"))
	if got := drain(t, d); len(got) != 1 {
		t.Fatalf("family hit: %d alerts, want 1", len(got))
	}
	d.Enqueue(ev(ip, "WAF_RCE:SHELL", "329"))
	d.Enqueue(ev(ip, "WAF_RCE:SHELL", "329"))
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("rule trip after the family ban alerted %d times, want 0", len(got))
	}
}

// Thresholds 0 and 1 (every shipped config) keep the (ip, family) key: an
// explicit RULE_<id> = 1 hit after the family fired stays one alert.
func TestRuleOverrideOfOneSharesTheFamilyKey(t *testing.T) {
	d := New(Config{
		Families:      map[string]int{"WAF_BACKDOOR": 1},
		RuleOverrides: map[string]int{"440": 1, "438": 0},
	})
	ip := "203.0.113.22"
	d.Enqueue(ev(ip, "WAF_BACKDOOR:B64", "439"))
	d.Enqueue(ev(ip, "WAF_BACKDOOR:PLUGIN", "440"))
	d.Enqueue(ev(ip, "WAF_BACKDOOR:B64PHP", "438"))
	got := drain(t, d)
	if len(got) != 1 || got[0].Extra["rule_id"] != "439" {
		t.Fatalf("got %d alerts (%+v), want exactly the first hit's", len(got), got)
	}
	if k := counterKey(ip, "WAF_BACKDOOR", "440", 1, true); k != ip+"|WAF_BACKDOOR" {
		t.Fatalf("threshold-1 override key = %q, want the family key", k)
	}
}

// A rule-scoped trip suppresses a later family trip for the same IP in the
// window: one alert per IP and family, as with the shared key.
func TestFamilyTripAfterRuleScopedBanIsQuiet(t *testing.T) {
	d := New(Config{
		Families:      map[string]int{"WAF_RCE": 5},
		RuleOverrides: map[string]int{"329": 2},
	})
	ip := "203.0.113.23"
	d.Enqueue(ev(ip, "WAF_RCE:SHELL", "329"))
	d.Enqueue(ev(ip, "WAF_RCE:SHELL", "329"))
	if got := drain(t, d); len(got) != 1 {
		t.Fatalf("rule trip: %d alerts, want 1", len(got))
	}
	for i := 0; i < 5; i++ {
		d.Enqueue(ev(ip, "WAF_RCE:CMD", "320"))
	}
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("family trip after the rule ban alerted %d times, want 0", len(got))
	}
}

// A campaign that keeps hitting a rule-scoped rule after the family ban stays
// one alert while it continues (its hits keep the family alive even after the
// family's own counter drained), and the state is released once the family
// has been quiet for a full Window.
func TestRuleScopedHitsKeepFamilyBanAlive(t *testing.T) {
	d := New(Config{
		Window:        30 * time.Second,
		Families:      map[string]int{"WAF_RCE": 1},
		RuleOverrides: map[string]int{"329": 3},
	})
	ip := "203.0.113.24"
	ago := func(dur time.Duration, reason, rule string) core.InputEvent {
		e := ev(ip, reason, rule)
		e.When = time.Now().Add(-dur)
		return e
	}
	// The family hit is already past the 30 s window when pruning runs; the
	// 329 hit is not.
	d.Enqueue(ago(40*time.Second, "WAF_RCE:CMD", "320"))
	d.Enqueue(ago(20*time.Second, "WAF_RCE:SHELL", "329"))
	if got := drain(t, d); len(got) != 1 {
		t.Fatalf("family hit: %d alerts, want 1", len(got))
	}
	d.Enqueue(ago(10*time.Second, "WAF_RCE:SHELL", "329"))
	d.Enqueue(ago(5*time.Second, "WAF_RCE:SHELL", "329"))
	if got := drain(t, d); len(got) != 0 {
		t.Fatalf("continuing campaign alerted again: %d", len(got))
	}
	// Long quiet: everything is released.
	d.famSeen[ip+"|WAF_RCE"] = time.Now().Add(-time.Minute)
	drain(t, d)
	if len(d.fired) != 0 || len(d.famSeen) != 0 {
		t.Fatalf("state not pruned after a quiet Window: fired=%v famSeen=%v", d.fired, d.famSeen)
	}
}
