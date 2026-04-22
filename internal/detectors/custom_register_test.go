package detectors

import (
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

func TestParseCustomRulesRequiresNamedCapturesForTarget(t *testing.T) {
	kv := KV{
		"FAIL_REGEX": "(?P<ip>\\S+)\n(?P<user>\\S+)\n(?P<ip>\\S+) user=(?P<user>\\S+)",
	}

	rules := parseCustomRules(kv, customTargetBoth)
	if len(rules) != 1 {
		t.Fatalf("expected 1 valid rule, got %d", len(rules))
	}
	if !rules[0].hasIP || !rules[0].hasUser {
		t.Fatalf("expected rule to include both named captures")
	}
}

func TestCustomDetectorConsumeIgnoreAndNormalizeMappedIPv4(t *testing.T) {
	re := parseCustomRules(KV{
		"FAIL_REGEX": `src=(?P<ip>\S+) user=(?P<user>\S+) reason=fail`,
	}, customTargetBoth)
	ignores := parseCustomIgnoreRules(KV{
		"IGNORE_REGEX": `reason=healthcheck`,
	})
	if len(re) != 1 {
		t.Fatalf("expected one fail regex")
	}
	if len(ignores) != 1 {
		t.Fatalf("expected one ignore regex")
	}

	d := &customDetector{
		cfg: customConfig{
			MatchTarget:     customTargetBoth,
			AuthFailPerIP:   1,
			AuthFailPerUser: 1,
			Cooldown:        0,
		},
		rules:   re,
		ignores: ignores,
		samples: core.NewSampleRing(5),
		counts:  core.NewSlidingCounter(5*time.Minute, 0),
		gate:    core.NewAlertGate(0),
	}

	out := make(chan core.Alert, 4)
	now := time.Now()
	d.consume(now, "src=::ffff:203.0.113.4 user=alice reason=healthcheck", out)
	if len(out) != 0 {
		t.Fatalf("expected ignored line to produce no alerts")
	}

	d.consume(now, "src=::ffff:203.0.113.4 user=alice reason=fail", out)
	if len(out) != 2 {
		t.Fatalf("expected 2 alerts (ip+user), got %d", len(out))
	}

	var sawIP, sawUser bool
	for i := 0; i < 2; i++ {
		a := <-out
		switch a.Extra["reason"] {
		case "AUTHFAIL|ip":
			sawIP = a.Key == "203.0.113.4"
		case "AUTHFAIL|user":
			sawUser = a.Key == "alice"
		}
	}
	if !sawIP {
		t.Fatalf("expected normalized IPv4 key in alert")
	}
	if !sawUser {
		t.Fatalf("expected user key in alert")
	}
}
