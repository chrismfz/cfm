package webdetector

import (
	"testing"
	"time"
)

// A host matched by a WILDCARD CHALLENGE_VHOST entry (the default list:
// webmail.*, whm.*, cpanel.*) is at v2 from its first solve, noted by the tick
// or not. The tick notes such a host only while it is a candidate, so a quiet
// panel subdomain's first visitors solved at v1 (orion/titan, 2026-11-18).
func TestAutoV2Trigger_VhostConfigListWithoutNote(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2VhostConfig)
	e.cfg.ChallengeVHost = []string{"webmail.*", "cpanel.*"}
	e.nginxBridge.mu.Lock()
	e.nginxBridge.vhState["webmail.*"] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Hour), Reason: "vhost_config"}
	e.nginxBridge.mu.Unlock()

	if got := e.autoV2Trigger("webmail.quiet.example"); got != autoV2VhostConfig {
		t.Fatalf("unnoted listed host: trigger %q, want %q", got, autoV2VhostConfig)
	}
	if tr := e.challengeV2VhostTier("webmail.quiet.example"); tr.Rung != "v2" {
		t.Fatalf("unnoted listed host: rung %q, want v2", tr.Rung)
	}

	// A suppressed host (CHALLENGE_VHOST_IGNORE, like an exclude) stays
	// unarmed through the list read too.
	e.cfg.ChallengeVHostIgnore = []string{"webmail.quiet.example"}
	if got := e.autoV2Trigger("webmail.quiet.example"); got != "" {
		t.Fatalf("ignored listed host: trigger %q, want none", got)
	}
	e.cfg.ChallengeVHostIgnore = nil

	// No live entry covers the host: the list alone arms nothing (cpanel.* is
	// listed but not pushed, e.g. an excluded or not-yet-reconciled pattern).
	if got := e.autoV2Trigger("cpanel.quiet.example"); got != "" {
		t.Fatalf("listed host with no live challenge: trigger %q, want none", got)
	}

	// Covered by the entry but off the list (a list edit removed it): the
	// pattern entry's sticky Reason alone never arms.
	e.cfg.ChallengeVHost = []string{"cpanel.*"}
	if got := e.autoV2Trigger("webmail.quiet.example"); got != "" {
		t.Fatalf("host off the list: trigger %q, want none", got)
	}

	// Listed, but the knob leaves vhost_config at v1: reported, not armed.
	e.cfg.ChallengeVHost = []string{"webmail.*"}
	delete(e.autoV2Armed, autoV2VhostConfig)
	if tr := e.challengeV2VhostTier("webmail.quiet.example"); tr.Rung == "v2" || tr.Trigger != autoV2VhostConfig {
		t.Fatalf("unarmed source: rung %q trigger %q, want not v2 with trigger %q", tr.Rung, tr.Trigger, autoV2VhostConfig)
	}
	e.autoV2Armed[autoV2VhostConfig] = true

	// A v1 pin still decides.
	if _, _, changed := e.SetChallengeTierPinAs("webmail.quiet.example", "v1", 0, ""); !changed {
		t.Fatal("pin not set")
	}
	if tr := e.challengeV2VhostTier("webmail.quiet.example"); tr.Rung == "v2" {
		t.Fatal("v1 pin overridden by the list read")
	}
}
