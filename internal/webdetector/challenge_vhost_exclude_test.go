package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

// The dynamic Challenge-excludes must be honoured by the vhost-wide challenge
// decision (auto-suspicious + the CHALLENGE_VHOST list), not just per-IP. Before
// this, a host an operator explicitly excluded still got vhost-challenged when
// its suspicious score tripped (operator report: www.gokids.gr was excluded but
// still auto_on reason=uniqip_on). These cover the decision helpers the vhost
// gate uses.

func TestHostChallengeExcluded(t *testing.T) {
	e := &Engine{}
	// nil store must never match (and must not panic).
	if e.hostChallengeExcluded("gokids.gr") {
		t.Fatalf("nil challengeExcludes must not match")
	}
	e.challengeExcludes = newExcludeStore(filepath.Join(t.TempDir(), "ch.json"))
	scope := map[string]struct{}{"gokids.gr": {}}
	if !e.challengeExcludes.Add("host", "gokids.gr", scope) {
		t.Fatalf("add exclude failed")
	}
	if !e.hostChallengeExcluded("gokids.gr") {
		t.Fatalf("expected gokids.gr to be excluded")
	}
	if e.hostChallengeExcluded("other.gr") {
		t.Fatalf("did not expect other.gr to be excluded")
	}
	if e.hostChallengeExcluded("") {
		t.Fatalf("empty host must not match")
	}
}

// tripReason names the trigger for the suppressed_by_exclude audit
// line — it must mirror the auto-suspicious scorer's trip conditions.
func TestTripReason(t *testing.T) {
	e := &Engine{}
	e.cfg.ChallengeSuspiciousUniqIP = true
	e.cfg.ChallengeSuspiciousUniqIPOn = 150
	e.cfg.ChallengeSuspiciousUniqIPMax = 260
	e.cfg.ChallengeSuspiciousScoreOn = 0.72
	e.cfg.ChallengeSuspiciousMinUniqIP = 20

	// Below every threshold → no would-challenge.
	if why := e.tripReason(SuspiciousRow{UniqueIPs: 10, Score: 0.3}); why != "" {
		t.Fatalf("expected no reason, got %q", why)
	}
	// The operator's real case: 160 unique IPs over the ON threshold.
	if why := e.tripReason(SuspiciousRow{UniqueIPs: 160, Score: 0.58}); why != "uniqip_on" {
		t.Fatalf("expected uniqip_on, got %q", why)
	}
	// Over the hard cap → uniqip_max (checked before uniqip_on).
	if why := e.tripReason(SuspiciousRow{UniqueIPs: 300}); why != "uniqip_max" {
		t.Fatalf("expected uniqip_max, got %q", why)
	}
	// Score path (uniqIP mode off).
	e.cfg.ChallengeSuspiciousUniqIP = false
	if why := e.tripReason(SuspiciousRow{UniqueIPs: 25, Score: 0.80}); why != "score_on" {
		t.Fatalf("expected score_on, got %q", why)
	}
	// High score but too few unique IPs → no (min-uniq gate).
	if why := e.tripReason(SuspiciousRow{UniqueIPs: 5, Score: 0.90}); why != "" {
		t.Fatalf("expected no reason under min-uniq, got %q", why)
	}
}

// The audit line is throttled to once per holddown window per host so a
// sustained excluded-under-attack vhost doesn't spam the challenge log.
func TestShouldLogVhostSuppress_Throttle(t *testing.T) {
	e := &Engine{}
	e.cfg.ChallengeSuspiciousHolddown = 25 * time.Minute
	e.vhostSuppressLoggedAt = make(map[string]time.Time)
	base := time.Unix(1783335982, 0)

	if !e.shouldLogVhostSuppress("gokids.gr", base) {
		t.Fatalf("first call must log")
	}
	if e.shouldLogVhostSuppress("gokids.gr", base.Add(5*time.Minute)) {
		t.Fatalf("within holddown must NOT log again")
	}
	if !e.shouldLogVhostSuppress("gokids.gr", base.Add(26*time.Minute)) {
		t.Fatalf("after holddown must log again")
	}
	// A different host throttles independently.
	if !e.shouldLogVhostSuppress("other.gr", base.Add(1*time.Minute)) {
		t.Fatalf("distinct host must log")
	}
}
