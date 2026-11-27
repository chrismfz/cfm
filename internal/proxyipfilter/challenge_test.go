package proxyipfilter

import (
	"fmt"
	"strings"
	"testing"
)

func TestChallengeFeed(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	var lines []string
	orig := logf
	logf = func(f string, a ...interface{}) { lines = append(lines, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() { logf = orig })

	PrepareChallengeFeed("TOR", []string{"185.220.101.1", "192.0.2.0/24"}, []string{"2001:db8::/32"}).Publish()
	SetFeed("MYALLOW", true, []string{"192.0.2.7"}, nil)

	// Never a block source.
	if v := Check("185.220.101.1"); v.Listed() {
		t.Fatalf("a challenge list blocks: %+v", v)
	}

	// Enforce is the default; log mode: listed, not enforced.
	if ChallengeMode() != ModeEnforce || DefaultModeChallenge != ModeEnforce {
		t.Fatalf("default mode %q", ChallengeMode())
	}
	SetChallengeMode("log")
	if enforce, listed := DecideChallenge("185.220.101.1", "example.gr"); enforce || !listed {
		t.Fatalf("log mode: enforce=%v listed=%v", enforce, listed)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "[list_challenge] would_challenge ip=185.220.101.1 host=example.gr list=feed:TOR allow=- mode=log n=1") {
		t.Fatalf("log line: %q", lines)
	}

	SetChallengeMode("enforce")
	for _, ip := range []string{"185.220.101.1", "192.0.2.9", "2001:db8::1", "::ffff:185.220.101.1"} {
		if enforce, listed := DecideChallenge(ip, "example.gr"); !enforce || !listed {
			t.Errorf("%s enforce: enforce=%v listed=%v", ip, enforce, listed)
		}
	}
	// An allow cancels: neither enforced nor listed (its allow stays cacheable).
	if enforce, listed := DecideChallenge("192.0.2.7", "example.gr"); enforce || listed {
		t.Errorf("allowed: enforce=%v listed=%v", enforce, listed)
	}
	if v := CheckChallenge("192.0.2.7"); len(v.Allows) != 1 || v.Enforce {
		t.Errorf("allowed verdict %+v", v)
	}
	// Not listed.
	if enforce, listed := DecideChallenge("198.51.100.1", "example.gr"); enforce || listed {
		t.Errorf("unlisted: enforce=%v listed=%v", enforce, listed)
	}
	// off: nothing, not even the log.
	SetChallengeMode("off")
	n := len(lines)
	if enforce, listed := DecideChallenge("185.220.101.1", "x.gr"); enforce || listed || len(lines) != n {
		t.Errorf("off: enforce=%v listed=%v lines=%d", enforce, listed, len(lines)-n)
	}
	// An unknown value is log, the safe side.
	SetChallengeMode("bogus")
	if ChallengeMode() != ModeLog {
		t.Errorf("unknown mode = %q", ChallengeMode())
	}
	SetChallengeMode("")
	if ChallengeMode() != DefaultModeChallenge {
		t.Errorf("empty mode = %q", ChallengeMode())
	}

	st := Stats()
	if st["mode_challenge"] != DefaultModeChallenge || st["challenged"].(int64) != 4 || st["challenge_allow"].(int64) != 1 || st["would_challenge"].(int64) != 1 {
		t.Errorf("stats %v", st)
	}
	if _, ok := st["sources"].(map[string]any)["feed:TOR"]; !ok {
		t.Errorf("stats sources miss the challenge feed: %v", st["sources"])
	}

	DropFeed("TOR")
	SetChallengeMode("enforce")
	if v := CheckChallenge("185.220.101.1"); len(v.Lists) != 0 {
		t.Errorf("dropped feed still listed: %+v", v)
	}
}
