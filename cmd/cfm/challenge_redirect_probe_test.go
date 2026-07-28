package main

import (
	"testing"

	"cfm/internal/firewall/nft"
	"cfm/internal/firewall/nftlib"
)

// The challenge server decides what to log about the DNAT redirect by probing
// the firewall backend through an anonymous interface:
//
//	if q, ok := any(s.fw).(interface{ ChallengeRedirectEnabled() bool }); ok
//
// A probe that fails to match does not error — it falls back to reporting the
// redirect as armed, which is precisely the wrong answer in edge mode and the
// reason that log line was misleading in the first place. Both backends are
// selected at runtime (CFM_FIREWALL_ENGINE), so both must satisfy it, and this
// is the only package that can see both.
//
// Compile-time assertion on purpose: a method renamed on one side should break
// the build, not go quiet.
type challengeRedirectProbe interface{ ChallengeRedirectEnabled() bool }

var (
	_ challengeRedirectProbe = (*nft.Backend)(nil)
	_ challengeRedirectProbe = (*nftlib.Backend)(nil)
)

func TestBothFirewallBackendsAnswerTheChallengeRedirectProbe(t *testing.T) {
	// The assertions above are the test; this keeps `go test` reporting it.
	var b challengeRedirectProbe = nft.New()
	if b == nil {
		t.Fatal("nft backend does not satisfy the probe")
	}
}
