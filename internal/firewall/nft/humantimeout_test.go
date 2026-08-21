//go:build linux

package nft

import (
	"testing"
	"time"
)

// humanTimeout's output is written directly into nftables rule syntax (the
// `timeout <v>` element of set/rule commands), NOT displayed to a human — so it
// must stay a single, nft-parseable unit (Ns/Nm/Nh/Nd). This test pins that
// contract so a well-meaning "unify the duration formatters" refactor can't
// quietly swap in a multi-unit display string (e.g. "1h30m", "1d0h0m0s") that
// nft would reject at rule-load time. It is deliberately NOT the same formatter
// as healthcli.formatShortDuration (uptime display) or webdetector.shortDur
// (TTL-remaining display); those three have different jobs.
func TestHumanTimeout_EmitsSingleUnitNftSyntax(t *testing.T) {
	cases := map[time.Duration]string{
		0:                          "0s",
		-5 * time.Second:           "0s",
		45 * time.Second:           "45s",
		90 * time.Second:           "90s", // NOT "1m30s" — nft element, kept whole-seconds
		5 * time.Minute:            "5m",
		time.Hour:                  "1h",
		24 * time.Hour:             "1d",
		48 * time.Hour:             "2d",
		time.Hour + 30*time.Minute: "90m", // non-round hour → minutes, still one unit
	}
	for in, want := range cases {
		if got := humanTimeout(in); got != want {
			t.Errorf("humanTimeout(%s) = %q, want %q", in, got, want)
		}
	}
}
