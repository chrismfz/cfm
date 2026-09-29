package detectors

import (
	"strings"
	"testing"

	webdet "cfm/internal/webdetector"
)

// CHALLENGE_V2_AUTO_VHOST: only an explicit `off` disarms the node. A blank,
// comment-only or typo'd value keeps the shipped default — silently
// disarming every automatic challenge is the dangerous direction.
func TestChallengeV2AutoVhostKnob(t *testing.T) {
	def := webdet.DefaultChallengeV2AutoVhost
	cases := []struct {
		raw  *string
		want string
	}{
		{nil, def},
		{strp(""), def},
		{strp(`""`), def},
		{strp("; note"), def},
		{strp("bogus"), def},
		{strp("1"), def},
		{strp("off"), ""},
		{strp("off ; keep v1 everywhere"), ""},
		{strp("off,under_attack"), ""},
		{strp("under_attack"), "under_attack"},
		{strp("suspicious_vhost, vhost_config"), "suspicious_vhost,vhost_config"},
	}
	for _, c := range cases {
		kv := KV{}
		if c.raw != nil {
			kv["CHALLENGE_V2_AUTO_VHOST"] = *c.raw
		}
		if got := strings.Join(challengeV2AutoVhost(kv), ","); got != c.want {
			name := "<absent>"
			if c.raw != nil {
				name = *c.raw
			}
			t.Errorf("CHALLENGE_V2_AUTO_VHOST=%q: got %q, want %q", name, got, c.want)
		}
	}
}

func strp(s string) *string { return &s }
