package config

import (
	"strings"
	"testing"
)

// THROTTLE_GOODBOT_EXEMPT is on unless explicitly turned off: a typo must not
// silently let the flood autoblock ban verified crawlers again.
func TestThrottleGoodBotExempt(t *testing.T) {
	for _, c := range []struct {
		line    string
		wantOff bool
	}{
		{"", false},
		{`THROTTLE_GOODBOT_EXEMPT = "1"`, false},
		{`THROTTLE_GOODBOT_EXEMPT = "0"`, true},
		{`THROTTLE_GOODBOT_EXEMPT = off # kill switch`, true},
		{`THROTTLE_GOODBOT_EXEMPT = "no"`, true},
		{`THROTTLE_GOODBOT_EXEMPT = "nope"`, false},
	} {
		cfg, err := ParseCFMConf(strings.NewReader(c.line))
		if err != nil {
			t.Fatalf("%q: %v", c.line, err)
		}
		if cfg.Throttle.GoodBotExemptOff != c.wantOff {
			t.Errorf("%q: GoodBotExemptOff = %t, want %t", c.line, cfg.Throttle.GoodBotExemptOff, c.wantOff)
		}
	}
}
