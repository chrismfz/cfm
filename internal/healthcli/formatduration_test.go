package healthcli

import (
	"testing"
	"time"
)

// formatShortDuration is uptime/age display: a coarse "<1m" floor and a
// two-unit d/h or h/m form (e.g. "2d3h", "1h30m"), never seconds. It is a
// distinct formatter from nft.humanTimeout (which emits nftables rule syntax)
// and webdetector.shortDur (second-precision TTL remaining); this test pins its
// output so those three don't silently converge — see the note on humanTimeout.
func TestFormatShortDuration_Contract(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Second:           "<1m",
		time.Minute:                "1m",
		5 * time.Minute:            "5m",
		time.Hour + 30*time.Minute: "1h30m",
		25 * time.Hour:             "1d1h",
		51 * time.Hour:             "2d3h",
	}
	for in, want := range cases {
		if got := formatShortDuration(in); got != want {
			t.Errorf("formatShortDuration(%s) = %q, want %q", in, got, want)
		}
	}
}
