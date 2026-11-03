package webdetector

import (
	"reflect"
	"testing"

	core "cfm/internal/detectors/core"
)

// Humanity rides the event only behind the HumanityScored gate (as on the
// solve line): an unscored solve carries nil, never a fabricated hs 0, and a
// scored hs 0 stays a real reading. CountryISO is carried as resolved.
func TestChallengeSolveInputEventHumanityGate(t *testing.T) {
	cases := []struct {
		name string
		in   ChallengeSolve
		want *core.Humanity
	}{
		{"unscored solve carries nil", ChallengeSolve{IP: "203.0.113.9", Host: "h"}, nil},
		{"unscored ignores stray fields", ChallengeSolve{IP: "203.0.113.9", Host: "h", HumanityScore: 140, HumanityTells: "webdriver", HumanityNoPayload: true}, nil},
		{"scored clean is a real 0", ChallengeSolve{IP: "203.0.113.9", Host: "h", HumanityScored: true}, &core.Humanity{Scored: true}},
		{"scored with tells", ChallengeSolve{IP: "203.0.113.9", Host: "h", HumanityScored: true, HumanityScore: 120, HumanityTells: "sw_renderer,no_input"},
			&core.Humanity{Scored: true, Score: 120, Tells: "sw_renderer,no_input"}},
		{"no payload", ChallengeSolve{IP: "203.0.113.9", Host: "h", HumanityScored: true, HumanityNoPayload: true},
			&core.Humanity{Scored: true, NoPayload: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in.InputEvent().Humanity
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("Humanity = %+v, want %+v", got, c.want)
			}
		})
	}
	if ev := (ChallengeSolve{IP: "203.0.113.9", Host: "h", CountryISO: "GR"}).InputEvent(); ev.CountryISO != "GR" {
		t.Errorf("CountryISO = %q, want GR", ev.CountryISO)
	}
}

func withCleanSolveSubs(t *testing.T) {
	t.Helper()
	solveSubsMu.Lock()
	saved := solveSubs
	solveSubs = nil
	solveSubsMu.Unlock()
	t.Cleanup(func() {
		solveSubsMu.Lock()
		solveSubs = saved
		solveSubsMu.Unlock()
	})
}

func TestSubscribeAndPublishChallengeSolve(t *testing.T) {
	withCleanSolveSubs(t)

	var got []ChallengeSolve
	SubscribeChallengeSolveEvents(func(s ChallengeSolve) { got = append(got, s) })
	SubscribeChallengeSolveEvents(nil) // must be ignored, not stored

	publishChallengeSolveEvent(ChallengeSolve{IP: "203.0.113.9", Host: "shop.example.com"})
	if len(got) != 1 {
		t.Fatalf("delivered %d events, want 1", len(got))
	}
	if got[0].IP != "203.0.113.9" || got[0].Host != "shop.example.com" {
		t.Errorf("delivered %+v", got[0])
	}
}

// A config reload tears down and re-creates every detector, and the factory
// subscribes each time. Without a reset the retired detector's closure keeps
// receiving solves into a buffer nothing drains any more — an unbounded leak
// that grows with reload count, and reloads happen on every logrotate.
func TestResetChallengeSolveSubscribers(t *testing.T) {
	withCleanSolveSubs(t)

	retired := 0
	SubscribeChallengeSolveEvents(func(ChallengeSolve) { retired++ })

	ResetChallengeSolveSubscribers()

	current := 0
	SubscribeChallengeSolveEvents(func(ChallengeSolve) { current++ })

	publishChallengeSolveEvent(ChallengeSolve{IP: "203.0.113.9"})

	if retired != 0 {
		t.Errorf("retired subscriber received %d events after reset, want 0", retired)
	}
	if current != 1 {
		t.Errorf("current subscriber received %d events, want 1", current)
	}
}

// The detector layer aggregates on Scope (vhost) and SrcIP, and reads the
// UA-plausibility verdict off Signal. A transposition here would ship silently:
// the detector would simply never fire.
func TestChallengeSolveInputEventMapping(t *testing.T) {
	s := ChallengeSolve{
		IP:           "203.0.113.9",
		Host:         "shop.example.com",
		URI:          "/product-category/lamps/page/5",
		UA:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/118.0.0.0 Safari/537.36",
		UAImpossible: true,
		UAReason:     "ios_with_blink_webkit",
	}
	ev := s.InputEvent()

	if ev.Scope != s.Host {
		t.Errorf("Scope = %q, want the vhost %q", ev.Scope, s.Host)
	}
	if ev.SrcIP != s.IP {
		t.Errorf("SrcIP = %q, want %q", ev.SrcIP, s.IP)
	}
	if ev.UserAgent != s.UA {
		t.Errorf("UserAgent = %q, want %q", ev.UserAgent, s.UA)
	}
	if ev.Signal != s.UAReason {
		t.Errorf("Signal = %q, want the UA verdict %q", ev.Signal, s.UAReason)
	}
	if ev.Path != s.URI {
		t.Errorf("Path = %q, want %q", ev.Path, s.URI)
	}
	if ev.Source != "challenge" || ev.Reason != "CHALLENGE_SOLVED" {
		t.Errorf("Source/Reason = %q/%q", ev.Source, ev.Reason)
	}
}

func TestChallengeSolveInputEventCarriesNoVerdictWhenUACoherent(t *testing.T) {
	ev := ChallengeSolve{IP: "203.0.113.9", Host: "shop.example.com"}.InputEvent()
	if ev.Signal != "" {
		t.Errorf("Signal = %q, want empty for a coherent UA", ev.Signal)
	}
}
