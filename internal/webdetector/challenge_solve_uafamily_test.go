package webdetector

import "testing"

// TestChallengeSolveUAFamilyOrDash pins the log-rendering contract: an empty
// UAFamily (an unclassifiable UA — notably a HeadlessChrome token, which
// uaplausible deliberately returns "" for) renders as "-", never a blank that
// would produce `ua_family= ` and read as a parse failure; a classified family
// passes through verbatim. Mirrors the TLSFingerprintOrDash contract so the two
// solve-line writers can never disagree about what absence looks like.
func TestChallengeSolveUAFamilyOrDash(t *testing.T) {
	cases := []struct {
		name   string
		family string
		want   string
	}{
		{"empty (headless / unclassifiable) renders dash", "", "-"},
		{"chrome passthrough", "Chrome", "Chrome"},
		{"firefox passthrough", "Firefox", "Firefox"},
		{"safari passthrough", "Safari", "Safari"},
		{"crios passthrough", "CriOS", "CriOS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := ChallengeSolve{UAFamily: c.family}
			if got := s.UAFamilyOrDash(); got != c.want {
				t.Fatalf("UAFamilyOrDash() with UAFamily=%q = %q, want %q", c.family, got, c.want)
			}
		})
	}
}
