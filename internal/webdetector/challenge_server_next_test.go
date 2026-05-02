package webdetector

import "testing"

func TestNormalizeChallengeNext(t *testing.T) {
	tests := []struct {
		name string
		in   string
		out  string
	}{
		{name: "simple", in: "/admin", out: "/admin"},
		{name: "challenge unwrap", in: "/__cfm_challenge?next=%2Fadmin%3Fa%3D1", out: "/admin?a=1"},
		{name: "nested encoded challenge unwrap", in: "/__cfm_challenge?next=%252F__cfm_challenge%253Fnext%253D%25252Fapp", out: "/app"},
		{name: "strip recursive nested param", in: "/target?next=%2F__cfm_challenge%3Fnext%3D%252Finner&x=1", out: "/target?x=1"},
		{name: "malformed recursive falls back", in: "/__cfm_challenge?next=%2", out: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeChallengeNext(tt.in); got != tt.out {
				t.Fatalf("normalizeChallengeNext(%q)=%q want %q", tt.in, got, tt.out)
			}
		})
	}
}
