package detectors

import (
	"strings"
	"testing"
)

func TestValidateChallengeHostPatterns(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		entries []string
		wantErr bool
	}{
		{name: "exact", key: "CHALLENGE_VHOST", entries: []string{"cpanel.example.com"}, wantErr: false},
		{name: "suffix wildcard", key: "CHALLENGE_VHOST", entries: []string{"*.example.com"}, wantErr: false},
		{name: "prefix-label wildcard", key: "CHALLENGE_VHOST", entries: []string{"cpanel.*"}, wantErr: false},
		{name: "invalid wildcard placement", key: "CHALLENGE_VHOST", entries: []string{"cp*nel.example.com"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateChallengeHostPatterns(tt.key, tt.entries)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateChallengeHostPatterns() error=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestChallengeVhostListParsing_NormalizesWhitespace(t *testing.T) {
	raw := "  cpanel.* ,   whm.*  "
	var got []string
	for _, h := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ':' || r == ' ' || r == '\t'
	}) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			got = append(got, h)
		}
	}
	want := []string{"cpanel.*", "whm.*"}
	if len(got) != len(want) {
		t.Fatalf("parsed len=%d want len=%d parsed=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed[%d]=%q want %q (all=%v)", i, got[i], want[i], got)
		}
	}
}
