package detectors

import "testing"

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
