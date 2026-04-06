package webdetector

import "testing"

func TestMatchHostExclude(t *testing.T) {
	tests := []struct {
		name        string
		excludes    []string
		host        string
		wantMatched bool
		wantValue   string
		wantExact   bool
	}{
		{
			name:        "exact match",
			excludes:    []string{"foo.com"},
			host:        "foo.com",
			wantMatched: true,
			wantValue:   "foo.com",
			wantExact:   true,
		},
		{
			name:        "subdomain match",
			excludes:    []string{"foo.com"},
			host:        "www.foo.com",
			wantMatched: true,
			wantValue:   "foo.com",
			wantExact:   false,
		},
		{
			name:        "false positive prevention",
			excludes:    []string{"foo.com"},
			host:        "badfoo.com",
			wantMatched: false,
			wantValue:   "",
			wantExact:   false,
		},
		{
			name:        "wildcard behavior",
			excludes:    []string{"*.foo.com"},
			host:        "www.foo.com",
			wantMatched: true,
			wantValue:   "*.foo.com",
			wantExact:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMatched, gotValue, gotExact := matchHostExclude(tt.excludes, tt.host)
			if gotMatched != tt.wantMatched || gotValue != tt.wantValue || gotExact != tt.wantExact {
				t.Fatalf("matchHostExclude(%v, %q) = (%v, %q, %v), want (%v, %q, %v)",
					tt.excludes, tt.host,
					gotMatched, gotValue, gotExact,
					tt.wantMatched, tt.wantValue, tt.wantExact)
			}
		})
	}
}
