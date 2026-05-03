package webdetector

import "testing"

func TestHostMatch_ExactAndWildcardBehavior(t *testing.T) {
	host := "cpanel.example.com"
	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "exact", pattern: "cpanel.example.com", want: true},
		{name: "prefix-label-wildcard", pattern: "cpanel.*", want: true},
		{name: "suffix-wildcard", pattern: "*.example.com", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostMatch(host, tc.pattern); got != tc.want {
				t.Fatalf("hostMatch(%q,%q)=%v want %v", host, tc.pattern, got, tc.want)
			}
		})
	}
}
