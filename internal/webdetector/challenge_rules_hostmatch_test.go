package webdetector

import "testing"

func TestHostMatch_ExactAndWildcardBehavior(t *testing.T) {
	host := "cpanel.anyhost.gr"
	cases := []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "exact", pattern: "cpanel.anyhost.gr", want: true},
		{name: "prefix-label-wildcard", pattern: "cpanel.*", want: true},
		{name: "suffix-wildcard", pattern: "*.anyhost.gr", want: true},
		{name: "non-matching-exact", pattern: "whm.anyhost.gr", want: false},
		{name: "non-matching-prefix-label-wildcard", pattern: "whm.*", want: false},
		{name: "non-matching-suffix-wildcard", pattern: "*.other.gr", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostMatch(host, tc.pattern); got != tc.want {
				t.Fatalf("hostMatch(%q,%q)=%v want %v", host, tc.pattern, got, tc.want)
			}
		})
	}
}
