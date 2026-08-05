package webdetector

import "testing"

// Exclude add/remove is logged so the exclude lifecycle is observable (an
// exclude silently governs whether the challenge/WAF layer runs for a host or
// path). These assert the rendered line for the shapes an operator produces.
func TestFormatExcludeChange(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		action  string
		typ     string
		value   string
		scope   map[string]struct{}
		ruleIDs []int
		ok      bool
		want    string
	}{
		{
			name: "challenge host add, global, ok",
			kind: "challenge", action: "add", typ: "host", value: "example.gr",
			ok:   true,
			want: `[exclude] action=add kind=challenge type=host value="example.gr" scope=global rule_ids=all result=ok`,
		},
		{
			name: "waf path remove, scoped, rule-scoped, noop",
			kind: "waf", action: "remove", typ: "path", value: "/wp-json/foo",
			scope:   map[string]struct{}{"b.gr": {}, "a.gr": {}},
			ruleIDs: []int{402, 305},
			ok:      false,
			want:    `[exclude] action=remove kind=waf type=path value="/wp-json/foo" scope=a.gr,b.gr rule_ids=402,305 result=noop`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := formatExcludeChange(c.kind, c.action, c.typ, c.value, c.scope, c.ruleIDs, c.ok)
			if got != c.want {
				t.Fatalf("\n got: %s\nwant: %s", got, c.want)
			}
		})
	}
}
