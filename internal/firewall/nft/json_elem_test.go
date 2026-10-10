package nft

import (
	"encoding/json"
	"testing"
)

// Interval-set elements as `nft -j list set` prints them: the edge ban
// reconcile reads every allow set through ListSetElementsTimed, and an allow
// net it cannot parse would leave an allowed client banned at the edge.
func TestJSONElemString(t *testing.T) {
	cases := map[string]string{
		`"203.0.113.7"`:                                       "203.0.113.7",
		`{"prefix":{"addr":"10.0.0.0","len":8}}`:              "10.0.0.0/8",
		`{"prefix":{"addr":"2001:db8::","len":32}}`:           "2001:db8::/32",
		`{"range":["192.0.2.10","192.0.2.20"]}`:               "192.0.2.10-192.0.2.20",
		`{"val":{"prefix":{"addr":"198.51.100.0","len":24}}}`: "",
		`42`: "",
	}
	for in, want := range cases {
		var v any
		if err := json.Unmarshal([]byte(in), &v); err != nil {
			t.Fatal(err)
		}
		if got := jsonElemString(v); got != want {
			t.Errorf("jsonElemString(%s) = %q, want %q", in, got, want)
		}
	}
}
