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

// The whole `nft -j list set` walk: plain, elem+timeout, bare prefix and
// range (interval sets without per-element timeouts, the main shape of an
// allow net).
func TestParseTimedSetJSON(t *testing.T) {
	raw := `{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"allow_v4_nets","table":"cfm","type":"ipv4_addr","flags":["interval"],
	 "elem":["203.0.113.7",
	   {"prefix":{"addr":"10.0.0.0","len":8}},
	   {"range":["192.0.2.10","192.0.2.20"]},
	   {"elem":{"val":{"prefix":{"addr":"198.51.100.0","len":24}},"timeout":3600,"expires":1800}},
	   {"elem":{"val":"203.0.113.9","timeout":600,"expires":0}}]}}]}`
	got, err := parseTimedSetJSON([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"203.0.113.7": true, "10.0.0.0/8": true, "192.0.2.10-192.0.2.20": true, "198.51.100.0/24": true, "203.0.113.9": true}
	if len(got) != len(want) {
		t.Fatalf("got %d elements %+v, want %d", len(got), got, len(want))
	}
	for _, e := range got {
		if !want[e.Elem] {
			t.Errorf("unexpected element %q", e.Elem)
		}
		if e.Elem == "198.51.100.0/24" && e.Expires.Seconds() != 1800 {
			t.Errorf("prefix with timeout: expires %v, want 30m", e.Expires)
		}
		if e.Elem == "203.0.113.9" && e.Expires <= 0 {
			t.Errorf("an element in its last second must not read permanent: %v", e.Expires)
		}
	}
}
