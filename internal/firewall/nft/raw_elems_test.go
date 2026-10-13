package nft

import (
	"encoding/json"
	"testing"
)

// ListSetElementsRaw printed an interval set's {"prefix"} / {"range"}
// elements as "<nil>" and timeout-wrapped ones as "map[…]"; every caller
// (cfm status, unblock, firewall status) wants the nftlib backend's strings.
func TestRawElemString(t *testing.T) {
	var elems []any
	if err := json.Unmarshal([]byte(`[
		"198.51.100.1",
		{"prefix":{"addr":"192.0.2.0","len":24}},
		{"range":["198.18.0.1","198.18.0.9"]},
		{"elem":{"val":"198.51.100.2","timeout":3600,"expires":3500}},
		{"elem":{"val":{"prefix":{"addr":"203.0.113.0","len":25}},"timeout":60}},
		{"elem":{"val":{"range":["10.0.0.1","10.0.0.5"]},"timeout":60}},
		{"bogus":1}
	]`), &elems); err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.1", "192.0.2.0/24", "198.18.0.1-198.18.0.9", "198.51.100.2", "203.0.113.0/25", "10.0.0.1-10.0.0.5", ""}
	for i, e := range elems {
		if got := rawElemString(e); got != want[i] {
			t.Errorf("elem %d: got %q, want %q", i, got, want[i])
		}
	}
}
