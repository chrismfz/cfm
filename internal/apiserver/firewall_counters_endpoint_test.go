package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// countersStubBackend serves a fixed `nft -j list table` payload.
type countersStubBackend struct {
	stubFirewallBackend
	json string
	err  error
}

func (b *countersStubBackend) ListTableJSON(_, _ string) ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	return []byte(b.json), nil
}

// A realistic nft -j list table payload: metadata + a rule + a set + three
// counters (one idle). Non-counter objects must be ignored.
const sampleCountersJSON = `{"nftables":[
 {"metainfo":{"version":"1.0.6"}},
 {"table":{"family":"inet","name":"cfm"}},
 {"chain":{"family":"inet","table":"cfm","name":"input"}},
 {"rule":{"family":"inet","table":"cfm","chain":"input"}},
 {"set":{"family":"inet","table":"cfm","name":"block4"}},
 {"counter":{"family":"inet","table":"cfm","name":"portflood_80_tcp","packets":420,"bytes":31000}},
 {"counter":{"family":"inet","table":"cfm","name":"synrate_v4","packets":15,"bytes":900}},
 {"counter":{"family":"inet","table":"cfm","name":"connlimit_25_tcp","packets":0,"bytes":0}}
]}`

func decodeCounters(t *testing.T, rr *httptest.ResponseRecorder) struct {
	OK           bool              `json:"ok"`
	Total        int               `json:"total"`
	TotalPackets uint64            `json:"total_packets"`
	ByFamily     map[string]uint64 `json:"by_family"`
	Counters     []fwCounterRow    `json:"counters"`
} {
	t.Helper()
	var out struct {
		OK           bool              `json:"ok"`
		Total        int               `json:"total"`
		TotalPackets uint64            `json:"total_packets"`
		ByFamily     map[string]uint64 `json:"by_family"`
		Counters     []fwCounterRow    `json:"counters"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, rr.Body.String())
	}
	return out
}

func TestFirewallCountersEndpoint(t *testing.T) {
	be := &countersStubBackend{json: sampleCountersJSON}

	// Default: all counters, busiest first, non-counter objects ignored.
	rr := httptest.NewRecorder()
	makeFirewallCountersHandler(be)(rr, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/counters", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	out := decodeCounters(t, rr)
	if !out.OK || out.Total != 3 {
		t.Fatalf("summary: %+v", out)
	}
	if out.Counters[0].Name != "portflood_80_tcp" || out.Counters[0].Family != "portflood" {
		t.Fatalf("busiest-first / classify: %+v", out.Counters[0])
	}
	if out.TotalPackets != 435 {
		t.Fatalf("total_packets=%d want 435", out.TotalPackets)
	}
	if out.ByFamily["portflood"] != 420 || out.ByFamily["synflood"] != 15 || out.ByFamily["connlimit"] != 0 {
		t.Fatalf("by_family: %+v", out.ByFamily)
	}

	// nonzero=1 hides the idle connlimit counter.
	rr2 := httptest.NewRecorder()
	makeFirewallCountersHandler(be)(rr2, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/counters?nonzero=1", nil))
	out2 := decodeCounters(t, rr2)
	if out2.Total != 2 {
		t.Fatalf("nonzero total=%d want 2 (%+v)", out2.Total, out2.Counters)
	}
	for _, c := range out2.Counters {
		if c.Packets == 0 {
			t.Fatalf("nonzero returned an idle counter: %+v", c)
		}
	}

	// POST is rejected.
	rr3 := httptest.NewRecorder()
	makeFirewallCountersHandler(be)(rr3, httptest.NewRequest(http.MethodPost, "/api/v1/firewall/counters", nil))
	if rr3.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post status=%d", rr3.Code)
	}

	// nil backend → 503.
	rr4 := httptest.NewRecorder()
	makeFirewallCountersHandler(nil)(rr4, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/counters", nil))
	if rr4.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil-backend status=%d", rr4.Code)
	}
}

func TestParseFirewallCounters_Garbage(t *testing.T) {
	if _, _, err := parseFirewallCounters([]byte("not json")); err == nil {
		t.Fatal("expected error on non-JSON")
	}
	// Valid nft shape, no counters → empty, supported, no error.
	rows, supported, err := parseFirewallCounters([]byte(`{"nftables":[{"table":{"name":"cfm"}}]}`))
	if err != nil || len(rows) != 0 || !supported {
		t.Fatalf("empty-counters parse: rows=%v supported=%v err=%v", rows, supported, err)
	}
}

// The nftlib backend's ListTableJSON emits {family,table,sets} — no "nftables"
// array — so the endpoint must report available:false, not an empty counter list.
func TestFirewallCounters_NftlibShape(t *testing.T) {
	be := &countersStubBackend{json: `{"family":"inet","table":"cfm","sets":["block4","block6"]}`}
	rr := httptest.NewRecorder()
	makeFirewallCountersHandler(be)(rr, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/counters", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		OK        bool `json:"ok"`
		Available *bool `json:"available"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.OK || out.Available == nil || *out.Available {
		t.Fatalf("nftlib shape must report available:false, got %s", rr.Body.String())
	}
}
