package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cfm/internal/firewall"
)

// selfTestBackend is a stub that DOES implement firewall.SelfTester (like nftlib).
type selfTestBackend struct {
	*stubFirewallBackend
}

func (s *selfTestBackend) Engine() string { return "nftlib" }
func (s *selfTestBackend) NftlibSelfTest() firewall.NftlibSelfTest {
	return firewall.NftlibSelfTest{
		Engine:  "nftlib",
		Samples: 2,
		EnsureBaseRecent: []firewall.EnsureBaseSample{
			{At: "2026-08-11T13:00:00Z", LockWaitMs: 5, NLWorkMs: 700, CLIWorkMs: 20},
			{At: "2026-08-11T13:00:20Z", LockWaitMs: 6, NLWorkMs: 9000, CLIWorkMs: 25},
		},
		EnsureBaseWorst: &firewall.EnsureBaseSample{At: "2026-08-11T13:00:20Z", NLWorkMs: 9000},
		FeedWrites: []firewall.FeedWriteSample{
			{Set: "block_ext_v4_hosts", At: "2026-08-11T13:00:10Z", Elems: 50000, DurMs: 12000, Err: "message too long"},
		},
	}
}

func TestFirewallSelfTest_AvailableOnNftlib(t *testing.T) {
	be := &selfTestBackend{stubFirewallBackend: &stubFirewallBackend{}}
	h := makeFirewallSelfTestHandler(be)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/firewall/selftest", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		OK        bool                    `json:"ok"`
		Available bool                    `json:"available"`
		SelfTest  firewall.NftlibSelfTest `json:"selftest"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.OK || !body.Available {
		t.Fatalf("expected ok+available, got %+v", body)
	}
	if body.SelfTest.Engine != "nftlib" || body.SelfTest.Samples != 2 {
		t.Fatalf("selftest payload wrong: %+v", body.SelfTest)
	}
	if body.SelfTest.EnsureBaseWorst == nil || body.SelfTest.EnsureBaseWorst.NLWorkMs != 9000 {
		t.Fatalf("worst not surfaced: %+v", body.SelfTest.EnsureBaseWorst)
	}
	if len(body.SelfTest.FeedWrites) != 1 || body.SelfTest.FeedWrites[0].Err == "" {
		t.Fatalf("feed-write error not surfaced: %+v", body.SelfTest.FeedWrites)
	}
}

func TestFirewallSelfTest_UnavailableOnExecNft(t *testing.T) {
	// A plain backend that does NOT implement firewall.SelfTester (like exec-nft).
	be := &stubFirewallBackend{}
	h := makeFirewallSelfTestHandler(be)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/firewall/selftest", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", body)
	}
	if avail, _ := body["available"].(bool); avail {
		t.Fatalf("expected available=false on a non-SelfTester backend, got %v", body)
	}
	if _, has := body["selftest"]; has {
		t.Fatalf("no selftest payload expected when unavailable: %v", body)
	}
}

func TestFirewallSelfTest_RejectsNonGET(t *testing.T) {
	h := makeFirewallSelfTestHandler(&selfTestBackend{stubFirewallBackend: &stubFirewallBackend{}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/selftest", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}
