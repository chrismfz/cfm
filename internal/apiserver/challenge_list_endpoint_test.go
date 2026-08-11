package apiserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// challengeStubBackend serves fixed challenge-set contents: challenge_v4 has two
// members (one with a TTL, one without), challenge_v6 errors (e.g. a node with no
// v6 set) so the per-set error path is exercised.
type challengeStubBackend struct {
	stubFirewallBackend
}

func (b *challengeStubBackend) Engine() string { return "nftlib" }

func (b *challengeStubBackend) ListSetElementsTimed(name string) ([]firewall.SetElementTimed, error) {
	switch name {
	case "challenge_v4":
		return []firewall.SetElementTimed{
			{Elem: "203.0.113.7", Expires: 90 * time.Second},
			{Elem: "198.51.100.9"}, // no timeout → permanent
		}, nil
	case "challenge_v6":
		return nil, fmt.Errorf("set challenge_v6 in inet cfm: no such file or directory")
	}
	return nil, nil
}

func TestChallengeListEndpoint(t *testing.T) {
	be := &challengeStubBackend{}

	rr := httptest.NewRecorder()
	makeChallengeListHandler(be)(rr, httptest.NewRequest(http.MethodGet, "/api/v1/firewall/challenge/list", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		OK     bool   `json:"ok"`
		Engine string `json:"engine"`
		Total  int    `json:"total"`
		Sets   map[string]struct {
			Count int            `json:"count"`
			Rows  []challengeRow `json:"rows"`
			Error string         `json:"error"`
		} `json:"sets"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.OK || out.Engine != "nftlib" || out.Total != 2 {
		t.Fatalf("summary: %+v", out)
	}
	v4 := out.Sets["challenge_v4"]
	if v4.Count != 2 || len(v4.Rows) != 2 {
		t.Fatalf("v4: %+v", v4)
	}
	// TTL member: ttl_sec populated, not permanent.
	if v4.Rows[0].IP != "203.0.113.7" || v4.Rows[0].TTLSec != 90 || v4.Rows[0].Permanent {
		t.Fatalf("v4 ttl row: %+v", v4.Rows[0])
	}
	// No-timeout member: permanent, ttl_sec omitted (0).
	if v4.Rows[1].IP != "198.51.100.9" || !v4.Rows[1].Permanent || v4.Rows[1].TTLSec != 0 {
		t.Fatalf("v4 permanent row: %+v", v4.Rows[1])
	}
	// v6 surfaced its error per-set (not fatal to the response).
	if v6 := out.Sets["challenge_v6"]; v6.Error == "" || v6.Count != 0 {
		t.Fatalf("v6 error path: %+v", v6)
	}

	// POST is rejected.
	rr2 := httptest.NewRecorder()
	makeChallengeListHandler(be)(rr2, httptest.NewRequest(http.MethodPost, "/api/v1/firewall/challenge/list", nil))
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post status=%d", rr2.Code)
	}
}
