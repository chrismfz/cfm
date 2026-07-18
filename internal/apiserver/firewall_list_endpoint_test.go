package apiserver

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// listStubBackend serves a fixed block list.
type listStubBackend struct {
	stubFirewallBackend
	entries []firewall.BlockedEntry
}

func (b *listStubBackend) ListBlocks() ([]firewall.BlockedEntry, error) { return b.entries, nil }

func TestFirewallListEndpoint(t *testing.T) {
	soon := time.Now().Add(30 * time.Minute)
	later := time.Now().Add(6 * time.Hour)
	be := &listStubBackend{entries: []firewall.BlockedEntry{
		{IP: net.ParseIP("9.9.9.9")}, // permanent
		{IP: net.ParseIP("2.2.2.2"), Expires: &later, Comment: "bulk"},
		{IP: net.ParseIP("1.1.1.1"), Expires: &soon, Comment: "webui manual block"},
	}}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/firewall/list", nil)
	makeFirewallListHandler(be)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		OK        bool              `json:"ok"`
		Total     int               `json:"total"`
		Permanent int               `json:"permanent"`
		Rows      []firewallListRow `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.OK || out.Total != 3 || out.Permanent != 1 {
		t.Fatalf("summary: %+v", out)
	}
	// Expiring-soonest first, permanent last.
	if out.Rows[0].IP != "1.1.1.1" || out.Rows[1].IP != "2.2.2.2" || out.Rows[2].IP != "9.9.9.9" {
		t.Fatalf("order: %+v", out.Rows)
	}
	if !out.Rows[2].Permanent || out.Rows[2].Expires != "" {
		t.Fatalf("permanent row: %+v", out.Rows[2])
	}
	if out.Rows[0].ExpiresInSec <= 0 || out.Rows[0].ExpiresInSec > 1900 {
		t.Fatalf("expires_in_sec: %+v", out.Rows[0])
	}
	if out.Rows[0].Comment != "webui manual block" {
		t.Fatalf("comment: %+v", out.Rows[0])
	}

	// POST is rejected.
	rr2 := httptest.NewRecorder()
	makeFirewallListHandler(be)(rr2, httptest.NewRequest(http.MethodPost, "/api/v1/firewall/list", nil))
	if rr2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("post status=%d", rr2.Code)
	}
}
