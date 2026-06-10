package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"cfm/internal/locate"
)

func TestSearchEndpointRejectsNonGET(t *testing.T) {
	h := makeSearchHandler(nil, "")
	req := httptest.NewRequest(http.MethodPost, "/search?ip=192.0.2.10", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestSearchEndpointValidation(t *testing.T) {
	h := makeSearchHandler(nil, "")
	for _, target := range []string{"/search", "/search?ip=not-an-ip"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", target, rec.Code)
		}
	}
}

func TestSearchEndpointReturnsLocations(t *testing.T) {
	orig := locateFind
	defer func() { locateFind = orig }()
	locateFind = func(_ context.Context, arg string, _ locate.Options) (*locate.Result, error) {
		return &locate.Result{
			Query: arg,
			Locations: []locate.Location{
				{Source: "fail2ban", List: "sshd", Action: locate.ActionBlock, Match: arg},
			},
			Skipped: map[string]string{"imunify360": "not installed"},
		}, nil
	}

	h := makeSearchHandler(nil, "")
	req := httptest.NewRequest(http.MethodGet, "/search?ip=192.0.2.10", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		OK        bool              `json:"ok"`
		Hostname  string            `json:"hostname"`
		Query     string            `json:"query"`
		Locations []locate.Location `json:"locations"`
		Skipped   map[string]string `json:"skipped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if !resp.OK || resp.Query != "192.0.2.10" {
		t.Errorf("ok=%v query=%q", resp.OK, resp.Query)
	}
	if len(resp.Locations) != 1 || resp.Locations[0].List != "sshd" {
		t.Errorf("locations = %+v", resp.Locations)
	}
	if resp.Skipped["imunify360"] != "not installed" {
		t.Errorf("skipped = %+v", resp.Skipped)
	}
}
