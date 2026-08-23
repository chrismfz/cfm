package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesSettingsPage(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "https://host/settings/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `id="settingsApp"`) {
		t.Fatalf("expected settings app marker, got body=%q", body)
	}
}

func TestHandlerServesFirewallNetfilterView(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "https://host/firewall/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, marker := range []string{`id="pathSummary"`, `id="pathBody"`, `id="natBody"`} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected firewall marker %s", marker)
		}
	}
}
