package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A logout another site started (Sec-Fetch-Site: cross-site) ends nothing:
// no cookie is cleared. A same-origin click, or a browser that sends no
// Sec-Fetch-Site, logs out as before.
func TestLogoutIgnoresCrossSiteRequests(t *testing.T) {
	cleared := func(rec *httptest.ResponseRecorder) bool {
		for _, c := range rec.Result().Cookies() {
			if c.MaxAge < 0 && strings.HasPrefix(c.Name, "cfm-embed") {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		site      string
		wantClear bool
	}{
		{"cross-site", false},
		{"same-origin", true},
		{"same-site", true},
		{"", true},
	} {
		req := httptest.NewRequest(http.MethodGet, "/cfm-admin/logout", nil)
		if c.site != "" {
			req.Header.Set("Sec-Fetch-Site", c.site)
		}
		rec := httptest.NewRecorder()
		handleLogout(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%q: status %d, want 303", c.site, rec.Code)
		}
		if got := cleared(rec); got != c.wantClear {
			t.Errorf("Sec-Fetch-Site %q: cookies cleared=%v, want %v", c.site, got, c.wantClear)
		}
	}
}
