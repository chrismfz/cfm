package apiserver

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// admin token IP-binding: the token_admin branch is gated by source IP when the
// policy is enforce, logged-only under logonly, and untouched when off.

func adminIPHandler(mode, cfgDir, apiURL string) http.Handler {
	reached := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return TokenMiddleware("admin-secret", NewTokenStore(),
		WithAdminTokenIPBinding(mode, cfgDir, apiURL))(reached)
}

func adminIPRequest(remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
	req.Header.Set("Token", "admin-secret")
	req.RemoteAddr = remoteAddr
	return req
}

func TestAdminTokenIPBinding_EnforceBlocksForeignSource(t *testing.T) {
	h := adminIPHandler("enforce", t.TempDir(), "")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, adminIPRequest("203.0.113.9:5555")) // not loopback, not selfIP, empty allowlist

	if rr.Code != http.StatusForbidden {
		t.Fatalf("foreign source with a valid admin token must be 403 under enforce; got %d", rr.Code)
	}
}

func TestAdminTokenIPBinding_EnforceAllowsLoopback(t *testing.T) {
	h := adminIPHandler("enforce", t.TempDir(), "")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, adminIPRequest("127.0.0.1:5555")) // the WHM-plugin path

	if rr.Code != http.StatusOK {
		t.Fatalf("loopback (WHM plugin) must always be allowed; got %d", rr.Code)
	}
}

func TestAdminTokenIPBinding_EnforceAllowsApiURLHost(t *testing.T) {
	// cfm-web's egress == the API_URL host; the allowlist resolves that host.
	orig := ipAllowLookupIP
	ipAllowLookupIP = func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.9")}, nil
	}
	defer func() { ipAllowLookupIP = orig }()

	h := adminIPHandler("enforce", t.TempDir(), "https://cfm.example.test")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, adminIPRequest("203.0.113.9:5555"))

	if rr.Code != http.StatusOK {
		t.Fatalf("source == resolved API_URL host must be allowed; got %d", rr.Code)
	}
}

func TestAdminTokenIPBinding_LogonlyAllowsForeignSource(t *testing.T) {
	h := adminIPHandler("logonly", t.TempDir(), "")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, adminIPRequest("203.0.113.9:5555"))

	if rr.Code != http.StatusOK {
		t.Fatalf("logonly must allow (burn-in), only log would-block; got %d", rr.Code)
	}
}

func TestAdminTokenIPBinding_OffIsUnchanged(t *testing.T) {
	// No option at all → default off → behaviour identical to before this feature.
	reached := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := TokenMiddleware("admin-secret", NewTokenStore())(reached)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, adminIPRequest("203.0.113.9:5555"))

	if rr.Code != http.StatusOK {
		t.Fatalf("with the gate off a valid admin token from any IP must pass; got %d", rr.Code)
	}
}

func TestNormalizeAdminIPMode(t *testing.T) {
	cases := map[string]string{
		"":         adminIPModeOff,
		"off":      adminIPModeOff,
		"nonsense": adminIPModeOff,
		"logonly":  adminIPModeLogonly,
		"dryrun":   adminIPModeLogonly,
		"enforce":  adminIPModeEnforce,
		"ENFORCE":  adminIPModeEnforce,
		"on":       adminIPModeEnforce,
	}
	for in, want := range cases {
		if got := normalizeAdminIPMode(in); got != want {
			t.Errorf("normalizeAdminIPMode(%q) = %q, want %q", in, got, want)
		}
	}
}
