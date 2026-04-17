package apiserver

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	cfgpkg "cfm/internal/config"
)

func TestEffectiveClientIP_TrustsFirstXFFOnLoopbackPeer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "198.51.100.10, 127.0.0.1")

	ip, ok := effectiveClientIP(r)
	if !ok {
		t.Fatalf("expected parsed client IP")
	}
	if got, want := ip.String(), "198.51.100.10"; got != want {
		t.Fatalf("client ip=%q want=%q", got, want)
	}
}

func TestIPAllowMiddleware_AllowsFromConfigFilesAndAPIURL(t *testing.T) {
	tmp := t.TempDir()
	allowPath := filepath.Join(tmp, "cfm.allow")
	dyPath := filepath.Join(tmp, "cfm.dyndns")
	if err := os.WriteFile(allowPath, []byte("198.51.100.0/24\nallow.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dyPath, []byte("dyn.example\n"), 0600); err != nil {
		t.Fatal(err)
	}

	oldLookup := ipAllowLookupIP
	ipAllowLookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "allow.example":
			return []net.IP{net.ParseIP("203.0.113.7")}, nil
		case "dyn.example":
			return []net.IP{net.ParseIP("203.0.113.8")}, nil
		case "api.example":
			return []net.IP{net.ParseIP("203.0.113.9")}, nil
		default:
			return nil, nil
		}
	}
	t.Cleanup(func() { ipAllowLookupIP = oldLookup })

	cfg := &cfgpkg.Config{}
	cfg.API.URL = "https://api.example:8443"

	mw := IPAllowMiddleware(cfg, tmp)
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	cases := []string{"198.51.100.20", "203.0.113.7", "203.0.113.8", "203.0.113.9"}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
			r.RemoteAddr = ip + ":44321"
			rr := httptest.NewRecorder()
			next.ServeHTTP(rr, r)
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestIPAllowMiddleware_RejectsDisallowedIP(t *testing.T) {
	tmp := t.TempDir()
	cfg := &cfgpkg.Config{}
	mw := IPAllowMiddleware(cfg, tmp)
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
	r.RemoteAddr = "203.0.113.55:33333"
	rr := httptest.NewRecorder()
	next.ServeHTTP(rr, r)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type=%q", got)
	}
}
