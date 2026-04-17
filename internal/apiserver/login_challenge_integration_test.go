package apiserver

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPreAuthChallenge_HumanBrowserLoginChallenged(t *testing.T) {
	resetPreAuthChallengeStateForTests()
	t.Cleanup(resetPreAuthChallengeStateForTests)

	var challenged int
	SetPreAuthLoginChallengeEnforcer(func(ip net.IP, ttl time.Duration, reason string) error {
		challenged++
		if ip == nil || ip.String() != "198.51.100.42" {
			t.Fatalf("unexpected challenge ip: %v", ip)
		}
		if ttl <= 0 {
			t.Fatalf("expected positive ttl, got %s", ttl)
		}
		if reason == "" {
			t.Fatalf("expected challenge reason")
		}
		return nil
	}, time.Minute)
	SetPreAuthLoginChallengeEnabled(true)

	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/login", nil)
	req.RemoteAddr = "198.51.100.42:43210"
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected %d got %d", http.StatusSeeOther, rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "/cfm-admin/login") || !strings.Contains(loc, "__cfm_ch=1") {
		t.Fatalf("expected challenge redirect location, got %q", loc)
	}
	if challenged != 1 {
		t.Fatalf("expected enforcer call count=1 got %d", challenged)
	}
}

func TestPreAuthChallenge_EmbedBootstrapNotChallenged(t *testing.T) {
	resetPreAuthChallengeStateForTests()
	t.Cleanup(resetPreAuthChallengeStateForTests)

	var challenged int
	SetPreAuthLoginChallengeEnforcer(func(net.IP, time.Duration, string) error {
		challenged++
		return nil
	}, time.Minute)
	SetPreAuthLoginChallengeEnabled(true)

	called := false
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/embed/bootstrap?code=abc", nil)
	req.RemoteAddr = "198.51.100.60:443"
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected bootstrap route to reach handler")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
	if challenged != 0 {
		t.Fatalf("expected no challenge for bootstrap route, got %d", challenged)
	}
}

func TestPreAuthChallenge_AuthenticatedSessionBypassesChallenge(t *testing.T) {
	resetPreAuthChallengeStateForTests()
	t.Cleanup(resetPreAuthChallengeStateForTests)
	withSessionAllowedStub(t, true)

	var challenged int
	SetPreAuthLoginChallengeEnforcer(func(net.IP, time.Duration, string) error {
		challenged++
		return nil
	}, time.Minute)
	SetPreAuthLoginChallengeEnabled(true)

	called := false
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/login", nil)
	req.RemoteAddr = "198.51.100.70:443"
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected authenticated session request to bypass challenge gate")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
	if challenged != 0 {
		t.Fatalf("expected no challenge when session exists, got %d", challenged)
	}
}

func TestPreAuthChallenge_APITokenCallsRemainFunctional(t *testing.T) {
	resetPreAuthChallengeStateForTests()
	t.Cleanup(resetPreAuthChallengeStateForTests)

	var challenged int
	SetPreAuthLoginChallengeEnforcer(func(net.IP, time.Duration, string) error {
		challenged++
		return nil
	}, time.Minute)
	SetPreAuthLoginChallengeEnabled(true)

	called := false
	h := TokenMiddleware("secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/dnat", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Accept", "application/json")
	req.RemoteAddr = "203.0.113.5:9000"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected API bearer request to reach handler")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
	if challenged != 0 {
		t.Fatalf("expected no pre-auth challenge for API bearer requests, got %d", challenged)
	}
}
