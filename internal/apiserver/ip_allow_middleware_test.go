package apiserver

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	core "cfm/internal/detectors/core"
	cfgpkg "cfm/internal/config"
)

var stdoutCaptureMu sync.Mutex

func writeTempAllowFiles(t *testing.T, allow, dyndns string) string {
	t.Helper()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "cfm.allow"), []byte(allow), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "cfm.dyndns"), []byte(dyndns), 0600); err != nil {
		t.Fatal(err)
	}
	return tmp
}

func withStubbedLookup(t *testing.T, lookup func(context.Context, string) ([]net.IP, error)) {
	t.Helper()
	oldLookup := ipAllowLookupIP
	ipAllowLookupIP = lookup
	t.Cleanup(func() { ipAllowLookupIP = oldLookup })
}

func runIPAllowRequest(t *testing.T, h http.Handler, remoteAddr string, xff string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
	r.RemoteAddr = remoteAddr
	if strings.TrimSpace(xff) != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	stdoutCaptureMu.Lock()
	defer stdoutCaptureMu.Unlock()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	defer func() {
		os.Stdout = orig
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if _, err := io.Copy(&b, r); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestIPAllowMiddleware_AllowsImmediateLoopbackAndSelfIP(t *testing.T) {
	cfg := &cfgpkg.Config{}
	mw := IPAllowMiddleware(cfg, "")
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	cases := []string{"127.0.0.1", "::1"}
	if self := core.SelfIPSet(); len(self) > 0 {
		for ip := range self {
			if ip != "127.0.0.1" && ip != "::1" {
				cases = append(cases, ip)
				break
			}
		}
	}

	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			rr := runIPAllowRequest(t, next, net.JoinHostPort(ip, "12345"), "")
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestIPAllowMiddleware_AllowsConfiguredCIDRAndExactIP(t *testing.T) {
	tmp := writeTempAllowFiles(t, "198.51.100.0/24\n203.0.113.77\n", "")
	cfg := &cfgpkg.Config{}
	mw := IPAllowMiddleware(cfg, tmp)
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, tc := range []string{"198.51.100.99", "203.0.113.77"} {
		t.Run(tc, func(t *testing.T) {
			rr := runIPAllowRequest(t, next, net.JoinHostPort(tc, "1111"), "")
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestIPAllowMiddleware_AllowsResolvedDYNDNSAndAPIURLHost(t *testing.T) {
	tmp := writeTempAllowFiles(t, "", "dyn.example\n")
	withStubbedLookup(t, func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "dyn.example":
			return []net.IP{net.ParseIP("203.0.113.8")}, nil
		case "api.example":
			return []net.IP{net.ParseIP("203.0.113.9")}, nil
		default:
			return nil, nil
		}
	})

	cfg := &cfgpkg.Config{}
	cfg.API.URL = "https://api.example:8443"

	mw := IPAllowMiddleware(cfg, tmp)
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, tc := range []string{"203.0.113.8", "203.0.113.9"} {
		t.Run(tc, func(t *testing.T) {
			rr := runIPAllowRequest(t, next, net.JoinHostPort(tc, "2222"), "")
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestIPAllowMiddleware_RejectsUnknownIPWith403(t *testing.T) {
	cfg := &cfgpkg.Config{}
	mw := IPAllowMiddleware(cfg, t.TempDir())
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rr := runIPAllowRequest(t, next, "203.0.113.55:33333", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type=%q", got)
	}
}

func TestIPAllowMiddleware_ProxyTrustBoundary(t *testing.T) {
	tmp := writeTempAllowFiles(t, "198.51.100.10\n", "")
	cfg := &cfgpkg.Config{}
	mw := IPAllowMiddleware(cfg, tmp)
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("loopback peer honors first XFF hop", func(t *testing.T) {
		rr := runIPAllowRequest(t, next, "127.0.0.1:12345", "198.51.100.10, 127.0.0.1")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("non-loopback peer ignores spoofed XFF", func(t *testing.T) {
		rr := runIPAllowRequest(t, next, "203.0.113.55:12345", "198.51.100.10")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestIPAllowMiddleware_DeniedRequestsDoNotReachProtectedHandler(t *testing.T) {
	cfg := &cfgpkg.Config{}
	var called atomic.Int32
	mw := IPAllowMiddleware(cfg, t.TempDir())
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))

	rr := runIPAllowRequest(t, next, "203.0.113.201:4444", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := called.Load(); got != 0 {
		t.Fatalf("protected handler should not be called, got=%d", got)
	}
}

func TestIPAllowMiddleware_LogsStableRejectionReasonCode(t *testing.T) {
	cfg := &cfgpkg.Config{}
	mw := IPAllowMiddleware(cfg, t.TempDir())
	next := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	out := captureStdout(t, func() {
		_ = runIPAllowRequest(t, next, "203.0.113.250:5555", "")
	})

	if !strings.Contains(out, "event=api_audit") {
		t.Fatalf("expected api audit event in log output, got: %q", out)
	}
	if !strings.Contains(out, "reason=source_ip_not_allowlisted") {
		t.Fatalf("expected stable reason code in log output, got: %q", out)
	}
}

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
