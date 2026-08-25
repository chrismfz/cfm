package apiserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type transportNextSpy struct{ called bool }

func (n *transportNextSpy) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		n.called = true
		w.WriteHeader(http.StatusOK)
	}
}

// transportReq builds a request as if it arrived on the given local listener
// address from the given remote peer, with optional headers.
func transportReq(method, rawurl, localAddr, remoteAddr string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, rawurl, nil)
	r.RemoteAddr = remoteAddr
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return withLocalAddr(r, localAddr)
}

func runTransport(tlsPort int, tlsReady bool, r *http.Request) (*httptest.ResponseRecorder, bool) {
	spy := &transportNextSpy{}
	h := AdminTransportRedirect(spy.handler(), tlsPort, func() bool { return tlsReady })
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	return rr, spy.called
}

const htmlAccept = "text/html,application/xhtml+xml"

func TestAdminTransportRedirect_UpgradesDirectExternalBrowserGET(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		r := transportReq(m, "http://host:6060/cfm-admin/x?q=1", "0.0.0.0:6060", "198.51.100.5:5000",
			map[string]string{"Accept": htmlAccept})
		rr, nextCalled := runTransport(6061, true, r)
		if nextCalled {
			t.Fatalf("%s: next ran; request should have been redirected", m)
		}
		if rr.Code != http.StatusFound {
			t.Fatalf("%s: code = %d, want 302", m, rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "https://host:6061/cfm-admin/x?q=1" {
			t.Fatalf("%s: Location = %q, want https://host:6061/cfm-admin/x?q=1 (URI preserved)", m, got)
		}
	}
}

func TestAdminTransportRedirect_RejectsDirectExternalUnsafeMethod(t *testing.T) {
	// A login POST over direct plaintext must be refused, not processed and not
	// method-redirected (which would re-send the already-leaked body).
	r := transportReq(http.MethodPost, "http://host:6060/cfm-admin/login", "0.0.0.0:6060", "198.51.100.5:5000",
		map[string]string{"Accept": htmlAccept})
	rr, nextCalled := runTransport(6061, true, r)
	if nextCalled {
		t.Fatal("next ran; an unsafe plaintext admin request must not be processed")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rr.Code)
	}
	if rr.Header().Get("Location") != "" {
		t.Fatalf("unsafe method must not be redirected, got Location=%q", rr.Header().Get("Location"))
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("403 Content-Type = %q, want application/json", ct)
	}
}

func TestAdminTransportRedirect_RefusesUnsafeEvenWhenDegraded(t *testing.T) {
	// LOW-1 hardening: a plaintext admin WRITE must be refused regardless of TLS
	// state or Host — it must never slip into the degraded pass-through and be
	// processed over cleartext. Covers the three ways the degraded branch is
	// reachable: empty Host (even with TLS ready), TLS not ready, invalid TLS port.
	newPOST := func() *http.Request {
		return transportReq(http.MethodPost, "http://host:6060/cfm-admin/login", "0.0.0.0:6060", "198.51.100.5:5000",
			map[string]string{"Accept": htmlAccept})
	}

	// (a) empty Host, TLS ready — previously slipped through to next as plaintext.
	ra := newPOST()
	ra.Host = ""
	if rr, nextCalled := runTransport(6061, true, ra); nextCalled || rr.Code != http.StatusForbidden {
		t.Fatalf("empty-Host POST must be 403 not processed (next=%v code=%d)", nextCalled, rr.Code)
	}

	// (b) TLS not ready.
	if rr, nextCalled := runTransport(6061, false, newPOST()); nextCalled || rr.Code != http.StatusForbidden {
		t.Fatalf("TLS-down POST must be 403 not processed (next=%v code=%d)", nextCalled, rr.Code)
	}

	// (c) invalid TLS port (TLS effectively disabled) — still refuse, generic body.
	if rr, nextCalled := runTransport(0, true, newPOST()); nextCalled || rr.Code != http.StatusForbidden {
		t.Fatalf("invalid-TLS-port POST must be 403 not processed (next=%v code=%d)", nextCalled, rr.Code)
	}
}

func TestAdminTransportRedirect_RejectsAllUnsafeMethods(t *testing.T) {
	// Every non-safe method on a direct external plaintext admin route must be
	// refused with 403 and never redirected — guards against someone widening the
	// GET/HEAD redirect case to include a body-bearing method.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		r := transportReq(m, "http://host:6060/cfm-admin/x", "0.0.0.0:6060", "198.51.100.5:5000",
			map[string]string{"Accept": htmlAccept})
		rr, nextCalled := runTransport(6061, true, r)
		if nextCalled {
			t.Fatalf("%s: next ran; an unsafe plaintext admin request must not be processed", m)
		}
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s: code = %d, want 403", m, rr.Code)
		}
		if rr.Header().Get("Location") != "" {
			t.Fatalf("%s: unsafe method must not be redirected, got Location=%q", m, rr.Header().Get("Location"))
		}
	}
}

func TestAdminTransportRedirect_MachineAPIWriteLeftAsIs(t *testing.T) {
	// Design §6a: a direct-external machine /api/v1 WRITE (no Accept: text/html) is
	// not a browser admin route, so it passes through untouched — R01 closure for
	// the machine API rests on the loopback bind default, not this middleware. This
	// pins that boundary so an accidental flip in either direction is caught.
	r := transportReq(http.MethodPost, "http://host:6060/api/v1/firewall/block", "0.0.0.0:6060", "198.51.100.5:5000",
		map[string]string{"Accept": "*/*"})
	rr, nextCalled := runTransport(6061, true, r)
	if !nextCalled || rr.Code != http.StatusOK {
		t.Fatalf("machine /api/v1 write must pass through (next=%v code=%d)", nextCalled, rr.Code)
	}
	if rr.Header().Get("Location") != "" {
		t.Fatalf("machine /api/v1 write must not be redirected, got Location=%q", rr.Header().Get("Location"))
	}
}

func TestAdminTransportRedirect_EdgeBackendWriteNeverRedirected(t *testing.T) {
	// A legitimate admin WRITE arriving via the edge (loopback peer + forwarded id →
	// Entry "edge") must be served, never 403'd — the public :443 admin UI does POSTs
	// and they must not be broken by the transport guard.
	r := transportReq(http.MethodPost, "http://host/cfm-admin/waf/exclude/add", "0.0.0.0:6060", "127.0.0.1:41000",
		map[string]string{"Accept": htmlAccept, "X-Real-IP": "203.0.113.9", "X-Forwarded-Proto": "https"})
	rr, nextCalled := runTransport(6061, true, r)
	if !nextCalled || rr.Code != http.StatusOK {
		t.Fatalf("edge admin write must be served (next=%v code=%d)", nextCalled, rr.Code)
	}
}

func TestAdminTransportRedirect_EdgeBackendNeverRedirected(t *testing.T) {
	// The public :443 browser via the edge arrives at loopback:6060 with forwarded
	// identity → Entry "edge" → must be served, never bounced to :6061.
	r := transportReq(http.MethodGet, "http://host/cfm-admin/", "0.0.0.0:6060", "127.0.0.1:41000",
		map[string]string{"Accept": htmlAccept, "X-Real-IP": "203.0.113.9", "X-Forwarded-Proto": "https"})
	rr, nextCalled := runTransport(6061, true, r)
	if !nextCalled || rr.Code != http.StatusOK {
		t.Fatalf("edge request must be served (next=%v code=%d)", nextCalled, rr.Code)
	}
}

func TestAdminTransportRedirect_LoopbackDirectExempt(t *testing.T) {
	// Local CLI/curl to loopback:6060 (no forwarded id) — plaintext never hits the
	// wire, so it is served, not redirected.
	r := transportReq(http.MethodGet, "http://127.0.0.1:6060/cfm-admin/", "127.0.0.1:6060", "127.0.0.1:5000",
		map[string]string{"Accept": htmlAccept})
	rr, nextCalled := runTransport(6061, true, r)
	if !nextCalled || rr.Code != http.StatusOK {
		t.Fatalf("loopback direct must be served (next=%v code=%d)", nextCalled, rr.Code)
	}
}

func TestAdminTransportRedirect_MachineAPILeftAsIs(t *testing.T) {
	// Direct external /api/v1 without Accept: text/html (a machine client) is not a
	// browser admin route → left as-is (design §6a).
	r := transportReq(http.MethodGet, "http://host:6060/api/v1/system/status", "0.0.0.0:6060", "198.51.100.5:5000", nil)
	rr, nextCalled := runTransport(6061, true, r)
	if !nextCalled || rr.Code != http.StatusOK {
		t.Fatalf("machine /api/v1 must be served (next=%v code=%d)", nextCalled, rr.Code)
	}
}

func TestAdminTransportRedirect_TLSListenerNeverRedirected(t *testing.T) {
	// A request already on the :6061 TLS listener (Entry "6061") passes through.
	r := transportReq(http.MethodGet, "https://host:6061/cfm-admin/", "0.0.0.0:6061", "198.51.100.5:5000",
		map[string]string{"Accept": htmlAccept})
	rr, nextCalled := runTransport(6061, true, r)
	if !nextCalled || rr.Code != http.StatusOK {
		t.Fatalf(":6061 request must be served (next=%v code=%d)", nextCalled, rr.Code)
	}
}

func TestAdminTransportRedirect_DegradedWhenTLSNotReady(t *testing.T) {
	// TLS not yet bound → serve over HTTP (degraded), don't redirect to a dead port.
	r := transportReq(http.MethodGet, "http://host:6060/cfm-admin/", "0.0.0.0:6060", "198.51.100.5:5000",
		map[string]string{"Accept": htmlAccept})
	rr, nextCalled := runTransport(6061, false, r)
	if !nextCalled || rr.Code != http.StatusOK {
		t.Fatalf("degraded fallback must serve over HTTP (next=%v code=%d)", nextCalled, rr.Code)
	}
	if rr.Header().Get("Location") != "" {
		t.Fatal("must not redirect when TLS is not ready")
	}
}

func TestAdminTransportRedirect_DegradedWhenTLSPortInvalidOrNoHost(t *testing.T) {
	// Invalid TLS port → no trustworthy target → degraded serve.
	r := transportReq(http.MethodGet, "http://host:6060/cfm-admin/", "0.0.0.0:6060", "198.51.100.5:5000",
		map[string]string{"Accept": htmlAccept})
	if rr, nextCalled := runTransport(0, true, r); !nextCalled || rr.Header().Get("Location") != "" {
		t.Fatalf("invalid TLS port must degrade, not redirect (next=%v loc=%q)", nextCalled, rr.Header().Get("Location"))
	}

	// Empty Host → cannot build a target → degraded serve.
	r2 := transportReq(http.MethodGet, "http://host:6060/cfm-admin/", "0.0.0.0:6060", "198.51.100.5:5000",
		map[string]string{"Accept": htmlAccept})
	r2.Host = ""
	if rr, nextCalled := runTransport(6061, true, r2); !nextCalled || rr.Header().Get("Location") != "" {
		t.Fatalf("empty Host must degrade, not redirect (next=%v loc=%q)", nextCalled, rr.Header().Get("Location"))
	}
}

func TestAdminTransportRedirect_IgnoresForwardedHostFromDirectClient(t *testing.T) {
	// The redirect target host comes from r.Host, never a forged X-Forwarded-Host.
	r := transportReq(http.MethodGet, "http://real.example:6060/cfm-admin/", "0.0.0.0:6060", "198.51.100.5:5000",
		map[string]string{"Accept": htmlAccept, "X-Forwarded-Host": "evil.example"})
	rr, _ := runTransport(6061, true, r)
	if got := rr.Header().Get("Location"); got != "https://real.example:6061/cfm-admin/" {
		t.Fatalf("Location = %q, want the real Host, not the forged X-Forwarded-Host", got)
	}
}

func TestAdminTransportRedirect_IPv6HostTarget(t *testing.T) {
	r := transportReq(http.MethodGet, "http://[2001:db8::1]:6060/cfm-admin/", "0.0.0.0:6060", "198.51.100.5:5000",
		map[string]string{"Accept": htmlAccept})
	rr, _ := runTransport(6061, true, r)
	if got := rr.Header().Get("Location"); got != "https://[2001:db8::1]:6061/cfm-admin/" {
		t.Fatalf("Location = %q, want bracketed IPv6 host with :6061", got)
	}
}

func TestHTTPBindAddr(t *testing.T) {
	// The secure default (R01): an unset LISTEN_ADDRESS binds loopback, never the
	// wildcard; an explicit value — including the 0.0.0.0/:: opt-in — is unchanged.
	cases := []struct{ in, want string }{
		{"", "127.0.0.1"},
		{"   ", "127.0.0.1"},
		{"0.0.0.0", "0.0.0.0"},
		{"::", "::"},
		{"127.0.0.1", "127.0.0.1"},
		{"192.0.2.7", "192.0.2.7"},
	}
	for _, c := range cases {
		if got := HTTPBindAddr(c.in); got != c.want {
			t.Fatalf("HTTPBindAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
