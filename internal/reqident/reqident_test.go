package reqident

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFromRequest_LoopbackEdgeTrustsForwarded(t *testing.T) {
	// Edge hop: loopback peer, edge authored a single canonical client IP and
	// scheme. This is every live CFM path (apiserver control plane AND the
	// challenge server, both reached only from 127.0.0.1 by the edge).
	r := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	r.RemoteAddr = "127.0.0.1:41000"
	r.Header.Set("X-Real-IP", "203.0.113.10")
	r.Header.Set("X-Forwarded-For", "203.0.113.10")
	r.Header.Set("X-Forwarded-Proto", "https")

	p := FromRequest(r)
	if p.ClientIP.String() != "203.0.113.10" {
		t.Fatalf("ClientIP = %v, want 203.0.113.10", p.ClientIP)
	}
	if !p.TrustedProxy {
		t.Fatal("TrustedProxy should be true for a loopback edge with a canonical forwarded IP")
	}
	if p.Scheme != "https" {
		t.Fatalf("Scheme = %q, want https", p.Scheme)
	}
	if ClientIPString(r) != "203.0.113.10" {
		t.Fatalf("ClientIPString = %q, want 203.0.113.10", ClientIPString(r))
	}
}

func TestFromRequest_DirectPeerIgnoresForgedHeaders(t *testing.T) {
	// A direct (non-loopback) client cannot spoof identity or scheme. This is the
	// property that makes it safe to mount the challenge handlers on a public
	// listener (audit Step 2): forged X-Real-IP / X-Forwarded-For /
	// X-Forwarded-Proto from a non-loopback peer are ignored.
	r := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	r.RemoteAddr = "198.51.100.20:42000"
	r.Header.Set("X-Real-IP", "8.8.8.8")
	r.Header.Set("X-Forwarded-For", "8.8.8.8")
	r.Header.Set("X-Forwarded-Proto", "https")

	p := FromRequest(r)
	if p.ClientIP.String() != "198.51.100.20" {
		t.Fatalf("ClientIP = %v, want the real socket peer 198.51.100.20", p.ClientIP)
	}
	if p.TrustedProxy {
		t.Fatal("TrustedProxy must be false for a direct non-loopback peer")
	}
	if p.Scheme != "http" {
		t.Fatalf("Scheme = %q, want http (forged X-Forwarded-Proto ignored, no r.TLS)", p.Scheme)
	}
}

func TestFromRequest_DirectTLSSchemeFromConn(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://host/", nil) // sets r.TLS
	r.RemoteAddr = "198.51.100.21:43000"
	r.Header.Set("X-Forwarded-Proto", "http") // forged downgrade, must be ignored

	p := FromRequest(r)
	if p.ClientIP.String() != "198.51.100.21" || p.Scheme != "https" || p.TrustedProxy {
		t.Fatalf("direct TLS peer = %+v, want ClientIP=198.51.100.21 Scheme=https TrustedProxy=false", p)
	}
}

func TestFromRequest_LoopbackAmbiguousFailsClosed(t *testing.T) {
	// A loopback edge that forwards a multi-hop chain (should have been collapsed
	// to one IP) or an unparseable value fails closed to ClientIP=nil rather than
	// guessing or inheriting loopback's trust.
	chain := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	chain.RemoteAddr = "127.0.0.1:41000"
	chain.Header.Set("X-Forwarded-For", "8.8.8.8, 203.0.113.10")
	chain.Header.Set("X-Forwarded-Proto", "https")
	if p := FromRequest(chain); p.ClientIP != nil || p.TrustedProxy || p.Scheme != "http" {
		t.Fatalf("ambiguous chain = %+v, want ClientIP=nil TrustedProxy=false Scheme=http", p)
	}
	if ClientIPString(chain) != "" {
		t.Fatalf("ClientIPString = %q, want empty for a fail-closed identity", ClientIPString(chain))
	}

	badRealIP := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	badRealIP.RemoteAddr = "127.0.0.1:41000"
	badRealIP.Header.Set("X-Real-IP", "not-an-ip")
	badRealIP.Header.Set("X-Forwarded-For", "203.0.113.10")
	if p := FromRequest(badRealIP); p.ClientIP != nil || p.TrustedProxy {
		t.Fatalf("malformed higher-priority X-Real-IP must fail closed: %+v", p)
	}
}

func TestFromRequest_LoopbackNoForwardedIsLoopbackItself(t *testing.T) {
	// Loopback peer with no forwarded identity (e.g. local tooling) resolves to
	// loopback itself, not nil.
	r := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	p := FromRequest(r)
	if p.ClientIP == nil || !p.ClientIP.IsLoopback() || p.TrustedProxy {
		t.Fatalf("loopback with no forwarded identity = %+v, want loopback ClientIP, TrustedProxy=false", p)
	}
	if HasForwardedClientIdentity(r) {
		t.Fatal("HasForwardedClientIdentity should be false with no X-Real-IP/X-Forwarded-For")
	}
}

func TestFromRequest_SchemeXFPOnlyUnderLoopback(t *testing.T) {
	// X-Forwarded-Proto is honored only across the loopback edge hop.
	loop := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	loop.RemoteAddr = "127.0.0.1:41000"
	loop.Header.Set("X-Real-IP", "203.0.113.10")
	loop.Header.Set("X-Forwarded-Proto", "https")
	if got := FromRequest(loop).Scheme; got != "https" {
		t.Fatalf("loopback XFP=https Scheme = %q, want https", got)
	}

	// XFP with a comma is not canonical → ignored.
	comma := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	comma.RemoteAddr = "127.0.0.1:41000"
	comma.Header.Set("X-Real-IP", "203.0.113.10")
	comma.Header.Set("X-Forwarded-Proto", "https, http")
	if got := FromRequest(comma).Scheme; got != "http" {
		t.Fatalf("non-canonical XFP Scheme = %q, want http", got)
	}
}

func TestFromRequest_NilRequest(t *testing.T) {
	p := FromRequest(nil)
	if p.ClientIP != nil || p.Scheme != "http" || p.TrustedProxy {
		t.Fatalf("nil request = %+v, want zero Peer with Scheme=http", p)
	}
	if ClientIPString(nil) != "" || HasForwardedClientIdentity(nil) {
		t.Fatal("nil request helpers must be safe and empty")
	}
}
