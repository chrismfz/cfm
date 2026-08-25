package webdetector

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFirewallBlockableIP guards the blast-radius rule for rlFirewallBlock: a
// self-protection ban is escalated to nft only for public addresses. If the
// loopback-only identity rule ever resolves a "client" to an infrastructure
// address (a misconfigured non-loopback front-end, a fail-closed identity), the
// escalation is skipped so we never nft-ban the edge / an LB / the host itself.
func TestFirewallBlockableIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.7", true},     // public v4
		{"2606:4700::1111", true}, // public v6
		{"100.64.0.1", true},      // CGNAT — a real client behind carrier NAT
		{"127.0.0.1", false},      // loopback
		{"::1", false},            // loopback v6
		{"10.0.0.1", false},       // RFC1918
		{"172.16.5.4", false},     // RFC1918
		{"192.168.1.1", false},    // RFC1918
		{"fd00::1", false},        // IPv6 ULA
		{"169.254.1.1", false},    // link-local
		{"fe80::1", false},        // link-local v6
		{"0.0.0.0", false},        // unspecified
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test setup: unparseable IP %q", tc.ip)
		}
		if got := firewallBlockableIP(ip); got != tc.want {
			t.Errorf("firewallBlockableIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if firewallBlockableIP(nil) {
		t.Error("firewallBlockableIP(nil) = true, want false")
	}
}

// These tests pin the challenge server to the shared loopback-only identity /
// scheme rule (internal/reqident). The exhaustive branch coverage lives in the
// reqident package; here we guard the challenge-server contract specifically —
// so a future reintroduction of a divergent clientIP()/trustedForwardedProto()
// (e.g. the retired DNAT-era CF/private trust) is caught.

func TestChallengeClientIP_LoopbackEdgeVsForgedDirect(t *testing.T) {
	// Live edge path: loopback peer, edge authored X-Real-IP → real client.
	edge := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	edge.RemoteAddr = "127.0.0.1:9098"
	edge.Header.Set("X-Real-IP", "203.0.113.7")
	edge.Header.Set("X-Forwarded-For", "203.0.113.7")
	if ip := clientIP(edge); ip == nil || ip.String() != "203.0.113.7" {
		t.Fatalf("edge clientIP = %v, want 203.0.113.7", ip)
	}

	// Direct (non-loopback) peer forging identity headers: headers ignored, the
	// real socket peer wins. This is the property that makes public direct
	// mounting (Step 2) safe.
	direct := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	direct.RemoteAddr = "198.51.100.30:5000"
	direct.Header.Set("X-Real-IP", "203.0.113.7")
	direct.Header.Set("CF-Connecting-IP", "203.0.113.7") // no longer trusted at all
	if ip := clientIP(direct); ip == nil || ip.String() != "198.51.100.30" {
		t.Fatalf("direct clientIP = %v, want the real socket peer 198.51.100.30", ip)
	}

	// Loopback edge that forwarded an ambiguous chain fails closed to nil;
	// callers treat that as "bad client ip".
	ambiguous := httptest.NewRequest(http.MethodGet, "http://host/", nil)
	ambiguous.RemoteAddr = "127.0.0.1:9098"
	ambiguous.Header.Set("X-Forwarded-For", "8.8.8.8, 203.0.113.7")
	if ip := clientIP(ambiguous); ip != nil {
		t.Fatalf("ambiguous forwarded chain clientIP = %v, want nil (fail closed)", ip)
	}
}

func TestChallengeScheme_EffectiveProtoDrivesSecureCookie(t *testing.T) {
	// trustedForwardedProto is what the cfm_chal / clearance / cfm_ok cookies use
	// for their Secure flag, so these cases also pin the Secure-flag behavior.
	// The live edge always authors X-Forwarded-Proto together with X-Real-IP, and
	// the canonical rule honors the forwarded scheme only alongside a trusted
	// forwarded client IP — so the loopback cases carry X-Real-IP as the edge does.
	cases := []struct {
		name    string
		peer    string
		tls     bool
		realip  string
		xfproto string
		want    string
	}{
		{name: "edge https", peer: "127.0.0.1:9098", realip: "203.0.113.7", xfproto: "https", want: "https"},
		{name: "edge http", peer: "127.0.0.1:9098", realip: "203.0.113.7", xfproto: "http", want: "http"},
		{name: "direct forged xfp ignored", peer: "198.51.100.30:5000", realip: "203.0.113.7", xfproto: "https", want: "http"},
		{name: "direct tls", peer: "198.51.100.30:5000", tls: true, xfproto: "http", want: "https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := "http://host/"
			if tc.tls {
				scheme = "https://host/"
			}
			r := httptest.NewRequest(http.MethodGet, scheme, nil)
			r.RemoteAddr = tc.peer
			if tc.realip != "" {
				r.Header.Set("X-Real-IP", tc.realip)
			}
			if tc.xfproto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.xfproto)
			}
			if got := trustedForwardedProto(r); got != tc.want {
				t.Fatalf("trustedForwardedProto = %q, want %q", got, tc.want)
			}
		})
	}
}
