package webdetector

import (
	"net/http/httptest"
	"testing"
)

// Only the local edge may name the client: a direct peer that is not
// loopback/private (Cloudflare included - it connects to the edge, never
// here) gets no header trust, so it can't pick the IP the challenge server
// scores and blocks.
func TestClientIPTrustsHeadersOnlyFromLocalPeers(t *testing.T) {
	cases := []struct {
		name, peer, want string
	}{
		{"loopback edge", "127.0.0.1:40000", "198.51.100.7"},
		{"loopback v6 edge", "[::1]:40000", "198.51.100.7"},
		{"private edge (split setup)", "10.0.0.5:40000", "198.51.100.7"},
		{"Cloudflare peer", "104.16.0.1:40000", "104.16.0.1"},
		{"Cloudflare v6 peer", "[2606:4700::1]:40000", "2606:4700::1"},
		{"public peer", "203.0.114.9:40000", "203.0.114.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("CF-Connecting-IP", "198.51.100.7")
			r.Header.Set("X-Real-IP", "198.51.100.8")
			r.Header.Set("X-Forwarded-For", "198.51.100.9")
			got := clientIP(r)
			if got == nil || got.String() != tc.want {
				t.Fatalf("clientIP(peer %s) = %v, want %s", tc.peer, got, tc.want)
			}
		})
	}
}
