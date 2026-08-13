package apiserver

import (
	"net/http/httptest"
	"testing"
)

// A non-loopback caller must NOT be able to force the advertised scheme to https
// via X-Forwarded-Proto; only the loopback edge is trusted for forwarded headers.
func TestMCPRequestSchemeForwardedProtoTrust(t *testing.T) {
	// direct, non-loopback caller spoofing XFP → http (not trusted)
	r := httptest.NewRequest("GET", "/mcp", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := mcpRequestScheme(r); got != "http" {
		t.Errorf("non-loopback XFP spoof: scheme=%q, want http", got)
	}
	// loopback edge (sets prefix header) with XFP=https → https
	r2 := httptest.NewRequest("GET", "/mcp", nil)
	r2.RemoteAddr = "127.0.0.1:5555"
	r2.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	r2.Header.Set("X-Forwarded-Proto", "https")
	if got := mcpRequestScheme(r2); got != "https" {
		t.Errorf("loopback edge XFP: scheme=%q, want https", got)
	}
	// loopback edge, no XFP → https (edge terminates TLS)
	r3 := httptest.NewRequest("GET", "/mcp", nil)
	r3.RemoteAddr = "127.0.0.1:5555"
	r3.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	if got := mcpRequestScheme(r3); got != "https" {
		t.Errorf("loopback edge no-XFP: scheme=%q, want https", got)
	}
}

func TestMCPTokenUsable(t *testing.T) {
	cases := []struct {
		name string
		tok  string
		want bool
	}{
		{"empty", "", false},
		{"whitespace", "       ", false},
		{"too short", "short-token", false},
		{"exactly min", "abcdefghijklmnopqrstuvwx", true}, // 24 chars
		{"strong", "cfm-mcp-3f9a2b7c8d1e4f6a9b0c2d5e", true},
		{"padded but short", "  abc  ", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mcpTokenUsable(c.tok); got != c.want {
				t.Errorf("mcpTokenUsable(%q) = %v, want %v", c.tok, got, c.want)
			}
		})
	}
}

// The /mcp static bearer must accept BOTH the MCP_TOKEN and the admin AUTH_TOKEN
// (so a fleet gateway holding AUTH_TOKEN can reach /mcp without a separate
// MCP_TOKEN), reject anything else, and never match an empty bearer even when a
// configured token is somehow empty (ConstantTimeCompare("","") is true).
func TestMCPStaticBearer(t *testing.T) {
	const mcpTok = "cfm-mcp-3f9a2b7c8d1e4f6a9b0c2d5e"
	const adminTok = "cfm-admin-1a2b3c4d5e6f7a8b9c0d1e2f"

	cases := []struct {
		name          string
		tok, m, a     string
		want          bool
	}{
		{"mcp token", mcpTok, mcpTok, adminTok, true},
		{"admin token", adminTok, mcpTok, adminTok, true},
		{"wrong token", "nope", mcpTok, adminTok, false},
		{"empty bearer", "", mcpTok, adminTok, false},
		{"empty bearer, empty mcp", "", "", adminTok, false},   // must not match "" vs ""
		{"empty bearer, both empty", "", "", "", false},        // defensive
		{"admin accepted when mcp unset", adminTok, "", adminTok, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mcpStaticBearer(c.tok, c.m, c.a); got != c.want {
				t.Errorf("mcpStaticBearer(%q, m, a) = %v, want %v", c.tok, got, c.want)
			}
		})
	}
}
