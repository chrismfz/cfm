package apiserver

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	cfgpkg "cfm/internal/config"
)

func boolPtr(b bool) *bool { return &b }

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
	// loopback edge (sets canonical client identity) with XFP=https → https
	r2 := httptest.NewRequest("GET", "/mcp", nil)
	r2.RemoteAddr = "127.0.0.1:5555"
	r2.Header.Set("X-Real-IP", "198.51.100.10")
	r2.Header.Set("X-Forwarded-Proto", "https")
	if got := mcpRequestScheme(r2); got != "https" {
		t.Errorf("loopback edge XFP: scheme=%q, want https", got)
	}
	// An old live edge config with the trusted public prefix but no XFP keeps
	// advertising HTTPS for OAuth compatibility.
	r3 := httptest.NewRequest("GET", "/mcp", nil)
	r3.RemoteAddr = "127.0.0.1:5555"
	r3.Header.Set("X-Real-IP", "198.51.100.10")
	r3.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	if got := mcpRequestScheme(r3); got != "https" {
		t.Errorf("legacy loopback edge no-XFP: scheme=%q, want https", got)
	}
	// The fallback is narrow: no trusted public prefix means plain HTTP.
	r4 := httptest.NewRequest("GET", "/mcp", nil)
	r4.RemoteAddr = "127.0.0.1:5555"
	r4.Header.Set("X-Real-IP", "198.51.100.10")
	if got := mcpRequestScheme(r4); got != "http" {
		t.Errorf("loopback request no-prefix/no-XFP: scheme=%q, want http", got)
	}
	// Explicit HTTP from the current edge config remains authoritative.
	r5 := httptest.NewRequest("GET", "/mcp", nil)
	r5.RemoteAddr = "127.0.0.1:5555"
	r5.Header.Set("X-Real-IP", "198.51.100.10")
	r5.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	r5.Header.Set("X-Forwarded-Proto", "http")
	if got := mcpRequestScheme(r5); got != "http" {
		t.Errorf("explicit edge HTTP: scheme=%q, want http", got)
	}
	// Malformed client identity cannot unlock forwarded scheme trust.
	r6 := httptest.NewRequest("GET", "/mcp", nil)
	r6.RemoteAddr = "127.0.0.1:5555"
	r6.Header.Set("X-Forwarded-For", "198.51.100.10, 203.0.113.10")
	r6.Header.Set("X-Forwarded-Prefix", "/cfm-admin")
	r6.Header.Set("X-Forwarded-Proto", "https")
	if got := mcpRequestScheme(r6); got != "http" {
		t.Errorf("malformed edge identity: scheme=%q, want http", got)
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
		name      string
		tok, m, a string
		want      bool
	}{
		{"mcp token", mcpTok, mcpTok, adminTok, true},
		{"admin token", adminTok, mcpTok, adminTok, true},
		{"wrong token", "nope", mcpTok, adminTok, false},
		{"empty bearer", "", mcpTok, adminTok, false},
		{"empty bearer, empty mcp", "", "", adminTok, false}, // must not match "" vs ""
		{"empty bearer, both empty", "", "", "", false},      // defensive
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

// The default-ON arming policy: arm when AUTH_TOKEN is present (auto-generating
// a distinct MCP_TOKEN if none is configured); MCP=off is a hard kill switch;
// no AUTH_TOKEN, a weak explicit MCP_TOKEN, or an auto-generate failure all keep
// the server disabled.
func TestMCPArmToken(t *testing.T) {
	const strong = "cfm-mcp-3f9a2b7c8d1e4f6a9b0c2d5e" // >= 24
	const gen = "auto-generated-abcdefghijklmnop"     // 31 chars, >= 24
	okLoader := func() (string, error) { return gen, nil }
	failLoader := func() (string, error) { return "", errors.New("boom") }
	panicLoader := func() (string, error) { t.Fatal("loader must not be called when MCP_TOKEN is set"); return "", nil }

	cases := []struct {
		name        string
		cfg         cfgpkg.APIConfig
		loader      func() (string, error)
		wantOK      bool
		wantAutogen bool
		wantTok     string
	}{
		{"off kill-switch wins", cfgpkg.APIConfig{AuthToken: "admintok", MCPToken: strong, MCPEnabled: boolPtr(false)}, panicLoader, false, false, ""},
		{"no auth token", cfgpkg.APIConfig{MCPToken: strong}, panicLoader, false, false, ""},
		{"explicit strong token, default on", cfgpkg.APIConfig{AuthToken: "admintok", MCPToken: strong}, panicLoader, true, false, strong},
		{"explicit on, autogen", cfgpkg.APIConfig{AuthToken: "admintok", MCPEnabled: boolPtr(true)}, okLoader, true, true, gen},
		{"default on, no mcp token, autogen", cfgpkg.APIConfig{AuthToken: "admintok"}, okLoader, true, true, gen},
		{"autogen failure disables", cfgpkg.APIConfig{AuthToken: "admintok"}, failLoader, false, false, ""},
		{"weak explicit token disables", cfgpkg.APIConfig{AuthToken: "admintok", MCPToken: "short"}, panicLoader, false, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &cfgpkg.Config{API: c.cfg}
			tok, autogen, ok, reason := mcpArmToken(cfg, c.loader)
			if ok != c.wantOK {
				t.Fatalf("ok=%v want %v (reason=%q)", ok, c.wantOK, reason)
			}
			if !ok {
				if reason == "" {
					t.Errorf("disabled but empty reason")
				}
				return
			}
			if autogen != c.wantAutogen {
				t.Errorf("autogen=%v want %v", autogen, c.wantAutogen)
			}
			if c.wantTok != "" && tok != c.wantTok {
				t.Errorf("tok=%q want %q", tok, c.wantTok)
			}
		})
	}
}

// loadOrCreateMCPToken generates a strong token on first use, persists it 0600,
// and returns the SAME token on the next call (stable across restarts).
func TestLoadOrCreateMCPToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "mcp_token")

	first, err := loadOrCreateMCPToken(path)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if !mcpTokenUsable(first) {
		t.Errorf("generated token not usable (len=%d): %q", len(first), first)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode=%o want 0600", perm)
	}

	second, err := loadOrCreateMCPToken(path)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second != first {
		t.Errorf("token not stable across calls: %q vs %q", first, second)
	}

	if _, err := loadOrCreateMCPToken(""); err == nil {
		t.Errorf("empty path should error")
	}
}
