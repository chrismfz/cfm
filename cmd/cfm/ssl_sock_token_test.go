package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/hostsecrets"
	"cfm/internal/sslcollector"
)

// The CLI sends the token the edge has (cfm_token.lua), which is the one the
// daemon serves even when it could not store it; the store is the fallback.
func TestSSLSockTokenPrefersTheEdgeCopy(t *testing.T) {
	dir := t.TempDir()
	defer hostsecrets.SetDirForTest(filepath.Join(dir, "secrets"))()
	lua := filepath.Join(dir, "cfm_token.lua")
	stored := strings.Repeat("a1", 24)
	served := strings.Repeat("b2", 20) + `;x#"y\z`

	// No edge copy, no store: the cfm.conf value is what the daemon would copy.
	if got := sslSockToken(lua, stored); got != stored {
		t.Fatalf("no edge copy, no store: got %q, want the cfm.conf value", got)
	}
	if _, _, err := hostsecrets.Resolve(hostsecrets.SSLCollectorToken, stored); err != nil {
		t.Fatal(err)
	}
	if got := sslSockToken(lua, "placeholder"); got != stored {
		t.Fatalf("no edge copy: got %q, want the stored token", got)
	}
	// An edge copy that holds no usable token is skipped.
	if err := os.WriteFile(lua, []byte("return \"placeholder\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sslSockToken(lua, "placeholder"); got != stored {
		t.Fatalf("weak edge copy: got %q, want the stored token", got)
	}
	// The daemon's own write is read back verbatim, ';', '#', '"' and '\' included.
	if err := sslcollector.WriteLuaToken(lua, served, 0); err != nil {
		t.Fatal(err)
	}
	if got := sslSockToken(lua, "placeholder"); got != served {
		t.Fatalf("edge copy: got %q, want %q", got, served)
	}
}
