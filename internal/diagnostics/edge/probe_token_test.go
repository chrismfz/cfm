package edge

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestReadBridgeTokenProbeRequiresCanonicalFile(t *testing.T) {
	t.Setenv("OPENRESTY_TOKEN", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("BRIDGE_TOKEN", "012345abcdefghijklmnopqrstuvwxyz")

	got := ReadBridgeTokenProbe(filepath.Join(t.TempDir(), "missing-bridge-token.lua"))
	if got.Present || got.Token != "" {
		t.Fatalf("expected missing canonical bridge file, got %+v", got)
	}
}

func TestReadLuaTokenDecodesCanonicalWriterEscapes(t *testing.T) {
	const token = `bridge-token-"quoted"-\path-0123456789abcdef`
	path := filepath.Join(t.TempDir(), "cfm_bridge_token.lua")
	if err := os.WriteFile(path, []byte("return "+strconv.Quote(token)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := ReadLuaToken(path)
	if !got.Present || !got.Valid || got.Token != token {
		t.Fatalf("ReadLuaToken() = %+v, want valid token %q", got, token)
	}
}
