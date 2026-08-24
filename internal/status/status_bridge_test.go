package status

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type fakeFileInfo struct {
	mode fs.FileMode
}

func (f fakeFileInfo) Name() string       { return "sock" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Now() }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func withBridgeTestHooks(t *testing.T) {
	t.Helper()
	oldDetectorsPath := detectorsConfigPath
	oldSocketStat := socketStat
	oldSocketProbe := bridgeSocketProbe
	oldTokenPath := canonicalBridgeTokenPath
	t.Cleanup(func() {
		detectorsConfigPath = oldDetectorsPath
		socketStat = oldSocketStat
		bridgeSocketProbe = oldSocketProbe
		canonicalBridgeTokenPath = oldTokenPath
	})
}

func TestBridgeConfigConfiguredSocketAndSuccessfulProbe(t *testing.T) {
	withBridgeTestHooks(t)
	tmp := t.TempDir()
	detectorsConfigPath = filepath.Join(tmp, "detectors.conf")
	if err := os.WriteFile(detectorsConfigPath, []byte("[webdetector]\nOPENRESTY_MODE=1\nOPENRESTY_SOCK=/var/run/cfm/cfm_nginx.sock\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := resolveBridgeRuntimeConfig()
	if cfg.SocketPath != "/var/run/cfm/cfm_nginx.sock" || cfg.SocketSource != "config" || !cfg.Enabled {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}

	socketStat = func(path string) (os.FileInfo, error) {
		if path == cfg.SocketPath {
			return fakeFileInfo{mode: os.ModeSocket | 0o660}, nil
		}
		return nil, os.ErrNotExist
	}
	bridgeSocketProbe = func(sockPath, token string) (int, string, error) {
		if sockPath != cfg.SocketPath {
			t.Fatalf("probe used wrong socket path: %s", sockPath)
		}
		if token == "" {
			t.Fatalf("expected token")
		}
		return 200, "json ok", nil
	}

	got := probeBridgeRuntime(cfg, luaTokenProbe{Token: "abcdefghijklmnopqrstuvwxyz012345", Present: true, Valid: true})
	if got.Status != "OK" {
		t.Fatalf("expected OK, got %+v", got)
	}
}

func TestBridgeConfigAbsentUsesFallback(t *testing.T) {
	withBridgeTestHooks(t)
	tmp := t.TempDir()
	detectorsConfigPath = filepath.Join(tmp, "detectors.conf")
	if err := os.WriteFile(detectorsConfigPath, []byte("[webdetector]\nOPENRESTY_MODE=1\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	socketStat = func(path string) (os.FileInfo, error) {
		return nil, os.ErrNotExist
	}
	cfg := resolveBridgeRuntimeConfig()
	if cfg.SocketPath != "/var/run/cfm/cfm_nginx.sock" || cfg.SocketSource != "fallback" {
		t.Fatalf("unexpected fallback cfg: %+v", cfg)
	}
}

func TestBridgeProbeUsesConfiguredPathNotLegacyFallback(t *testing.T) {
	withBridgeTestHooks(t)
	tmp := t.TempDir()
	detectorsConfigPath = filepath.Join(tmp, "detectors.conf")
	if err := os.WriteFile(detectorsConfigPath, []byte("[webdetector]\nOPENRESTY_MODE=1\nOPENRESTY_SOCK=/var/run/cfm/cfm_nginx.sock\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg := resolveBridgeRuntimeConfig()

	socketStat = func(path string) (os.FileInfo, error) {
		if path == "/var/run/cfm/cfm_nginx.sock" {
			return fakeFileInfo{mode: os.ModeSocket | 0o660}, nil
		}
		return nil, os.ErrNotExist
	}
	bridgeSocketProbe = func(sockPath, token string) (int, string, error) {
		if sockPath != "/var/run/cfm/cfm_nginx.sock" {
			return 0, "", errors.New("used wrong path")
		}
		return 200, "json ok", nil
	}

	got := probeBridgeRuntime(cfg, luaTokenProbe{Token: "abcdefghijklmnopqrstuvwxyz012345", Present: true, Valid: true})
	if got.Status != "OK" {
		t.Fatalf("expected OK with configured socket, got %+v", got)
	}
}

func TestBridgeTokenSpecificStatuses(t *testing.T) {
	withBridgeTestHooks(t)
	cfg := bridgeRuntimeConfig{Enabled: true, SocketPath: "/var/run/cfm/cfm_nginx.sock"}

	missing := probeBridgeRuntime(cfg, luaTokenProbe{})
	if missing.Status != "TOKEN_MISSING" {
		t.Fatalf("expected TOKEN_MISSING, got %+v", missing)
	}

	invalid := probeBridgeRuntime(cfg, luaTokenProbe{Present: true})
	if invalid.Status != "TOKEN_INVALID" {
		t.Fatalf("expected TOKEN_INVALID, got %+v", invalid)
	}
}

func TestBridgeTokenProbeRequiresCanonicalFile(t *testing.T) {
	withBridgeTestHooks(t)
	canonicalBridgeTokenPath = filepath.Join(t.TempDir(), "missing-bridge-token.lua")
	t.Setenv("OPENRESTY_TOKEN", "abcdefghijklmnopqrstuvwxyz012345")
	t.Setenv("BRIDGE_TOKEN", "012345abcdefghijklmnopqrstuvwxyz")

	got := readBridgeTokenProbe()
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

	got := readLuaToken(path)
	if !got.Present || !got.Valid || got.Token != token {
		t.Fatalf("readLuaToken() = %+v, want valid token %q", got, token)
	}
}
