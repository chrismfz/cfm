package sslcollector

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestWriteLuaTokenMissingParentDir(t *testing.T) {
	t.Parallel()

	luaPath := filepath.Join(t.TempDir(), "missing", "cfm_token.lua")
	err := WriteLuaToken(luaPath, "abc123", 0)
	if err == nil {
		t.Fatalf("expected error for missing parent dir, got nil")
	}
	if !strings.Contains(err.Error(), "missing parent directory") {
		t.Fatalf("expected missing parent directory error, got: %v", err)
	}
	if !strings.Contains(err.Error(), luaPath) {
		t.Fatalf("expected error to include target path %q, got: %v", luaPath, err)
	}
}

func TestWriteLuaTokenSuccessWhenDirExists(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "lua")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	luaPath := filepath.Join(dir, "cfm_token.lua")
	if err := WriteLuaToken(luaPath, "tok123", 0); err != nil {
		t.Fatalf("WriteLuaToken: %v", err)
	}

	data, err := os.ReadFile(luaPath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, `return "tok123"`) {
		t.Fatalf("unexpected lua token content: %q", got)
	}
}

func TestWriteLuaTokenFinalModeAndOwnershipUnchangedBehavior(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	luaPath := filepath.Join(dir, "cfm_token.lua")
	if err := WriteLuaToken(luaPath, "tok123", 0); err != nil {
		t.Fatalf("WriteLuaToken: %v", err)
	}

	info, err := os.Stat(luaPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o640 {
		t.Fatalf("mode mismatch: got %o want %o", mode, 0o640)
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("unexpected stat type %T", info.Sys())
	}
	if int(st.Gid) != os.Getgid() {
		t.Fatalf("gid mismatch: got %d want current gid %d", st.Gid, os.Getgid())
	}
}
