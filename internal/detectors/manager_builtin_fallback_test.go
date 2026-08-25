package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

// A broken OVERLAY on first load must degrade to the base config only — never
// to builtin-only mode, which is reserved for a base file that itself cannot
// be read. While running, the same error keeps the current detectors.
func TestReadSectionsForReloadBrokenOverlayFirstLoadUsesBase(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "detectors.conf")
	if err := os.WriteFile(base, []byte("[ssh_auth]\nENABLED = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	original := readLayered
	readLayered = func(string, string) (Sections, []byte, error) {
		return Sections{}, nil, os.ErrPermission // simulated unreadable overlay
	}
	t.Cleanup(func() { readLayered = original })

	secs, err, fallback := readSectionsForReload(base, false)
	if err != nil || fallback {
		t.Fatalf("first load with parseable base: err=%v fallback=%t, want base-only start", err, fallback)
	}
	if _, ok := secs.ByName["ssh_auth"]; !ok {
		t.Fatalf("base sections lost: %+v", secs.ByName)
	}

	if _, err, fallback := readSectionsForReload(base, true); fallback || !os.IsPermission(err) {
		t.Fatalf("running: fallback=%t err=%v, want keep-current posture", fallback, err)
	}
}

func TestReadSectionsForReloadFallsBackOnFirstLoadPermissionError(t *testing.T) {
	original := readLayered
	readLayered = func(string, string) (Sections, []byte, error) {
		return Sections{}, nil, os.ErrPermission
	}
	t.Cleanup(func() { readLayered = original })

	secs, err, fallback := readSectionsForReload("/unreadable/detectors.conf", false)
	if !fallback || !os.IsPermission(err) {
		t.Fatalf("first load fallback=%t err=%v, want permission-error fallback", fallback, err)
	}
	applyBuiltinCFMEndpoints(&secs)
	if !kvBool(secs.ByName[cfmEndpointsType], "ENABLED", false) {
		t.Fatal("first-load read error did not produce built-in CFM endpoint protection")
	}

	if _, err, fallback := readSectionsForReload("/unreadable/detectors.conf", true); fallback || !os.IsPermission(err) {
		t.Fatalf("reload fallback=%t err=%v, want existing detectors retained", fallback, err)
	}
}
