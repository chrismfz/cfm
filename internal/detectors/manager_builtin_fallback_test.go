package detectors

import (
	"os"
	"testing"
)

func TestReadSectionsForReloadFallsBackOnFirstLoadPermissionError(t *testing.T) {
	original := readSections
	readSections = func(string) (Sections, []byte, error) {
		return Sections{}, nil, os.ErrPermission
	}
	t.Cleanup(func() { readSections = original })

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
