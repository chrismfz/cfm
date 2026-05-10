package kernsec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTempLockPath redirects KernsecLockPath to a per-test temp path
// so tests don't contend on /run/lock/ (which would also be
// non-writable without root).
func withTempLockPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := KernsecLockPath
	KernsecLockPath = filepath.Join(dir, "cfm-kernsec.lock")
	t.Cleanup(func() { KernsecLockPath = orig })
	return KernsecLockPath
}

func TestAcquireKernsecLock_HappyPath(t *testing.T) {
	withTempLockPath(t)

	release, err := acquireKernsecLock()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if release == nil {
		t.Fatal("happy-path acquire returned nil release func")
	}
	release()
}

func TestAcquireKernsecLock_ContentionRefuses(t *testing.T) {
	withTempLockPath(t)

	// First acquire holds the lock for the rest of the test.
	release, err := acquireKernsecLock()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	t.Cleanup(release)

	// Second acquire on the same path within the same process must
	// fail with the documented error — flock(LOCK_EX|LOCK_NB) on an
	// already-locked file returns EWOULDBLOCK, which we translate
	// into ErrKernsecLockHeld.
	if _, err := acquireKernsecLock(); err == nil {
		t.Fatal("second acquire on held lock should have failed, got nil error")
	} else if !errors.Is(err, ErrKernsecLockHeld) {
		t.Errorf("expected ErrKernsecLockHeld, got %v", err)
	} else if !strings.Contains(err.Error(), "another `cfm kernsec` command") {
		t.Errorf("error should be operator-actionable: %v", err)
	}
}

func TestAcquireKernsecLock_ReleaseAllowsReacquire(t *testing.T) {
	withTempLockPath(t)

	first, err := acquireKernsecLock()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	first()

	// After release, a fresh acquire must succeed — release()
	// unflocks AND closes the fd.
	second, err := acquireKernsecLock()
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	second()
}

func TestAcquireKernsecLock_LockFileCreated(t *testing.T) {
	path := withTempLockPath(t)

	release, err := acquireKernsecLock()
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer release()

	// Lock file is created on first acquire even though the parent
	// dir was empty. (t.TempDir provides a real directory; production
	// systems have /run/lock pre-created by systemd-tmpfiles.)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock file %s should exist after acquire: %v", path, err)
	}
}
