package kernsec

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// KernsecLockPath is the advisory-lock file every mutating kernsec
// command flock()s before touching shared state. Two concurrent
// invocations (e.g. an admin running `cfm kernsec apply` while
// monitoring runs `cfm kernsec apply --check` racing with operator
// `cfm kernsec disable --purge`) are refused with a clear error
// rather than allowed to interleave writes to ConfPath / SysctlPath /
// ModprobePath / bootloader state / monitor units.
//
// Declared as var (not const) so tests can redirect it to per-test
// temp paths and avoid contention across the test suite.
var KernsecLockPath = "/run/lock/cfm-kernsec.lock"

// ErrKernsecLockHeld is returned by acquireKernsecLock when another
// process holds the advisory lock. CLI callers translate it to
// "kernsec X: another `cfm kernsec` command is already running" and
// exit non-zero.
var ErrKernsecLockHeld = errors.New("another `cfm kernsec` command is already running")

// acquireKernsecLock tries a non-blocking exclusive flock on
// KernsecLockPath. Returns a release func() that unlocks + closes the
// file; callers should `defer release()` immediately.
//
// Non-blocking by design: a stuck `apply` (e.g. waiting on grubby in
// a stalled subshell) shouldn't make a concurrent monitor invocation
// hang the timer. The operator gets a fast, clear "already running"
// signal and can investigate or retry.
//
// Creates the lock file with mode 0600 if absent. Parent directory
// is expected to exist on every supported platform (/run/lock is a
// systemd-tmpfiles standard); we fail loudly if it doesn't rather
// than auto-creating since the operator likely has a deeper
// configuration issue.
func acquireKernsecLock() (release func(), err error) {
	f, err := os.OpenFile(KernsecLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("kernsec lock: open %s: %w", KernsecLockPath, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (lock at %s)", ErrKernsecLockHeld, KernsecLockPath)
		}
		return nil, fmt.Errorf("kernsec lock: flock %s: %w", KernsecLockPath, err)
	}
	return func() {
		// Best-effort: unflock then close. Errors here are rare
		// (kernel-level oddity) and don't affect correctness — the
		// FD close releases the lock unconditionally per flock(2).
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
