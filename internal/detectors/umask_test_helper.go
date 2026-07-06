//go:build linux

package detectors

import "syscall"

// syscallUmask is a thin wrapper around syscall.Umask, isolated in its own
// file so ignore_test.go can flip the umask deterministically when verifying
// that IPIgnore.WriteLuaCache produces 0640 regardless of the daemon's
// inherited mask. syscall.Umask is global, so tests must restore the previous
// value via defer.
func syscallUmask(mask int) int { return syscall.Umask(mask) }
