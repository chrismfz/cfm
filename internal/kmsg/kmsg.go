// Package kmsg tails the kernel ring buffer (the `dmesg` view): OOM kills, I/O
// errors, segfaults, nftables drops, hardware/driver messages. It backs the
// read-only MCP tool `dmesg_tail` / GET /api/v1/system/dmesg — the "why did it
// crash / get OOM-killed / reset?" check that system_health can't answer.
//
// It shells out to util-linux `dmesg -T` (human timestamps); the ring buffer is
// bounded (~1 MB), so reading it whole and returning the last N lines is cheap —
// none of the I/O cost of a filesystem walk. Requires CAP_SYSLOG (the daemon
// runs privileged, like its smartctl/nft probes); a restricted kernel yields a
// clean error rather than partial data.
package kmsg

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

const dmesgTimeout = 5 * time.Second

// DefaultLines / MaxLines bound how much of the ring buffer we return.
const (
	DefaultLines = 80
	MaxLines     = 1000
)

// Tail returns the last `lines` kernel-ring lines (newest last), optionally
// keeping only lines that contain `grep` (case-insensitive). truncated is true
// when older lines were dropped to honour the limit.
func Tail(ctx context.Context, lines int, grep string) (out []string, truncated bool, err error) {
	cctx, cancel := context.WithTimeout(ctx, dmesgTimeout)
	defer cancel()

	raw, err := runDmesg(cctx)
	if err != nil {
		return nil, false, err
	}
	all := splitNonEmpty(string(raw))
	kept, truncated := tailFilter(all, lines, grep)
	return kept, truncated, nil
}

// tailFilter applies the grep filter then the last-N window. Separated from exec
// so it is unit-tested without a kernel.
func tailFilter(all []string, lines int, grep string) ([]string, bool) {
	if lines <= 0 {
		lines = DefaultLines
	}
	if lines > MaxLines {
		lines = MaxLines
	}
	if g := strings.ToLower(strings.TrimSpace(grep)); g != "" {
		filtered := all[:0:0]
		for _, l := range all {
			if strings.Contains(strings.ToLower(l), g) {
				filtered = append(filtered, l)
			}
		}
		all = filtered
	}
	if len(all) > lines {
		return all[len(all)-lines:], true
	}
	return all, false
}

func splitNonEmpty(s string) []string {
	raw := strings.Split(strings.TrimRight(s, "\n"), "\n")
	out := raw[:0]
	for _, l := range raw {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// dmesgPath resolves the dmesg binary, falling back to the usual locations for a
// daemon whose PATH may not include sbin.
func dmesgPath() string {
	if p, err := exec.LookPath("dmesg"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/bin/dmesg", "/bin/dmesg", "/usr/sbin/dmesg", "/sbin/dmesg"} {
		if _, err := exec.Command(p, "--version").CombinedOutput(); err == nil {
			return p
		}
	}
	return "dmesg"
}

// runDmesg runs `dmesg -T`, falling back to plain `dmesg` if -T is unsupported.
func runDmesg(ctx context.Context) ([]byte, error) {
	bin := dmesgPath()
	if out, err := exec.CommandContext(ctx, bin, "-T").Output(); err == nil {
		return out, nil
	}
	return exec.CommandContext(ctx, bin).Output()
}
