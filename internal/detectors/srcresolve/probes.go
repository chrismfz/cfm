package srcresolve

// probes.go — the real environment probes behind DefaultProbes(). Each one is
// a bounded, best-effort check: probe failure never errors, it just means
// "candidate not confirmed" and resolution moves on.

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// probeTimeout bounds every external probe command. Probes run serially, so
// the worst case on a wedged systemd/docker is a few candidates × 3s per
// detector at (re)registration time — bounded and boot-only, but not free.
// On a healthy host each probe returns in single-digit milliseconds.
const probeTimeout = 3 * time.Second

// DefaultProbes returns the real environment probes.
func DefaultProbes() Probes {
	return Probes{
		JournalHasEntries: journalHasEntries,
		JournalMatches:    journalMatches,
		UnitActive:        unitActive,
		CanonicalUnit:     canonicalUnit,
		JournalReadable:   journalReadableProbe,
		FileExists:        regularFileExists,
		ListContainers:    listDockerContainers,
	}
}

// journalHasEntries reports whether journald holds at least one entry for the
// unit. This — not `systemctl is-active` — is the decisive candidate check:
// on Debian, sshd.service is an alias of ssh.service, so is-active succeeds
// for BOTH names while `journalctl -u sshd.service` can match nothing; probing
// for actual entries picks the name the journal indexes.
func journalHasEntries(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl",
		"-u", unit, "-n", "1", "--no-pager", "--quiet", "-o", "cat").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

// journalMatchWindow bounds how many recent entries the signature probe reads.
const journalMatchWindow = "200"

// journalMatches reports whether any of the unit's recent journal entries
// match the signature regex. Probed in short-unix format — the same framing
// JournalTailer feeds the parsers, syslog identifier included — so "matches"
// means "the parser would actually see service lines". This is the
// content-aware defence against journald's cgroup attribution (a unit's
// journal carrying other services' lines) and startup-only noise.
func journalMatches(unit, signature string) bool {
	re, err := regexp.Compile(signature)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl",
		"-u", unit, "-n", journalMatchWindow, "--no-pager", "--quiet", "-o", "short-unix").Output()
	if err != nil {
		return false
	}
	return re.Match(out)
}

// unitActive reports whether systemd considers the unit active.
func unitActive(unit string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil
}

// canonicalUnit resolves a unit name to its canonical Id (Alias= resolved),
// e.g. sshd.service → ssh.service on Debian. Returns "" when unknown so the
// caller keeps the queried name.
func canonicalUnit(unit string) string {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "Id", "--value", unit).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// journalReadableProbe reports whether journalctl exists and can read the
// journal at all (unit-independent). False on non-systemd hosts and where the
// journal is unreadable — the cue to fall back to file sources even for an
// explicitly configured journal unit.
func journalReadableProbe() bool {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	return exec.CommandContext(ctx, "journalctl", "-n", "0", "--no-pager", "--quiet").Run() == nil
}

// regularFileExists reports whether path is an existing regular file.
func regularFileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// listDockerContainers returns the names of running docker containers, or nil
// when docker is absent/unreachable.
func listDockerContainers() []string {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.Names}}").Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	return names
}
