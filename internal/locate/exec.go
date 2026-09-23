// internal/locate/exec.go
//
// Minimal exec plumbing for the read-only probes. Mirrors the gating in
// internal/unblock (binary allowlist + systemd unit allowlist) but lives
// here so unblock can later import locate without a cycle.
package locate

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

// allowedBinary restricts exec to the two read-only query CLIs locate
// needs. csf and cfm.deny are probed via file reads, never exec.
func allowedBinary(name string) bool {
	switch name {
	case "fail2ban-client", "imunify360-agent":
		return true
	default:
		return false
	}
}

func allowedSystemdUnit(unit string) bool {
	switch unit {
	case "fail2ban", "imunify360", "imunify360-agent",
		"imunify360.service", "imunify360-agent.service":
		return true
	default:
		return false
	}
}

func binaryExists(name string) bool { _, err := exec.LookPath(name); return err == nil }

// unitActive returns true if `systemctl is-active --quiet <unit>` succeeds.
// Best-effort: without systemd we assume active rather than hiding results.
func unitActive(unit string) bool {
	if !binaryExists("systemctl") {
		return true
	}
	if !allowedSystemdUnit(unit) {
		return false
	}
	// #nosec G204 -- unit is restricted to a static allowlist.
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}

// runOut executes an allowlisted binary and returns combined output.
func runOut(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !allowedBinary(name) {
		return nil, errBlockedBinary
	}
	// #nosec G204 -- name is constrained by allowedBinary, args by fixed callsites.
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// runStdout is runOut with stdout alone, for output that is parsed: a warning
// on stderr would make it unreadable. stderr comes back for error text.
func runStdout(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error) {
	if !allowedBinary(name) {
		return nil, nil, errBlockedBinary
	}
	var so, se bytes.Buffer
	// #nosec G204 -- name is constrained by allowedBinary, args by fixed callsites.
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	return so.Bytes(), se.Bytes(), err
}

var errBlockedBinary = errors.New("binary not in allowlist")
