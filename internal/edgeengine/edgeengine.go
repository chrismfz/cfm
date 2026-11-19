// Package edgeengine is the single source of truth for the in-path edge
// engines (OpenResty, Angie, cfm-edge): their facts (Profiles, profiles.go),
// detecting which one is active on this host, and reading its version. The heartbeat
// agent, edge_health, health, status, dnat, edgelog, sslcollector and the rest
// read the engines from here; keeping ONE copy avoids the drift CLAUDE.md §5
// warns about (a new binary path added in one place but not the other would
// silently mis-detect the engine). Leaf package: no CFM deps.
package edgeengine

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ServiceCandidates are the systemd units probed in order; the first active one
// wins (both active at once is a rare manual-switchover state). An init-time
// snapshot of Profiles (profiles.go), kept as a var for its existing users:
// never edit it by hand, and a test that changes Profiles must reset it too.
var ServiceCandidates = Names()

// BinaryPaths lists where each edge's binary lives so its version can be read
// via `-v`. Same init-time snapshot of Profiles as ServiceCandidates.
var BinaryPaths = binaryPaths()

func binaryPaths() map[string][]string {
	m := make(map[string][]string, len(Profiles))
	for _, p := range Profiles {
		m[p.Name] = p.Binaries
	}
	return m
}

// Stub seams (overridden in tests).
var (
	SystemctlRunner = func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, "systemctl", args...).Run()
	}
	VersionRunner = func(ctx context.Context, bin string) (string, error) {
		out, err := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
		return string(out), err
	}
	LookPath = exec.LookPath
	Stat     = os.Stat
)

// Detect reports which edge proxy service is active (a Profiles name:
// "angie", "openresty", "cfm-edge"; "" when none is) plus that edge's binary
// version string. ok=false means
// detection could not run at all (no systemctl); callers that persist state
// should then keep their last known value instead of clearing it. An ok=true
// empty name is a real "no edge running" observation.
func Detect(ctx context.Context) (name, version string, ok bool) {
	if _, err := LookPath("systemctl"); err != nil {
		return "", "", false
	}
	for _, candidate := range ServiceCandidates {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := SystemctlRunner(cctx, "is-active", "--quiet", candidate)
		cancel()
		if err != nil {
			continue
		}
		return candidate, Version(ctx, candidate), true
	}
	return "", "", true
}

// Version best-effort reads the edge binary's version via `-v`. cfm-edge
// prints nginx's own line ("nginx version: nginx/1.31.9"): its version IS the
// nginx version it packages. Empty when no
// known binary path exists or the output is unparseable.
func Version(ctx context.Context, name string) string {
	for _, bin := range BinaryPaths[name] {
		if _, err := Stat(bin); err != nil {
			continue
		}
		vctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, err := VersionRunner(vctx, bin)
		cancel()
		if err != nil {
			continue
		}
		if v := ParseVersionToken(out); v != "" {
			return v
		}
	}
	return ""
}

// ParseVersionToken extracts the version token from `-v` output. OpenResty
// prints "nginx version: openresty/1.31.1.1"; Angie prints "Angie version:
// Angie/1.12.1". Both print on stderr, first line.
func ParseVersionToken(out string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	_, after, found := strings.Cut(line, "version:")
	if !found {
		return ""
	}
	v := strings.TrimSpace(after)
	if len(v) > 64 {
		v = strings.TrimSpace(v[:64])
	}
	return v
}
