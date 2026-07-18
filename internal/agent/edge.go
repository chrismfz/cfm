package agent

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Edge detection for the heartbeat: cfm-web's Agents table shows which
// in-path edge proxy (openresty or angie) each server runs, so the
// operator can see the fleet's edge mix and spot a server whose edge
// went down. Detection mirrors sslcollector's reload path: ask systemd
// which of the two candidate units is active right now.

// edgeServiceCandidates are probed in order; the first active unit wins
// (both active at once is a rare manual-switchover state).
var edgeServiceCandidates = []string{"angie", "openresty"}

// edgeBinaryPaths lists where each edge's binary lives so the version
// can be read via `-v`. Paths mirror internal/healthmodel's candidates.
var edgeBinaryPaths = map[string][]string{
	"angie":     {"/usr/sbin/angie", "/usr/bin/angie"},
	"openresty": {"/usr/local/openresty/nginx/sbin/nginx", "/opt/openresty/nginx/sbin/nginx"},
}

// Stubbed in tests.
var (
	edgeSystemctlRunner = func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, "systemctl", args...).Run()
	}
	edgeVersionRunner = func(ctx context.Context, bin string) (string, error) {
		out, err := exec.CommandContext(ctx, bin, "-v").CombinedOutput()
		return string(out), err
	}
	edgeLookPath = exec.LookPath
	edgeStat     = os.Stat
)

// detectEdge reports which edge proxy service is active ("angie",
// "openresty", or "" when neither is) plus that edge's binary version
// string. ok=false means detection could not run at all (no systemctl);
// callers should then omit the fields from the heartbeat so cfm-web
// keeps its last known value instead of wrongly clearing it. An
// ok=true empty name is a real "no edge running" observation.
func detectEdge(ctx context.Context) (name, version string, ok bool) {
	if _, err := edgeLookPath("systemctl"); err != nil {
		return "", "", false
	}
	for _, candidate := range edgeServiceCandidates {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := edgeSystemctlRunner(cctx, "is-active", "--quiet", candidate)
		cancel()
		if err != nil {
			continue
		}
		return candidate, edgeVersion(ctx, candidate), true
	}
	return "", "", true
}

// edgeVersion best-effort reads the edge binary's version via `-v`.
// Empty string when no known binary path exists or the output is
// unparseable — the heartbeat still carries the edge name.
func edgeVersion(ctx context.Context, name string) string {
	for _, bin := range edgeBinaryPaths[name] {
		if _, err := edgeStat(bin); err != nil {
			continue
		}
		vctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, err := edgeVersionRunner(vctx, bin)
		cancel()
		if err != nil {
			continue
		}
		if v := parseEdgeVersion(out); v != "" {
			return v
		}
	}
	return ""
}

// parseEdgeVersion extracts the version token from `-v` output.
// OpenResty prints "nginx version: openresty/1.25.3.2"; Angie prints
// "Angie version: Angie/1.12.1". Both print on stderr, first line.
func parseEdgeVersion(out string) string {
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
