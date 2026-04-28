package healthmodel

import (
	"cfm/internal/dnat"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cfm/internal/detectors/health"
	"cfm/internal/firewall/nft"
)

// snapshotNowFn exists as a small test seam to force collector failures.
var snapshotNowFn = health.SnapshotNow

// RawDetectorSnapshot aliases the detector snapshot type for tests outside this package.
type RawDetectorSnapshot = health.Snapshot

// TestOnlySwapSnapshotNowFn replaces the snapshot collector function and returns the previous one.
func TestOnlySwapSnapshotNowFn(fn func() health.Snapshot) func() health.Snapshot {
	prev := snapshotNowFn
	snapshotNowFn = fn
	return prev
}

// CollectSnapshotNow builds the canonical health snapshot directly from live host collectors.
func CollectSnapshotNow(nodeID string) (snap HealthSnapshotV1) {
	snap = HealthSnapshotV1{
		SchemaVersion: SchemaVersionV1,
		NodeID:        nodeID,
		CollectedAt:   time.Now().UTC(),
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			snap = HealthSnapshotV1{
				SchemaVersion: SchemaVersionV1,
				NodeID:        nodeID,
				CollectedAt:   time.Now().UTC(),
				Error:         fmt.Sprintf("collector panic: %v", recovered),
			}
		}
	}()

	raw := snapshotNowFn()
	collectedAt := raw.Time
	if collectedAt.IsZero() {
		collectedAt = time.Now().UTC()
	}
	snap = FromDetectorSnapshot(raw, nodeID, collectedAt)
	enrichHostMemoryAndLoad(&snap.Host)
	snap.Services = collectServiceStatuses()
	snap.Runtime = collectRuntimeStatus()
	return snap
}

func collectRuntimeStatus() RuntimeStatus {
	out := RuntimeStatus{
		CFMServiceState: "unknown",
		DNATEnabled:     "unknown",
		DNATFrontend:    "unknown",
	}
	out.CFMDaemonLive, out.CFMDaemonPID = probeCFMDaemonLive()
	if state, ok := probeSystemdServiceState("cfm.service"); ok {
		out.CFMServiceState = state
	}
	if !out.CFMDaemonLive && out.CFMServiceState == "active" {
		out.CFMDaemonLive = true
	}
	if enabled, err := dnat.Status(nft.New()); err == nil {
		if enabled {
			out.DNATEnabled = "on"
		} else {
			out.DNATEnabled = "off"
		}
	}
	frontend, warning := detectDNATFrontend()
	out.DNATFrontend = frontend
	out.DNATWarning = warning
	return out
}

type frontendSignal struct {
	name            string
	serviceUnit     string
	processAliases  []string
	configHookPaths []string
	active          bool
	enabled         bool
	listenerHits    int
	configHits      int
	score           int
}

func detectDNATFrontend() (string, string) {
	candidates := []frontendSignal{
		{
			name:            "angie",
			serviceUnit:     "angie.service",
			processAliases:  []string{"angie", "nginx"},
			configHookPaths: []string{"/etc/angie/conf.d/cfm.conf", "/etc/angie/conf.d/nginx-cfm.conf", "/etc/angie/angie.conf"},
		},
		{
			name:            "openresty",
			serviceUnit:     "openresty.service",
			processAliases:  []string{"openresty", "nginx"},
			configHookPaths: []string{"/usr/local/openresty/nginx/conf/nginx-cfm.conf", "/usr/local/openresty/nginx/conf/openresty-cfm-tsv.conf", "/usr/local/openresty/nginx/conf/nginx.conf"},
		},
		{
			name:            "nginx",
			serviceUnit:     "nginx.service",
			processAliases:  []string{"nginx"},
			configHookPaths: []string{"/etc/nginx/conf.d/nginx-cfm.conf", "/etc/nginx/nginx.conf"},
		},
	}

	listeners := probeListenerProcessNames()
	activeUnits := make([]string, 0, len(candidates))
	for i := range candidates {
		active, enabled, ok := probeSystemdUnit(candidates[i].serviceUnit)
		if ok {
			candidates[i].active = active
			candidates[i].enabled = enabled
		}
		if candidates[i].active {
			activeUnits = append(activeUnits, candidates[i].name)
			candidates[i].score += 3
		}
		if candidates[i].enabled {
			candidates[i].score++
		}
		for _, alias := range candidates[i].processAliases {
			candidates[i].listenerHits += listeners[alias]
		}
		candidates[i].score += candidates[i].listenerHits * 2
		for _, p := range candidates[i].configHookPaths {
			if _, err := os.Stat(p); err == nil {
				candidates[i].configHits++
			}
		}
		candidates[i].score += candidates[i].configHits
	}

	best := candidates[0]
	tie := false
	for i := 1; i < len(candidates); i++ {
		if candidates[i].score > best.score {
			best = candidates[i]
			tie = false
			continue
		}
		if candidates[i].score == best.score {
			tie = true
		}
	}
	if best.score <= 0 {
		if len(activeUnits) == 1 {
			return activeUnits[0], ""
		}
		if len(activeUnits) > 1 {
			return activeUnits[0], fmt.Sprintf("ambiguous ownership: multiple active frontends (%s)", strings.Join(activeUnits, ", "))
		}
		return "unknown", ""
	}

	warning := ""
	if tie || len(activeUnits) > 1 {
		parts := make([]string, 0, len(candidates))
		for _, c := range candidates {
			if c.score <= 0 {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s(score=%d)", c.name, c.score))
		}
		if len(parts) > 1 {
			warning = fmt.Sprintf("ambiguous ownership: %s", strings.Join(parts, ", "))
		}
	}

	return best.name, warning
}

func probeSystemdUnit(unit string) (active bool, enabled bool, ok bool) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, false, false
	}
	activeState := strings.TrimSpace(string(mustCombinedOutput(exec.Command("systemctl", "is-active", unit))))
	enabledState := strings.TrimSpace(string(mustCombinedOutput(exec.Command("systemctl", "is-enabled", unit))))
	return activeState == "active", enabledState == "enabled", true
}

var ssListenerOwnerRE = regexp.MustCompile(`users:\(\("([^"]+)",pid=([0-9]+),fd=[0-9]+\)\)`)

func probeListenerProcessNames() map[string]int {
	out := map[string]int{}
	if _, err := exec.LookPath("ss"); err != nil {
		return out
	}
	queries := [][]string{
		{"-H", "-ltnp", "( sport = :80 or sport = :443 )"},
		{"-H", "-lunp", "sport = :443"},
	}
	for _, args := range queries {
		lines := strings.Split(string(mustCombinedOutput(exec.Command("ss", args...))), "\n")
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			match := ssListenerOwnerRE.FindStringSubmatch(ln)
			if len(match) != 3 {
				continue
			}
			name := strings.ToLower(strings.TrimSpace(match[1]))
			if name == "" {
				continue
			}
			out[name]++
		}
	}
	return out
}

func probeCFMDaemonLive() (bool, *int) {
	if _, err := exec.LookPath("pgrep"); err == nil {
		out := strings.TrimSpace(string(mustCombinedOutput(exec.Command("pgrep", "-fa", "cfm daemon"))))
		for _, ln := range strings.Split(out, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			parts := strings.Fields(ln)
			if len(parts) < 2 {
				continue
			}
			pid, err := strconv.Atoi(parts[0])
			if err != nil || pid <= 0 {
				continue
			}
			cmd := strings.TrimSpace(strings.TrimPrefix(ln, parts[0]))
			if strings.Contains(cmd, "cfm") && strings.Contains(cmd, "daemon") {
				return true, &pid
			}
		}
	}
	return false, nil
}

func probeSystemdServiceState(unit string) (string, bool) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", false
	}
	state := strings.TrimSpace(string(mustCombinedOutput(exec.Command("systemctl", "is-active", unit))))
	if state == "" {
		state = "unknown"
	}
	return state, true
}

func enrichHostMemoryAndLoad(host *HostSystem) {
	if host == nil {
		return
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) >= 3 {
			if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
				host.LoadAvg5 = v
			}
			if v, err := strconv.ParseFloat(fields[2], 64); err == nil {
				host.LoadAvg15 = v
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var totalKB uint64
		var availKB uint64
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			switch f[0] {
			case "MemTotal:":
				totalKB, _ = strconv.ParseUint(f[1], 10, 64)
			case "MemAvailable:":
				availKB, _ = strconv.ParseUint(f[1], 10, 64)
			}
		}
		if totalKB > 0 {
			host.MemTotalBytes = totalKB * 1024
			if availKB <= totalKB {
				host.MemUsedBytes = (totalKB - availKB) * 1024
			}
		}
	}
}

func collectServiceStatuses() []ServiceStatus {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	units := []string{"cfm.service", "nginx.service", "openresty.service", "angie.service"}
	out := make([]ServiceStatus, 0, len(units))
	for _, unit := range units {
		active := strings.TrimSpace(string(mustCombinedOutput(exec.Command("systemctl", "is-active", unit))))
		enabled := strings.TrimSpace(string(mustCombinedOutput(exec.Command("systemctl", "is-enabled", unit))))
		state := active
		if state == "" {
			state = "unknown"
		}
		out = append(out, ServiceStatus{
			Name:    strings.TrimSuffix(unit, ".service"),
			Active:  active == "active",
			Enabled: enabled == "enabled",
			State:   state,
		})
	}
	return out
}

func mustCombinedOutput(cmd *exec.Cmd) []byte {
	out, _ := cmd.CombinedOutput()
	return out
}
