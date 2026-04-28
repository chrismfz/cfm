package healthmodel

import (
	"cfm/internal/dnat"
	"fmt"
	"os"
	"os/exec"
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
	units := []string{"cfm.service", "nginx.service", "openresty.service"}
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
