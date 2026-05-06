package healthmodel

import (
	"fmt"
	"strings"
	"time"

	"cfm/internal/detectors/health"
)

// FromDetectorSnapshot maps detectors/health.Snapshot into HealthSnapshotV1.
// Some fields are best-effort when source Snapshot doesn't expose exact values
// (e.g. memory used/total bytes and 5m/15m load averages).
func FromDetectorSnapshot(src health.Snapshot, nodeID string, collectedAt time.Time) HealthSnapshotV1 {
	if collectedAt.IsZero() {
		collectedAt = time.Now().UTC()
	}
	out := HealthSnapshotV1{
		SchemaVersion: SchemaVersionV1,
		NodeID:        strings.TrimSpace(nodeID),
		CollectedAt:   collectedAt,
		Host: HostSystem{
			Hostname:   src.Host,
			Timestamp:  src.Time,
			LoadAvg1:   src.Load1,
			LoadAvg5:   0,
			LoadAvg15:  0,
			CPUPercent: cpuPercentEstimate(src.Load1, src.CPUCores),
		},
		Disk: DiskSnapshot{
			Mounts:       mapDiskMounts(src.DiskStats),
			DiskHealth:   diskHealthFromUsage(src.DiskStats),
			SmartHealth:  smartHealth(src.Smart),
			DiskWearout:  wearoutHealth(src.Smart),
			SmartDevices: mapSmartDevices(src.Smart),
			MDADMHealth:  mdadmHealth(src.Mdadm),
			MDADM:        mapMDADM(src.Mdadm),
			ZFSHealth:    zfsHealth(src.Zfs),
			ZFSPools:     mapZFSPools(src.Zfs),
		},
		Network: NetworkThroughput{
			BandwidthInBytesPerSec:  mbpsToBytesPerSec(src.RxMbps),
			BandwidthOutBytesPerSec: mbpsToBytesPerSec(src.TxMbps),
		},
		Services: []ServiceStatus{},
	}
	return out
}

func mapSmartDevices(in map[string]health.SmartInfo) map[string]SmartDevice {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]SmartDevice, len(in))
	for dev, s := range in {
		out[dev] = SmartDevice{
			Health:           s.Health,
			WearoutPctUsed:   s.WearoutPctUsed,
			WearoutSource:    s.WearoutSource,
			TemperatureC:     s.TempC,
			Model:            s.Model,
			Serial:           s.Serial,
			DeviceType:       s.Type,
			Error:            s.Error,
			NormalizedHealth: normalizeSMARTHealth(s),
		}
	}
	return out
}

func normalizeSMARTHealth(s health.SmartInfo) string {
	x := strings.ToLower(strings.TrimSpace(s.Health))
	switch {
	case strings.Contains(x, "fail"), strings.Contains(x, "bad"), strings.Contains(x, "crit"):
		return "critical"
	case strings.Contains(x, "warn"):
		return "warning"
	}
	if s.WearoutPctUsed != nil {
		switch {
		case *s.WearoutPctUsed >= 95:
			return "critical"
		case *s.WearoutPctUsed >= 80:
			return "warning"
		}
	}
	if x == "" && strings.TrimSpace(s.Error) != "" {
		return "unknown"
	}
	return "ok"
}

func mapMDADM(in health.MdstatSummary) MDADMStatus {
	out := MDADMStatus{Status: in.Status}
	if len(in.Arrays) == 0 {
		return out
	}
	out.Arrays = make([]MDADMArray, 0, len(in.Arrays))
	for _, a := range in.Arrays {
		out.Arrays = append(out.Arrays, MDADMArray{
			Name:            a.Name,
			Level:           a.Level,
			ExpectedMembers: a.ExpectedMembers,
			ActiveMembers:   a.ActiveMembers,
			FailedMissing:   a.FailedMissing,
			MemberStates:    append([]string(nil), a.MemberStates...),
			ProgressPct:     a.ProgressPct,
			ProgressPhase:   a.ProgressPhase,
		})
	}
	return out
}

func mapZFSPools(in map[string]health.ZpoolStatus) map[string]ZFSPoolState {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]ZFSPoolState, len(in))
	for k, z := range in {
		out[k] = ZFSPoolState{
			PoolName:        z.Pool,
			State:           z.State,
			UnhealthyVdevs:  z.UnhealthyVdevs,
			ScanStatus:      z.ScanStatus,
			Resilvering:     z.Resilvering,
			ResilverPercent: z.ResilverPercent,
		}
	}
	return out
}

// ApplyCounterSnapshot maps existing CFM counters/sources into this model.
func ApplyCounterSnapshot(dst *HealthSnapshotV1, src CounterSnapshot) {
	if dst == nil {
		return
	}
	dst.CFM = src.CFM
	if len(src.Services) > 0 {
		dst.Services = append([]ServiceStatus(nil), src.Services...)
	}
	if src.Network.BandwidthInBytesPerSec > 0 {
		dst.Network.BandwidthInBytesPerSec = src.Network.BandwidthInBytesPerSec
	}
	if src.Network.BandwidthOutBytesPerSec > 0 {
		dst.Network.BandwidthOutBytesPerSec = src.Network.BandwidthOutBytesPerSec
	}
	if src.Network.ConntrackMax > 0 {
		dst.Network.ConntrackCount = src.Network.ConntrackCount
		dst.Network.ConntrackMax = src.Network.ConntrackMax
		dst.Network.ConntrackUsagePct = src.Network.ConntrackUsagePct
	}
}

func mapDiskMounts(in []health.DiskStat) []DiskMount {
	out := make([]DiskMount, 0, len(in))
	for _, d := range in {
		out = append(out, DiskMount{
			Mount:        d.MountPath,
			UsedBytes:    d.UsedBytes,
			TotalBytes:   d.TotalBytes,
			UsedPct:      d.UsedPct,
			UsedInodes:   d.UsedInodes,
			TotalInodes:  d.TotalInodes,
			InodeUsedPct: d.InodeUsedPct,
		})
	}
	return out
}

func cpuPercentEstimate(load1 float64, cores int) float64 {
	if cores <= 0 {
		cores = 1
	}
	pct := (load1 / float64(cores)) * 100
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

func mbpsToBytesPerSec(v float64) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64((v * 1000 * 1000) / 8)
}

func diskHealthFromUsage(stats []health.DiskStat) string {
	status := "ok"
	for _, d := range stats {
		switch {
		case d.UsedPct >= 95:
			return "critical"
		case d.UsedPct >= 85:
			status = "warning"
		}
	}
	return status
}

func smartHealth(m map[string]health.SmartInfo) string {
	if len(m) == 0 {
		return "unknown"
	}
	status := "ok"
	for dev, s := range m {
		h := strings.ToLower(strings.TrimSpace(s.Health))
		switch {
		case h == "":
			status = "unknown"
		case strings.Contains(h, "fail") || strings.Contains(h, "bad"):
			return fmt.Sprintf("critical:%s", dev)
		case strings.Contains(h, "warn"):
			status = "warning"
		}
	}
	return status
}

func wearoutHealth(m map[string]health.SmartInfo) string {
	if len(m) == 0 {
		return "unknown"
	}
	status := "ok"
	for dev, s := range m {
		if s.WearoutPctUsed == nil {
			continue
		}
		pct := *s.WearoutPctUsed
		switch {
		case pct >= 95:
			return fmt.Sprintf("critical:%s", dev)
		case pct >= 80:
			status = "warning"
		}
	}
	return status
}

func mdadmHealth(m health.MdstatSummary) string {
	if strings.TrimSpace(m.Status) == "" {
		return "unknown"
	}
	status := strings.ToLower(strings.TrimSpace(m.Status))
	if strings.Contains(status, "degraded") || strings.Contains(status, "failed") {
		return "critical"
	}
	if strings.Contains(status, "recover") || strings.Contains(status, "resync") {
		return "warning"
	}
	return "ok"
}

func zfsHealth(z map[string]health.ZpoolStatus) string {
	if len(z) == 0 {
		return "unknown"
	}
	status := "ok"
	for _, pool := range z {
		s := strings.ToLower(strings.TrimSpace(pool.State))
		switch {
		case s == "", s == "online":
			if pool.UnhealthyVdevs > 0 {
				status = "warning"
			}
		default:
			return "critical"
		}
	}
	return status
}
