package healthmodel

import (
	"testing"
	"time"

	"cfm/internal/detectors/health"
)

func TestFromDetectorSnapshot(t *testing.T) {
	ts := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	wear := 96
	src := health.Snapshot{
		Time:     ts,
		Host:     "node-a",
		CPUCores: 4,
		Load1:    2,
		DiskStats: []health.DiskStat{{
			MountPath:    "/",
			UsedBytes:    50,
			TotalBytes:   100,
			UsedPct:      50,
			UsedInodes:   5,
			TotalInodes:  10,
			InodeUsedPct: 50,
		}},
		Smart: map[string]health.SmartInfo{
			"/dev/sda": {Health: "PASSED", WearoutPctUsed: &wear},
		},
		Mdadm: health.MdstatSummary{Status: "clean"},
		Zfs: map[string]health.ZpoolStatus{
			"tank": {Pool: "tank", State: "ONLINE"},
		},
		RxMbps: 8,
		TxMbps: 4,
	}

	out := FromDetectorSnapshot(src, "node-id-1", ts)
	if out.SchemaVersion != SchemaVersionV1 {
		t.Fatalf("schema version = %q", out.SchemaVersion)
	}
	if out.Host.CPUPercent != 50 {
		t.Fatalf("cpu percent = %v", out.Host.CPUPercent)
	}
	if out.Disk.DiskWearout != "critical:/dev/sda" {
		t.Fatalf("wearout = %q", out.Disk.DiskWearout)
	}
	if out.Disk.SmartDevices["/dev/sda"].NormalizedHealth != "critical" {
		t.Fatalf("normalized smart health = %q", out.Disk.SmartDevices["/dev/sda"].NormalizedHealth)
	}
	if out.Disk.MDADM.Status != "clean" {
		t.Fatalf("mdadm status = %q", out.Disk.MDADM.Status)
	}
	if out.Disk.ZFSPools["tank"].State != "ONLINE" {
		t.Fatalf("zfs state = %q", out.Disk.ZFSPools["tank"].State)
	}
	if out.Network.BandwidthInBytesPerSec == 0 || out.Network.BandwidthOutBytesPerSec == 0 {
		t.Fatalf("bandwidth should be mapped")
	}
}

func TestApplyCounterSnapshot(t *testing.T) {
	dst := HealthSnapshotV1{}
	ApplyCounterSnapshot(&dst, CounterSnapshot{
		Services: []ServiceStatus{{Name: "cfm", Active: true, Enabled: true, State: "active"}},
		CFM:      CFMMetrics{ActiveBlocks: 2, ChallengeQueue: 3, WAFEvents1h: 4, OutboundAlerts: 5},
		Network:  NetworkThroughput{BandwidthInBytesPerSec: 100, BandwidthOutBytesPerSec: 200},
	})
	if dst.CFM.ActiveBlocks != 2 || dst.CFM.OutboundAlerts != 5 {
		t.Fatalf("cfm counters not mapped: %+v", dst.CFM)
	}
	if len(dst.Services) != 1 || dst.Services[0].Name != "cfm" {
		t.Fatalf("service mapping failed: %+v", dst.Services)
	}
	if dst.Network.BandwidthOutBytesPerSec != 200 {
		t.Fatalf("network mapping failed: %+v", dst.Network)
	}
}
