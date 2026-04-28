package healthmodel

import "time"

const SchemaVersionV1 = "health_snapshot.v1"

// HealthSnapshotV1 is the canonical versioned health payload envelope.
type HealthSnapshotV1 struct {
	SchemaVersion string            `json:"schema_version"`
	NodeID        string            `json:"node_id"`
	CollectedAt   time.Time         `json:"collected_at"`
	Host          HostSystem        `json:"host"`
	Disk          DiskSnapshot      `json:"disk"`
	Services      []ServiceStatus   `json:"services"`
	CFM           CFMMetrics        `json:"cfm_metrics"`
	Network       NetworkThroughput `json:"network"`
}

type HostSystem struct {
	Hostname      string    `json:"hostname"`
	Timestamp     time.Time `json:"timestamp"`
	LoadAvg1      float64   `json:"load_avg_1"`
	LoadAvg5      float64   `json:"load_avg_5"`
	LoadAvg15     float64   `json:"load_avg_15"`
	CPUPercent    float64   `json:"cpu_percent"`
	MemUsedBytes  uint64    `json:"mem_used_bytes"`
	MemTotalBytes uint64    `json:"mem_total_bytes"`
}

type DiskSnapshot struct {
	Mounts      []DiskMount `json:"mounts"`
	DiskHealth  string      `json:"disk_health"`
	SmartHealth string      `json:"smart_health"`
	DiskWearout string      `json:"disk_wearout"`
	MDADMHealth string      `json:"mdadm_health"`
	ZFSHealth   string      `json:"zfs_health"`
}

type DiskMount struct {
	Mount       string  `json:"mount"`
	UsedBytes   uint64  `json:"used_bytes"`
	TotalBytes  uint64  `json:"total_bytes"`
	UsedPct     float64 `json:"used_pct"`
	UsedInodes  uint64  `json:"used_inodes,omitempty"`
	TotalInodes uint64  `json:"total_inodes,omitempty"`
	InodeUsedPct float64 `json:"inode_used_pct,omitempty"`
}

type ServiceStatus struct {
	Name      string `json:"name"`
	Active    bool   `json:"active"`
	Enabled   bool   `json:"enabled"`
	State     string `json:"state"`
	LastError string `json:"last_error,omitempty"`
}

type CFMMetrics struct {
	ActiveBlocks   int `json:"active_blocks"`
	ChallengeQueue int `json:"challenge_queue"`
	WAFEvents1h    int `json:"waf_events_1h"`
	OutboundAlerts int `json:"outbound_alerts"`
}

type NetworkThroughput struct {
	BandwidthInBytesPerSec  uint64 `json:"bandwidth_in_bps"`
	BandwidthOutBytesPerSec uint64 `json:"bandwidth_out_bps"`
}

type CounterSnapshot struct {
	Services []ServiceStatus
	CFM      CFMMetrics
	Network  NetworkThroughput
}
