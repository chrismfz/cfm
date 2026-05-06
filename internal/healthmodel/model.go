package healthmodel

import "time"

const SchemaVersionV1 = "health.snapshot.v1"

// HealthSnapshotV1 is the canonical versioned health payload envelope.
type HealthSnapshotV1 struct {
	SchemaVersion string            `json:"schema_version"`
	NodeID        string            `json:"node_id"`
	CollectedAt   time.Time         `json:"collected_at"`
	Error         string            `json:"error,omitempty"`
	Host          HostSystem        `json:"host"`
	Disk          DiskSnapshot      `json:"disk"`
	Services      []ServiceStatus   `json:"services"`
	CFM           CFMMetrics        `json:"cfm_metrics"`
	Network       NetworkThroughput `json:"network"`
	Runtime       RuntimeStatus     `json:"runtime"`
}

type RuntimeStatus struct {
	CFMDaemonLive           bool          `json:"cfm_daemon_live"`
	CFMDaemonPID            *int          `json:"cfm_daemon_pid,omitempty"`
	CFMServiceState         string        `json:"cfm_service_state,omitempty"`
	DNATEnabled             string        `json:"dnat_enabled,omitempty"`       // on/off/unknown
	PanelDNATEnabled        string        `json:"panel_dnat_enabled,omitempty"` // on/off/unknown
	DNATFrontend            string        `json:"dnat_frontend,omitempty"`
	DNATConfidence          string        `json:"dnat_confidence,omitempty"` // high/medium/low
	DNATWarning             string        `json:"dnat_warning,omitempty"`
	FrontendWorking         string        `json:"frontend_working,omitempty"` // working/degraded/down
	FrontendReason          string        `json:"frontend_reason,omitempty"`
	EdgeService             string        `json:"edge_service,omitempty"`        // angie/openresty/nginx/unknown
	UpstreamService         string        `json:"upstream_service,omitempty"`    // nginx/apache/...
	EdgeStatus              string        `json:"edge_status,omitempty"`         // active/inactive/degraded/unknown
	UpstreamStatus          string        `json:"upstream_status,omitempty"`     // active/inactive/unknown
	EdgeConfidence          string        `json:"edge_confidence,omitempty"`     // high/medium/low
	UpstreamConfidence      string        `json:"upstream_confidence,omitempty"` // high/medium/low
	EdgeReasonCode          string        `json:"edge_reason_code,omitempty"`
	UpstreamReasonCode      string        `json:"upstream_reason_code,omitempty"`
	ChallengeFlowState      string        `json:"challenge_flow_state,omitempty"`
	ChallengeFlowCode       string        `json:"challenge_flow_code,omitempty"`
	ChallengeFlowReason     string        `json:"challenge_flow_reason,omitempty"`
	BridgeSocketStatus      string        `json:"bridge_socket_status,omitempty"`
	BridgeSocketReason      string        `json:"bridge_socket_reason,omitempty"`
	BridgeSocketLatencyMs   int64         `json:"bridge_socket_latency_ms,omitempty"`
	ChallengeListenerStatus string        `json:"challenge_listener_status,omitempty"`
	ChallengeListenerReason string        `json:"challenge_listener_reason,omitempty"`
	SSLCollectorStatus      string        `json:"sslcollector_status,omitempty"`
	IngestSocketPath        string        `json:"ingest_socket_path,omitempty"`
	IngestSocketStatus      string        `json:"ingest_socket_status,omitempty"`
	IngestSocketReason      string        `json:"ingest_socket_reason,omitempty"`
	FrontendDebug           FrontendDebug `json:"frontend_debug,omitempty"`
}

type FrontendDebug struct {
	CheckedPorts []int               `json:"checked_ports,omitempty"`
	PortOwners   []FrontendPortOwner `json:"port_owners,omitempty"`
}

type FrontendPortOwner struct {
	Port           int      `json:"port"`
	ListenerOwners []string `json:"listener_owners,omitempty"`
	FlowOwners     []string `json:"flow_owners,omitempty"`
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
	Mounts       []DiskMount             `json:"mounts"`
	DiskHealth   string                  `json:"disk_health"`
	SmartHealth  string                  `json:"smart_health"`
	DiskWearout  string                  `json:"disk_wearout"`
	SmartDevices map[string]SmartDevice  `json:"smart_devices,omitempty"`
	MDADMHealth  string                  `json:"mdadm_health"`
	MDADM        MDADMStatus             `json:"mdadm"`
	ZFSHealth    string                  `json:"zfs_health"`
	ZFSPools     map[string]ZFSPoolState `json:"zfs_pools,omitempty"`
}

type DiskMount struct {
	Mount        string  `json:"mount"`
	UsedBytes    uint64  `json:"used_bytes"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedPct      float64 `json:"used_pct"`
	UsedInodes   uint64  `json:"used_inodes,omitempty"`
	TotalInodes  uint64  `json:"total_inodes,omitempty"`
	InodeUsedPct float64 `json:"inode_used_pct,omitempty"`
}

type SmartDevice struct {
	Health           string `json:"health"`
	WearoutPctUsed   *int   `json:"wearout_pct_used,omitempty"`
	WearoutSource    string `json:"wearout_source,omitempty"`
	TemperatureC     string `json:"temperature_c,omitempty"`
	Model            string `json:"model,omitempty"`
	Serial           string `json:"serial,omitempty"`
	DeviceType       string `json:"device_type,omitempty"`
	Error            string `json:"error,omitempty"`
	NormalizedHealth string `json:"normalized_health"`
}

type MDADMStatus struct {
	Status string       `json:"status"`
	Arrays []MDADMArray `json:"arrays,omitempty"`
}

type MDADMArray struct {
	Name            string   `json:"name"`
	Level           string   `json:"level,omitempty"`
	ExpectedMembers int      `json:"expected_members"`
	ActiveMembers   int      `json:"active_members"`
	FailedMissing   int      `json:"failed_missing_members"`
	MemberStates    []string `json:"member_states,omitempty"`
	ProgressPct     float64  `json:"progress_pct,omitempty"`
	ProgressPhase   string   `json:"progress_phase,omitempty"`
}

type ZFSPoolState struct {
	PoolName        string `json:"pool_name"`
	State           string `json:"state"`
	UnhealthyVdevs  int    `json:"unhealthy_vdev_count"`
	ScanStatus      string `json:"scan_status,omitempty"`
	Resilvering     bool   `json:"resilvering,omitempty"`
	ResilverPercent string `json:"resilver_progress,omitempty"`
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
