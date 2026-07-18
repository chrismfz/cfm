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

	// Mail is the latest MTA queue measurement published by the
	// exim_queues/postfix_queues detectors (internal/mailq); nil when
	// neither detector is enabled or nothing has been measured yet.
	Mail *MailQueueStatus `json:"mail,omitempty"`
}

// MailQueueStatus mirrors the latest mailq.Measurement into the snapshot.
type MailQueueStatus struct {
	MTA        string `json:"mta"`    // "exim" | "postfix"
	Queued     int    `json:"queued"` // messages in queue
	Frozen     int    `json:"frozen,omitempty"`
	AgeSeconds int64  `json:"age_seconds"` // measurement age at snapshot time
}

type RuntimeStatus struct {
	CFMDaemonLive                bool          `json:"cfm_daemon_live"`
	CFMDaemonPID                 *int          `json:"cfm_daemon_pid,omitempty"`
	CFMServiceState              string        `json:"cfm_service_state,omitempty"`
	DNATEnabled                  string        `json:"dnat_enabled,omitempty"`       // on/off/unknown
	PanelDNATEnabled             string        `json:"panel_dnat_enabled,omitempty"` // on/off/unknown
	DNATFrontend                 string        `json:"dnat_frontend,omitempty"`
	DNATConfidence               string        `json:"dnat_confidence,omitempty"` // high/medium/low
	DNATWarning                  string        `json:"dnat_warning,omitempty"`
	FrontendWorking              string        `json:"frontend_working,omitempty"` // working/degraded/down
	FrontendReason               string        `json:"frontend_reason,omitempty"`
	EdgeService                  string        `json:"edge_service,omitempty"`        // angie/openresty/nginx/unknown
	UpstreamService              string        `json:"upstream_service,omitempty"`    // nginx/apache/...
	EdgeStatus                   string        `json:"edge_status,omitempty"`         // active/inactive/degraded/unknown
	UpstreamStatus               string        `json:"upstream_status,omitempty"`     // active/inactive/unknown
	EdgeConfidence               string        `json:"edge_confidence,omitempty"`     // high/medium/low
	UpstreamConfidence           string        `json:"upstream_confidence,omitempty"` // high/medium/low
	EdgeReasonCode               string        `json:"edge_reason_code,omitempty"`
	UpstreamReasonCode           string        `json:"upstream_reason_code,omitempty"`
	ChallengeFlowState           string        `json:"challenge_flow_state,omitempty"`
	ChallengeFlowCode            string        `json:"challenge_flow_code,omitempty"`
	ChallengeFlowReason          string        `json:"challenge_flow_reason,omitempty"`
	BridgeSocketStatus           string        `json:"bridge_socket_status,omitempty"`
	BridgeSocketReason           string        `json:"bridge_socket_reason,omitempty"`
	BridgeSocketLatencyMs        int64         `json:"bridge_socket_latency_ms,omitempty"`
	ChallengeListenerStatus      string        `json:"challenge_listener_status,omitempty"`
	ChallengeListenerReason      string        `json:"challenge_listener_reason,omitempty"`
	ChallengeListenerAddress     string        `json:"challenge_listener_address,omitempty"`
	SSLCollectorStatus           string        `json:"sslcollector_status,omitempty"`
	IngestSocketPath             string        `json:"ingest_socket_path,omitempty"`
	IngestSocketStatus           string        `json:"ingest_socket_status,omitempty"`
	IngestSocketReason           string        `json:"ingest_socket_reason,omitempty"`
	IngestSourceActive           string        `json:"ingest_source_active,omitempty"`
	IngestSourceSockListening    bool          `json:"ingest_source_sock_listening,omitempty"`
	IngestSourceLastReceivedUnix int64         `json:"ingest_source_last_received_unix,omitempty"`
	FrontendDebug                FrontendDebug `json:"frontend_debug,omitempty"`
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

	// CPUPercentSource says how CPUPercent was produced: "procstat"
	// (real busy% from /proc/stat deltas, with the breakdown below
	// populated) or "load_estimate" (load1/cores heuristic — the only
	// source before 2026-07; breakdown fields are zero).
	CPUPercentSource string  `json:"cpu_percent_source,omitempty"`
	CPUUserPct       float64 `json:"cpu_user_pct,omitempty"`
	CPUSystemPct     float64 `json:"cpu_system_pct,omitempty"`
	CPUIOWaitPct     float64 `json:"cpu_iowait_pct,omitempty"`
	CPUStealPct      float64 `json:"cpu_steal_pct,omitempty"`

	MemAvailableBytes uint64 `json:"mem_available_bytes,omitempty"`
	MemBuffersBytes   uint64 `json:"mem_buffers_bytes,omitempty"`
	MemCachedBytes    uint64 `json:"mem_cached_bytes,omitempty"`
	SwapTotalBytes    uint64 `json:"swap_total_bytes,omitempty"`
	SwapUsedBytes     uint64 `json:"swap_used_bytes,omitempty"`

	UptimeSeconds uint64  `json:"uptime_seconds,omitempty"`
	CPUModel      string  `json:"cpu_model,omitempty"`
	CPUThreads    int     `json:"cpu_threads,omitempty"`
	CPUMHz        float64 `json:"cpu_mhz,omitempty"`
	OSPrettyName  string  `json:"os_pretty_name,omitempty"`
	KernelVersion string  `json:"kernel_version,omitempty"`
}

type DiskSnapshot struct {
	Mounts       []DiskMount             `json:"mounts"`
	IORates      []DiskIORate            `json:"io_rates,omitempty"`
	DiskHealth   string                  `json:"disk_health"`
	SmartHealth  string                  `json:"smart_health"`
	DiskWearout  string                  `json:"disk_wearout"`
	SmartDevices map[string]SmartDevice  `json:"smart_devices,omitempty"`
	MDADMHealth  string                  `json:"mdadm_health"`
	MDADM        MDADMStatus             `json:"mdadm"`
	ZFSHealth    string                  `json:"zfs_health"`
	ZFSPools     map[string]ZFSPoolState `json:"zfs_pools,omitempty"`
}

// DiskIORate is bytes/sec read/written on one whole block device,
// delta-based; absent on the collector's first (seeding) call.
type DiskIORate struct {
	Device   string `json:"device"`
	ReadBps  uint64 `json:"read_bps"`
	WriteBps uint64 `json:"write_bps"`
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
	BandwidthInBytesPerSec  uint64  `json:"bandwidth_in_bps"`
	BandwidthOutBytesPerSec uint64  `json:"bandwidth_out_bps"`
	ConntrackCount          int     `json:"conntrack_count,omitempty"`
	ConntrackMax            int     `json:"conntrack_max,omitempty"`
	ConntrackUsagePct       float64 `json:"conntrack_usage_pct,omitempty"`
	NICs                    []NICThroughput `json:"nics,omitempty"`
}

// NICThroughput is per-interface throughput (loopback excluded),
// busiest first, capped at the collector; delta-based like bandwidth.
type NICThroughput struct {
	Name   string `json:"name"`
	RxBps  uint64 `json:"rx_bps"`
	TxBps  uint64 `json:"tx_bps"`
}

type CounterSnapshot struct {
	Services []ServiceStatus
	CFM      CFMMetrics
	Network  NetworkThroughput
}
