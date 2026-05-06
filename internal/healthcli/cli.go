package healthcli

import (
	"cfm/internal/clihttp"
	"cfm/internal/healthmodel"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	edgediag "cfm/internal/diagnostics/edge"
	"golang.org/x/term"
)

type cliOptions struct {
	NoColor      bool
	Compact      bool
	DiskDetail   bool
	FullIdent    bool
	DebugRuntime bool
}

type snapshotEnvelope struct {
	SchemaVersion string          `json:"schema_version"`
	NodeID        string          `json:"node_id"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Snapshot      json.RawMessage `json:"snapshot"`
}

type legacySample struct {
	NodeID      string    `json:"node_id"`
	Hostname    string    `json:"hostname"`
	CollectedAt time.Time `json:"collected_at"`
	Load1       float64   `json:"load1"`
	RamUsedPct  float64   `json:"ram_used_pct"`
	DiskRootPct float64   `json:"disk_root_pct"`
	DiskTmpPct  float64   `json:"disk_tmp_pct"`
	TempMaxC    float64   `json:"temp_max_c"`
	RxMbps      float64   `json:"rx_mbps"`
	TxMbps      float64   `json:"tx_mbps"`
}

type modernSample struct {
	NodeID      string    `json:"node_id"`
	CollectedAt time.Time `json:"collected_at"`
	Host        struct {
		Hostname      string  `json:"hostname"`
		LoadAvg1      float64 `json:"load_avg_1"`
		CPUPercent    float64 `json:"cpu_percent"`
		MemUsedBytes  uint64  `json:"mem_used_bytes"`
		MemTotalBytes uint64  `json:"mem_total_bytes"`
	} `json:"host"`
	Disk struct {
		Mounts []struct {
			Mount        string  `json:"mount"`
			UsedBytes    uint64  `json:"used_bytes"`
			TotalBytes   uint64  `json:"total_bytes"`
			UsedPct      float64 `json:"used_pct"`
			UsedInodes   uint64  `json:"used_inodes"`
			TotalInodes  uint64  `json:"total_inodes"`
			InodeUsedPct float64 `json:"inode_used_pct"`
		} `json:"mounts"`
		SmartHealth  string                             `json:"smart_health"`
		DiskWearout  string                             `json:"disk_wearout"`
		SmartDevices map[string]healthmodel.SmartDevice `json:"smart_devices"`
		MDADMHealth  string                             `json:"mdadm_health"`
		MDADM        healthmodel.MDADMStatus            `json:"mdadm"`
		ZFSHealth    string                             `json:"zfs_health"`
	} `json:"disk"`
	CFM struct {
		ActiveBlocks   int `json:"active_blocks"`
		ChallengeQueue int `json:"challenge_queue"`
		WAFEvents1h    int `json:"waf_events_1h"`
		OutboundAlerts int `json:"outbound_alerts"`
	} `json:"cfm_metrics"`
	Runtime struct {
		CFMDaemonLive                bool   `json:"cfm_daemon_live"`
		CFMDaemonPID                 *int   `json:"cfm_daemon_pid"`
		CFMServiceState              string `json:"cfm_service_state"`
		DNATEnabled                  string `json:"dnat_enabled"`
		PanelDNATEnabled             string `json:"panel_dnat_enabled"`
		DNATFrontend                 string `json:"dnat_frontend"`
		DNATConfidence               string `json:"dnat_confidence"`
		DNATWarning                  string `json:"dnat_warning"`
		FrontendWorking              string `json:"frontend_working"`
		FrontendReason               string `json:"frontend_reason"`
		EdgeService                  string `json:"edge_service"`
		UpstreamService              string `json:"upstream_service"`
		EdgeStatus                   string `json:"edge_status"`
		UpstreamStatus               string `json:"upstream_status"`
		EdgeConfidence               string `json:"edge_confidence"`
		UpstreamConfidence           string `json:"upstream_confidence"`
		EdgeReasonCode               string `json:"edge_reason_code"`
		UpstreamReasonCode           string `json:"upstream_reason_code"`
		BridgeSocketStatus           string `json:"bridge_socket_status"`
		BridgeSocketReason           string `json:"bridge_socket_reason"`
		BridgeSocketLatencyMs        int64  `json:"bridge_socket_latency_ms"`
		ChallengeListenerStatus      string `json:"challenge_listener_status"`
		ChallengeListenerReason      string `json:"challenge_listener_reason"`
		ChallengeFlowState           string `json:"challenge_flow_state"`
		ChallengeFlowCode            string `json:"challenge_flow_code"`
		ChallengeFlowReason          string `json:"challenge_flow_reason"`
		SSLCollectorStatus           string `json:"sslcollector_status"`
		IngestSocketPath             string `json:"ingest_socket_path"`
		IngestSocketStatus           string `json:"ingest_socket_status"`
		IngestSocketReason           string `json:"ingest_socket_reason"`
		IngestSourceActive           string `json:"ingest_source_active"`
		IngestSourceSockListening    bool   `json:"ingest_source_sock_listening"`
		IngestSourceLastReceivedUnix int64  `json:"ingest_source_last_received_unix"`
	} `json:"runtime"`
	Network struct {
		InBps             uint64         `json:"bandwidth_in_bps"`
		OutBps            uint64         `json:"bandwidth_out_bps"`
		ConntrackCount    int            `json:"conntrack_count"`
		ConntrackMax      int            `json:"conntrack_max"`
		ConntrackUsagePct float64        `json:"conntrack_usage_pct"`
		TCP               map[string]int `json:"connection_states"`
	} `json:"network"`
	Services []serviceStatus `json:"services"`
}

type serviceStatus struct {
	Name                 string `json:"name"`
	Active               bool   `json:"active"`
	Enabled              bool   `json:"enabled"`
	State                string `json:"state"`
	LastError            string `json:"last_error"`
	ActiveEnterTimestamp string `json:"active_enter_timestamp,omitempty"`
}

type parsedSnapshot struct {
	Envelope snapshotEnvelope
	Legacy   legacySample
	Modern   modernSample
	RawMap   map[string]any
}

func Run(baseURL string, args []string) error {
	opts, argv := parseGlobalFlags(args)
	if len(argv) == 0 {
		return runSummary(baseURL, opts)
	}

	switch argv[0] {
	case "json":
		return runJSON(baseURL)
	case "live":
		if !isTTY() {
			return runWatch(baseURL, append(argv[1:], "--once"), opts)
		}
		return runLive(baseURL, argv[1:], opts)
	case "watch":
		return runWatch(baseURL, argv[1:], opts)
	case "help", "-h", "--help":
		printHelp()
		return nil
	default:
		return fmt.Errorf("unknown subcommand: %s", argv[0])
	}
}

func parseGlobalFlags(args []string) (cliOptions, []string) {
	var opts cliOptions
	out := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--no-color":
			opts.NoColor = true
		case "--compact":
			opts.Compact = true
		case "--disk-detail":
			opts.DiskDetail = true
		case "--full-ident":
			opts.FullIdent = true
		case "--debug-runtime":
			opts.DebugRuntime = true
		default:
			out = append(out, a)
		}
	}
	return opts, out
}

func isTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

func printHelp() {
	fmt.Println("Usage:")
	fmt.Println("  cfm health [--compact] [--disk-detail] [--full-ident] [--no-color]             # summary")
	fmt.Println("  cfm health json                                 # machine-readable snapshot")
	fmt.Println("  cfm health live [--interval=2s] [--compact] [--full-ident] [--no-color] # live dashboard (TTY), fallback to watch")
	fmt.Println("  cfm health watch [N] [--compact] [--no-color]   # periodic text refresh every N seconds (default 5)")
}

func runSummary(baseURL string, opts cliOptions) error {
	snap, err := fetchSnapshot(baseURL)
	if err != nil {
		return err
	}
	printSummary(snap, opts)
	return nil
}

func runJSON(baseURL string) error {
	res, err := getJSON(baseURL + "/api/v1/health/snapshot")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("health snapshot failed: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload any
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(b))
	return nil
}

type watchConfig struct {
	interval time.Duration
	once     bool
}

func parseWatchConfig(args []string) watchConfig {
	cfg := watchConfig{interval: 5 * time.Second}
	for i := 0; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		switch {
		case a == "--once":
			cfg.once = true
		case a == "--interval" || a == "-i":
			if i+1 < len(args) {
				i++
				if d, err := time.ParseDuration(args[i]); err == nil && d > 0 {
					cfg.interval = d
				}
			}
		case strings.HasPrefix(a, "--interval="):
			if d, err := time.ParseDuration(strings.TrimPrefix(a, "--interval=")); err == nil && d > 0 {
				cfg.interval = d
			}
		default:
			if n, err := strconv.Atoi(a); err == nil && n > 0 {
				cfg.interval = time.Duration(n) * time.Second
			}
		}
	}
	return cfg
}

func runWatch(baseURL string, args []string, opts cliOptions) error {
	cfg := parseWatchConfig(args)
	fmt.Printf("[cfm health watch] interval=%s\n", cfg.interval)
	for {
		snap, err := fetchSnapshot(baseURL)
		if err != nil {
			fmt.Printf("[%s] error: %v\n", time.Now().Format(time.RFC3339), err)
		} else {
			printOneLine(snap, opts)
		}
		if cfg.once {
			return nil
		}
		time.Sleep(cfg.interval)
	}
}

func parseInterval(args []string, def time.Duration) time.Duration {
	if len(args) == 0 {
		return def
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Second
}

func printSummary(s parsedSnapshot, opts cliOptions) {
	host := chooseHost(s)
	collected := chooseCollectedAt(s)
	fmt.Printf("Node: %s\n", host)
	if !collected.IsZero() {
		fmt.Printf("Collected: %s\n\n", collected.Local().Format(time.RFC3339))
	}
	printHostSection(s, opts)
	printRuntimeSection(s, opts)
	printDiskSection(s, opts)
	printStorageSection(s, opts)
	printNetworkSection(s, opts)
	printCFMSection(s, opts)
}

func printRuntimeSection(s parsedSnapshot, opts cliOptions) {
	r := s.Modern.Runtime
	daemon := "down"
	if r.CFMDaemonLive {
		daemon = "live"
	}
	if r.CFMDaemonPID != nil && *r.CFMDaemonPID > 0 {
		daemon = fmt.Sprintf("%s (pid %d)", daemon, *r.CFMDaemonPID)
	}
	serviceState := strings.TrimSpace(r.CFMServiceState)
	if serviceState == "" {
		serviceState = "unknown"
	}
	confidence := strings.ToLower(strings.TrimSpace(r.DNATConfidence))
	if confidence == "" {
		confidence = "low"
	}
	if opts.Compact {
		fmt.Printf("Runtime %-6s daemon=%s service=%s\n", badge(okLabel, opts), daemon, serviceState)
		if opts.DebugRuntime {
			fmt.Printf("Runtime %-6s edge=%s upstream=%s\n", badge(okLabel, opts), formatRuntimeServiceRole(r.EdgeService, r.EdgeStatus, r.EdgeConfidence, r.EdgeReasonCode), formatRuntimeServiceRole(r.UpstreamService, r.UpstreamStatus, r.UpstreamConfidence, r.UpstreamReasonCode))
		}
		if confidence == "low" {
			if w := strings.TrimSpace(r.DNATWarning); w != "" {
				fmt.Printf("Runtime %-6s warning=%s\n", badge(warnLabel, opts), w)
			}
		}
		printRuntimeSubcheckWarnings(s.Modern, opts, true)
		printWebStackSection(s, opts)
		return
	}
	fmt.Printf("Runtime %s\n", badge(okLabel, opts))
	fmt.Printf("  CFM daemon: %s\n", daemon)
	fmt.Printf("  Service: %s\n", serviceState)
	if opts.DebugRuntime {
		fmt.Printf("  Edge: %s\n", formatRuntimeServiceRole(r.EdgeService, r.EdgeStatus, r.EdgeConfidence, r.EdgeReasonCode))
		fmt.Printf("  Upstream: %s\n", formatRuntimeServiceRole(r.UpstreamService, r.UpstreamStatus, r.UpstreamConfidence, r.UpstreamReasonCode))
	}
	if confidence == "low" {
		if w := strings.TrimSpace(r.DNATWarning); w != "" {
			fmt.Printf("  Warning: %s\n", w)
		}
	}
	printRuntimeSubcheckWarnings(s.Modern, opts, false)
	printWebStackSection(s, opts)
}

func printRuntimeSubcheckWarnings(sample modernSample, opts cliOptions, compact bool) {
	r := sample.Runtime
	warn := func(name, reason string) {
		if compact {
			fmt.Printf("Runtime %-6s %s=%s\n", badge(warnLabel, opts), name, reason)
			return
		}
		fmt.Printf("  Warning (%s): %s\n", name, reason)
	}
	if st := strings.ToLower(strings.TrimSpace(r.BridgeSocketStatus)); st == "warn" || st == "fail" {
		reason := strings.TrimSpace(r.BridgeSocketReason)
		if r.BridgeSocketLatencyMs > 0 {
			reason = fmt.Sprintf("%s (latency=%dms)", reason, r.BridgeSocketLatencyMs)
		}
		warn("bridge_socket", reason)
	}
	if st := strings.ToLower(strings.TrimSpace(r.ChallengeListenerStatus)); st == "warn" || st == "fail" {
		warn("challenge_listener", strings.TrimSpace(r.ChallengeListenerReason))
	}
	if st := strings.ToLower(strings.TrimSpace(r.SSLCollectorStatus)); st == "auth" || st == "perm" {
		warn("sslcollector", st)
	}
}

func formatRuntimeServiceRole(service, status, confidence, reasonCode string) string {
	name := strings.ToLower(strings.TrimSpace(service))
	if name == "" || strings.EqualFold(name, "unknown") {
		name = "unknown"
	}
	state := strings.ToLower(strings.TrimSpace(status))
	if state == "" {
		state = "unknown"
	}
	conf := strings.ToLower(strings.TrimSpace(confidence))
	if conf == "" {
		conf = "low"
	}
	reason := strings.TrimSpace(reasonCode)
	if reason == "" {
		reason = "unknown"
	}
	portCtx := ""
	switch {
	case strings.HasPrefix(reason, "ports_80_443"):
		portCtx = "port 80/443"
	case strings.HasPrefix(reason, "ports_80_only"):
		portCtx = "port 80"
	case strings.HasPrefix(reason, "ports_443_only"):
		portCtx = "port 443"
	case strings.HasPrefix(reason, "mixed_80_443"):
		portCtx = "ports 80/443 mixed"
	}
	if portCtx != "" {
		return fmt.Sprintf("%s (%s, confidence=%s, via %s)", name, portCtx, conf, reason)
	}
	return fmt.Sprintf("%s (confidence=%s, via %s)", name, conf, reason)
}

func printWebStackSection(s parsedSnapshot, opts cliOptions) {
	rows := collectWebStackRows(s)
	if len(rows) == 0 {
		return
	}
	status := webStackStatus(rows, s.Modern.Runtime.EdgeService, s.Modern.Runtime.DNATFrontend)
	if opts.Compact {
		parts := make([]string, 0, len(rows))
		for _, row := range rows {
			parts = append(parts, fmt.Sprintf("%s: enabled=%s active=%s state=%s%s", row.Name, yesNo(row.Enabled), yesNo(row.Active), row.State, formatWebStackUptime(row)))
		}
		fmt.Printf("Web stack - Edge Interceptor %-6s %s\n", badge(status, opts), strings.Join(parts, "; "))
		printDNATSubchecks(s.Modern.Runtime.DNATEnabled, s.Modern.Runtime.PanelDNATEnabled, opts)
		printChallengeFlowReadiness(s.Modern.Runtime.ChallengeFlowState, s.Modern.Runtime.ChallengeFlowCode, s.Modern.Runtime.ChallengeFlowReason, opts)
		printEdgeInterceptorDiagnostics(s, opts)
		return
	}
	fmt.Printf("Web stack - Edge Interceptor %s\n", badge(status, opts))
	printDNATSubchecks(s.Modern.Runtime.DNATEnabled, s.Modern.Runtime.PanelDNATEnabled, opts)
	printChallengeFlowReadiness(s.Modern.Runtime.ChallengeFlowState, s.Modern.Runtime.ChallengeFlowCode, s.Modern.Runtime.ChallengeFlowReason, opts)
	printEdgeInterceptorDiagnostics(s, opts)
	for _, row := range rows {
		fmt.Printf("  %s: enabled=%s active=%s state=%s%s\n", row.Name, yesNo(row.Enabled), yesNo(row.Active), row.State, formatWebStackUptime(row))
	}
}

func printDNATSubchecks(webState, panelState string, opts cliOptions) {
	webState = normalizeDNATState(webState)
	panelState = normalizeDNATState(panelState)
	fmt.Printf("  %s  Web Traffic DNAT: %s\n", badge(dnatLabel(webState), opts), webState)
	fmt.Printf("  %s  Panel Traffic DNAT: %s\n", badge(dnatLabel(panelState), opts), panelState)
}

func normalizeDNATState(state string) string {
	state = strings.ToLower(strings.TrimSpace(state))
	if state == "" {
		return "unknown"
	}
	return state
}

func dnatLabel(state string) healthLabelRank {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "off", "unavailable":
		return critLabel
	default:
		return okLabel
	}
}

func printChallengeFlowReadiness(state, code, reason string, opts cliOptions) {
	label, detail, ok := challengeFlowReadiness(state, code, reason)
	if !ok {
		return
	}
	fmt.Printf("  %s  Challenge flow readiness: %s\n", badge(label, opts), detail)
}

func challengeFlowReadiness(state, code, reason string) (healthLabelRank, string, bool) {
	state = strings.TrimSpace(state)
	code = strings.TrimSpace(code)
	reason = strings.TrimSpace(reason)
	if state == "" && code == "" && reason == "" {
		return okLabel, "", false
	}

	displayState := strings.ToUpper(state)
	if displayState == "" {
		displayState = "UNKNOWN"
	}
	label := critLabel
	switch displayState {
	case "OK":
		label = okLabel
	case "WARN":
		label = warnLabel
	case "FAIL":
		label = critLabel
	}

	detail := displayState
	if reason == "" {
		reason = code
	}
	if reason != "" {
		detail += " " + reason
	}
	return label, detail, true
}

func printEdgeInterceptorDiagnostics(s parsedSnapshot, opts cliOptions) {
	sslToken := edgediag.ResolveLuaToken([]string{"/var/lib/cfm/lua/cfm_token.lua", "/usr/local/openresty/nginx/lua/cfm_token.lua", "/etc/angie/lua/cfm_token.lua"})
	challengeToken := edgediag.ReadChallengeTokenProbe("/etc/cfm/detectors.conf")
	bridgeToken := edgediag.ReadBridgeTokenProbe(edgediag.CanonicalBridgeTokenPath)
	sock := edgediag.ProbeSSLCollector("/var/run/sslcollector.sock", sslToken)
	cfg := edgediag.ResolveBridgeRuntimeConfig("/etc/cfm/detectors.conf")
	bridge := edgediag.ProbeNginxBridgeRuntime(cfg, bridgeToken)
	fmt.Printf("  SSL Collector Socket: %s\n", mapEdgeStatus(sock.Category))
	fmt.Printf("    path=%s uid=%s gid=%s mode=%s probe=%s%s\n", sock.Path, sock.UID, sock.GID, sock.Mode, sock.Category, sock.ErrorText)
	fmt.Printf("  challenge token (CHALLENGE_TOKEN): %s\n", edgediag.TokenHealth(challengeToken))
	fmt.Printf("  edge bridge token (OPENRESTY_TOKEN): %s\n", edgediag.TokenHealth(bridgeToken))
	fmt.Printf("  bridge socket auth: %s\n", bridge.Summary())
	status := effectiveIngestSocketStatus(s.Modern.Runtime.IngestSocketStatus, s.Modern.Runtime.IngestSourceActive, s.Modern.Runtime.IngestSourceSockListening, s.Modern.Runtime.IngestSourceLastReceivedUnix)
	if status == "" && len(missingRuntimeFields(s, "ingest_socket_status", "challenge_flow_state", "panel_dnat_enabled")) > 0 {
		printMissingRuntimeSocketFieldsWarning(opts)
		return
	}
	printIngestSocketHealth(s.Modern.Runtime.IngestSocketPath, status, s.Modern.Runtime.IngestSocketReason, opts)
}

func missingRuntimeFields(s parsedSnapshot, fields ...string) []string {
	runtime, ok := runtimeRawMap(s)
	if !ok {
		return nil
	}
	missing := make([]string, 0, len(fields))
	for _, field := range fields {
		if _, ok := runtime[field]; !ok {
			missing = append(missing, field)
		}
	}
	return missing
}

func runtimeRawMap(s parsedSnapshot) (map[string]any, bool) {
	raw, ok := s.RawMap["runtime"]
	if !ok {
		return nil, false
	}
	runtime, ok := raw.(map[string]any)
	return runtime, ok
}

func printMissingRuntimeSocketFieldsWarning(opts cliOptions) {
	fmt.Printf("  %s  Health daemon snapshot is missing runtime socket fields; restart cfm service or upgrade daemon\n", badge(warnLabel, opts))
}

func effectiveIngestSocketStatus(status, active string, listening bool, lastReceivedUnix int64) string {
	status = strings.TrimSpace(status)
	if status != "" {
		return status
	}
	if listening && strings.EqualFold(strings.TrimSpace(active), "socket") && recentUnix(lastReceivedUnix, 30*time.Second) {
		return "live"
	}
	return status
}

func recentUnix(ts int64, window time.Duration) bool {
	if ts <= 0 {
		return false
	}
	d := time.Since(time.Unix(ts, 0))
	return d >= 0 && d <= window
}

func printIngestSocketHealth(path, status, reason string, opts cliOptions) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/run/cfm/ingest.sock"
	}
	display, label := ingestSocketDisplay(status)
	if label != okLabel {
		reason = strings.TrimSpace(reason)
		if reason != "" {
			display += " (" + reason + ")"
		}
	}
	fmt.Printf("  %s  Using ingest socket %s - %s\n", badge(label, opts), path, display)
}

func ingestSocketDisplay(status string) (string, healthLabelRank) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "live", "ok":
		return "Live", okLabel
	case "missing":
		return "Missing", critLabel
	case "invalid":
		return "Invalid", critLabel
	case "down":
		return "Down", critLabel
	case "":
		return "Unknown", warnLabel
	default:
		return strings.TrimSpace(status), warnLabel
	}
}

func mapEdgeStatus(v string) string {
	u := strings.ToUpper(strings.TrimSpace(v))
	switch u {
	case "OK":
		return "OK"
	case "MISSING", "AUTH_FAIL", "TOKEN_MISSING", "TOKEN_INVALID", "CONNECT_FAIL", "INVALID":
		return "CRIT"
	default:
		return "WARN"
	}
}
func collectWebStackRows(s parsedSnapshot) []serviceStatus {
	targets := []string{"angie", "openresty"}
	byName := make(map[string]serviceStatus, len(s.Modern.Services))
	for _, svc := range s.Modern.Services {
		name := strings.ToLower(strings.TrimSpace(svc.Name))
		if name == "" {
			continue
		}
		byName[name] = svc
	}
	out := make([]serviceStatus, 0, len(targets))
	for _, name := range targets {
		row, ok := byName[name]
		if !ok {
			row = serviceStatus{Name: name, State: "inactive"}
		}
		row.Name = name
		state := strings.ToLower(strings.TrimSpace(row.State))
		if state == "" {
			if row.Active {
				state = "active"
			} else {
				state = "inactive"
			}
		}
		row.State = state
		out = append(out, row)
	}
	return out
}

func webStackStatus(rows []serviceStatus, edgeService, dnatFrontend string) healthLabelRank {
	status := okLabel
	edge := strings.ToLower(strings.TrimSpace(edgeService))
	if edge == "" || edge == "unknown" {
		edge = strings.ToLower(strings.TrimSpace(dnatFrontend))
	}
	for _, row := range rows {
		switch strings.ToLower(strings.TrimSpace(row.State)) {
		case "failed":
			status = worstLabel(status, critLabel)
		case "inactive":
			if edge == "" || edge == "unknown" || strings.EqualFold(row.Name, edge) {
				status = worstLabel(status, warnLabel)
			}
		}
	}
	return status
}

func formatWebStackUptime(svc serviceStatus) string {
	ts := strings.TrimSpace(svc.ActiveEnterTimestamp)
	if ts == "" {
		return ""
	}
	t, err := parseActiveEnterTimestamp(ts)
	if err != nil {
		return fmt.Sprintf(" started=%s", ts)
	}
	if delta := time.Since(t); delta > 0 {
		return fmt.Sprintf(" uptime=%s", formatShortDuration(delta))
	}
	return fmt.Sprintf(" started=%s", t.Local().Format("2006-01-02 15:04:05"))
}

func parseActiveEnterTimestamp(v string) (time.Time, error) {
	layouts := []string{
		time.RFC3339,
		"Mon 2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05 UTC",
		"Mon 2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("parse active enter timestamp")
}

func formatShortDuration(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	if days > 0 {
		return fmt.Sprintf("%dd%dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh%dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func printOneLine(s parsedSnapshot, opts cliOptions) {
	host := chooseHost(s)
	load := nonZero(s.Modern.Host.LoadAvg1, s.Legacy.Load1)
	ram := s.Legacy.RamUsedPct
	if s.Modern.Host.MemTotalBytes > 0 {
		ram = 100 * float64(s.Modern.Host.MemUsedBytes) / float64(s.Modern.Host.MemTotalBytes)
	}
	inBps, outBps := networkBps(s)
	fmt.Printf("[%s] host=%s load=%.2f ram=%s net=%s/%s %s\n",
		time.Now().Format("15:04:05"), host, load, pctStr(ram),
		bytesPerSec(inBps), bytesPerSec(outBps),
		badge(labelByPct(max(ram, load*25)), opts),
	)
}

func printHostSection(s parsedSnapshot, opts cliOptions) {
	load := nonZero(s.Modern.Host.LoadAvg1, s.Legacy.Load1)
	cpu := nonZero(s.Modern.Host.CPUPercent, load*25)
	ramUsed := s.Modern.Host.MemUsedBytes
	ramTotal := s.Modern.Host.MemTotalBytes
	ramPct := s.Legacy.RamUsedPct
	if ramTotal > 0 {
		ramPct = 100 * float64(ramUsed) / float64(ramTotal)
	}

	if opts.Compact {
		fmt.Printf("Host %-6s load=%.2f cpu=%s ram=%s", badge(labelByPct(max(cpu, ramPct)), opts), load, pctStr(cpu), pctStr(ramPct))
		if ramTotal > 0 {
			fmt.Printf(" (%s/%s)", bytesIEC(ramUsed), bytesIEC(ramTotal))
		}
		fmt.Println()
		return
	}
	fmt.Printf("Host %s\n", badge(labelByPct(max(cpu, ramPct)), opts))
	fmt.Printf("  Load avg: %.2f\n", load)
	fmt.Printf("  CPU: %s\n", pctStr(cpu))
	if ramTotal > 0 {
		fmt.Printf("  RAM: %s / %s (%s)\n", bytesIEC(ramUsed), bytesIEC(ramTotal), pctStr(ramPct))
	} else {
		fmt.Printf("  RAM: %s\n", pctStr(ramPct))
	}
}

func printDiskSection(s parsedSnapshot, opts cliOptions) {
	rows := collectDiskMountRows(s)
	if len(rows) == 0 {
		return
	}
	if opts.Compact {
		for _, r := range rows {
			status := labelByPct(r.usedPct)
			if r.hasInode && labelByPct(r.inodePct) > status {
				status = labelByPct(r.inodePct)
			}
			fmt.Printf("Disk %-6s %s=%s", badge(status, opts), r.mount, pctStr(r.usedPct))
			if r.hasInode {
				fmt.Printf(" i=%s", pctStr(r.inodePct))
			}
			fmt.Println()
		}
		return
	}

	fmt.Println("Disk")
	fmt.Printf("  %-6s %-16s %-29s %-7s %-24s\n", "state", "mount", "used / total / free", "disk %", "inode %")
	for _, r := range rows {
		status := labelByPct(r.usedPct)
		if r.hasInode && labelByPct(r.inodePct) > status {
			status = labelByPct(r.inodePct)
		}
		usage := pctStr(r.usedPct)
		capacity := "n/a"
		if r.totalBytes > 0 {
			capacity = fmt.Sprintf("%s / %s / %s", bytesIEC(r.usedBytes), bytesIEC(r.totalBytes), bytesIEC(r.freeBytes))
		}
		inode := "n/a"
		if r.hasInode {
			inode = pctStr(r.inodePct)
			if r.totalInodes > 0 {
				inode = fmt.Sprintf("%s (%d/%d)", inode, r.usedInodes, r.totalInodes)
			}
		}
		fmt.Printf("  %-6s %-16s %-29s %-7s %-24s\n", badge(status, opts), r.mount, capacity, usage, inode)
	}
}

type diskMountRow struct {
	mount       string
	usedBytes   uint64
	totalBytes  uint64
	freeBytes   uint64
	usedPct     float64
	inodePct    float64
	hasInode    bool
	usedInodes  uint64
	totalInodes uint64
}

func collectDiskMountRows(s parsedSnapshot) []diskMountRow {
	rows := make([]diskMountRow, 0, len(s.Modern.Disk.Mounts)+2)
	for _, m := range s.Modern.Disk.Mounts {
		usedPct := m.UsedPct
		if usedPct <= 0 && m.TotalBytes > 0 {
			usedPct = 100 * float64(m.UsedBytes) / float64(m.TotalBytes)
		}
		free := uint64(0)
		if m.TotalBytes > m.UsedBytes {
			free = m.TotalBytes - m.UsedBytes
		}
		r := diskMountRow{
			mount:      m.Mount,
			usedBytes:  m.UsedBytes,
			totalBytes: m.TotalBytes,
			freeBytes:  free,
			usedPct:    usedPct,
		}
		if m.TotalInodes > 0 {
			r.hasInode = true
			r.usedInodes = m.UsedInodes
			r.totalInodes = m.TotalInodes
			r.inodePct = m.InodeUsedPct
			if r.inodePct <= 0 {
				r.inodePct = 100 * float64(m.UsedInodes) / float64(m.TotalInodes)
			}
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		if s.Legacy.DiskRootPct > 0 {
			rows = append(rows, diskMountRow{mount: "/", usedPct: s.Legacy.DiskRootPct})
		}
		if s.Legacy.DiskTmpPct > 0 {
			rows = append(rows, diskMountRow{mount: "/tmp", usedPct: s.Legacy.DiskTmpPct})
		}
	}
	return rows
}

func printStorageSection(s parsedSnapshot, opts cliOptions) {
	smart := firstNonEmpty(s.Modern.Disk.SmartHealth, getStr(s.RawMap, "smart_health"))
	wear := firstNonEmpty(s.Modern.Disk.DiskWearout, getStr(s.RawMap, "disk_wearout"))
	mdadm := firstNonEmpty(s.Modern.Disk.MDADMHealth, getStr(s.RawMap, "mdadm_health"))
	mdadmRawStatus := firstNonEmpty(s.Modern.Disk.MDADM.Status, getRawMDADMStatus(s.RawMap))
	zfs := firstNonEmpty(s.Modern.Disk.ZFSHealth, getStr(s.RawMap, "zfs_health"))
	if smart == "" && wear == "" && mdadm == "" && mdadmRawStatus == "" && zfs == "" {
		return
	}
	mdadmText, mdadmRank := mdadmRAIDStatus(s, firstNonEmpty(mdadmRawStatus, mdadm))
	zfsText, zfsRank := optionalStorageSubsystemStatus(s, "zfs_present", zfs)
	storageRank := worstLabel(healthLabel(smart), healthLabel(wear), mdadmRank, zfsRank)
	if opts.Compact {
		fmt.Printf("Storage %-6s smart=%s wear=%s mdadm=%s zfs=%s\n", badge(storageRank, opts),
			nonEmptyOr(smart, "n/a"), nonEmptyOr(wear, "n/a"), mdadmText, zfsText)
		printDiskSmartDeviceSection(s, opts)
		return
	}
	fmt.Printf("Storage health %s\n", badge(storageRank, opts))
	fmt.Printf("  SMART summary: %s\n", nonEmptyOr(smart, "n/a"))
	fmt.Printf("  Wearout (highest devices): %s\n", nonEmptyOr(wear, "n/a"))
	fmt.Printf("  %s  MDADM RAID: %s\n", badge(mdadmRank, opts), mdadmText)
	fmt.Printf("  ZFS: %s\n", zfsText)
	printDiskSmartDeviceSection(s, opts)
}

func optionalStorageSubsystemStatus(s parsedSnapshot, presentKey, health string) (string, healthLabelRank) {
	present, known := getOptionalBool(s.RawMap, presentKey)
	if known && !present {
		return "not present", okLabel
	}
	return nonEmptyOr(health, "n/a"), healthLabel(health)
}

func mdadmRAIDStatus(s parsedSnapshot, source string) (string, healthLabelRank) {
	present, known := getOptionalBool(s.RawMap, "mdadm_present")
	if known && !present {
		return "not present", okLabel
	}
	if source == "" {
		source = s.Modern.Disk.MDADM.Status
	}
	status, rank, why := normalizeMDADMStatus(source)
	if rank != critLabel {
		if degradedWhy := mdadmDegradedWhy(s.Modern.Disk.MDADM); degradedWhy != "" {
			status, rank, why = "degraded", critLabel, degradedWhy
		}
	}
	if rank == okLabel {
		if syncingWhy := mdadmSyncingWhy(s.Modern.Disk.MDADM); syncingWhy != "" {
			status, rank, why = "syncing", warnLabel, syncingWhy
		}
	}
	if status == "" {
		return "n/a", okLabel
	}
	if why != "" && rank != okLabel {
		status += " [" + strings.ToUpper(why) + "]"
	}
	return status, rank
}

func normalizeMDADMStatus(source string) (string, healthLabelRank, string) {
	x := strings.ToLower(strings.TrimSpace(source))
	switch {
	case x == "", x == "unknown", x == "n/a":
		return "", okLabel, ""
	case strings.Contains(x, "degraded"):
		return "degraded", critLabel, "degraded"
	case strings.Contains(x, "failed") || strings.Contains(x, "fail"):
		return "degraded", critLabel, "failed"
	case strings.Contains(x, "missing"):
		return "degraded", critLabel, "missing"
	case strings.Contains(x, "recover"):
		return "syncing", warnLabel, "recover"
	case strings.Contains(x, "resync"):
		return "syncing", warnLabel, "resync"
	case strings.Contains(x, "sync"):
		return "syncing", warnLabel, "sync"
	case strings.Contains(x, "check"):
		return "syncing", warnLabel, "check"
	case strings.Contains(x, "clean") || strings.Contains(x, "active") || strings.Contains(x, "ok") || strings.Contains(x, "healthy"):
		return "normal", okLabel, ""
	case strings.Contains(x, "critical"):
		return "degraded", critLabel, "critical"
	case strings.Contains(x, "warning") || strings.Contains(x, "warn"):
		return "syncing", warnLabel, "warning"
	default:
		return strings.TrimSpace(source), healthLabel(source), ""
	}
}

func mdadmDegradedWhy(m healthmodel.MDADMStatus) string {
	for _, arr := range m.Arrays {
		if arr.FailedMissing > 0 {
			return "degraded"
		}
		if arr.ExpectedMembers > 0 && arr.ActiveMembers > 0 && arr.ActiveMembers < arr.ExpectedMembers {
			return "missing"
		}
		for _, state := range arr.MemberStates {
			state = strings.ToLower(strings.TrimSpace(state))
			if state == "missing" || state == "failed" {
				return state
			}
		}
	}
	return ""
}

func mdadmSyncingWhy(m healthmodel.MDADMStatus) string {
	for _, arr := range m.Arrays {
		phase := strings.ToLower(strings.TrimSpace(arr.ProgressPhase))
		switch phase {
		case "recovery", "recover":
			return "recover"
		case "resync":
			return "resync"
		case "sync":
			return "sync"
		case "check":
			return "check"
		}
	}
	return ""
}

func getRawMDADMStatus(raw map[string]any) string {
	v, ok := raw["mdadm"]
	if !ok {
		if disk, ok := raw["disk"].(map[string]any); ok {
			v = disk["mdadm"]
		} else {
			return ""
		}
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if status, ok := m["status"].(string); ok {
		return strings.TrimSpace(status)
	}
	return ""
}

type diskSmartRow struct {
	Key            string
	Model          string
	Serial         string
	DeviceType     string
	Normalized     string
	WearoutUsed    *int
	WearoutSource  string
	TemperatureC   string
	ProbeOrErr     string
	normalizedRank healthLabelRank
}

func collectDiskSmartRows(s parsedSnapshot) []diskSmartRow {
	if len(s.Modern.Disk.SmartDevices) == 0 {
		return nil
	}
	rows := make([]diskSmartRow, 0, len(s.Modern.Disk.SmartDevices))
	for key, dev := range s.Modern.Disk.SmartDevices {
		r := diskSmartRow{
			Key:            strings.TrimPrefix(strings.TrimSpace(key), "/dev/"),
			Model:          strings.TrimSpace(dev.Model),
			Serial:         strings.TrimSpace(dev.Serial),
			DeviceType:     strings.TrimSpace(dev.DeviceType),
			Normalized:     strings.TrimSpace(dev.NormalizedHealth),
			WearoutUsed:    dev.WearoutPctUsed,
			WearoutSource:  strings.TrimSpace(dev.WearoutSource),
			TemperatureC:   strings.TrimSpace(dev.TemperatureC),
			ProbeOrErr:     strings.TrimSpace(dev.Error),
			normalizedRank: healthLabel(strings.TrimSpace(dev.NormalizedHealth)),
		}
		if r.Key == "" {
			r.Key = strings.TrimSpace(key)
		}
		if r.ProbeOrErr == "" && strings.TrimSpace(dev.Health) != "" && strings.TrimSpace(dev.Health) != strings.TrimSpace(dev.NormalizedHealth) {
			r.ProbeOrErr = strings.TrimSpace(dev.Health)
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].normalizedRank != rows[j].normalizedRank {
			return rows[i].normalizedRank > rows[j].normalizedRank
		}
		wi := -1
		if rows[i].WearoutUsed != nil {
			wi = *rows[i].WearoutUsed
		}
		wj := -1
		if rows[j].WearoutUsed != nil {
			wj = *rows[j].WearoutUsed
		}
		if wi != wj {
			return wi > wj
		}
		return rows[i].Key < rows[j].Key
	})
	return rows
}

func printDiskSmartDeviceSection(s parsedSnapshot, opts cliOptions) {
	rows := collectDiskSmartRows(s)
	if len(rows) == 0 {
		return
	}
	if !opts.Compact {
		fmt.Println("Disk SMART devices")
		fmt.Printf("  %-10s %-16s %-14s %-10s %-10s %-18s %-7s %s\n",
			"device", "model", "serial", "type", "health", "wearout_used", "temp", "probe/error")
	}
	limit := len(rows)
	if !opts.DiskDetail {
		limit = 3
		if limit > len(rows) {
			limit = len(rows)
		}
	}
	for i := 0; i < limit; i++ {
		row := rows[i]
		wear := "n/a"
		if row.WearoutUsed != nil {
			wear = fmt.Sprintf("%d%%", *row.WearoutUsed)
			if row.WearoutSource != "" {
				wear += " (" + row.WearoutSource + ")"
			}
		}
		model := truncateIdentifier(nonEmptyOr(row.Model, "-"), 16, opts.FullIdent)
		serial := maskOrTrimSerial(row.Serial, opts.FullIdent)
		dtype := nonEmptyOr(row.DeviceType, "-")
		health := nonEmptyOr(row.Normalized, "unknown")
		temp := nonEmptyOr(row.TemperatureC, "-")
		probe := nonEmptyOr(row.ProbeOrErr, "-")
		if len(probe) > 42 {
			probe = probe[:41] + "…"
		}
		if opts.Compact {
			fmt.Printf("DiskDev %-6s %s %s h=%s wear=%s temp=%s err=%s\n",
				badge(healthLabel(health), opts), row.Key, serial, health, wear, temp, probe)
			continue
		}
		fmt.Printf("  %-10s %-16s %-14s %-10s %-10s %-18s %-7s %s\n",
			row.Key, model, serial, dtype, health, wear, temp, probe)
	}
	if !opts.DiskDetail && len(rows) > limit {
		if opts.Compact {
			fmt.Printf("DiskDev %-6s +%d more (use --disk-detail)\n", badge(okLabel, opts), len(rows)-limit)
		} else {
			fmt.Printf("  ... +%d more devices (use --disk-detail)\n", len(rows)-limit)
		}
	}
}

func maskOrTrimSerial(serial string, showFull bool) string {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return "-"
	}
	if showFull {
		return serial
	}
	if len(serial) <= 8 {
		return serial
	}
	return serial[:4] + "…" + serial[len(serial)-3:]
}

func truncateIdentifier(v string, n int, showFull bool) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	if showFull || len(v) <= n {
		return v
	}
	if n <= 1 {
		return v[:n]
	}
	return v[:n-1] + "…"
}

func printNetworkSection(s parsedSnapshot, opts cliOptions) {
	ctCount, ctMax, ctPct, ctAvailable := conntrackUsage(s)
	tcp := s.Modern.Network.TCP
	if len(tcp) == 0 {
		if m, ok := getMapInt(s.RawMap, "connection_states"); ok {
			tcp = m
		}
	}
	if len(tcp) == 0 {
		if m, ok := getNestedMapInt(s.RawMap, "network", "connection_states"); ok {
			tcp = m
		}
	}
	ifaces := networkInterfaces(s)
	status := okLabel
	if ctAvailable {
		status = labelByPct(ctPct)
	}
	if opts.Compact {
		fmt.Printf("Network %-6s", badge(status, opts))
		if ctAvailable {
			fmt.Printf(" conntrack=%d/%d (%s)", ctCount, ctMax, pctWholeStr(ctPct))
		} else {
			fmt.Printf(" conntrack=unavailable")
		}
		if len(tcp) > 0 {
			fmt.Printf(" conn=%s", renderConnStates(tcp))
		}
		if len(ifaces) > 0 {
			fmt.Printf(" if=%s", strings.Join(ifaces, ","))
		}
		fmt.Println()
		return
	}
	fmt.Printf("Network %s\n", badge(status, opts))
	if ctAvailable {
		fmt.Printf("  Conntrack: %d / %d (%s)\n", ctCount, ctMax, pctWholeStr(ctPct))
	} else {
		fmt.Printf("  Conntrack: unavailable\n")
	}
	if len(tcp) > 0 {
		fmt.Printf("  Connection states: %s\n", renderConnStates(tcp))
	}
	if len(ifaces) > 0 {
		fmt.Printf("  Interfaces: %s\n", strings.Join(ifaces, ", "))
	}
}

func conntrackUsage(s parsedSnapshot) (count, max int, pct float64, ok bool) {
	count = s.Modern.Network.ConntrackCount
	max = s.Modern.Network.ConntrackMax
	pct = s.Modern.Network.ConntrackUsagePct
	if max <= 0 {
		if networkRaw, rawOK := s.RawMap["network"].(map[string]any); rawOK {
			count = getInt(networkRaw, "conntrack_count")
			max = getInt(networkRaw, "conntrack_max")
			pct = getFloat(networkRaw, "conntrack_usage_pct")
			if pct == 0 {
				pct = getFloat(networkRaw, "conntrack_pct")
			}
		}
	}
	if max <= 0 {
		count = getInt(s.RawMap, "conntrack_count")
		max = getInt(s.RawMap, "conntrack_max")
		pct = getFloat(s.RawMap, "conntrack_usage_pct")
		if pct == 0 {
			pct = getFloat(s.RawMap, "conntrack_pct")
		}
	}
	if max <= 0 {
		return 0, 0, 0, false
	}
	if pct == 0 && count > 0 {
		pct = float64(count) * 100 / float64(max)
	}
	return count, max, pct, true
}

func printCFMSection(s parsedSnapshot, opts cliOptions) {
	m := s.Modern.CFM
	if m == (struct {
		ActiveBlocks   int "json:\"active_blocks\""
		ChallengeQueue int "json:\"challenge_queue\""
		WAFEvents1h    int "json:\"waf_events_1h\""
		OutboundAlerts int "json:\"outbound_alerts\""
	}{}) {
		m.ActiveBlocks = getInt(s.RawMap, "active_blocks")
		m.ChallengeQueue = getInt(s.RawMap, "challenge_queue")
		m.WAFEvents1h = getInt(s.RawMap, "waf_events_1h")
		m.OutboundAlerts = getInt(s.RawMap, "outbound_alerts")
	}
	if m.ActiveBlocks == 0 && m.ChallengeQueue == 0 && m.WAFEvents1h == 0 && m.OutboundAlerts == 0 {
		fmt.Printf("CFM %s metrics not available\n", badge(okLabel, opts))
		return
	}
	status := worstLabel(labelByCount(m.ChallengeQueue, 5, 25), labelByCount(m.WAFEvents1h, 50, 200), labelByCount(m.OutboundAlerts, 1, 5))
	if opts.Compact {
		fmt.Printf("CFM %-6s blocks=%d queue=%d waf1h=%d alerts=%d\n", badge(status, opts), m.ActiveBlocks, m.ChallengeQueue, m.WAFEvents1h, m.OutboundAlerts)
		return
	}
	fmt.Printf("CFM %s\n", badge(status, opts))
	fmt.Printf("  Active blocks: %d\n", m.ActiveBlocks)
	fmt.Printf("  Challenge queue: %d\n", m.ChallengeQueue)
	fmt.Printf("  WAF events (1h): %d\n", m.WAFEvents1h)
	fmt.Printf("  Outbound alerts: %d\n", m.OutboundAlerts)
}

func fetchSnapshot(baseURL string) (parsedSnapshot, error) {
	var out parsedSnapshot
	res, err := getJSON(baseURL + "/api/v1/health/snapshot")
	if err != nil {
		return out, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return out, fmt.Errorf("health snapshot failed: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out.Envelope); err == nil && len(out.Envelope.Snapshot) > 0 {
		_ = json.Unmarshal(out.Envelope.Snapshot, &out.Legacy)
		_ = json.Unmarshal(out.Envelope.Snapshot, &out.Modern)
		_ = json.Unmarshal(out.Envelope.Snapshot, &out.RawMap)
		return out, nil
	}
	var latest healthmodel.HealthSnapshotV1
	if err := json.Unmarshal(body, &latest); err == nil && latest.SchemaVersion == healthmodel.SchemaVersionV1 {
		out.Modern.NodeID = latest.NodeID
		out.Modern.CollectedAt = latest.CollectedAt
		out.Modern.Host.Hostname = latest.Host.Hostname
		out.Modern.Host.LoadAvg1 = latest.Host.LoadAvg1
		out.Modern.Host.CPUPercent = latest.Host.CPUPercent
		out.Modern.Host.MemUsedBytes = latest.Host.MemUsedBytes
		out.Modern.Host.MemTotalBytes = latest.Host.MemTotalBytes
		out.Modern.Disk.SmartHealth = latest.Disk.SmartHealth
		out.Modern.Disk.DiskWearout = latest.Disk.DiskWearout
		out.Modern.Disk.SmartDevices = latest.Disk.SmartDevices
		out.Modern.Disk.MDADMHealth = latest.Disk.MDADMHealth
		out.Modern.Disk.MDADM = latest.Disk.MDADM
		out.Modern.Disk.ZFSHealth = latest.Disk.ZFSHealth
		for _, m := range latest.Disk.Mounts {
			out.Modern.Disk.Mounts = append(out.Modern.Disk.Mounts, struct {
				Mount        string  "json:\"mount\""
				UsedBytes    uint64  "json:\"used_bytes\""
				TotalBytes   uint64  "json:\"total_bytes\""
				UsedPct      float64 "json:\"used_pct\""
				UsedInodes   uint64  "json:\"used_inodes\""
				TotalInodes  uint64  "json:\"total_inodes\""
				InodeUsedPct float64 "json:\"inode_used_pct\""
			}{
				Mount:        m.Mount,
				UsedBytes:    m.UsedBytes,
				TotalBytes:   m.TotalBytes,
				UsedPct:      m.UsedPct,
				UsedInodes:   m.UsedInodes,
				TotalInodes:  m.TotalInodes,
				InodeUsedPct: m.InodeUsedPct,
			})
		}
		out.Modern.CFM.ActiveBlocks = latest.CFM.ActiveBlocks
		out.Modern.CFM.ChallengeQueue = latest.CFM.ChallengeQueue
		out.Modern.CFM.WAFEvents1h = latest.CFM.WAFEvents1h
		out.Modern.CFM.OutboundAlerts = latest.CFM.OutboundAlerts
		out.Modern.Network.InBps = latest.Network.BandwidthInBytesPerSec
		out.Modern.Network.OutBps = latest.Network.BandwidthOutBytesPerSec
		out.Modern.Network.ConntrackCount = latest.Network.ConntrackCount
		out.Modern.Network.ConntrackMax = latest.Network.ConntrackMax
		out.Modern.Network.ConntrackUsagePct = latest.Network.ConntrackUsagePct
		out.Modern.Runtime.CFMDaemonLive = latest.Runtime.CFMDaemonLive
		out.Modern.Runtime.CFMDaemonPID = latest.Runtime.CFMDaemonPID
		out.Modern.Runtime.CFMServiceState = latest.Runtime.CFMServiceState
		out.Modern.Runtime.DNATEnabled = latest.Runtime.DNATEnabled
		out.Modern.Runtime.PanelDNATEnabled = latest.Runtime.PanelDNATEnabled
		out.Modern.Runtime.DNATFrontend = latest.Runtime.DNATFrontend
		out.Modern.Runtime.DNATConfidence = latest.Runtime.DNATConfidence
		out.Modern.Runtime.DNATWarning = latest.Runtime.DNATWarning
		out.Modern.Runtime.FrontendWorking = latest.Runtime.FrontendWorking
		out.Modern.Runtime.FrontendReason = latest.Runtime.FrontendReason
		out.Modern.Runtime.EdgeService = latest.Runtime.EdgeService
		out.Modern.Runtime.UpstreamService = latest.Runtime.UpstreamService
		out.Modern.Runtime.EdgeStatus = latest.Runtime.EdgeStatus
		out.Modern.Runtime.UpstreamStatus = latest.Runtime.UpstreamStatus
		out.Modern.Runtime.EdgeConfidence = latest.Runtime.EdgeConfidence
		out.Modern.Runtime.UpstreamConfidence = latest.Runtime.UpstreamConfidence
		out.Modern.Runtime.EdgeReasonCode = latest.Runtime.EdgeReasonCode
		out.Modern.Runtime.UpstreamReasonCode = latest.Runtime.UpstreamReasonCode
		out.Modern.Runtime.ChallengeFlowState = latest.Runtime.ChallengeFlowState
		out.Modern.Runtime.ChallengeFlowCode = latest.Runtime.ChallengeFlowCode
		out.Modern.Runtime.ChallengeFlowReason = latest.Runtime.ChallengeFlowReason
		out.Modern.Runtime.BridgeSocketStatus = latest.Runtime.BridgeSocketStatus
		out.Modern.Runtime.BridgeSocketReason = latest.Runtime.BridgeSocketReason
		out.Modern.Runtime.BridgeSocketLatencyMs = latest.Runtime.BridgeSocketLatencyMs
		out.Modern.Runtime.ChallengeListenerStatus = latest.Runtime.ChallengeListenerStatus
		out.Modern.Runtime.ChallengeListenerReason = latest.Runtime.ChallengeListenerReason
		out.Modern.Runtime.SSLCollectorStatus = latest.Runtime.SSLCollectorStatus
		out.Modern.Runtime.IngestSocketPath = latest.Runtime.IngestSocketPath
		out.Modern.Runtime.IngestSocketStatus = latest.Runtime.IngestSocketStatus
		out.Modern.Runtime.IngestSocketReason = latest.Runtime.IngestSocketReason
		out.Modern.Runtime.IngestSourceActive = latest.Runtime.IngestSourceActive
		out.Modern.Runtime.IngestSourceSockListening = latest.Runtime.IngestSourceSockListening
		out.Modern.Runtime.IngestSourceLastReceivedUnix = latest.Runtime.IngestSourceLastReceivedUnix
		for _, svc := range latest.Services {
			out.Modern.Services = append(out.Modern.Services, serviceStatus{
				Name:      svc.Name,
				Active:    svc.Active,
				Enabled:   svc.Enabled,
				State:     svc.State,
				LastError: svc.LastError,
			})
		}
		_ = json.Unmarshal(body, &out.RawMap)
		out.Envelope.SchemaVersion = latest.SchemaVersion
		out.Envelope.NodeID = latest.NodeID
		out.Envelope.GeneratedAt = latest.CollectedAt
		return out, nil
	}
	return out, fmt.Errorf("decode health snapshot: unsupported payload")
}

func getJSON(u string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return clihttp.Do(req)
}

type healthLabelRank int

const (
	okLabel healthLabelRank = iota
	warnLabel
	critLabel
)

func labelByPct(v float64) healthLabelRank {
	switch {
	case v >= 95:
		return critLabel
	case v >= 85:
		return warnLabel
	default:
		return okLabel
	}
}

func labelByCount(v, warn, crit int) healthLabelRank {
	if v >= crit {
		return critLabel
	}
	if v >= warn {
		return warnLabel
	}
	return okLabel
}

func labelByThroughput(bps uint64) healthLabelRank {
	if bps > 5*1024*1024*1024 {
		return warnLabel
	}
	return okLabel
}

func healthLabel(s string) healthLabelRank {
	x := strings.ToLower(strings.TrimSpace(s))
	switch {
	case x == "", x == "unknown", x == "n/a":
		return okLabel
	case strings.Contains(x, "crit"), strings.Contains(x, "fail"), strings.Contains(x, "degraded"):
		return critLabel
	case strings.Contains(x, "warn"), strings.Contains(x, "recover"), strings.Contains(x, "resilver"):
		return warnLabel
	default:
		return okLabel
	}
}

func worstLabel(in ...healthLabelRank) healthLabelRank {
	out := okLabel
	for _, v := range in {
		if v > out {
			out = v
		}
	}
	return out
}

func badge(l healthLabelRank, opts cliOptions) string {
	text := "[OK]"
	color := "\033[32m"
	switch l {
	case warnLabel:
		text = "[WARN]"
		color = "\033[33m"
	case critLabel:
		text = "[CRIT]"
		color = "\033[31m"
	}
	if opts.NoColor || !isTTY() {
		return text
	}
	return color + text + "\033[0m"
}

func chooseHost(s parsedSnapshot) string {
	for _, v := range []string{s.Modern.Host.Hostname, s.Legacy.Hostname, s.Envelope.NodeID, s.Legacy.NodeID, s.Modern.NodeID} {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "local"
}

func chooseCollectedAt(s parsedSnapshot) time.Time {
	for _, ts := range []time.Time{s.Modern.CollectedAt, s.Legacy.CollectedAt, s.Envelope.GeneratedAt} {
		if !ts.IsZero() {
			return ts
		}
	}
	return time.Time{}
}

func networkBps(s parsedSnapshot) (uint64, uint64) {
	if s.Modern.Network.InBps > 0 || s.Modern.Network.OutBps > 0 {
		return s.Modern.Network.InBps, s.Modern.Network.OutBps
	}
	return mbpsToBps(s.Legacy.RxMbps), mbpsToBps(s.Legacy.TxMbps)
}

func networkBandwidthAvailable(s parsedSnapshot) bool {
	if s.Modern.Network.InBps > 0 || s.Modern.Network.OutBps > 0 || s.Legacy.RxMbps > 0 || s.Legacy.TxMbps > 0 {
		return true
	}
	if hasKey(s.RawMap, "bandwidth_in_bps") || hasKey(s.RawMap, "bandwidth_out_bps") ||
		hasKey(s.RawMap, "rx_mbps") || hasKey(s.RawMap, "tx_mbps") {
		return true
	}
	if networkRaw, ok := s.RawMap["network"].(map[string]any); ok {
		if hasKey(networkRaw, "bandwidth_in_bps") || hasKey(networkRaw, "bandwidth_out_bps") {
			return true
		}
	}
	return false
}

func networkInterfaces(s parsedSnapshot) []string {
	if out, ok := getStringSlice(s.RawMap, "network_interfaces"); ok {
		return out
	}
	if networkRaw, ok := s.RawMap["network"].(map[string]any); ok {
		for _, key := range []string{"interfaces", "ifaces", "network_interfaces"} {
			if out, ok := getStringSlice(networkRaw, key); ok {
				return out
			}
		}
	}
	return nil
}

func mbpsToBps(v float64) uint64 {
	if v <= 0 {
		return 0
	}
	return uint64(v * 1024 * 1024 / 8)
}

func bytesIEC(v uint64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%d B", v)
	}
	div, exp := uint64(unit), 0
	for n := v / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(v)/float64(div), "KMGTPE"[exp])
}

func bytesPerSec(v uint64) string { return bytesIEC(v) + "/s" }

func pctWholeStr(v float64) string {
	if v <= 0 {
		return "0%"
	}
	return fmt.Sprintf("%.0f%%", v)
}

func pctStr(v float64) string {
	if v <= 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", v)
}

func renderConnStates(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", strings.ToLower(k), m[k]))
	}
	return strings.Join(parts, " ")
}

func getMapInt(m map[string]any, key string) (map[string]int, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	raw, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := map[string]int{}
	for k, vv := range raw {
		switch n := vv.(type) {
		case float64:
			out[k] = int(n)
		case int:
			out[k] = n
		}
	}
	return out, len(out) > 0
}

func getNestedMapInt(m map[string]any, parent, key string) (map[string]int, bool) {
	v, ok := m[parent]
	if !ok {
		return nil, false
	}
	raw, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	return getMapInt(raw, key)
}

func getStringSlice(m map[string]any, key string) ([]string, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out, len(out) > 0
}

func hasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

func getStr(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func getOptionalBool(m map[string]any, key string) (bool, bool) {
	if v, ok := m[key]; ok {
		if b, ok := parseOptionalBool(v); ok {
			return b, true
		}
	}
	if rawDisk, ok := m["disk"].(map[string]any); ok {
		if v, ok := rawDisk[key]; ok {
			if b, ok := parseOptionalBool(v); ok {
				return b, true
			}
		}
	}
	return false, false
}

func parseOptionalBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "true", "1", "yes", "y", "on":
			return true, true
		case "false", "0", "no", "n", "off":
			return false, true
		}
	case float64:
		if x == 0 {
			return false, true
		}
		if x == 1 {
			return true, true
		}
	case int:
		if x == 0 {
			return false, true
		}
		if x == 1 {
			return true, true
		}
	}
	return false, false
}

func getFloat(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case json.Number:
		out, _ := n.Float64()
		return out
	default:
		return 0
	}
}

func getInt(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func nonEmptyOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func nonZero(a, b float64) float64 {
	if a != 0 {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
