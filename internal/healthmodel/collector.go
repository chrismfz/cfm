package healthmodel

import (
	"cfm/internal/conntrack"
	edgediag "cfm/internal/diagnostics/edge"
	"cfm/internal/dnat"
	"cfm/internal/firewall"
	"cfm/internal/mailq"
	webdet "cfm/internal/webdetector"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/detectors/health"
)

// snapshotNowFn exists as a small test seam to force collector failures.
var snapshotNowFn = health.SnapshotNow
var readConntrackUsage = conntrack.ReadUsage
var challengeDialTimeout = func(network, addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}
var bridgeDecisionProbe = func(sockPath, token string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", sockPath)
			},
			DisableKeepAlives: true,
		},
		Timeout: 2 * time.Second,
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/nginx/status", nil)
	req.Header.Set("X-CFM-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
var challengeFlowDetectorsConfigPath = "/etc/cfm/detectors.conf"
var challengeFlowBridgeTokenPath = edgediag.CanonicalBridgeTokenPath

// RawDetectorSnapshot aliases the detector snapshot type for tests outside this package.
type RawDetectorSnapshot = health.Snapshot

// TestOnlySwapSnapshotNowFn replaces the snapshot collector function and returns the previous one.
func TestOnlySwapSnapshotNowFn(fn func() health.Snapshot) func() health.Snapshot {
	prev := snapshotNowFn
	snapshotNowFn = fn
	return prev
}

// CollectSnapshotNow builds the canonical health snapshot directly from live host collectors.
func CollectSnapshotNow(nodeID string, backend firewall.Backend) (snap HealthSnapshotV1) {
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
	populateConntrackUsage(&snap.Network)
	snap.Runtime = collectRuntimeStatus(backend)
	snap.Mail = latestMailQueueStatus()
	// cfm_metrics.waf_events_1h: durable last-rolling-hour WAF event count
	// (waf_observe+waf_trigger, node-wide) from the SAME history store the
	// /api/v1/waf/engine/summary endpoint uses, so this reconciles with
	// security_overview's waf_last_hour. Before this it was never populated and
	// always read 0 next to a non-zero summary. A COUNT(*) over the type+ts
	// index is cheap on this collection path. (The sibling CFMMetrics fields —
	// active_blocks/challenge_queue/outbound_alerts — remain unwired; separate
	// follow-up. See docs/ROADMAP.md.)
	if n, ok := webdet.WAFEventsLastHour(time.Now()); ok {
		snap.CFM.WAFEvents1h = n
	}
	return snap
}

// latestMailQueueStatus maps the mailq store's freshest measurement into
// the snapshot; nil when no queue detector has published anything.
func latestMailQueueStatus() *MailQueueStatus {
	m, ok := mailq.Latest()
	if !ok {
		return nil
	}
	age := int64(time.Since(m.MeasuredAt).Seconds())
	if age < 0 {
		age = 0
	}
	return &MailQueueStatus{MTA: m.MTA, Queued: m.Total, Frozen: m.Frozen, AgeSeconds: age}
}

func populateConntrackUsage(network *NetworkThroughput) {
	if network == nil {
		return
	}
	usage, err := readConntrackUsage()
	if err != nil || usage.Max <= 0 {
		return
	}
	network.ConntrackCount = usage.Count
	network.ConntrackMax = usage.Max
	network.ConntrackUsagePct = usage.UsagePct
}

func collectRuntimeStatus(backend firewall.Backend) RuntimeStatus {
	out := RuntimeStatus{
		CFMServiceState:    "unknown",
		DNATEnabled:        "unknown",
		PanelDNATEnabled:   "unknown",
		DNATFrontend:       "unknown",
		DNATConfidence:     "low",
		FrontendWorking:    "down",
		EdgeService:        "unknown",
		UpstreamService:    "unknown",
		EdgeStatus:         "unknown",
		UpstreamStatus:     "unknown",
		EdgeConfidence:     "low",
		UpstreamConfidence: "low",
		EdgeReasonCode:     "unknown",
		UpstreamReasonCode: "unknown",
	}
	out.CFMDaemonLive, out.CFMDaemonPID = probeCFMDaemonLive()
	if state, ok := probeSystemdServiceState("cfm.service"); ok {
		out.CFMServiceState = state
	}
	if !out.CFMDaemonLive && out.CFMServiceState == "active" {
		out.CFMDaemonLive = true
	}
	if backend == nil {
		out.DNATEnabled = "unavailable"
	} else if enabled, err := dnat.Status(backend); err == nil {
		if enabled {
			out.DNATEnabled = "on"
		} else {
			out.DNATEnabled = "off"
		}
	}
	if enabled, _, err := dnat.PanelStatus(); err == nil {
		if enabled {
			out.PanelDNATEnabled = "on"
		} else {
			out.PanelDNATEnabled = "off"
		}
	} else {
		out.PanelDNATEnabled = "unavailable"
	}
	resolution := ResolveWebRoles(out.DNATEnabled)
	out.DNATFrontend = resolution.frontend
	out.DNATConfidence = resolution.frontendConfidence
	out.DNATWarning = resolution.frontendWarning
	out.FrontendWorking = resolution.frontendVerdict
	out.FrontendReason = resolution.frontendReason
	out.FrontendDebug = resolution.frontendDebug
	out.EdgeService = resolution.edge.service
	out.EdgeStatus = resolution.edge.status
	out.EdgeConfidence = resolution.edge.confidence
	out.EdgeReasonCode = resolution.edge.reasonCode
	out.UpstreamService = resolution.upstream.service
	out.UpstreamStatus = resolution.upstream.status
	out.UpstreamConfidence = resolution.upstream.confidence
	out.UpstreamReasonCode = resolution.upstream.reasonCode
	flow := probeChallengeFlowReadiness()
	out.ChallengeFlowState = flow.Status
	out.ChallengeFlowCode = flow.Code
	out.ChallengeFlowReason = flow.Reason
	out.BridgeSocketStatus = flow.BridgeSocketStatus
	out.BridgeSocketReason = flow.BridgeSocketReason
	out.BridgeSocketLatencyMs = flow.BridgeSocketLatencyMs
	out.ChallengeListenerStatus = flow.ChallengeListenerStatus
	out.ChallengeListenerReason = flow.ChallengeListenerReason
	out.ChallengeListenerAddress = flow.ChallengeListenerAddress
	out.SSLCollectorStatus = probeSSLCollectorStatus()
	populateIngestSocketHealth(&out)
	return out
}

type flowProbe struct {
	Status                   string
	Code                     string
	Reason                   string
	BridgeSocketStatus       string
	BridgeSocketReason       string
	BridgeSocketLatencyMs    int64
	ChallengeListenerStatus  string
	ChallengeListenerReason  string
	ChallengeListenerAddress string
}

func resolvedChallengeListenAddr(envKey string, defPort int) string {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return fmt.Sprintf("127.0.0.1:%d", defPort)
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	if p, err := strconv.Atoi(raw); err == nil && p > 0 && p <= 65535 {
		return fmt.Sprintf("127.0.0.1:%d", p)
	}
	return raw
}

func probeChallengeFlowReadiness() flowProbe {
	httpPort, _ := dnat.EffectiveTargetPorts()
	listenAddr := resolvedChallengeListenAddr("CHALLENGE_HTTP_LISTEN", httpPort)
	out := flowProbe{}
	conn, err := challengeDialTimeout("tcp", listenAddr, 1200*time.Millisecond)
	if err != nil {
		out.ChallengeListenerStatus = "fail"
		out.ChallengeListenerAddress = listenAddr
		out.ChallengeListenerReason = fmt.Sprintf("%s: %v", listenAddr, err)
		out.BridgeSocketStatus = "fail"
		out.BridgeSocketReason = "listener unavailable"
		return flowProbe{Status: "FAIL", Code: "challenge_listener_unreachable", Reason: out.ChallengeListenerReason, BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
	}
	out.ChallengeListenerStatus = "ok"
	out.ChallengeListenerAddress = listenAddr
	out.ChallengeListenerReason = fmt.Sprintf("listener reachable at %s", listenAddr)
	_ = conn.Close()
	cfg := edgediag.ResolveBridgeRuntimeConfig(challengeFlowDetectorsConfigPath)
	sockPath := cfg.SocketPath
	st, err := os.Stat(sockPath)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		out.BridgeSocketStatus = "fail"
		out.BridgeSocketReason = sockPath
		return flowProbe{Status: "FAIL", Code: "bridge_socket_unreachable", Reason: sockPath, BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
	}
	challengeToken := edgediag.ReadChallengeTokenProbe(challengeFlowDetectorsConfigPath)
	bridgeToken := edgediag.ReadBridgeTokenProbe(challengeFlowBridgeTokenPath)
	if !challengeToken.Present || !bridgeToken.Present {
		out.BridgeSocketStatus = "fail"
		out.BridgeSocketReason = "token missing"
		return flowProbe{Status: "FAIL", Code: "token_missing", Reason: "challenge/bridge token missing", BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
	}
	if !challengeToken.Valid || !bridgeToken.Valid {
		out.BridgeSocketStatus = "fail"
		out.BridgeSocketReason = "token weak"
		return flowProbe{Status: "FAIL", Code: "token_weak", Reason: "challenge/bridge token weak", BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
	}
	started := time.Now()
	statusCode, err := bridgeDecisionProbe(sockPath, bridgeToken.Token)
	out.BridgeSocketLatencyMs = time.Since(started).Milliseconds()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
			out.BridgeSocketStatus = "warn"
			out.BridgeSocketReason = "decision path timeout"
			return flowProbe{Status: "WARN", Code: "decision_path_timeout", Reason: "partial_ok: listener/socket/token present but decision path timed out", BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, BridgeSocketLatencyMs: out.BridgeSocketLatencyMs, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
		}
		out.BridgeSocketStatus = "fail"
		out.BridgeSocketReason = err.Error()
		return flowProbe{Status: "FAIL", Code: "decision_path_connect_fail", Reason: err.Error(), BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, BridgeSocketLatencyMs: out.BridgeSocketLatencyMs, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
	}
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		out.BridgeSocketStatus = "fail"
		out.BridgeSocketReason = fmt.Sprintf("http %d", statusCode)
		return flowProbe{Status: "FAIL", Code: "bridge_auth_fail", Reason: fmt.Sprintf("http %d", statusCode), BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, BridgeSocketLatencyMs: out.BridgeSocketLatencyMs, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
	}
	if statusCode != http.StatusOK {
		out.BridgeSocketStatus = "warn"
		out.BridgeSocketReason = fmt.Sprintf("http %d", statusCode)
		return flowProbe{Status: "WARN", Code: "decision_path_unexpected_status", Reason: fmt.Sprintf("partial_ok: http %d", statusCode), BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, BridgeSocketLatencyMs: out.BridgeSocketLatencyMs, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
	}
	out.BridgeSocketStatus = "ok"
	out.BridgeSocketReason = "ok"
	return flowProbe{Status: "OK", Code: "ok", Reason: "challenge flow ready", BridgeSocketStatus: out.BridgeSocketStatus, BridgeSocketReason: out.BridgeSocketReason, BridgeSocketLatencyMs: out.BridgeSocketLatencyMs, ChallengeListenerStatus: out.ChallengeListenerStatus, ChallengeListenerReason: out.ChallengeListenerReason, ChallengeListenerAddress: out.ChallengeListenerAddress}
}

func populateIngestSocketHealth(out *RuntimeStatus) {
	if out == nil {
		return
	}
	state, ok := webdet.CurrentIngestSourceState()
	if !ok {
		out.IngestSocketPath = webdet.DefaultIngestSockPath
		return
	}
	out.IngestSourceActive = state.Active
	out.IngestSourceSockListening = state.SockListening
	out.IngestSourceLastReceivedUnix = state.LastReceivedUnix
	out.IngestSocketPath = strings.TrimSpace(state.SockPath)
	if out.IngestSocketPath == "" {
		out.IngestSocketPath = webdet.DefaultIngestSockPath
	}
	activeSocket := strings.EqualFold(strings.TrimSpace(state.Active), "socket")
	recentSocket := false
	if state.LastReceivedUnix > 0 {
		d := time.Since(time.Unix(state.LastReceivedUnix, 0))
		recentSocket = d >= 0 && d <= webdet.SocketActiveWindow
	}
	if state.SockListening && activeSocket && recentSocket {
		out.IngestSocketStatus = "live"
		out.IngestSocketReason = "webdetector ingest arbiter: socket active and listening"
		return
	}
	if state.SockListening {
		out.IngestSocketStatus = "listening"
		out.IngestSocketReason = fmt.Sprintf("webdetector ingest arbiter: active=%s last_received=%s", state.Active, humanUnixTime(state.LastReceivedUnix))
		return
	}
	out.IngestSocketStatus = "down"
	out.IngestSocketReason = fmt.Sprintf("webdetector ingest arbiter: socket not listening active=%s last_received=%s", state.Active, humanUnixTime(state.LastReceivedUnix))
}

func humanUnixTime(ts int64) string {
	if ts <= 0 {
		return "never"
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

func probeSSLCollectorStatus() string {
	cfmToken := edgediag.ResolveLuaToken([]string{"/var/lib/cfm/lua/cfm_token.lua", "/usr/local/openresty/nginx/lua/cfm_token.lua", "/etc/angie/lua/cfm_token.lua"})
	sock := edgediag.ProbeSSLCollector("/var/run/sslcollector.sock", cfmToken)
	category := strings.ToUpper(strings.TrimSpace(sock.Category))
	switch category {
	case "OK":
		return "transport"
	case "AUTH_FAIL", "TOKEN_MISSING", "TOKEN_INVALID":
		return "auth"
	default:
		return "perm"
	}
}

type webRoleResolution struct {
	frontend           string
	frontendConfidence string
	frontendWarning    string
	frontendVerdict    string
	frontendReason     string
	frontendDebug      FrontendDebug
	edge               runtimeRoleSignal
	upstream           runtimeRoleSignal
}

func ResolveWebRoles(dnatState string) webRoleResolution {
	frontend, confidence, warning := detectDNATFrontend(dnatState)
	verdict, reason, debug := deriveFrontendWorking(frontend, dnatState)
	edge := detectEdgeRuntime(frontend, dnatState)
	upstream := detectUpstreamRuntime(edge.service)
	return webRoleResolution{
		frontend:           frontend,
		frontendConfidence: confidence,
		frontendWarning:    warning,
		frontendVerdict:    verdict,
		frontendReason:     reason,
		frontendDebug:      debug,
		edge:               edge,
		upstream:           upstream,
	}
}

type runtimeRoleSignal struct {
	service       string
	status        string
	confidence    string
	reasonCode    string
	listeningPort []int
}

type frontendSignal struct {
	name            string
	serviceUnit     string
	processAliases  []string
	configHookPaths []string
	binaryPaths     []string
	binaryCommands  []string
	active          bool
	enabled         bool
	binaryPresent   bool
	ownsDNATPorts   bool
	ownsPublicPorts bool
	listenerHits    int
	configHits      int
	score           int
}

func detectDNATFrontend(dnatState string) (string, string, string) {
	dnatOn := strings.EqualFold(strings.TrimSpace(dnatState), "on")
	candidates := []frontendSignal{
		{
			name:            "angie",
			serviceUnit:     "angie.service",
			processAliases:  []string{"angie", "nginx"},
			configHookPaths: []string{"/etc/angie/conf.d/cfm.conf", "/etc/angie/conf.d/nginx-cfm.conf", "/etc/angie/angie.conf"},
			binaryPaths:     []string{"/usr/sbin/angie", "/usr/bin/angie"},
			binaryCommands:  []string{"angie"},
		},
		{
			name:            "openresty",
			serviceUnit:     "openresty.service",
			processAliases:  []string{"openresty", "nginx"},
			configHookPaths: []string{"/usr/local/openresty/nginx/conf/nginx-cfm.conf", "/usr/local/openresty/nginx/conf/openresty-cfm-tsv.conf", "/usr/local/openresty/nginx/conf/nginx.conf"},
			binaryPaths:     []string{"/usr/local/openresty/nginx/sbin/nginx", "/opt/openresty/nginx/sbin/nginx"},
			binaryCommands:  []string{"openresty"},
		},
		{
			name:            "nginx",
			serviceUnit:     "nginx.service",
			processAliases:  []string{"nginx"},
			configHookPaths: []string{"/etc/nginx/conf.d/nginx-cfm.conf", "/etc/nginx/nginx.conf"},
			binaryPaths:     []string{"/usr/sbin/nginx", "/usr/bin/nginx"},
			binaryCommands:  []string{"nginx"},
		},
	}

	dnatListeners := probeFrontendListeners()
	dnatHTTP, dnatHTTPS := dnat.EffectiveTargetPorts()
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
		candidates[i].binaryPresent = hasAnyBinary(candidates[i].binaryPaths, candidates[i].binaryCommands)
		if candidates[i].binaryPresent {
			candidates[i].score += 2
		}
		candidates[i].ownsDNATPorts = dnatListeners.hasOwnerOnAllPorts(candidates[i].processAliases, dnatHTTP, dnatHTTPS)
		candidates[i].ownsPublicPorts = dnatListeners.hasOwnerOnAllPorts(candidates[i].processAliases, 80, 443)
		if dnatOn {
			if candidates[i].ownsPublicPorts {
				candidates[i].score++
			}
		} else if candidates[i].ownsPublicPorts {
			candidates[i].score += 2
		}
		if candidates[i].ownsDNATPorts {
			candidates[i].score += 5
		}
		for _, p := range candidates[i].configHookPaths {
			if _, err := os.Stat(p); err == nil {
				candidates[i].configHits++
			}
		}
		candidates[i].score += candidates[i].configHits
	}

	if frontend, confidence := resolveFrontendDeterministically(candidates, dnatOn); frontend != "" {
		warning := ""
		if confidence == "low" {
			warning = buildAmbiguityWarning(candidates)
		}
		return frontend, confidence, warning
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
			return activeUnits[0], "low", "ambiguous ownership: weak signals only"
		}
		if len(activeUnits) > 1 {
			return activeUnits[0], "low", fmt.Sprintf("ambiguous ownership: multiple active frontends (%s)", strings.Join(activeUnits, ", "))
		}
		return "unknown", "low", ""
	}

	confidence := "medium"
	if best.score >= 9 && !tie {
		confidence = "high"
	}
	warning := ""
	if confidence == "low" || tie || len(activeUnits) > 1 {
		confidence = "low"
		warning = buildAmbiguityWarning(candidates)
	}

	return best.name, confidence, warning
}

func resolveFrontendDeterministically(candidates []frontendSignal, dnatOn bool) (string, string) {
	if dnatOn {
		owners := filterFrontendSignals(candidates, func(c frontendSignal) bool { return c.ownsDNATPorts })
		if len(owners) == 1 {
			return owners[0].name, "high"
		}
		if len(owners) > 1 {
			activeOwners := filterFrontendSignals(owners, func(c frontendSignal) bool { return c.active })
			if len(activeOwners) == 1 {
				return activeOwners[0].name, "high"
			}
			strongOwners := filterFrontendSignals(owners, func(c frontendSignal) bool { return c.binaryPresent && c.configHits > 0 })
			if len(strongOwners) == 1 {
				return strongOwners[0].name, "medium"
			}
		}
	}

	strongActive := filterFrontendSignals(candidates, func(c frontendSignal) bool { return c.active && c.binaryPresent && c.configHits > 0 })
	if len(strongActive) == 1 {
		return strongActive[0].name, "medium"
	}
	strongConfigured := filterFrontendSignals(candidates, func(c frontendSignal) bool { return c.binaryPresent && c.configHits > 0 })
	if len(strongConfigured) == 1 {
		return strongConfigured[0].name, "medium"
	}
	return "", ""
}

func filterFrontendSignals(in []frontendSignal, keep func(frontendSignal) bool) []frontendSignal {
	out := make([]frontendSignal, 0, len(in))
	for _, c := range in {
		if keep(c) {
			out = append(out, c)
		}
	}
	return out
}

func hasAnyBinary(paths []string, commands []string) bool {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	for _, cmd := range commands {
		if cmd == "" {
			continue
		}
		if _, err := exec.LookPath(cmd); err == nil {
			return true
		}
	}
	return false
}

func buildAmbiguityWarning(candidates []frontendSignal) string {
	parts := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if c.score <= 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s(score=%d)", c.name, c.score))
	}
	if len(parts) <= 1 {
		return ""
	}
	return fmt.Sprintf("ambiguous ownership: %s", strings.Join(parts, ", "))
}

func probeSystemdUnit(unit string) (active bool, enabled bool, ok bool) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, false, false
	}
	activeState := strings.TrimSpace(string(mustCombinedOutput(exec.Command("systemctl", "is-active", unit))))
	enabledState := strings.TrimSpace(string(mustCombinedOutput(exec.Command("systemctl", "is-enabled", unit))))
	return activeState == "active", enabledState == "enabled", true
}

var ssOwnerTupleRE = regexp.MustCompile(`\("([^"]+)",pid=([0-9]+),fd=[0-9]+\)`)
var ssAddrPortSuffixRE = regexp.MustCompile(`:([0-9]+)$`)

func probeListenerProcessNames() map[string]int {
	out := map[string]int{}
	snap := probeFrontendListeners()
	for _, ln := range snap.listeners {
		out[ln.name]++
	}
	for _, ln := range snap.flows {
		out[ln.name]++
	}
	return out
}

type listenerEntry struct {
	name        string
	port        int
	established bool
}

type frontendListenerSnapshot struct {
	listeners []listenerEntry
	flows     []listenerEntry
}

func probeFrontendListeners() frontendListenerSnapshot {
	out := frontendListenerSnapshot{
		listeners: make([]listenerEntry, 0, 8),
		flows:     make([]listenerEntry, 0, 8),
	}
	if _, err := exec.LookPath("ss"); err != nil {
		return out
	}
	queries := [][]string{
		{"-H", "-ltnp"},
		{"-H", "-lunp"},
		{"-H", "-tnp"},
	}
	for _, args := range queries {
		lines := strings.Split(string(mustCombinedOutput(exec.Command("ss", args...))), "\n")
		for _, ln := range lines {
			for _, entry := range parseSocketOwnerEntries(ln) {
				if entry.established {
					out.flows = append(out.flows, entry)
					continue
				}
				out.listeners = append(out.listeners, entry)
			}
		}
	}
	return out
}

func (s frontendListenerSnapshot) hasOwnerOnAllPorts(owners []string, ports ...int) bool {
	if len(ports) == 0 {
		return false
	}
	for _, port := range ports {
		if !s.hasOwnerOnPorts(owners, port) {
			return false
		}
	}
	return true
}

func parseListenerPort(ssLine string) int {
	parts := strings.Fields(strings.TrimSpace(ssLine))
	if len(parts) < 4 {
		return 0
	}
	localCandidates := []string{parts[3]}
	if len(parts) > 4 {
		localCandidates = append(localCandidates, parts[4])
	}
	for _, localAddr := range localCandidates {
		match := ssAddrPortSuffixRE.FindStringSubmatch(localAddr)
		if len(match) != 2 {
			continue
		}
		port, _ := strconv.Atoi(match[1])
		return port
	}
	return 0
}

func parseSocketOwnerEntries(ssLine string) []listenerEntry {
	ln := strings.TrimSpace(ssLine)
	if ln == "" || !strings.Contains(ln, "pid=") {
		return nil
	}
	port := parseListenerPort(ln)
	if port <= 0 {
		return nil
	}
	matches := ssOwnerTupleRE.FindAllStringSubmatch(ln, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]listenerEntry, 0, len(matches))
	established := strings.HasPrefix(ln, "ESTAB ") || strings.HasPrefix(ln, "ESTAB\t")
	for _, m := range matches {
		if len(m) != 3 {
			continue
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(m[2]))
		name := normalizeFrontendProcessName(m[1], pid)
		if name == "" {
			continue
		}
		out = append(out, listenerEntry{name: name, port: port, established: established})
	}
	return out
}

func normalizeFrontendProcessName(raw string, pid int) string {
	candidates := []string{raw}
	if pid > 0 {
		if comm := readProcComm(pid); comm != "" {
			candidates = append(candidates, comm)
		}
	}
	for _, c := range candidates {
		name := normalizeFrontendProcessToken(c)
		if name != "" {
			return name
		}
	}
	return ""
}

func normalizeFrontendProcessToken(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	if strings.Contains(s, "/openresty/") {
		return "openresty"
	}
	if strings.Contains(s, "/") {
		s = strings.ToLower(strings.TrimSpace(filepath.Base(s)))
	}
	if strings.Contains(s, "openresty") {
		return "openresty"
	}
	if strings.HasPrefix(s, "angie:") || strings.HasPrefix(s, "angie ") || s == "angie" {
		return "angie"
	}
	if strings.HasPrefix(s, "nginx:") || strings.HasPrefix(s, "nginx ") || s == "nginx" {
		return "nginx"
	}
	if strings.HasPrefix(s, "httpd") || strings.HasPrefix(s, "apache2") || strings.Contains(s, "apache") {
		return "httpd"
	}
	// LiteSpeed / OpenLiteSpeed present as "lshttpd" (older) or "litespeed"
	// (current) in ps/comm; both are the LiteSpeed origin.
	if strings.HasPrefix(s, "lshttpd") || strings.HasPrefix(s, "litespeed") || strings.HasPrefix(s, "openlitespeed") {
		return "lshttpd"
	}
	if strings.HasPrefix(s, "caddy") {
		return "caddy"
	}
	return ""
}

func canonicalUpstreamServiceLabel(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "apache", "apache2", "httpd":
		return "httpd"
	case "nginx", "lshttpd", "caddy", "unknown", "mixed":
		return n
	default:
		if n == "" {
			return "unknown"
		}
		return "unknown"
	}
}

func readProcComm(pid int) string {
	if pid <= 0 {
		return ""
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func deriveFrontendWorking(frontend, dnatState string) (string, string, FrontendDebug) {
	frontend = strings.ToLower(strings.TrimSpace(frontend))
	if frontend == "" || frontend == "unknown" {
		return "down", "frontend unknown", FrontendDebug{}
	}

	candidates := map[string]frontendSignal{
		"angie": {
			name:           "angie",
			serviceUnit:    "angie.service",
			processAliases: []string{"angie", "nginx"},
		},
		"openresty": {
			name:           "openresty",
			serviceUnit:    "openresty.service",
			processAliases: []string{"openresty", "nginx"},
		},
		"nginx": {
			name:           "nginx",
			serviceUnit:    "nginx.service",
			processAliases: []string{"nginx"},
		},
	}
	sig, ok := candidates[frontend]
	if !ok {
		return "down", fmt.Sprintf("unsupported frontend: %s", frontend), FrontendDebug{}
	}

	active, _, systemdOK := probeSystemdUnit(sig.serviceUnit)
	if !systemdOK || !active {
		return "down", fmt.Sprintf("service inactive: %s", sig.serviceUnit), FrontendDebug{}
	}

	listeners := probeFrontendListeners()
	expectedHTTP, expectedHTTPS := 80, 443
	if strings.EqualFold(strings.TrimSpace(dnatState), "on") {
		expectedHTTP, expectedHTTPS = dnat.EffectiveTargetPorts()
	}
	debug := listeners.debugForOwners(sig.processAliases, expectedHTTP, expectedHTTPS)
	missing := make([]int, 0, 2)
	for _, info := range debug.PortOwners {
		if len(info.ListenerOwners) == 0 && len(info.FlowOwners) == 0 {
			missing = append(missing, info.Port)
		}
	}
	if len(missing) > 0 {
		return "degraded", fmt.Sprintf("no listener/active flow ownership on expected ports: %s", joinPorts(missing)), debug
	}

	return "working", "", debug
}

func joinPorts(ports []int) string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, fmt.Sprintf(":%d", p))
	}
	return strings.Join(out, "/")
}

func detectEdgeRuntime(frontend, dnatState string) runtimeRoleSignal {
	service := strings.ToLower(strings.TrimSpace(frontend))
	if service == "" {
		service = "unknown"
	}
	out := runtimeRoleSignal{
		service:    service,
		status:     "inactive",
		confidence: "low",
		reasonCode: "unknown",
	}
	if strings.TrimSpace(out.service) == "" {
		out.service = "unknown"
	}
	listeners := probeFrontendListeners()
	expectedHTTP, expectedHTTPS := 80, 443
	if strings.EqualFold(strings.TrimSpace(dnatState), "on") {
		expectedHTTP, expectedHTTPS = dnat.EffectiveTargetPorts()
	}
	out.listeningPort = detectedPortsForService(listeners, out.service, expectedHTTP, expectedHTTPS)
	switch out.service {
	case "angie", "openresty", "nginx":
		active, _, ok := probeSystemdUnit(out.service + ".service")
		if !ok {
			out.status = "unknown"
			out.reasonCode = "unit_state_unknown"
		} else if active && len(out.listeningPort) >= 1 {
			out.status = "active"
			out.confidence = "high"
			out.reasonCode = "dnat_targets_owner"
		} else if active {
			out.status = "degraded"
			out.confidence = "medium"
			out.reasonCode = "service_active_no_listener"
		} else {
			out.status = "inactive"
			out.reasonCode = "service_inactive"
		}
	default:
		out.service = "unknown"
		if len(out.listeningPort) > 0 {
			out.status = "active"
			out.confidence = "low"
			out.reasonCode = "listener_owner_unknown"
		} else {
			out.status = "unknown"
			out.reasonCode = "unknown"
		}
	}
	return out
}

func detectUpstreamRuntime(edgeService string) runtimeRoleSignal {
	listeners := probeFrontendListeners()
	if sig, ok := detectUpstreamFromPublicPortOwnership(listeners); ok {
		return sig
	}

	candidates := []struct {
		name        string
		unit        string
		markerPaths []string
	}{
		{name: "nginx", unit: "nginx.service", markerPaths: []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"}},
		{name: "httpd", unit: "apache2.service", markerPaths: []string{"/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d"}},
		{name: "caddy", unit: "caddy.service", markerPaths: []string{"/etc/caddy/Caddyfile"}},
	}
	best := runtimeRoleSignal{service: "unknown", status: "unknown", confidence: "low", reasonCode: "no_public_listener"}
	bestScore := 0
	for _, c := range candidates {
		score := 0
		active, _, ok := probeSystemdUnit(c.unit)
		status := "inactive"
		if ok {
			if active {
				score += 3
				status = "active"
			}
		} else {
			status = "unknown"
		}
		for _, p := range c.markerPaths {
			if _, err := os.Stat(p); err == nil {
				score++
			}
		}
		if c.name == "nginx" && (edgeService == "angie" || edgeService == "openresty") {
			score++
		}
		if score > bestScore {
			bestScore = score
			reason := "marker_only"
			conf := "low"
			if ok && active {
				reason = "service_active"
				conf = "medium"
			}
			best = runtimeRoleSignal{service: c.name, status: status, confidence: conf, reasonCode: reason}
		}
	}
	if bestScore == 0 {
		return best
	}
	return best
}

func detectUpstreamFromPublicPortOwnership(listeners frontendListenerSnapshot) (runtimeRoleSignal, bool) {
	owner80 := publicPortOwner(listeners, 80)
	owner443 := publicPortOwner(listeners, 443)
	if owner80 == "" && owner443 == "" {
		return runtimeRoleSignal{service: "unknown", status: "unknown", confidence: "low", reasonCode: "no_public_listener"}, false
	}
	if owner80 != "" && owner443 != "" {
		if owner80 == owner443 {
			return runtimeRoleSignal{service: owner80, status: "active", confidence: "high", reasonCode: "ports_80_443", listeningPort: []int{80, 443}}, true
		}
		return runtimeRoleSignal{service: "mixed", status: "active", confidence: "medium", reasonCode: fmt.Sprintf("mixed_80_443:%s_%s", owner80, owner443), listeningPort: []int{80, 443}}, true
	}
	if owner80 != "" {
		return runtimeRoleSignal{service: owner80, status: "active", confidence: "medium", reasonCode: "ports_80_only", listeningPort: []int{80}}, true
	}
	return runtimeRoleSignal{service: owner443, status: "active", confidence: "medium", reasonCode: "ports_443_only", listeningPort: []int{443}}, true
}

func publicPortOwner(listeners frontendListenerSnapshot, port int) string {
	owners := map[string]struct{}{}
	for _, e := range listeners.listeners {
		if e.port == port {
			owners[canonicalUpstreamServiceLabel(e.name)] = struct{}{}
		}
	}
	for _, e := range listeners.flows {
		if e.port == port {
			owners[canonicalUpstreamServiceLabel(e.name)] = struct{}{}
		}
	}
	if len(owners) == 1 {
		for o := range owners {
			return o
		}
	}
	if len(owners) > 1 {
		return "mixed"
	}
	return ""
}
func detectedPortsForService(listeners frontendListenerSnapshot, service string, ports ...int) []int {
	aliases := frontendAliases(service)
	if len(aliases) == 0 {
		return nil
	}
	out := make([]int, 0, len(ports))
	seen := map[int]struct{}{}
	for _, port := range ports {
		if port <= 0 {
			continue
		}
		if listeners.hasOwnerOnPorts(aliases, port) || listeners.hasOwnerOnFlows(aliases, port) {
			if _, ok := seen[port]; !ok {
				out = append(out, port)
				seen[port] = struct{}{}
			}
		}
	}
	return out
}

func (s frontendListenerSnapshot) hasOwnerOnPorts(owners []string, ports ...int) bool {
	return s.hasOwnerInEntries(s.listeners, owners, ports...)
}

func (s frontendListenerSnapshot) hasOwnerOnFlows(owners []string, ports ...int) bool {
	return s.hasOwnerInEntries(s.flows, owners, ports...)
}

func (s frontendListenerSnapshot) hasOwnerInEntries(entries []listenerEntry, owners []string, ports ...int) bool {
	if len(owners) == 0 || len(ports) == 0 {
		return false
	}
	ownerSet := make(map[string]struct{}, len(owners))
	for _, owner := range owners {
		o := strings.ToLower(strings.TrimSpace(owner))
		if o == "" {
			continue
		}
		ownerSet[o] = struct{}{}
	}
	for _, e := range entries {
		if _, ok := ownerSet[e.name]; !ok {
			continue
		}
		for _, port := range ports {
			if e.port == port {
				return true
			}
		}
	}
	return false
}

func (s frontendListenerSnapshot) debugForOwners(owners []string, ports ...int) FrontendDebug {
	debug := FrontendDebug{
		CheckedPorts: append([]int(nil), ports...),
		PortOwners:   make([]FrontendPortOwner, 0, len(ports)),
	}
	for _, p := range ports {
		if p <= 0 {
			continue
		}
		debug.PortOwners = append(debug.PortOwners, FrontendPortOwner{
			Port:           p,
			ListenerOwners: s.ownersForPort(s.listeners, owners, p),
			FlowOwners:     s.ownersForPort(s.flows, owners, p),
		})
	}
	return debug
}

func (s frontendListenerSnapshot) ownersForPort(entries []listenerEntry, owners []string, port int) []string {
	if port <= 0 {
		return nil
	}
	ownerSet := make(map[string]struct{}, len(owners))
	for _, owner := range owners {
		o := strings.ToLower(strings.TrimSpace(owner))
		if o == "" {
			continue
		}
		ownerSet[o] = struct{}{}
	}
	found := map[string]struct{}{}
	for _, e := range entries {
		if e.port != port {
			continue
		}
		if len(ownerSet) > 0 {
			if _, ok := ownerSet[e.name]; !ok {
				continue
			}
		}
		found[e.name] = struct{}{}
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func frontendAliases(service string) []string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "angie":
		return []string{"angie", "nginx"}
	case "openresty":
		return []string{"openresty", "nginx"}
	case "nginx":
		return []string{"nginx"}
	default:
		return nil
	}
}

func probeFrontendHTTP() (bool, string) {
	clientHTTP := &http.Client{Timeout: 1500 * time.Millisecond}
	clientHTTPS := &http.Client{
		Timeout: 1500 * time.Millisecond,
		Transport: &http.Transport{
			// Local liveness probe to https://127.0.0.1/hello — the only target
			// of this client. MITM on loopback implies root-on-host already, so
			// certificate validation is not in the threat model. CodeQL #677
			// (2026-05-09 triage, accepted-risk).
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	type probeTarget struct {
		url    string
		client *http.Client
	}
	targets := []probeTarget{
		{url: "http://127.0.0.1/hello", client: clientHTTP},
		{url: "http://127.0.0.1/healthz", client: clientHTTP},
		{url: "http://127.0.0.1/", client: clientHTTP},
		{url: "https://127.0.0.1/hello", client: clientHTTPS},
	}
	lastErr := ""
	for _, target := range targets {
		req, err := http.NewRequest(http.MethodGet, target.url, nil)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		req.Host = "localhost"
		resp, err := target.client.Do(req)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			return true, ""
		}
		lastErr = fmt.Sprintf("probe status %d on %s", resp.StatusCode, target.url)
	}
	if lastErr == "" {
		lastErr = "probe failed"
	}
	return false, "http probe failed: " + lastErr
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
	if host.MemTotalBytes > 0 {
		// Already populated from the detector snapshot's meminfo detail
		// (FromDetectorSnapshot); don't re-read /proc/meminfo.
		return
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
