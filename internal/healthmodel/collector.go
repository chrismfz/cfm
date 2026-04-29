package healthmodel

import (
	"cfm/internal/dnat"
	"crypto/tls"
	"fmt"
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
		DNATConfidence:  "low",
		FrontendWorking: "down",
		EdgeService:     "unknown",
		UpstreamService: "unknown",
		EdgeStatus:      "unknown",
		UpstreamStatus:  "unknown",
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
	resolution := ResolveWebRoles(out.DNATEnabled)
	out.DNATFrontend = resolution.frontend
	out.DNATConfidence = resolution.frontendConfidence
	out.DNATWarning = resolution.frontendWarning
	out.FrontendWorking = resolution.frontendVerdict
	out.FrontendReason = resolution.frontendReason
	out.FrontendDebug = resolution.frontendDebug
	out.EdgeService = resolution.edge.service
	out.EdgeStatus = resolution.edge.status
	out.UpstreamService = resolution.upstream.service
	out.UpstreamStatus = resolution.upstream.status
	return out
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
	return ""
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
		service: service,
		status:  "inactive",
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
		} else if active && len(out.listeningPort) >= 1 {
			out.status = "active"
		} else if active {
			out.status = "degraded"
		} else {
			out.status = "inactive"
		}
	default:
		out.service = "unknown"
		if len(out.listeningPort) > 0 {
			out.status = "active"
		} else {
			out.status = "unknown"
		}
	}
	return out
}

func detectUpstreamRuntime(edgeService string) runtimeRoleSignal {
	listeners := probeFrontendListeners()
	active, _, _ := probeSystemdUnit("nginx.service")
	if sig, ok := detectNginxUpstreamFromSignals(listeners, active); ok {
		return sig
	}

	candidates := []struct {
		name        string
		unit        string
		markerPaths []string
	}{
		{name: "nginx", unit: "nginx.service", markerPaths: []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d", "/etc/nginx/sites-enabled"}},
		{name: "apache", unit: "apache2.service", markerPaths: []string{"/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d"}},
		{name: "caddy", unit: "caddy.service", markerPaths: []string{"/etc/caddy/Caddyfile"}},
	}
	best := runtimeRoleSignal{service: "unknown", status: "unknown"}
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
			best = runtimeRoleSignal{service: c.name, status: status}
		}
	}
	if bestScore == 0 {
		return best
	}
	return best
}

func detectNginxUpstreamFromSignals(listeners frontendListenerSnapshot, serviceActive bool) (runtimeRoleSignal, bool) {
	status := "inactive"
	if serviceActive {
		status = "active"
	}

	hasMasterWorker := false
	for _, ln := range listeners.listeners {
		if ln.name == "nginx" {
			hasMasterWorker = true
			break
		}
	}
	if !hasMasterWorker {
		for _, fl := range listeners.flows {
			if fl.name == "nginx" {
				hasMasterWorker = true
				break
			}
		}
	}

	hasPublic := listeners.hasOwnerOnPorts([]string{"nginx"}, 80, 443)
	hasDNATTier := listeners.hasOwnerOnPorts([]string{"nginx"}, 9080, 9043)
	if !hasDNATTier {
		hasDNATTier = listeners.hasOwnerOnFlows([]string{"nginx"}, 9080, 9043)
	}
	hasLoopbackPath := listeners.hasOwnerOnFlows([]string{"nginx"}, 80, 443) || listeners.hasOwnerOnFlows([]string{"nginx"}, 9080, 9043)

	strong := hasMasterWorker && serviceActive && hasPublic && hasDNATTier
	if strong {
		_ = hasLoopbackPath // optional supporting signal
		return runtimeRoleSignal{service: "nginx", status: status}, true
	}

	if !hasMasterWorker && !serviceActive && !hasPublic && !hasDNATTier {
		return runtimeRoleSignal{}, false
	}

	return runtimeRoleSignal{service: "unknown", status: "unknown"}, true
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local liveness probe only
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
