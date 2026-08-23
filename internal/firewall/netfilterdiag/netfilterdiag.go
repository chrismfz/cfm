// Package netfilterdiag provides a read-only, host-wide view of nftables hook
// ordering. It intentionally observes every table, not only CFM-owned state.
package netfilterdiag

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Schema = "firewall.netfilter_path.v1"

const (
	maxPublishedChains   = 512
	maxPublishedNATRules = 1024
	maxPublishedFindings = 200
	maxAnalysisSteps     = 100000
	maxReachableNATRules = 8192
)

type Expected struct {
	InputPriority     int `json:"input_priority"`
	DNATPriority      int `json:"dnat_priority"`
	PanelDNATPriority int `json:"panel_dnat_priority"`
}

func EffectiveExpected(inputPriority, dnatPriority, panelDNATPriority int) Expected {
	if inputPriority == 0 {
		inputPriority = -50
	}
	if dnatPriority == 0 {
		dnatPriority = -99
	}
	return Expected{InputPriority: inputPriority, DNATPriority: dnatPriority, PanelDNATPriority: panelDNATPriority}
}

type Filters struct {
	Hook   string
	Family string
	Proto  string
	DPort  int
}

type Chain struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"chain"`
	Type     string `json:"type,omitempty"`
	Hook     string `json:"hook"`
	Priority int    `json:"priority"`
	Policy   string `json:"policy,omitempty"`
	Owner    string `json:"owner"`
	Handle   int    `json:"handle,omitempty"`
}

type NATRule struct {
	Family        string      `json:"family"`
	Table         string      `json:"table"`
	Chain         string      `json:"chain"`
	Hook          string      `json:"hook,omitempty"`
	Priority      int         `json:"priority,omitempty"`
	Owner         string      `json:"owner"`
	Handle        int         `json:"handle,omitempty"`
	Action        string      `json:"action"`
	Target        string      `json:"target,omitempty"`
	Protocol      string      `json:"protocol,omitempty"`
	DPorts        []int       `json:"dports,omitempty"`
	Ranges        []PortRange `json:"dport_ranges,omitempty"`
	MatchUnknown  bool        `json:"match_unknown,omitempty"`
	Unsatisfiable bool        `json:"unsatisfiable,omitempty"`
	Summary       string      `json:"summary"`
	portSeen      bool
}

type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

type Finding struct {
	Level    string   `json:"level"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Chains   []string `json:"chains,omitempty"`
	Hook     string   `json:"hook,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	DPorts   []int    `json:"dports,omitempty"`
	Families []string `json:"families,omitempty"`
}

type Summary struct {
	BaseChains int `json:"base_chains"`
	NATRules   int `json:"nat_rules"`
	Findings   int `json:"findings"`
}

type Report struct {
	OK          bool      `json:"ok"`
	Schema      string    `json:"schema"`
	Status      string    `json:"status"`
	GeneratedAt time.Time `json:"generated_at"`
	Expected    Expected  `json:"expected"`
	Summary     Summary   `json:"summary"`
	Truncated   bool      `json:"truncated,omitempty"`
	Chains      []Chain   `json:"chains"`
	NATRules    []NATRule `json:"nat_rules"`
	Findings    []Finding `json:"findings"`
}

type ruleset struct {
	NFTables []map[string]json.RawMessage `json:"nftables"`
}

type rawChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
	Handle int    `json:"handle"`
}

type rawTable struct {
	Family string          `json:"family"`
	Name   string          `json:"name"`
	Flags  json.RawMessage `json:"flags"`
}

type rawRule struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Handle int               `json:"handle"`
	Expr   []json.RawMessage `json:"expr"`
}

var (
	cacheMu     sync.Mutex
	cacheAt     time.Time
	cacheIn     Expected
	cache       Report
	cacheFlight chan struct{}
)

type RulesetReader func(context.Context) ([]byte, error)

// Collect reads the kernel's complete nftables graph. A short cache prevents
// the admin page, MCP, and whats_wrong from spawning duplicate nft readers.
func Collect(ctx context.Context, expected Expected, read RulesetReader) (Report, error) {
	for {
		cacheMu.Lock()
		if time.Since(cacheAt) < 5*time.Second && cacheIn == expected {
			r := cache
			cacheMu.Unlock()
			return r, nil
		}
		if cacheFlight != nil {
			ch := cacheFlight
			cacheMu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return Report{}, ctx.Err()
			}
		}
		cacheFlight = make(chan struct{})
		cacheMu.Unlock()
		break
	}
	b, err := read(ctx)
	var r Report
	if err == nil {
		r, err = Analyze(b, expected)
	}
	cacheMu.Lock()
	if err == nil {
		cacheAt, cacheIn, cache = time.Now(), expected, r
	}
	close(cacheFlight)
	cacheFlight = nil
	cacheMu.Unlock()
	return r, err
}

// Analyze parses and evaluates one nft JSON ruleset without performing I/O.
func Analyze(data []byte, expected Expected) (Report, error) {
	var rs ruleset
	if err := json.Unmarshal(data, &rs); err != nil {
		return Report{}, fmt.Errorf("parse nft ruleset JSON: %w", err)
	}
	r := Report{OK: true, Schema: Schema, Status: "ok", GeneratedAt: time.Now().UTC(), Expected: expected}
	allChains := map[string]rawChain{}
	rulesByChain := map[string][]rawRule{}
	dormantTables := map[string]bool{}
	for _, obj := range rs.NFTables {
		if b := obj["table"]; len(b) > 0 {
			var table rawTable
			if json.Unmarshal(b, &table) == nil && tableIsDormant(table) {
				dormantTables[key(table.Family, table.Name, "")] = true
			}
		}
	}
	for _, obj := range rs.NFTables {
		if b := obj["chain"]; len(b) > 0 {
			var c rawChain
			if json.Unmarshal(b, &c) == nil && !dormantTables[key(c.Family, c.Table, "")] {
				allChains[key(c.Family, c.Table, c.Name)] = c
				if c.Hook != "" {
					r.Chains = append(r.Chains, Chain{Family: c.Family, Table: c.Table, Name: c.Name, Type: c.Type, Hook: c.Hook, Priority: c.Prio, Policy: c.Policy, Owner: owner(c.Table, c.Name), Handle: c.Handle})
				}
			}
		}
		if b := obj["rule"]; len(b) > 0 {
			var rule rawRule
			if json.Unmarshal(b, &rule) == nil && !dormantTables[key(rule.Family, rule.Table, "")] {
				k := key(rule.Family, rule.Table, rule.Chain)
				rulesByChain[k] = append(rulesByChain[k], rule)
			}
		}
	}
	analysisIncomplete := false
	steps := 0
	for _, base := range r.Chains {
		if analysisIncomplete {
			break
		}
		visiting := map[string]bool{}
		var walk func(string, NATRule) bool
		walk = func(chainKey string, inherited NATRule) bool {
			if analysisIncomplete {
				return false
			}
			if visiting[chainKey] {
				analysisIncomplete = true
				return false
			}
			visiting[chainKey] = true
			defer delete(visiting, chainKey)
			mayReturn := false
			for _, rule := range rulesByChain[chainKey] {
				steps++
				if steps > maxAnalysisSteps || len(r.NATRules) >= maxReachableNATRules {
					analysisIncomplete = true
					return false
				}
				if row, ok := parseNATRule(rule, base, inherited); ok {
					r.NATRules = append(r.NATRules, row)
				}
				if hasVerdictMap(rule) {
					analysisIncomplete = true
					return false
				}
				path := cloneConstraints(inherited)
				applyRuleMatches(rule, &path)
				unconditional := ruleIsUnconditional(rule)
				for _, transfer := range ruleTransfers(rule) {
					targetKey := key(rule.Family, rule.Table, transfer.target)
					_, exists := allChains[targetKey]
					if !exists {
						analysisIncomplete = true
						return false
					}
					childTerminates := walk(targetKey, path)
					if unconditional && transfer.kind == "goto" {
						return childTerminates && !mayReturn
					}
					if unconditional && transfer.kind == "jump" && childTerminates {
						return !mayReturn
					}
					if !unconditional && transfer.kind == "goto" && !childTerminates {
						mayReturn = true
					}
				}
				if ruleFinalTerminatesAllTraffic(rule) {
					return !mayReturn
				}
				if unconditional && ruleHasStatement(rule, "return") {
					return false
				}
				if !unconditional && ruleHasStatement(rule, "return") {
					mayReturn = true
				}
			}
			return false
		}
		walk(key(base.Family, base.Table, base.Name), NATRule{})
	}
	sort.Slice(r.Chains, func(i, j int) bool {
		a, b := r.Chains[i], r.Chains[j]
		if a.Hook != b.Hook {
			return hookOrder(a.Hook) < hookOrder(b.Hook)
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		return a.Name < b.Name
	})
	sort.Slice(r.NATRules, func(i, j int) bool {
		a, b := r.NATRules[i], r.NATRules[j]
		if a.Hook != b.Hook {
			return hookOrder(a.Hook) < hookOrder(b.Hook)
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		return a.Handle < b.Handle
	})
	findings, evalIncomplete := evaluate(r.Chains, r.NATRules, expected)
	r.Findings = findings
	analysisIncomplete = analysisIncomplete || evalIncomplete
	if analysisIncomplete {
		r.Truncated = true
		r.Findings = append(r.Findings, Finding{Level: "warning", Code: "analysis_incomplete", Message: "netfilter graph analysis hit a safety bound or an unsupported verdict map; displayed ordering may be incomplete"})
	}
	for _, finding := range r.Findings {
		if finding.Level == "warning" || finding.Level == "critical" {
			r.Status = "warning"
			break
		}
	}
	r.Summary = Summary{BaseChains: len(r.Chains), NATRules: len(r.NATRules), Findings: len(r.Findings)}
	return r, nil
}

// Limit applies response-size caps after optional filtering. Analysis and the
// cache retain the complete bounded graph so a narrow query can recover rows
// omitted from the unfiltered response.
func Limit(r Report) Report {
	if len(r.Chains) > maxPublishedChains {
		r.Chains = r.Chains[:maxPublishedChains]
		r.Truncated = true
	}
	if len(r.NATRules) > maxPublishedNATRules {
		r.NATRules = r.NATRules[:maxPublishedNATRules]
		r.Truncated = true
	}
	if len(r.Findings) > maxPublishedFindings {
		r.Findings = r.Findings[:maxPublishedFindings]
		r.Truncated = true
	}
	return r
}

// HasWebDNATRules validates the required web redirects without depending on
// nft JSON whitespace or object-field ordering.
func HasWebDNATRules(data []byte) bool {
	var rs ruleset
	if json.Unmarshal(data, &rs) != nil {
		return false
	}
	base := Chain{Family: "inet", Table: "cfm_redirect", Name: "prerouting", Hook: "prerouting"}
	dormant := false
	for _, obj := range rs.NFTables {
		if b := obj["table"]; len(b) > 0 {
			var table rawTable
			if json.Unmarshal(b, &table) == nil && table.Family == base.Family && table.Name == base.Table && tableIsDormant(table) {
				dormant = true
			}
		}
	}
	if dormant {
		return false
	}
	baseFound := false
	http, httpsTCP, httpsUDP := false, false, false
	for _, obj := range rs.NFTables {
		if b := obj["chain"]; len(b) > 0 {
			var c rawChain
			if json.Unmarshal(b, &c) == nil && c.Family == base.Family && c.Table == base.Table && c.Name == base.Name && c.Hook == base.Hook && c.Type == "nat" {
				baseFound = true
			}
		}
		b := obj["rule"]
		if len(b) == 0 {
			continue
		}
		var raw rawRule
		if json.Unmarshal(b, &raw) != nil || raw.Family != base.Family || raw.Table != base.Table || raw.Chain != base.Name {
			continue
		}
		rule, ok := parseNATRule(raw, base)
		if ok && rule.Action == "dnat" && !hasVerdictMap(raw) && !rule.MatchUnknown && !rule.Unsatisfiable {
			http = http || (rule.Protocol == "tcp" && containsInt(rule.DPorts, 80))
			httpsTCP = httpsTCP || (rule.Protocol == "tcp" && containsInt(rule.DPorts, 443))
			httpsUDP = httpsUDP || (rule.Protocol == "udp" && containsInt(rule.DPorts, 443))
		}
		if ruleFinalTerminatesAllTraffic(raw) || (ruleIsUnconditional(raw) && ruleHasStatement(raw, "return")) {
			break
		}
	}
	return baseFound && http && httpsTCP && httpsUDP
}

func Filter(r Report, f Filters) Report {
	if f.Hook == "" && f.Family == "" && f.Proto == "" && f.DPort == 0 {
		return r
	}
	chains := make([]Chain, 0, len(r.Chains))
	for _, c := range r.Chains {
		if f.Hook != "" && c.Hook != f.Hook {
			continue
		}
		if f.Family != "" && c.Family != f.Family {
			continue
		}
		chains = append(chains, c)
	}
	rules := make([]NATRule, 0, len(r.NATRules))
	for _, n := range r.NATRules {
		if f.Hook != "" && n.Hook != f.Hook {
			continue
		}
		if f.Family != "" && n.Family != f.Family {
			continue
		}
		if f.Proto != "" && n.Protocol != "" && n.Protocol != f.Proto {
			continue
		}
		if f.DPort > 0 && !ruleCanMatchPort(n, f.DPort) {
			continue
		}
		rules = append(rules, n)
	}
	findings := make([]Finding, 0, len(r.Findings))
	status := "ok"
	for _, finding := range r.Findings {
		if f.Hook != "" && finding.Hook != "" && finding.Hook != f.Hook {
			continue
		}
		if f.Family != "" && len(finding.Families) > 0 && !containsString(finding.Families, f.Family) {
			continue
		}
		if f.Proto != "" && finding.Protocol != "" && finding.Protocol != f.Proto {
			continue
		}
		if f.DPort > 0 && len(finding.DPorts) > 0 && !containsInt(finding.DPorts, f.DPort) {
			continue
		}
		findings = append(findings, finding)
		if finding.Level == "warning" || finding.Level == "critical" {
			status = "warning"
		}
	}
	r.Chains, r.NATRules, r.Findings, r.Status = chains, rules, findings, status
	r.Summary.BaseChains, r.Summary.NATRules, r.Summary.Findings = len(chains), len(rules), len(findings)
	return r
}

func ValidateFilters(f Filters) error {
	if f.Hook != "" && hookOrder(f.Hook) == 99 {
		return fmt.Errorf("unsupported hook %q", f.Hook)
	}
	if f.Family != "" && f.Family != "ip" && f.Family != "ip6" && f.Family != "inet" && f.Family != "bridge" && f.Family != "arp" && f.Family != "netdev" {
		return fmt.Errorf("unsupported family %q", f.Family)
	}
	if f.Proto != "" && f.Proto != "tcp" && f.Proto != "udp" {
		return fmt.Errorf("unsupported protocol %q", f.Proto)
	}
	if f.DPort < 0 || f.DPort > 65535 {
		return fmt.Errorf("invalid destination port %d", f.DPort)
	}
	return nil
}

func parseNATRule(rule rawRule, chain Chain, inherited ...NATRule) (NATRule, bool) {
	n := NATRule{Family: rule.Family, Table: rule.Table, Chain: rule.Chain, Hook: chain.Hook, Priority: chain.Priority, Owner: owner(rule.Table, rule.Chain), Handle: rule.Handle}
	if len(inherited) > 0 {
		copyConstraints(&n, inherited[0])
	}
	for _, raw := range rule.Expr {
		var expr map[string]json.RawMessage
		if json.Unmarshal(raw, &expr) != nil {
			continue
		}
		for _, action := range []string{"dnat", "snat", "redirect", "masquerade", "tproxy"} {
			if b, ok := expr[action]; ok {
				n.Action = action
				n.Target = targetString(b)
			}
		}
	}
	applyRuleMatches(rule, &n)
	if n.Action == "" {
		return NATRule{}, false
	}
	n.Summary = strings.TrimSpace(strings.Join([]string{matchSummary(n), n.Action, n.Target}, " "))
	return n, true
}

type ruleTransfer struct{ kind, target string }

func ruleTransfers(rule rawRule) []ruleTransfer {
	var out []ruleTransfer
	for _, raw := range rule.Expr {
		var expr map[string]json.RawMessage
		if json.Unmarshal(raw, &expr) != nil {
			continue
		}
		for _, verdict := range []string{"jump", "goto"} {
			b, ok := expr[verdict]
			if !ok {
				continue
			}
			var target string
			if json.Unmarshal(b, &target) != nil {
				var v struct {
					Target string `json:"target"`
				}
				_ = json.Unmarshal(b, &v)
				target = v.Target
			}
			if target != "" {
				out = append(out, ruleTransfer{kind: verdict, target: target})
			}
		}
	}
	return out
}

func hasVerdictMap(rule rawRule) bool {
	for _, raw := range rule.Expr {
		if rawContainsKey(raw, "vmap") || rawContainsKey(raw, "map") {
			return true
		}
	}
	return false
}

func rawContainsKey(raw json.RawMessage, wanted string) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(value any) bool {
		switch v := value.(type) {
		case map[string]any:
			for k, child := range v {
				if k == wanted || walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}

func ruleIsUnconditional(rule rawRule) bool {
	for _, raw := range rule.Expr {
		var expr map[string]json.RawMessage
		if json.Unmarshal(raw, &expr) != nil {
			return false
		}
		for statement := range expr {
			switch statement {
			case "accept", "drop", "reject", "return", "jump", "goto", "dnat", "snat", "redirect", "masquerade", "tproxy", "counter", "comment", "log":
			default:
				return false
			}
		}
	}
	return true
}

func ruleFinalTerminatesAllTraffic(rule rawRule) bool {
	if !ruleIsUnconditional(rule) {
		return false
	}
	for _, statement := range []string{"accept", "drop", "reject", "dnat", "snat", "redirect", "masquerade", "tproxy"} {
		if ruleHasStatement(rule, statement) {
			return true
		}
	}
	return false
}

func ruleHasStatement(rule rawRule, name string) bool {
	for _, raw := range rule.Expr {
		var expr map[string]json.RawMessage
		if json.Unmarshal(raw, &expr) == nil {
			if _, ok := expr[name]; ok {
				return true
			}
		}
	}
	return false
}

func tableIsDormant(table rawTable) bool {
	var one string
	if json.Unmarshal(table.Flags, &one) == nil {
		return one == "dormant"
	}
	var many []string
	return json.Unmarshal(table.Flags, &many) == nil && containsString(many, "dormant")
}

func cloneConstraints(in NATRule) NATRule {
	var out NATRule
	copyConstraints(&out, in)
	return out
}

func copyConstraints(dst *NATRule, src NATRule) {
	dst.Protocol = src.Protocol
	dst.DPorts = append([]int(nil), src.DPorts...)
	dst.Ranges = append([]PortRange(nil), src.Ranges...)
	dst.MatchUnknown = src.MatchUnknown
	dst.Unsatisfiable = src.Unsatisfiable
	dst.portSeen = src.portSeen
}

func applyRuleMatches(rule rawRule, n *NATRule) {
	for _, raw := range rule.Expr {
		var expr map[string]json.RawMessage
		if json.Unmarshal(raw, &expr) != nil {
			continue
		}
		if b := expr["match"]; len(b) > 0 {
			parseMatch(b, n)
		}
		if _, ok := expr["lookup"]; ok {
			n.MatchUnknown = true
		}
	}
}

func parseMatch(b json.RawMessage, n *NATRule) {
	var m struct {
		Left  json.RawMessage `json:"left"`
		Right json.RawMessage `json:"right"`
		Op    string          `json:"op"`
	}
	if json.Unmarshal(b, &m) != nil {
		return
	}
	var left struct {
		Payload struct {
			Protocol string `json:"protocol"`
			Field    string `json:"field"`
			Base     string `json:"base"`
			Offset   int    `json:"offset"`
			Len      int    `json:"len"`
		} `json:"payload"`
		Meta struct {
			Key string `json:"key"`
		} `json:"meta"`
	}
	if json.Unmarshal(m.Left, &left) != nil {
		return
	}
	if left.Meta.Key == "l4proto" && m.Op == "==" {
		if proto := protocolValue(m.Right); proto != "" {
			mergeProtocolConstraint(n, proto)
		}
		return
	}
	isDPort := left.Payload.Field == "dport" ||
		((left.Payload.Base == "th" && left.Payload.Offset == 16 && left.Payload.Len == 16) ||
			(left.Payload.Base == "transport header" && left.Payload.Offset == 2 && left.Payload.Len == 2))
	if !isDPort {
		return
	}
	if left.Payload.Protocol == "tcp" || left.Payload.Protocol == "udp" {
		mergeProtocolConstraint(n, left.Payload.Protocol)
	}
	if m.Op != "==" {
		n.MatchUnknown = true
		return
	}
	ports, ranges, unknown := portValues(m.Right)
	n.MatchUnknown = n.MatchUnknown || unknown
	if unknown {
		return
	}
	mergePortConstraint(n, ports, ranges)
}

func mergeProtocolConstraint(n *NATRule, protocol string) {
	if n.Protocol != "" && n.Protocol != protocol {
		n.Unsatisfiable = true
		return
	}
	n.Protocol = protocol
}

func mergePortConstraint(n *NATRule, ports []int, ranges []PortRange) {
	if !n.portSeen {
		n.DPorts, n.Ranges, n.portSeen = ports, ranges, true
		return
	}
	var exact []int
	for _, p := range n.DPorts {
		if portInConstraint(p, ports, ranges) {
			exact = append(exact, p)
		}
	}
	for _, p := range ports {
		if ruleCanMatchPort(*n, p) && !containsInt(exact, p) {
			exact = append(exact, p)
		}
	}
	var intersected []PortRange
	for _, a := range n.Ranges {
		for _, b := range ranges {
			from, to := a.From, a.To
			if b.From > from {
				from = b.From
			}
			if b.To < to {
				to = b.To
			}
			if from <= to {
				intersected = append(intersected, PortRange{From: from, To: to})
			}
		}
	}
	sort.Ints(exact)
	n.DPorts, n.Ranges = exact, intersected
	if len(exact) == 0 && len(intersected) == 0 {
		n.Unsatisfiable = true
	}
}

func portInConstraint(port int, exact []int, ranges []PortRange) bool {
	if containsInt(exact, port) {
		return true
	}
	for _, r := range ranges {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}

func portValues(b json.RawMessage) ([]int, []PortRange, bool) {
	var one int
	if json.Unmarshal(b, &one) == nil {
		return []int{one}, nil, false
	}
	var many []int
	if json.Unmarshal(b, &many) == nil {
		sort.Ints(many)
		return many, nil, false
	}
	var wrapper struct {
		Set   []int `json:"set"`
		Range []int `json:"range"`
	}
	if json.Unmarshal(b, &wrapper) == nil {
		if len(wrapper.Set) > 0 {
			sort.Ints(wrapper.Set)
			return wrapper.Set, nil, false
		}
		if len(wrapper.Range) == 2 {
			from, to := wrapper.Range[0], wrapper.Range[1]
			if from > to {
				from, to = to, from
			}
			return nil, []PortRange{{From: from, To: to}}, false
		}
	}
	return nil, nil, true
}

func protocolValue(b json.RawMessage) string {
	var one string
	if json.Unmarshal(b, &one) == nil && (one == "tcp" || one == "udp") {
		return one
	}
	return ""
}

func targetString(b json.RawMessage) string {
	if string(b) == "null" || len(b) == 0 {
		return ""
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return ""
	}
	parts := make([]string, 0, 2)
	for _, k := range []string{"addr", "port"} {
		if x, ok := v[k]; ok {
			parts = append(parts, k+"="+fmt.Sprint(x))
		}
	}
	return strings.Join(parts, " ")
}

func evaluate(chains []Chain, rules []NATRule, expected Expected) ([]Finding, bool) {
	var out []Finding
	comparisons := 0
	for _, c := range chains {
		want, applies := 0, false
		switch {
		case c.Family == "inet" && c.Table == "cfm" && c.Name == "input":
			want, applies = expected.InputPriority, true
		case c.Family == "inet" && c.Table == "cfm_redirect" && c.Name == "prerouting":
			want, applies = expected.DNATPriority, true
		case c.Family == "inet" && c.Table == "cfm_panel_redirect" && c.Name == "prerouting":
			want, applies = expected.PanelDNATPriority, true
		}
		if applies && c.Priority != want {
			out = append(out, Finding{Level: "warning", Code: "cfm_priority_drift", Message: fmt.Sprintf("%s runtime priority %d differs from configured priority %d", chainLabel(c), c.Priority, want), Chains: []string{chainLabel(c)}, Hook: c.Hook, Families: []string{c.Family}})
		}
	}
	groups := map[string][]Chain{}
	for _, c := range chains {
		groups[c.Hook+"\x00"+strconv.Itoa(c.Priority)] = append(groups[c.Hook+"\x00"+strconv.Itoa(c.Priority)], c)
	}
	for _, group := range groups {
		for i, a := range group {
			for j := i + 1; j < len(group); j++ {
				comparisons++
				if comparisons > maxAnalysisSteps {
					return dedupeFindings(out), true
				}
				b := group[j]
				if !familiesOverlap(a.Family, b.Family) || (a.Owner != "cfm" && b.Owner != "cfm") {
					continue
				}
				out = append(out, Finding{Level: "warning", Code: "same_priority_ambiguity", Message: fmt.Sprintf("hook %s has CFM and another overlapping base chain at priority %d; registration order is ambiguous", a.Hook, a.Priority), Chains: []string{chainLabel(a), chainLabel(b)}, Hook: a.Hook, Families: []string{a.Family, b.Family}})
				if len(out) > maxPublishedFindings {
					break
				}
			}
			if len(out) > maxPublishedFindings {
				break
			}
		}
		if len(out) > maxPublishedFindings {
			break
		}
	}
	for _, a := range rules {
		if a.Owner != "cfm" {
			continue
		}
		for _, b := range rules {
			comparisons++
			if comparisons > maxAnalysisSteps {
				return dedupeFindings(out), true
			}
			if b.Owner == "cfm" || a.Hook != b.Hook || !familiesOverlap(a.Family, b.Family) || !protocolsOverlap(a, b) || !portsOverlap(a, b) {
				continue
			}
			if a.Priority == b.Priority {
				continue
			}
			first, second := a, b
			if second.Priority < first.Priority {
				first, second = second, first
			}
			out = append(out, Finding{Level: "info", Code: "ordered_nat_overlap", Message: fmt.Sprintf("CFM and %s both match %s in %s; base-chain order is %s priority %d then %s priority %d", b.Owner, trafficLabel(a, b), a.Hook, first.Owner, first.Priority, second.Owner, second.Priority), Chains: []string{ruleLabel(first), ruleLabel(second)}, Hook: a.Hook, Protocol: commonProtocol(a, b), DPorts: commonPorts(a, b), Families: []string{a.Family, b.Family}})
			if len(out) > maxPublishedFindings {
				break
			}
		}
		if len(out) > maxPublishedFindings {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Message < out[j].Message
	})
	return dedupeFindings(out), false
}

func owner(table, chain string) string {
	s := strings.ToLower(table + " " + chain)
	table = strings.ToLower(table)
	switch {
	case strings.Contains(s, "cfm"):
		return "cfm"
	case strings.Contains(s, "imunify") || strings.Contains(s, "webshield"):
		return "imunify"
	case strings.Contains(s, "csf"):
		return "csf"
	case table == "nat" || table == "filter" || table == "mangle" || table == "raw":
		return "iptables-nft"
	default:
		return "other"
	}
}

func hookOrder(h string) int {
	switch h {
	case "ingress":
		return 0
	case "prerouting":
		return 1
	case "input":
		return 2
	case "forward":
		return 3
	case "output":
		return 4
	case "postrouting":
		return 5
	case "egress":
		return 6
	}
	return 99
}
func key(f, t, c string) string { return f + "\x00" + t + "\x00" + c }
func chainLabel(c Chain) string { return c.Family + " " + c.Table + "/" + c.Name }
func ruleLabel(r NATRule) string {
	return r.Family + " " + r.Table + "/" + r.Chain + "#" + strconv.Itoa(r.Handle)
}
func containsInt(xs []int, n int) bool {
	for _, x := range xs {
		if x == n {
			return true
		}
	}
	return false
}
func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func ruleCanMatchPort(rule NATRule, port int) bool {
	if rule.Unsatisfiable {
		return false
	}
	if len(rule.DPorts) == 0 && len(rule.Ranges) == 0 {
		return true
	}
	if containsInt(rule.DPorts, port) {
		return true
	}
	for _, r := range rule.Ranges {
		if port >= r.From && port <= r.To {
			return true
		}
	}
	return false
}
func portsOverlap(a, b NATRule) bool {
	if a.Unsatisfiable || b.Unsatisfiable {
		return false
	}
	if (len(a.DPorts) == 0 && len(a.Ranges) == 0) || (len(b.DPorts) == 0 && len(b.Ranges) == 0) {
		return true
	}
	for _, x := range a.DPorts {
		if ruleCanMatchPort(b, x) {
			return true
		}
	}
	for _, x := range b.DPorts {
		if ruleCanMatchPort(a, x) {
			return true
		}
	}
	for _, ar := range a.Ranges {
		for _, br := range b.Ranges {
			if ar.From <= br.To && br.From <= ar.To {
				return true
			}
		}
	}
	return false
}
func protocolsOverlap(a, b NATRule) bool {
	return a.Protocol == "" || b.Protocol == "" || a.Protocol == b.Protocol
}
func familiesOverlap(a, b string) bool {
	if a == b {
		return true
	}
	return (a == "inet" && (b == "ip" || b == "ip6")) || (b == "inet" && (a == "ip" || a == "ip6"))
}
func commonProtocol(a, b NATRule) string {
	if a.Protocol == b.Protocol {
		return a.Protocol
	}
	if a.Protocol == "" {
		return b.Protocol
	}
	return a.Protocol
}
func commonPorts(a, b NATRule) []int {
	var out []int
	for _, p := range a.DPorts {
		if ruleCanMatchPort(b, p) {
			out = append(out, p)
		}
	}
	for _, p := range b.DPorts {
		if ruleCanMatchPort(a, p) && !containsInt(out, p) {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}
func trafficLabel(a, b NATRule) string {
	p := a.Protocol
	if p == "" {
		p = b.Protocol
	}
	if p == "" {
		p = "traffic"
	}
	ports := a.DPorts
	if len(ports) == 0 {
		ports = b.DPorts
	}
	if len(ports) == 0 {
		return p
	}
	vals := make([]string, len(ports))
	for i, n := range ports {
		vals[i] = strconv.Itoa(n)
	}
	return p + " dport " + strings.Join(vals, ",")
}
func matchSummary(n NATRule) string {
	if n.Protocol == "" && len(n.DPorts) == 0 && len(n.Ranges) == 0 {
		return ""
	}
	vals := make([]string, len(n.DPorts))
	for i, p := range n.DPorts {
		vals[i] = strconv.Itoa(p)
	}
	for _, r := range n.Ranges {
		vals = append(vals, fmt.Sprintf("%d-%d", r.From, r.To))
	}
	if len(vals) == 0 {
		return n.Protocol
	}
	return strings.TrimSpace(n.Protocol + " dport " + strings.Join(vals, ","))
}

func dedupeFindings(in []Finding) []Finding {
	seen := map[string]bool{}
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		k := f.Code + "\x00" + f.Message
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
