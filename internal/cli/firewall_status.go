package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cfm/internal/blocklists"
	cfgpkg "cfm/internal/config"
	"cfm/internal/detectors"
	"cfm/internal/firewall"
	"cfm/internal/firewall/setinventory"
)

type fwDiagBackend interface {
	DNATStatus(family, table string) (bool, error)
	ListSetElementsRaw(setName string) ([]string, error)
	ListTableJSON(family, table string) ([]byte, error)
}

type counterProbe interface {
	CounterValue(name string) (int64, error)
}
type dnatShowProbe interface {
	DNATShow(family, table string) (string, error)
}
type diagNamesProbe interface {
	ThrottledSetNames() []string
	ScannerSetNames() []string
	CardinalitySetNames() map[string]string
}

type fwFinding struct {
	Level, Message string `json:"level"`
}

type setProbeRequirement struct {
	key        string
	setName    string
	required   bool
	applicable bool
	reason     string
}

type setProbeItem struct {
	key        string
	setName    string
	required   bool
	applicable bool
	reason     string
	feature    string
	dependsOn  string
}

func staticSetProbes(features map[string]bool, engine string, names map[string]string) []setProbeItem {
	items := make([]setProbeItem, 0, 24)
	for key, s := range names {
		required := true
		applicable := true
		reason := "core infrastructure"
		feature := "core"
		dependsOn := "always"
		switch s {
		case "challenge_v4", "challenge_v6":
			applicable = true
			required = features["dnat_challenge"] && engine == "nft"
			reason = "required only when challenge redirect is enabled and nft DNAT runtime mode is active"
			feature = "challenge_redirect"
			dependsOn = "features.dnat_challenge + engine=nft"
		}
		items = append(items, setProbeItem{key: key, setName: s, required: required, applicable: applicable, reason: reason, feature: feature, dependsOn: dependsOn})
	}
	for _, s := range []string{"smtp_ports", "smtp_allow_uids", "smtp_allow_gids"} {
		items = append(items, setProbeItem{
			key:        s,
			setName:    s,
			required:   features["smtp"],
			applicable: features["smtp"],
			reason:     "required only when smtpblock is enabled",
			feature:    "smtp",
			dependsOn:  "features.smtp",
		})
	}
	return items
}

func dynamicFeedSetProbes(feeds []blocklists.Feed) []setProbeItem {
	items := make([]setProbeItem, 0, len(feeds)*4)
	for key, s := range setinventory.BuildSetNames(feeds) {
		if !(strings.HasPrefix(key, "allow_ext_") || strings.HasPrefix(key, "block_ext_")) {
			continue
		}
		items = append(items, setProbeItem{
			key:        key,
			setName:    s,
			required:   true,
			applicable: true,
			reason:     "configured feed set",
			feature:    "feeds",
			dependsOn:  "cfm.blocklists",
		})
	}
	return items
}

type fwReport struct {
	Engine             string                        `json:"engine"`
	Capabilities       []string                      `json:"capabilities"`
	ConfigSource       string                        `json:"config_source"`
	Features           map[string]bool               `json:"features"`
	SetSizes           map[string]int                `json:"set_sizes"`
	PolicyDomainCounts map[string]int                `json:"policy_domain_counts,omitempty"`
	PolicyDomains      map[string][]fwRuleDescriptor `json:"policy_domains,omitempty"`
	Counters           map[string]int64              `json:"counters"`
	FeatureChecks      map[string]fwFeatureCheck     `json:"feature_checks,omitempty"`
	CanonicalChecks    fwCanonicalChecks             `json:"canonical_checks"`
	Unsupported        map[string]bool               `json:"unsupported,omitempty"`
	Findings           []fwFinding                   `json:"findings"`
	Status             string                        `json:"status"`
	Verbose            bool                          `json:"-"`
}

type fwCanonicalChecks struct {
	Score      float64                 `json:"score"`
	Summary    string                  `json:"summary"`
	ByDomain   map[string]fwDomainDiff `json:"by_domain,omitempty"`
	Actionable []string                `json:"actionable,omitempty"`
}

type fwDomainDiff struct {
	MissingObject           int `json:"missing_object"`
	MismatchedRuleCondition int `json:"mismatched_rule_condition"`
	MismatchedVerdict       int `json:"mismatched_verdict"`
	UnsupportedFeature      int `json:"unsupported_feature"`
}

type fwFeatureCheck struct {
	Status       string            `json:"status"`
	Reason       string            `json:"reason"`
	RequiredSets []string          `json:"required_sets,omitempty"`
	Counters     []string          `json:"counters,omitempty"`
	Samples      map[string]string `json:"samples,omitempty"`
}

type fwRuleDescriptor struct {
	Chain      string   `json:"chain"`
	Proto      string   `json:"proto,omitempty"`
	Ports      []string `json:"ports,omitempty"`
	Verdict    string   `json:"verdict,omitempty"`
	Conditions []string `json:"conditions,omitempty"`
}

func RunFirewall(args []string, be firewall.Backend, cfgDir string, engine, source string) int {
	if len(args) == 0 || args[0] != "status" {
		fmt.Fprintln(os.Stderr, "usage: cfm firewall status [--verbose] [--json] [--strict]")
		return 2
	}
	fs := flag.NewFlagSet("firewall status", flag.ExitOnError)
	verbose := fs.Bool("verbose", false, "include extra probes")
	jsonOut := fs.Bool("json", false, "output JSON")
	strict := fs.Bool("strict", true, "exit non-zero on fail findings")
	_ = fs.Parse(args[1:])

	report := collectFirewallStatus(be, cfgDir, engine, source, *verbose)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		printFirewallReport(report)
	}
	if *strict && report.Status == "fail" {
		return 1
	}
	return 0
}

func collectFirewallStatus(be fwDiagBackend, cfgDir, engine, source string, verbose bool) fwReport {
	r := fwReport{Engine: engine, ConfigSource: source, Features: map[string]bool{}, SetSizes: map[string]int{}, PolicyDomainCounts: map[string]int{}, PolicyDomains: map[string][]fwRuleDescriptor{}, Counters: map[string]int64{}, FeatureChecks: map[string]fwFeatureCheck{}, Unsupported: map[string]bool{}, Verbose: verbose}
	if caps, ok := any(be).(firewall.CapabilityReporter); ok {
		c := caps.Capabilities()
		if c.PortsPolicyInboundRules {
			r.Capabilities = append(r.Capabilities, "ports_policy")
		}
		if c.PortscanTrackingSets {
			r.Capabilities = append(r.Capabilities, "portscan_sets")
		}
		if c.NewStateDropFallback {
			r.Capabilities = append(r.Capabilities, "new_state_drop")
		}
	}
	sort.Strings(r.Capabilities)
	cfg := loadCfg(cfgDir)
	r.Features["ports"] = cfg.Ports.TCPIn != nil || cfg.Ports.UDPIn != nil
	r.Features["connlimit"] = len(cfg.Connlimit.Rules) > 0
	r.Features["portflood"] = len(cfg.PortFlood.Rules) > 0
	r.Features["smtp"] = cfg.SMTPBlock.Enabled
	r.Features["autoblock"] = cfg.Throttle.Enabled
	r.Features["feeds"] = true
	r.Features["dnat_edge"] = openrestyModeConfigured(cfgDir)
	r.Features["dnat_challenge"] = challengeRedirectConfigured(cfgDir)
	r.Features["challenge_runtime_mode"] = false

	if ok, err := be.DNATStatus("inet", "cfm"); err == nil {
		r.Features["dnat_challenge"] = r.Features["dnat_challenge"] && ok
		r.Features["challenge_runtime_mode"] = r.Features["dnat_challenge"] && engine == "nft"
	} else {
		r.Unsupported["dnat_redirect"] = true
		r.Findings = append(r.Findings, fwFinding{"warn", "dnat status unsupported: " + err.Error()})
	}

	feeds := loadConfiguredFeeds(cfgDir)
	setNames := setinventory.BuildSetNames(feeds)
	throttledSets := []string{"throttled_v4", "throttled_v6"}
	scannerSets := []string{"port_scanners_v4", "port_scanners_v6"}
	if np, ok := any(be).(diagNamesProbe); ok {
		if v := np.CardinalitySetNames(); len(v) > 0 {
			setNames = v
		}
		if v := np.ThrottledSetNames(); len(v) > 0 {
			throttledSets = v
		}
		if v := np.ScannerSetNames(); len(v) > 0 {
			scannerSets = v
		}
	}
	probeReq := map[string]setProbeItem{}
	for _, req := range staticSetProbes(r.Features, engine, setNames) {
		probeReq[req.setName] = req
	}
	dynReq := dynamicFeedSetProbes(feeds)
	if len(dynReq) == 0 {
		r.Findings = append(r.Findings, fwFinding{"info", "no feed-derived sets expected"})
	}
	for _, req := range dynReq {
		probeReq[req.setName] = req
	}

	for _, req := range probeReq {
		s := req.setName
		if !req.applicable {
			r.Findings = append(r.Findings, fwFinding{"info", fmt.Sprintf("set(%s) skipped (feature=%s dependency=%s; expected source: %s)", s, req.feature, req.dependsOn, req.reason)})
			continue
		}
		elems, err := be.ListSetElementsRaw(s)
		if err != nil {
			level := "warn"
			if req.required {
				level = "fail"
			}
			r.Findings = append(r.Findings, fwFinding{level, fmt.Sprintf("set(%s) missing (feature=%s dependency=%s; expected source: %s): %s", s, req.feature, req.dependsOn, req.reason, err.Error())})
			continue
		}
		r.SetSizes[s] = len(elems)
		r.SetSizes[req.key+"_cardinality"] = len(elems)
	}
	for _, s := range append(throttledSets, scannerSets...) {
		elems, err := be.ListSetElementsRaw(s)
		if err != nil {
			r.Unsupported[s+"_cardinality"] = true
			continue
		}
		r.SetSizes[s] = len(elems)
	}
	if tableJSON, err := be.ListTableJSON("inet", "cfm"); err != nil {
		r.Findings = append(r.Findings, fwFinding{"fail", "required table inet/cfm missing or unreadable: " + err.Error()})
	} else {
		r.PolicyDomains = collectPolicyDomains(tableJSON)
		for domain, rules := range r.PolicyDomains {
			r.PolicyDomainCounts[domain] = len(rules)
		}
	}
	if r.Features["dnat_challenge"] {
		tableJSON, err := be.ListTableJSON("inet", "cfm_redirect")
		if err != nil {
			r.Findings = append(r.Findings, fwFinding{"fail", "dnat redirect table inet/cfm_redirect missing or unreadable: " + err.Error()})
		} else if !hasExpectedDNATPreroutingRules(tableJSON) {
			r.Findings = append(r.Findings, fwFinding{"fail", "dnat redirect table inet/cfm_redirect missing expected prerouting dnat rules"})
		}
	}
	if cp, ok := any(be).(counterProbe); ok {
		for _, name := range []string{"cfm_input_drop", "cfm_forward_drop", "flood", "portflood", "connlimit"} {
			if v, err := cp.CounterValue(name); err == nil {
				r.Counters[name] = v
			} else {
				r.Unsupported[name+"_counter"] = true
			}
		}
	}
	if len(r.Counters) == 0 {
		r.Unsupported["flood_counter"] = true
		r.Unsupported["portflood_counter"] = true
		r.Unsupported["connlimit_counter"] = true
	}
	r.FeatureChecks = evaluateFeatureChecks(r)
	r.CanonicalChecks = evaluateCanonicalChecks(r)
	if verbose {
		if ds, ok := any(be).(dnatShowProbe); ok {
			if raw, err := ds.DNATShow("inet", "cfm"); err != nil {
				r.Findings = append(r.Findings, fwFinding{"warn", "dnat show probe failed: " + err.Error()})
			} else if strings.TrimSpace(raw) == "" {
				r.Findings = append(r.Findings, fwFinding{"warn", "dnat show returned empty output"})
			}
		}
	}
	r.Status = "ok"
	for _, f := range r.Findings {
		if f.Level == "fail" {
			r.Status = "fail"
			break
		}
	}
	return r
}

func loadCfg(cfgDir string) *cfgpkg.Config {
	if cfgDir == "" {
		return &cfgpkg.Config{}
	}
	b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.conf"))
	if err != nil {
		return &cfgpkg.Config{}
	}
	cfg, err := LoadConfigWithAPIOverride(cfgDir, b)
	if err != nil || cfg == nil {
		return &cfgpkg.Config{}
	}
	return cfg
}

func loadConfiguredFeeds(cfgDir string) []blocklists.Feed {
	if cfgDir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.blocklists"))
	if err != nil {
		return nil
	}
	feeds, err := blocklists.ParseConfig(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	return feeds
}


func openrestyModeConfigured(cfgDir string) bool {
	if cfgDir == "" {
		return false
	}
	secs, err := detectors.ReadSectionsFile(filepath.Join(cfgDir, "detectors.conf"))
	if err != nil {
		return false
	}
	for _, secName := range []string{"webdetector", "web"} {
		if sec, ok := secs.ByName[secName]; ok {
			if v := strings.TrimSpace(sec["OPENRESTY_MODE"]); strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "on") {
				return true
			}
		}
	}
	if v := strings.TrimSpace(secs.Global["OPENRESTY_MODE"]); strings.EqualFold(v, "1") || strings.EqualFold(v, "true") || strings.EqualFold(v, "on") {
		return true
	}
	return false
}

func challengeRedirectConfigured(cfgDir string) bool {
	if cfgDir == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(cfgDir, "detectors.conf"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if strings.Contains(trim, "CHALLENGE_") && !strings.Contains(trim, "_LOG") && !strings.Contains(trim, "_NOTIFY") && (strings.HasSuffix(trim, "=1") || strings.HasSuffix(strings.ToLower(trim), "=true") || strings.HasSuffix(strings.ToLower(trim), "=on")) {
			return true
		}
	}
	return false
}

func printFirewallReport(r fwReport) {
	fmt.Printf("Firewall diagnostics: %s (%s)\n", r.Engine, r.Status)
	fmt.Printf("Config source: %s\n", r.ConfigSource)
	fmt.Printf("Capabilities: %s\n", strings.Join(r.Capabilities, ", "))
	fmt.Println("Configured features:")
	for _, k := range []string{"ports", "connlimit", "portflood", "smtp", "autoblock", "feeds", "dnat_edge", "dnat_challenge", "challenge_redirect"} {
		fmt.Printf("  %-10s %v\n", k, r.Features[k])
	}
	fmt.Println("Detected runtime objects:")
	keys := make([]string, 0, len(r.SetSizes))
	for k := range r.SetSizes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-14s %d\n", k, r.SetSizes[k])
	}
	if len(r.SetSizes) > 0 {
		fmt.Println("Set cardinality:")
		keys := make([]string, 0, len(r.SetSizes))
		for k := range r.SetSizes {
			if strings.HasSuffix(k, "_cardinality") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-14s %d\n", k, r.SetSizes[k])
		}
	}
	if len(r.Counters) > 0 {
		fmt.Println("Counter snapshot:")
		ckeys := make([]string, 0, len(r.Counters))
		for k := range r.Counters {
			ckeys = append(ckeys, k)
		}
		sort.Strings(ckeys)
		for _, k := range ckeys {
			fmt.Printf("  %-16s %d\n", k, r.Counters[k])
		}
	}
	if len(r.FeatureChecks) > 0 {
		fmt.Println("Feature checks:")
		features := make([]string, 0, len(r.FeatureChecks))
		for k := range r.FeatureChecks {
			features = append(features, k)
		}
		sort.Strings(features)
		for _, k := range features {
			v := r.FeatureChecks[k]
			fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(v.Status), k, v.Reason)
			if len(v.Samples) > 0 {
				sks := make([]string, 0, len(v.Samples))
				for sk := range v.Samples {
					sks = append(sks, sk)
				}
				sort.Strings(sks)
				for _, sk := range sks {
					fmt.Printf("    - %s=%s\n", sk, v.Samples[sk])
				}
			}
		}
	}
	if len(r.PolicyDomainCounts) > 0 {
		fmt.Println("Policy domains:")
		keys := make([]string, 0, len(r.PolicyDomainCounts))
		for k := range r.PolicyDomainCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-16s %d\n", k, r.PolicyDomainCounts[k])
		}
	}
	if r.Verbose && len(r.PolicyDomains) > 0 {
		fmt.Println("Policy descriptors (--verbose):")
		keys := make([]string, 0, len(r.PolicyDomains))
		for k := range r.PolicyDomains {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  [%s]\n", k)
			for _, d := range r.PolicyDomains[k] {
				fmt.Printf("    chain=%s proto=%s ports=%s verdict=%s conditions=%s\n", d.Chain, d.Proto, strings.Join(d.Ports, ","), d.Verdict, strings.Join(d.Conditions, ","))
			}
		}
	}
	if len(r.Findings) > 0 {
		fmt.Println("Findings:")
		for _, f := range r.Findings {
			fmt.Printf("  [%s] %s\n", strings.ToUpper(f.Level), f.Message)
		}
	}
	if r.CanonicalChecks.Summary != "" {
		fmt.Println("Canonical diagnostics:")
		fmt.Printf("  score=%.2f summary=%s\n", r.CanonicalChecks.Score, r.CanonicalChecks.Summary)
		if len(r.CanonicalChecks.ByDomain) > 0 {
			domains := make([]string, 0, len(r.CanonicalChecks.ByDomain))
			for d := range r.CanonicalChecks.ByDomain {
				domains = append(domains, d)
			}
			sort.Strings(domains)
			for _, d := range domains {
				v := r.CanonicalChecks.ByDomain[d]
				fmt.Printf("  [%s] missing_object=%d mismatched_rule_condition=%d mismatched_verdict=%d unsupported_feature=%d\n", d, v.MissingObject, v.MismatchedRuleCondition, v.MismatchedVerdict, v.UnsupportedFeature)
			}
		}
		for _, a := range r.CanonicalChecks.Actionable {
			fmt.Printf("  - %s\n", a)
		}
	}
	if r.Status != "ok" {
		fmt.Println("Recommendation: run `cfm firewall status --verbose` for deeper diagnostics and apply the suggested set/table remediation above.")
	}
}

func evaluateCanonicalChecks(r fwReport) fwCanonicalChecks {
	cc := fwCanonicalChecks{ByDomain: map[string]fwDomainDiff{}}
	ensure := func(domain string) fwDomainDiff {
		return cc.ByDomain[domain]
	}
	for _, f := range r.Findings {
		msg := strings.ToLower(f.Message)
		domain := "base"
		for _, d := range []string{"dnat_edge", "dnat_challenge", "smtp", "portflood", "connlimit", "autoblock", "feeds", "ports"} {
			if strings.Contains(msg, d) {
				domain = d
				break
			}
		}
		d := ensure(domain)
		switch {
		case strings.Contains(msg, "missing"):
			d.MissingObject++
		case strings.Contains(msg, "verdict"):
			d.MismatchedVerdict++
		case strings.Contains(msg, "condition") || strings.Contains(msg, "dependency"):
			d.MismatchedRuleCondition++
		}
		cc.ByDomain[domain] = d
	}
	for k := range r.Unsupported {
		domain := "base"
		if strings.Contains(k, "dnat") {
			domain = "dnat"
		} else if strings.Contains(k, "smtp") {
			domain = "smtp"
		} else if strings.Contains(k, "flood") {
			domain = "portflood"
		} else if strings.Contains(k, "connlimit") {
			domain = "connlimit"
		}
		d := ensure(domain)
		d.UnsupportedFeature++
		cc.ByDomain[domain] = d
	}
	total := 0
	bad := 0
	for domain, v := range cc.ByDomain {
		sum := v.MissingObject + v.MismatchedRuleCondition + v.MismatchedVerdict + v.UnsupportedFeature
		total += sum
		if sum > 0 {
			bad += sum
			cc.Actionable = append(cc.Actionable, fmt.Sprintf("domain=%s mismatches=%d", domain, sum))
		}
	}
	if total == 0 {
		cc.Score = 1
		cc.Summary = "all canonical diagnostics passed"
		return cc
	}
	cc.Score = float64(total-bad) / float64(total)
	cc.Summary = fmt.Sprintf("%d mismatch(es) across %d domain(s)", bad, len(cc.ByDomain))
	sort.Strings(cc.Actionable)
	return cc
}

func evaluateFeatureChecks(r fwReport) map[string]fwFeatureCheck {
	checks := map[string]fwFeatureCheck{}
	for _, feature := range []string{"dnat_edge", "dnat_challenge", "challenge_redirect", "smtp", "portflood", "connlimit", "autoblock"} {
		sourceFeature := feature
		if feature == "challenge_redirect" {
			sourceFeature = "dnat_challenge"
		}
		enabled := r.Features[sourceFeature]
		if !enabled {
			checks[feature] = fwFeatureCheck{Status: "N/A", Reason: "feature disabled", Samples: map[string]string{"last_update": "n/a"}}
			continue
		}
		check := fwFeatureCheck{Status: "pass", Reason: "required runtime signals present", Samples: map[string]string{"last_update": "n/a"}}
		switch feature {
		case "dnat_edge":
			check.Samples["mode"] = "openresty/angie"
		case "dnat_challenge":
			check.Samples["table"] = "inet/cfm_redirect"
		case "challenge_redirect":
			check.RequiredSets = []string{"challenge_v4", "challenge_v6"}
		case "smtp":
			check.RequiredSets = []string{"smtp_ports", "smtp_allow_uids", "smtp_allow_gids"}
		case "portflood":
			check.Counters = []string{"portflood"}
		case "connlimit":
			check.Counters = []string{"connlimit"}
		case "autoblock":
			check.RequiredSets = []string{"throttled_v4", "throttled_v6"}
			check.Counters = []string{"flood"}
		}
		for _, s := range check.RequiredSets {
			v, ok := r.SetSizes[s]
			if !ok {
				if feature == "challenge_redirect" && !r.Features["challenge_runtime_mode"] {
					check.Status = "warn"
					check.Reason = "optional set missing outside nft DNAT runtime mode: " + s
					continue
				}
				check.Status = "fail"
				check.Reason = "missing required set: " + s
				break
			}
			check.Samples[s+"_size"] = fmt.Sprintf("%d", v)
		}
		if check.Status != "fail" {
			for _, c := range check.Counters {
				v, ok := r.Counters[c]
				if !ok {
					check.Status = "warn"
					check.Reason = "counter unavailable: " + c
					continue
				}
				if v < 0 {
					check.Status = "warn"
					check.Reason = "counter semantic check failed: negative " + c
				}
				check.Samples[c+"_total"] = fmt.Sprintf("%d", v)
			}
		}
		checks[feature] = check
	}
	return checks
}

func hasExpectedDNATPreroutingRules(tableJSON []byte) bool {
	raw := strings.ToLower(string(tableJSON))
	return strings.Contains(raw, `"chain":"prerouting"`) &&
		strings.Contains(raw, `"field":"dport"`) &&
		strings.Contains(raw, `"right":80`) &&
		strings.Contains(raw, `"right":443`) &&
		strings.Contains(raw, `"dnat"`)
}

func collectPolicyDomains(tableJSON []byte) map[string][]fwRuleDescriptor {
	var payload map[string]any
	if err := json.Unmarshal(tableJSON, &payload); err != nil {
		return map[string][]fwRuleDescriptor{}
	}
	out := map[string][]fwRuleDescriptor{}
	nft, _ := payload["nftables"].([]any)
	for _, item := range nft {
		entry, _ := item.(map[string]any)
		ruleWrap, ok := entry["rule"].(map[string]any)
		if !ok {
			continue
		}
		chain, _ := ruleWrap["chain"].(string)
		domain := classifyPolicyDomain(chain)
		if domain == "" {
			continue
		}
		desc := fwRuleDescriptor{Chain: chain}
		if exprs, ok := ruleWrap["expr"].([]any); ok {
			for _, ex := range exprs {
				s := canonicalExpr(ex)
				if s == "" {
					continue
				}
				if strings.HasPrefix(s, "proto=") {
					desc.Proto = strings.TrimPrefix(s, "proto=")
				} else if strings.HasPrefix(s, "port=") {
					desc.Ports = append(desc.Ports, strings.TrimPrefix(s, "port="))
				} else if strings.HasPrefix(s, "verdict=") {
					desc.Verdict = strings.TrimPrefix(s, "verdict=")
				} else {
					desc.Conditions = append(desc.Conditions, s)
				}
			}
		}
		sort.Strings(desc.Ports)
		sort.Strings(desc.Conditions)
		out[domain] = append(out[domain], desc)
	}
	return out
}

func classifyPolicyDomain(chain string) string {
	switch {
	case strings.Contains(chain, "smtp"):
		return "smtp"
	case strings.Contains(chain, "flood"):
		return "portflood"
	case strings.Contains(chain, "connlimit"):
		return "connlimit"
	case chain == "input" || chain == "output" || chain == "forward":
		return "base"
	default:
		return "ports"
	}
}

func canonicalExpr(ex any) string {
	m, ok := ex.(map[string]any)
	if !ok || len(m) != 1 {
		return ""
	}
	for k, v := range m {
		switch k {
		case "match":
			mv, _ := v.(map[string]any)
			left, _ := mv["left"].(map[string]any)
			if p, ok := left["payload"].(map[string]any); ok {
				proto, _ := p["protocol"].(string)
				field, _ := p["field"].(string)
				right := fmt.Sprintf("%v", mv["right"])
				if field == "dport" || field == "sport" {
					return "port=" + right
				}
				if proto != "" {
					return "proto=" + proto
				}
			}
			return "match"
		case "accept", "drop", "reject", "jump", "dnat":
			return "verdict=" + k
		default:
			return k
		}
	}
	return ""
}

func MarshalFirewallReport(r fwReport) string {
	b, _ := json.Marshal(r)
	return string(bytes.TrimSpace(b))
}
