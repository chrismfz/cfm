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
	"cfm/internal/firewall"
	"cfm/internal/firewall/feedutil"
)

type fwDiagBackend interface {
	DNATStatus(family, table string) (bool, error)
	ListSetElementsRaw(setName string) ([]string, error)
	ListTableJSON(family, table string) ([]byte, error)
}

type counterProbe interface { CounterValue(name string) (int64, error) }
type dnatShowProbe interface { DNATShow(family, table string) (string, error) }
type diagNamesProbe interface {
	ThrottledSetNames() []string
	ScannerSetNames() []string
	CardinalitySetNames() map[string]string
}

type fwFinding struct { Level, Message string `json:"level"` }

type setProbeRequirement struct {
	key        string
	setName    string
	required   bool
	applicable bool
	reason     string
}

type fwReport struct {
	Engine string `json:"engine"`
	Capabilities []string `json:"capabilities"`
	ConfigSource string `json:"config_source"`
	Features map[string]bool `json:"features"`
	SetSizes map[string]int `json:"set_sizes"`
	Counters map[string]int64 `json:"counters"`
	Unsupported map[string]bool `json:"unsupported,omitempty"`
	Findings []fwFinding `json:"findings"`
	Status string `json:"status"`
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
	if *strict && report.Status == "fail" { return 1 }
	return 0
}

func collectFirewallStatus(be fwDiagBackend, cfgDir, engine, source string, verbose bool) fwReport {
	r := fwReport{Engine: engine, ConfigSource: source, Features: map[string]bool{}, SetSizes: map[string]int{}, Counters: map[string]int64{}, Unsupported: map[string]bool{}}
	if caps, ok := any(be).(firewall.CapabilityReporter); ok {
		c := caps.Capabilities(); if c.PortsPolicyInboundRules { r.Capabilities = append(r.Capabilities, "ports_policy") }
		if c.PortscanTrackingSets { r.Capabilities = append(r.Capabilities, "portscan_sets") }
		if c.NewStateDropFallback { r.Capabilities = append(r.Capabilities, "new_state_drop") }
	}
	sort.Strings(r.Capabilities)
	cfg := loadCfg(cfgDir)
	r.Features["ports"] = cfg.Ports.TCPIn != nil || cfg.Ports.UDPIn != nil
	r.Features["connlimit"] = len(cfg.Connlimit.Rules) > 0
	r.Features["portflood"] = len(cfg.PortFlood.Rules) > 0
	r.Features["smtp"] = cfg.SMTPBlock.Enabled
	r.Features["autoblock"] = cfg.Throttle.Enabled
	r.Features["feeds"] = true
	r.Features["dnat"] = false

	if ok, err := be.DNATStatus("inet", "cfm"); err == nil { r.Features["dnat"] = ok } else { r.Unsupported["dnat_redirect"] = true; r.Findings = append(r.Findings, fwFinding{"warn", "dnat status unsupported: "+err.Error()}) }

	setNames := map[string]string{
		"block_v4":       "block_v4",
		"block_v6":       "block_v6",
		"block_v4_nets":  "block_v4_nets",
		"block_v6_nets":  "block_v6_nets",
		"allow_v4":       "allow_v4",
		"allow_v6":       "allow_v6",
		"allow_v4_nets":  "allow_v4_nets",
		"allow_v6_nets":  "allow_v6_nets",
		"ignore_v4":      "ignore_v4",
		"ignore_v6":      "ignore_v6",
		"ignore_v4_nets": "ignore_v4_nets",
		"ignore_v6_nets": "ignore_v6_nets",
		"allow_dyn_v4":   "allow_dyn_v4",
		"allow_dyn_v6":   "allow_dyn_v6",
		"challenge_v4":   "challenge_v4",
		"challenge_v6":   "challenge_v6",
	}
	legacyAliases := map[string]string{
		"block_ips":     "block_v4/block_v6",
		"allow_ips":     "allow_v4/allow_v6",
		"ignore_ips":    "ignore_v4/ignore_v6",
		"challenge_ips": "challenge_v4/challenge_v6",
		"feed_ext":      "allow_ext_*/block_ext_*",
	}
	throttledSets := []string{"throttled_v4","throttled_v6"}
	scannerSets := []string{"port_scanners_v4","port_scanners_v6"}
	if np, ok := any(be).(diagNamesProbe); ok {
		if v := np.CardinalitySetNames(); len(v) > 0 { setNames = v }
		if v := np.ThrottledSetNames(); len(v) > 0 { throttledSets = v }
		if v := np.ScannerSetNames(); len(v) > 0 { scannerSets = v }
	}
	for _, f := range loadConfiguredFeeds(cfgDir) {
		key := feedutil.SanitizeFeedName(f.Name)
		base := "block_ext"
		if f.Type == blocklists.TypeAllow {
			base = "allow_ext"
		}
		for _, suffix := range []string{"v4_hosts", "v4_nets", "v6_hosts", "v6_nets"} {
			name := base + "_" + suffix + "_" + key
			setNames[name] = name
		}
	}

	probeReq := map[string]setProbeRequirement{}
	for key, s := range setNames {
		required := true
		applicable := true
		reason := "core infrastructure"
		switch s {
		case "challenge_v4", "challenge_v6":
			required = r.Features["dnat"]
			applicable = r.Features["dnat"]
			reason = "required only when DNAT redirect is enabled"
		}
		probeReq[s] = setProbeRequirement{key: key, setName: s, required: required, applicable: applicable, reason: reason}
	}
	for _, s := range []string{"smtp_ports", "smtp_allow_uids", "smtp_allow_gids"} {
		probeReq[s] = setProbeRequirement{key: s, setName: s, required: r.Features["smtp"], applicable: r.Features["smtp"], reason: "required only when smtpblock is enabled"}
	}

	for _, req := range probeReq {
		s := req.setName
		if !req.applicable {
			r.Findings = append(r.Findings, fwFinding{"info", "set probe not applicable for " + s + " (" + req.reason + ")"})
			continue
		}
		elems, err := be.ListSetElementsRaw(s)
		if err != nil {
			if canonical, ok := legacyAliases[s]; ok {
				r.Findings = append(r.Findings, fwFinding{"warn", "legacy set alias "+s+" is absent (canonical: "+canonical+")"})
				continue
			}
			level := "warn"
			if req.required {
				level = "fail"
			}
			r.Findings = append(r.Findings, fwFinding{level, "set probe failed for "+s+": "+err.Error()})
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
	if _, err := be.ListTableJSON("inet", "cfm"); err != nil { r.Findings = append(r.Findings, fwFinding{"fail", "required table inet/cfm missing or unreadable: "+err.Error()}) }
	if cp, ok := any(be).(counterProbe); ok {
		for _, name := range []string{"cfm_input_drop", "cfm_forward_drop", "flood", "portflood", "connlimit"} { if v, err := cp.CounterValue(name); err == nil { r.Counters[name] = v } else { r.Unsupported[name+"_counter"] = true } }
	}
	if len(r.Counters) == 0 {
		r.Unsupported["flood_counter"] = true
		r.Unsupported["portflood_counter"] = true
		r.Unsupported["connlimit_counter"] = true
	}
	if verbose {
		if ds, ok := any(be).(dnatShowProbe); ok { if raw, err := ds.DNATShow("inet", "cfm"); err != nil { r.Findings = append(r.Findings, fwFinding{"warn", "dnat show probe failed: "+err.Error()}) } else if strings.TrimSpace(raw) == "" { r.Findings = append(r.Findings, fwFinding{"warn", "dnat show returned empty output"}) } }
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
	if cfgDir == "" { return &cfgpkg.Config{} }
	b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.conf")); if err != nil { return &cfgpkg.Config{} }
	cfg, err := LoadConfigWithAPIOverride(cfgDir, b); if err != nil || cfg == nil { return &cfgpkg.Config{} }
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

func printFirewallReport(r fwReport) {
	fmt.Printf("Firewall diagnostics: %s (%s)\n", r.Engine, r.Status)
	fmt.Printf("Config source: %s\n", r.ConfigSource)
	fmt.Printf("Capabilities: %s\n", strings.Join(r.Capabilities, ", "))
	fmt.Println("Features:")
	for _, k := range []string{"ports","connlimit","portflood","smtp","autoblock","feeds","dnat"} { fmt.Printf("  %-10s %v\n", k, r.Features[k]) }
	fmt.Println("Set sizes:")
	keys := make([]string,0,len(r.SetSizes)); for k := range r.SetSizes { keys = append(keys,k) }; sort.Strings(keys)
	for _, k := range keys { fmt.Printf("  %-14s %d\n", k, r.SetSizes[k]) }
	if len(r.Counters) > 0 { fmt.Println("Counters:"); ckeys := make([]string,0,len(r.Counters)); for k := range r.Counters { ckeys=append(ckeys,k)}; sort.Strings(ckeys); for _, k := range ckeys { fmt.Printf("  %-16s %d\n", k, r.Counters[k]) } }
	if len(r.Findings) > 0 { fmt.Println("Findings:"); for _, f := range r.Findings { fmt.Printf("  [%s] %s\n", strings.ToUpper(f.Level), f.Message) } }
}

func MarshalFirewallReport(r fwReport) string { b,_ := json.Marshal(r); return string(bytes.TrimSpace(b)) }
