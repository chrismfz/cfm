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

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall"
)

type fwDiagBackend interface {
	DNATStatus(family, table string) (bool, error)
	ListSetElementsRaw(setName string) ([]string, error)
	ListTableJSON(family, table string) ([]byte, error)
}

type counterProbe interface { CounterValue(name string) (int64, error) }
type dnatShowProbe interface { DNATShow(family, table string) (string, error) }

type fwFinding struct { Level, Message string `json:"level"` }

type fwReport struct {
	Engine string `json:"engine"`
	Capabilities []string `json:"capabilities"`
	ConfigSource string `json:"config_source"`
	Features map[string]bool `json:"features"`
	SetSizes map[string]int `json:"set_sizes"`
	Counters map[string]int64 `json:"counters"`
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
	r := fwReport{Engine: engine, ConfigSource: source, Features: map[string]bool{}, SetSizes: map[string]int{}, Counters: map[string]int64{}}
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

	if ok, err := be.DNATStatus("inet", "cfm"); err == nil { r.Features["dnat"] = ok } else { r.Findings = append(r.Findings, fwFinding{"warn", "dnat status unavailable: "+err.Error()}) }
	for _, s := range []string{"block_ips", "allow_ips", "ignore_ips", "challenge_ips"} {
		elems, err := be.ListSetElementsRaw(s)
		if err != nil { r.Findings = append(r.Findings, fwFinding{"warn", "set probe failed for "+s+": "+err.Error()}); continue }
		r.SetSizes[s] = len(elems)
	}
	if _, err := be.ListTableJSON("inet", "cfm"); err != nil { r.Findings = append(r.Findings, fwFinding{"fail", "required table inet/cfm missing or unreadable: "+err.Error()}) }
	if cp, ok := any(be).(counterProbe); ok {
		for _, name := range []string{"cfm_input_drop", "cfm_forward_drop"} { if v, err := cp.CounterValue(name); err == nil { r.Counters[name] = v } }
	}
	if verbose {
		if ds, ok := any(be).(dnatShowProbe); ok { if raw, err := ds.DNATShow("inet", "cfm"); err != nil { r.Findings = append(r.Findings, fwFinding{"warn", "dnat show probe failed: "+err.Error()}) } else if strings.TrimSpace(raw) == "" { r.Findings = append(r.Findings, fwFinding{"warn", "dnat show returned empty output"}) } }
	}
	r.Status = "ok"
	for _, f := range r.Findings { if f.Level == "fail" { r.Status = "fail"; break }; if f.Level == "warn" { r.Status = "warn" } }
	return r
}

func loadCfg(cfgDir string) *cfgpkg.Config {
	if cfgDir == "" { return &cfgpkg.Config{} }
	b, err := os.ReadFile(filepath.Join(cfgDir, "cfm.conf")); if err != nil { return &cfgpkg.Config{} }
	cfg, err := LoadConfigWithAPIOverride(cfgDir, b); if err != nil || cfg == nil { return &cfgpkg.Config{} }
	return cfg
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
