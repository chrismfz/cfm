package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"cfm/internal/dnat"
	"cfm/internal/firewall/netfilterdiag"
	"cfm/internal/firewall/nft"
)

type netfilterPathCollector func(context.Context, netfilterdiag.Expected) (netfilterdiag.Report, error)

func collectNetfilterPath(ctx context.Context, expected netfilterdiag.Expected) (netfilterdiag.Report, error) {
	return netfilterdiag.Collect(ctx, expected, nft.ListRulesetJSON)
}

func runNetfilterPath(args []string, cfgDir string, collect netfilterPathCollector, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("firewall path", flag.ContinueOnError)
	fs.SetOutput(errOut)
	hook := fs.String("hook", "", "filter by nftables hook")
	family := fs.String("family", "", "filter by nftables family")
	proto := fs.String("proto", "", "filter NAT rules by tcp or udp")
	dport := 0
	fs.Func("dport", "filter NAT rules by destination port", func(raw string) error {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid destination port %q", raw)
		}
		dport = port
		return nil
	})
	jsonOut := fs.Bool("json", false, "output JSON")
	strict := fs.Bool("strict", false, "exit non-zero on warning or critical findings")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(errOut, "firewall path: unexpected arguments:", strings.Join(fs.Args(), " "))
		return 2
	}
	f := netfilterdiag.Filters{Hook: strings.ToLower(*hook), Family: strings.ToLower(*family), Proto: strings.ToLower(*proto), DPort: dport}
	if err := netfilterdiag.ValidateFilters(f); err != nil {
		fmt.Fprintln(errOut, "firewall path:", err)
		return 2
	}
	cfg := loadCfg(cfgDir)
	report, err := collect(context.Background(), netfilterdiag.EffectiveExpected(cfg.NFT.InputPriority, cfg.NFT.DNATPriority, dnat.PanelStartupPriority()))
	if err != nil {
		fmt.Fprintln(errOut, "firewall path:", err)
		return 1
	}
	report = netfilterdiag.Limit(netfilterdiag.Filter(report, f))
	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		printNetfilterPath(out, report)
	}
	if *strict && report.Status != "ok" {
		return 1
	}
	return 0
}

func printNetfilterPath(out io.Writer, r netfilterdiag.Report) {
	fmt.Fprintf(out, "Netfilter hook order: %s (%d base chains, %d NAT rules, %d findings)\n", strings.ToUpper(r.Status), r.Summary.BaseChains, r.Summary.NATRules, r.Summary.Findings)
	fmt.Fprintf(out, "Configured CFM priorities: input=%d web-dnat=%d panel-dnat=%d\n\n", r.Expected.InputPriority, r.Expected.DNATPriority, r.Expected.PanelDNATPriority)
	if len(r.Findings) > 0 {
		fmt.Fprintln(out, "Findings:")
		for _, f := range r.Findings {
			fmt.Fprintf(out, "  %-7s %-25s %s\n", strings.ToUpper(f.Level), f.Code, f.Message)
		}
		fmt.Fprintln(out)
	}
	fmt.Fprintln(out, "Base chains (lower priority runs first):")
	for _, c := range r.Chains {
		fmt.Fprintf(out, "  %-11s %4d  %-4s %-24s %-18s owner=%s policy=%s\n", c.Hook, c.Priority, c.Family, c.Table+"/"+c.Name, c.Type, c.Owner, c.Policy)
	}
	if len(r.NATRules) > 0 {
		fmt.Fprintln(out, "\nNAT/redirect rules:")
		for _, n := range r.NATRules {
			parts := make([]string, 0, len(n.DPorts)+len(n.Ranges))
			for _, p := range n.DPorts {
				parts = append(parts, strconv.Itoa(p))
			}
			for _, pr := range n.Ranges {
				parts = append(parts, fmt.Sprintf("%d-%d", pr.From, pr.To))
			}
			ports := strings.Join(parts, ",")
			if ports == "" {
				ports = "*"
			}
			fmt.Fprintf(out, "  %-11s %4d  %-24s #%-5d owner=%-12s %s/%s -> %s %s\n", n.Hook, n.Priority, n.Table+"/"+n.Chain, n.Handle, n.Owner, n.Protocol, ports, n.Action, n.Target)
		}
	}
}

func RunNetfilterPath(args []string, cfgDir string) int {
	return runNetfilterPath(args, cfgDir, collectNetfilterPath, os.Stdout, os.Stderr)
}
