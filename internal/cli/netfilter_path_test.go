package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"cfm/internal/firewall/netfilterdiag"
)

func TestRunNetfilterPathTextAndStrict(t *testing.T) {
	collect := func(context.Context, netfilterdiag.Expected) (netfilterdiag.Report, error) {
		return netfilterdiag.Report{OK: true, Schema: netfilterdiag.Schema, Status: "warning", Expected: netfilterdiag.Expected{InputPriority: -50, DNATPriority: -99}, Summary: netfilterdiag.Summary{BaseChains: 1, Findings: 1}, Chains: []netfilterdiag.Chain{{Family: "inet", Table: "cfm_redirect", Name: "prerouting", Hook: "prerouting", Priority: -99, Type: "nat", Owner: "cfm"}}, Findings: []netfilterdiag.Finding{{Level: "warning", Code: "competing_nat_rules", Message: "overlap"}}}, nil
	}
	var out, errOut bytes.Buffer
	if code := runNetfilterPath([]string{"--strict"}, "", collect, &out, &errOut); code != 1 {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Netfilter hook order: WARNING") || !strings.Contains(out.String(), "cfm_redirect/prerouting") {
		t.Fatalf("output=%s", out.String())
	}
}

func TestRunNetfilterPathJSONAndBadFilter(t *testing.T) {
	collect := func(context.Context, netfilterdiag.Expected) (netfilterdiag.Report, error) {
		return netfilterdiag.Report{OK: true, Schema: netfilterdiag.Schema, Status: "ok"}, nil
	}
	var out, errOut bytes.Buffer
	if code := runNetfilterPath([]string{"--json"}, "", collect, &out, &errOut); code != 0 || !strings.Contains(out.String(), `"schema": "firewall.netfilter_path.v1"`) {
		t.Fatalf("code/output=%d %s", code, out.String())
	}
	if code := runNetfilterPath([]string{"--hook", "sideways"}, "", collect, &out, &errOut); code != 2 {
		t.Fatalf("bad filter code=%d", code)
	}
	if code := runNetfilterPath([]string{"--dport", "0"}, "", collect, &out, &errOut); code != 2 {
		t.Fatalf("zero destination port code=%d", code)
	}
	if code := runNetfilterPath([]string{"unexpected"}, "", collect, &out, &errOut); code != 2 {
		t.Fatalf("trailing argument code=%d", code)
	}
}

func TestRunNetfilterPathStrictAllowsInfoOnly(t *testing.T) {
	collect := func(context.Context, netfilterdiag.Expected) (netfilterdiag.Report, error) {
		return netfilterdiag.Report{OK: true, Schema: netfilterdiag.Schema, Status: "ok", Findings: []netfilterdiag.Finding{{Level: "info", Code: "ordered_nat_overlap"}}}, nil
	}
	var out, errOut bytes.Buffer
	if code := runNetfilterPath([]string{"--strict"}, "", collect, &out, &errOut); code != 0 {
		t.Fatalf("info-only strict code=%d", code)
	}
}
