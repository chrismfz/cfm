package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	cfgpkg "cfm/internal/config"
	"cfm/internal/dnat"
	"cfm/internal/firewall/netfilterdiag"
	"cfm/internal/firewall/nft"
)

type netfilterCollector func(context.Context, netfilterdiag.Expected) (netfilterdiag.Report, error)

func collectNetfilterPath(ctx context.Context, expected netfilterdiag.Expected) (netfilterdiag.Report, error) {
	return netfilterdiag.Collect(ctx, expected, nft.ListRulesetJSON)
}

// RegisterNetfilterPath adds the admin-only host-wide nftables hook-order view.
func RegisterNetfilterPath(m *http.ServeMux, cfg *cfgpkg.Config) {
	registerNetfilterPath(m, cfg, collectNetfilterPath)
}

func registerNetfilterPath(m *http.ServeMux, cfg *cfgpkg.Config, collect netfilterCollector) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/firewall/path", adminOnlyHandler(makeNetfilterPathHandler(cfg, collect)))
}

func makeNetfilterPathHandler(cfg *cfgpkg.Config, collect netfilterCollector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
			return
		}
		filters, err := netfilterFilters(r)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		var inputPriority, dnatPriority int
		if cfg != nil {
			inputPriority = cfg.NFT.InputPriority
			dnatPriority = cfg.NFT.DNATPriority
		}
		report, err := collect(r.Context(), netfilterdiag.EffectiveExpected(inputPriority, dnatPriority, dnat.PanelStartupPriority()))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "read nft ruleset: " + err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(netfilterdiag.Limit(netfilterdiag.Filter(report, filters)))
	}
}

func netfilterFilters(r *http.Request) (netfilterdiag.Filters, error) {
	q := r.URL.Query()
	f := netfilterdiag.Filters{
		Hook:   strings.ToLower(strings.TrimSpace(q.Get("hook"))),
		Family: strings.ToLower(strings.TrimSpace(q.Get("family"))),
		Proto:  strings.ToLower(strings.TrimSpace(q.Get("proto"))),
	}
	if raw := strings.TrimSpace(q.Get("dport")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return f, err
		}
		f.DPort = n
		if n == 0 {
			return f, fmt.Errorf("invalid destination port 0")
		}
	}
	return f, netfilterdiag.ValidateFilters(f)
}
