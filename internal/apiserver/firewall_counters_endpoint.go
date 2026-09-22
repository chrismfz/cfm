// internal/apiserver/firewall_counters_endpoint.go
//
// GET /api/v1/firewall/counters — the read side of the nftables named counters
// in `table inet cfm`. These count how much traffic each L3/L4 firewall RULE is
// matching (portflood/connlimit/SYN-flood/pps-flood/hardening drops/smtpblock) —
// distinct from /api/v1/firewall/list, which lists the blocked-IP SETS. Answers
// "which firewall rules are actually firing, and how hard?".
//
// Backend-agnostic: it reads the counters out of the table JSON via the same
// ListTableJSON("inet","cfm") both engines implement (nft parses `nft -j list
// table`, nftlib the same), so there is no new firewall.Backend method and no
// netlink object read (the nftlib GetObjects path that once wedged the shared
// connection — see the FIX B history — is never touched). Admin-only: a global
// firewall view is meaningless to a scoped vhost token.

package apiserver

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"cfm/internal/firewall"
)

type fwCounterRow struct {
	Name    string `json:"name"`
	Family  string `json:"family"` // portflood|connlimit|synflood|ppsflood|hardening|smtpblock|other
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// classifyCounter maps a counter name to a coarse family for grouping. Names are
// created by the nft/nftlib backends (ensureCounter): connlimit_*, portflood_*,
// synrate_*, ppsrate_*, smtpblock_*, and the fixed hardening set.
func classifyCounter(name string) string {
	switch {
	case strings.HasPrefix(name, "connlimit_"):
		return "connlimit"
	case strings.HasPrefix(name, "portflood_"):
		return "portflood"
	case strings.HasPrefix(name, "synrate_"):
		return "synflood"
	case strings.HasPrefix(name, "ppsrate_"):
		return "ppsflood"
	case strings.HasPrefix(name, "smtpblock_"):
		return "smtpblock"
	case name == "badflags_drop" || name == "newrate_v4" || name == "newrate_v6" ||
		name == "icmp_v4" || name == "icmp_v6":
		return "hardening"
	default:
		return "other"
	}
}

// RegisterFirewallCounters adds GET /api/v1/firewall/counters.
func RegisterFirewallCounters(m *http.ServeMux, be firewall.Backend) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/firewall/counters", adminOnlyHandler(makeFirewallCountersHandler(be)))
}

func makeFirewallCountersHandler(be firewall.Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
			return
		}
		if be == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "no firewall backend"})
			return
		}
		raw, err := be.ListTableJSON("inet", "cfm")
		if err != nil {
			// The daemon may not have built the table yet, or nft is unavailable.
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}

		rows, supported, err := parseFirewallCounters(raw)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if !supported {
			// The nftlib backend's ListTableJSON emits a custom {family,table,sets}
			// shape with no counter objects — so counters cannot be read here.
			// Report available:false honestly instead of a misleading empty list
			// (a zero-count list would read as "no firewall activity"). Reading
			// them would need a netlink counter dump the nftlib backend does
			// not implement.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":        true,
				"schema":    "firewall.counters.v1",
				"available": false,
				"note":      "nft named-counter read requires the exec-nft backend (CFM_FIREWALL_ENGINE=nft); this node runs the nftlib backend",
			})
			return
		}

		// nonzero=1 hides idle counters (rules that exist but have matched nothing)
		// so the operator sees only what is actually firing.
		nonzero := r.URL.Query().Get("nonzero") == "1"
		if nonzero {
			kept := rows[:0]
			for _, row := range rows {
				if row.Packets > 0 {
					kept = append(kept, row)
				}
			}
			rows = kept
		}

		// Busiest first (packets), then name for a stable order.
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Packets != rows[j].Packets {
				return rows[i].Packets > rows[j].Packets
			}
			return rows[i].Name < rows[j].Name
		})

		byFamily := map[string]uint64{} // family -> total packets
		var totalPackets, totalBytes uint64
		for _, row := range rows {
			byFamily[row.Family] += row.Packets
			totalPackets += row.Packets
			totalBytes += row.Bytes
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":            true,
			"schema":        "firewall.counters.v1",
			"total":         len(rows),
			"total_packets": totalPackets,
			"total_bytes":   totalBytes,
			"by_family":     byFamily,
			"counters":      rows,
		})
	}
}

// parseFirewallCounters extracts the named counters from `nft -j list table`
// output. Each counter is an object `{"counter":{"name":..,"packets":N,"bytes":M}}`
// in the top-level "nftables" array (rules/sets/chains are ignored).
//
// supported reports whether the payload is the nft `-j list table` shape at all:
// the nftlib backend's ListTableJSON emits a custom {family,table,sets} object
// with NO "nftables" array, so counters cannot be read from it. supported=false
// lets the caller say "not available on this backend" instead of silently
// returning an empty (misleading) counter list.
func parseFirewallCounters(raw []byte) (rows []fwCounterRow, supported bool, err error) {
	// Probe for the nft top-level "nftables" array; its absence means the nftlib
	// custom shape (or some other payload) — not counter-readable.
	var probe map[string]json.RawMessage
	if err = json.Unmarshal(raw, &probe); err != nil {
		return nil, false, err
	}
	nftArr, ok := probe["nftables"]
	if !ok {
		return nil, false, nil
	}
	var objs []map[string]json.RawMessage
	if err = json.Unmarshal(nftArr, &objs); err != nil {
		return nil, false, err
	}
	rows = make([]fwCounterRow, 0, 16)
	for _, obj := range objs {
		rawc, ok := obj["counter"]
		if !ok {
			continue
		}
		var c struct {
			Name    string `json:"name"`
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		}
		if err := json.Unmarshal(rawc, &c); err != nil {
			continue
		}
		if c.Name == "" {
			continue
		}
		rows = append(rows, fwCounterRow{
			Name:    c.Name,
			Family:  classifyCounter(c.Name),
			Packets: c.Packets,
			Bytes:   c.Bytes,
		})
	}
	return rows, true, nil
}
