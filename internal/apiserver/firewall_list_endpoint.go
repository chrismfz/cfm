// internal/apiserver/firewall_list_endpoint.go
//
// GET /api/v1/firewall/list — the read side of the manual block list, so the
// admin UI's Firewall page can SHOW what is blocked (with TTL and GeoIP
// context) instead of only writing blocks blindly. Wraps the same
// firewall.Backend the CLI `cfm list` uses; admin-only like the block
// endpoints (a global list is meaningless to a scoped vhost token).

package apiserver

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"cfm/internal/firewall"
)

type firewallListRow struct {
	IP           string `json:"ip"`
	Expires      string `json:"expires,omitempty"` // RFC3339; empty = permanent
	ExpiresInSec int64  `json:"expires_in_sec,omitempty"`
	Permanent    bool   `json:"permanent"`
	Comment      string `json:"comment,omitempty"`
	Country      string `json:"country,omitempty"`
	ASN          uint   `json:"asn,omitempty"`
	ASNName      string `json:"asn_name,omitempty"`
}

// RegisterFirewallList adds GET /api/v1/firewall/list.
func RegisterFirewallList(m *http.ServeMux, be firewall.Backend) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/firewall/list", adminOnlyHandler(makeFirewallListHandler(be)))
}

func makeFirewallListHandler(be firewall.Backend) http.HandlerFunc {
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
		entries, err := be.ListBlocks()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		enr := be.GetEnricher()
		now := time.Now()
		rows := make([]firewallListRow, 0, len(entries))
		permanent := 0
		for _, e := range entries {
			row := firewallListRow{IP: e.IP.String(), Comment: e.Comment, Permanent: e.Expires == nil}
			if e.Expires != nil {
				row.Expires = e.Expires.Format(time.RFC3339)
				if d := e.Expires.Sub(now); d > 0 {
					row.ExpiresInSec = int64(d.Seconds())
				}
			} else {
				permanent++
			}
			if enr != nil {
				g := enr.LookupCachedOrAsync(row.IP)
				row.Country = g.Country
				row.ASN = g.ASN
				row.ASNName = g.ASNName
			}
			rows = append(rows, row)
		}
		// Expiring-soonest first; permanent blocks last (they need the most
		// deliberate attention, but temporary noise dominates day-to-day).
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Permanent != rows[j].Permanent {
				return !rows[i].Permanent
			}
			if rows[i].ExpiresInSec != rows[j].ExpiresInSec {
				return rows[i].ExpiresInSec < rows[j].ExpiresInSec
			}
			return rows[i].IP < rows[j].IP
		})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"total":     len(rows),
			"permanent": permanent,
			"rows":      rows,
		})
	}
}
