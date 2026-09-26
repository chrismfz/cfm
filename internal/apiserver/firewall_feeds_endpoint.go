// internal/apiserver/firewall_feeds_endpoint.go
//
// GET /api/v1/firewall/feeds — read-only runtime state of the cfm.blocklists
// feeds: per feed its type, URL (query/userinfo redacted), interval, last
// fetch / last success / last apply, last HTTP status and error, IPv4/IPv6
// counts, and whether it is on the API_URL origin and was pulled WITH the
// node's AUTH_TOKEN (token_sent). That last pair is how an operator confirms,
// fleet-wide, that the cfm-web feeds (/blacklist.txt, /whitelist.txt) no
// longer depend on cfm-web's IP-only token fallback. Admin-only, like the
// other node-wide firewall routes. The token itself is never returned.

package apiserver

import (
	"encoding/json"
	"net/http"

	"cfm/internal/blocklists"
)

// RegisterFirewallFeeds adds GET /api/v1/firewall/feeds.
func RegisterFirewallFeeds(m *http.ServeMux) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/firewall/feeds", adminOnlyHandler(makeFirewallFeedsHandler(blocklists.ActiveManager)))
}

func makeFirewallFeedsHandler(get func() *blocklists.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
			return
		}
		mgr := get()
		if mgr == nil {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":        true,
				"available": false,
				"note":      "no blocklist feed manager in this process",
			})
			return
		}
		feeds := mgr.Status()
		failing := 0
		for _, f := range feeds {
			if f.LastErr != "" {
				failing++
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"available": true,
			"api_host":  mgr.APIHost(),
			"count":     len(feeds),
			"failing":   failing,
			"feeds":     feeds,
		})
	}
}
