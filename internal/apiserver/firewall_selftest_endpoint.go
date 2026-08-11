// internal/apiserver/firewall_selftest_endpoint.go
//
// GET /api/v1/firewall/selftest — read-only diagnostics for the firewall backend.
// Surfaces the nftlib self-test: recent EnsureBase timings split into
// lock_wait / netlink / CLI, plus per-set feed-write sizes/errors. This is the
// live view for root-causing an nftlib slowdown (EnsureBase duration climbing
// over a run) or a feed that fails to apply ("message too long"). Admin-only
// like the other global firewall routes; a scoped vhost token has no business
// with node-wide firewall internals. The exec-nft backend does not implement
// firewall.SelfTester, so there the endpoint reports available=false.

package apiserver

import (
	"encoding/json"
	"net/http"

	"cfm/internal/firewall"
)

// RegisterFirewallSelfTest adds GET /api/v1/firewall/selftest.
func RegisterFirewallSelfTest(m *http.ServeMux, be firewall.Backend) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/firewall/selftest", adminOnlyHandler(makeFirewallSelfTestHandler(be)))
}

func makeFirewallSelfTestHandler(be firewall.Backend) http.HandlerFunc {
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
		engine := "unknown"
		if m, ok := be.(interface{ Engine() string }); ok {
			engine = m.Engine()
		}
		st, ok := be.(firewall.SelfTester)
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":        true,
				"available": false,
				"engine":    engine,
				"note":      "self-test diagnostics are only recorded by the nftlib backend",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":        true,
			"available": true,
			"selftest":  st.NftlibSelfTest(),
		})
	}
}
