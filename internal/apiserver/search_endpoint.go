// internal/apiserver/search_endpoint.go
//
// RegisterSearch wires the read-only /search endpoint onto the mux.
//
//	GET /search?ip=1.2.3.4        (also accepts a CIDR)
//
// It runs the same multi-source locate used by `cfm search`: nft,
// cfm.deny, csf, fail2ban and imunify360 — strictly read-only, no state
// changes. It is nonetheless admin-only: the result enumerates every place
// an arbitrary IP is blocked host-wide (all vhosts, all planes), which is
// cross-tenant reconnaissance with no per-vhost scoping, so a scoped
// (cPanel/DA) token must not reach it. Intended consumers: cfm-web
// fleet-wide "where is this IP blocked?" lookups and the unblock pipeline's
// where-&-why reporting — both admin-token callers, same as /unblock.
package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/locate"
	"cfm/internal/logging"
)

var locateFind = locate.Find

// RegisterSearch adds the /search route to the provided mux.
func RegisterSearch(m *http.ServeMux, be firewall.Backend, cfgDir string) {
	if m == nil {
		return
	}
	m.Handle("/search", adminOnlyHandler(makeSearchHandler(be, cfgDir)))
}

func makeSearchHandler(be firewall.Backend, cfgDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "error": "method not allowed",
			})
			return
		}

		arg := strings.TrimSpace(r.URL.Query().Get("ip"))
		if arg == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "error": "missing ip parameter",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()

		res, err := locateFind(ctx, arg, locate.Options{BE: be, ConfigDir: cfgDir})
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "error": err.Error(),
			})
			return
		}

		logging.LogfAPI("[search] query=%s hits=%d skipped=%d took=%s",
			arg, len(res.Locations), len(res.Skipped), time.Since(start))

		if res.Locations == nil {
			res.Locations = []locate.Location{} // [] not null in JSON
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"hostname":    localNodeID(),
			"query":       res.Query,
			"locations":   res.Locations,
			"skipped":     res.Skipped,
			"duration_ms": time.Since(start).Milliseconds(),
		})
	}
}
