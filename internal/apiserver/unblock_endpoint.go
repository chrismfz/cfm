// internal/apiserver/unblock_endpoint.go
//
// RegisterUnblock wires the /unblock endpoint onto the provided mux.
//
// The handler is a direct lift from the original startDebug() in cmd/cfm/main.go
// with zero behavioural changes:
//
//   - Accepts POST with query (?ip=1.2.3.4), JSON, form, or plain-text body
//   - Immediately removes the IP from nft and replies with JSON
//   - Fires a background goroutine for CSF / Fail2Ban / Imunify cleanup
//     (via unblock.Do) and writes the full step log to api.log
package apiserver

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/logging"
	"cfm/internal/unblock"
)

var unblockDo = unblock.Do

// RegisterUnblock adds the /unblock route to the provided mux.
func RegisterUnblock(m *http.ServeMux, be firewall.Backend, cfgDir string) {
	if m == nil {
		return
	}
	m.HandleFunc("/unblock", makeUnblockHandler(be, cfgDir))
}

// makeUnblockHandler returns the http.HandlerFunc for /unblock.
// Separated from RegisterUnblock so it can be unit-tested independently.
func makeUnblockHandler(be firewall.Backend, cfgDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "method not allowed",
			})
			return
		}

		// ── 1. Parse target IP ────────────────────────────────────────────
		ipStr := strings.TrimSpace(r.URL.Query().Get("ip"))

		if ipStr == "" {
			ct := strings.ToLower(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0])
			switch {

			case ct == "application/json":
				var tmp struct {
					IP string `json:"ip"`
				}
				_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&tmp)
				ipStr = strings.TrimSpace(tmp.IP)

			case ct == "application/x-www-form-urlencoded" ||
				strings.HasPrefix(ct, "multipart/form-data"):
				if err := r.ParseForm(); err == nil {
					ipStr = strings.TrimSpace(r.Form.Get("ip"))
					if ipStr == "" && len(r.Form) == 1 {
						// Support bare payload: curl -d "1.2.3.4" /unblock
						for k := range r.Form {
							ipStr = strings.TrimSpace(k)
							break
						}
					}
				}

			default:
				// text/plain or unknown: accept "1.2.3.4" or "1.2.3.4 # comment"
				b, _ := io.ReadAll(io.LimitReader(r.Body, 256))
				s := strings.TrimSpace(string(b))
				if i := strings.IndexAny(s, " \t#"); i > 0 {
					s = strings.TrimSpace(s[:i])
				}
				ipStr = s
			}
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    false,
				"error": "invalid or missing ip",
			})
			return
		}

		if be == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok":    false,
				"error": "no firewall backend",
			})
			return
		}
		engine := "unknown"
		if m, ok := be.(interface{ Engine() string }); ok {
			engine = m.Engine()
		}
		backendType := "<nil>"
		if t := reflect.TypeOf(be); t != nil {
			backendType = t.String()
		}

		// ── 2. Fast local path: remove from nft immediately ───────────────
		// Point-lookup instead of full set dump — O(1) vs O(n)
		wasBlocked := false
		if found, _ := be.HasElem("block_v4", ip.String()); found {
			wasBlocked = true
		} else if found, _ := be.HasElem("block_v6", ip.String()); found {
			wasBlocked = true
		}
		removeStart := time.Now()
		removeMethod := "RemoveBlock"
		logging.LogfAPI("[unblock.exec] engine=%s backend_type=%s batch_size=%d method=%s ip=%s", engine, backendType, 1, removeMethod, ip.String())
		_ = be.RemoveBlock(ip) // idempotent
		logging.LogfAPI("[unblock.exec.done] engine=%s backend_type=%s batch_size=%d method=%s ip=%s duration=%s", engine, backendType, 1, removeMethod, ip.String(), time.Since(removeStart))

		// ── 3. Capture requester identity for the audit log ───────────────
		requester := func() string {
			if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
				parts := strings.Split(xf, ",")
				return strings.TrimSpace(parts[0])
			}
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return r.RemoteAddr
			}
			return host
		}()

		// ── 4. Immediate JSON response ─────────────────────────────────────
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"ip":          ip.String(),
			"was_blocked": wasBlocked,
			"duration_ms": time.Since(start).Milliseconds(),
			"bg_cleanup":  true,
		})

		// ── 5. Fire-and-forget cleanup ─────────────────────────────────────
		go func(ip net.IP, requester string) {
			bgStart := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			ttl := 24 * time.Hour
			res, _ := unblockDo(ctx, ip, unblock.Options{
				BE:            be,
				ConfigDir:     cfgDir,
				TempWhitelist: true,
				AllowTTL:      &ttl,
				Reporter:      nil,
				ReportWhy:     "debug-endpoint",
				SendAPI:       false,
				Fail2BanUnban: true,
				// RemoveFromFeeds: true,
			})

			elapsed := time.Since(bgStart)
			logging.LogfAPI(
				"[unblock] requester=%s ip=%s took=%s was_blocked=%t from_feeds=%s whitelisted=%t steps=%d",
				requester, ip.String(), elapsed,
				res.WasBlocked, strings.Join(res.FromFeeds, ","),
				res.Whitelisted, len(res.Steps),
			)

			for _, s := range res.Steps {
				detail := s.Detail
				if len(detail) > 200 {
					detail = detail[:200] + "…"
				}
				logging.LogfAPI(
					"[unblock.step] ip=%s src=%s action=%s dur=%s feeds=%v err=%q detail=%q",
					ip.String(), s.Source, s.Action, s.Dur, s.Feeds, s.Err, detail,
				)
			}
		}(ip, requester)
	}
}
