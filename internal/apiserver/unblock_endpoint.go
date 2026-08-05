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
	"cfm/internal/locate"
	"cfm/internal/logging"
	"cfm/internal/unblock"
)

var unblockDo = unblock.Do

// RegisterUnblock adds the /unblock route to the provided mux.
//
// Manual IP unblock is admin-only: it removes a global nft block AND lays down
// a 24h allow-whitelist for the IP across every enforcement plane (nft,
// cfm.deny, csf, fail2ban, imunify, OpenResty/Lua WAF). That is a host-wide
// state change with no per-vhost meaning, so a scoped (cPanel/DA) token must
// never reach it — otherwise a tenant could unblock and whitelist any IP on
// the box. Guard it like /api/v1/firewall/block and the other global routes
// rather than relying on the caller to hold the admin token by convention.
func RegisterUnblock(m *http.ServeMux, be firewall.Backend, cfgDir string) {
	if m == nil {
		return
	}
	m.Handle("/unblock", adminOnlyHandler(makeUnblockHandler(be, cfgDir)))
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

		// ── 3a. WAF planes (OpenResty/Lua) ────────────────────────────────
		// Clear the per-IP WAF enforcement state (challenge/block + shared-dict
		// throttle/decision caches) on this node. These live outside the
		// firewall/blocklist, so without this a user can stay stuck behind a
		// challenge/throttle while every blocklist search comes back empty.
		//
		// The clear always runs to completion in its own goroutine; we wait up
		// to a tight budget to fold the findings into this response (the
		// caller — cfm-web — has its own ~1.2s deadline). The findings double
		// as the "was this IP actually being enforced, and why" signal.
		var wafResult *unblock.WAFResult
		if c := unblock.WAFCleanerHook(); c != nil {
			done := make(chan unblock.WAFResult, 1)
			go func() { done <- c.ForceUnblock(ip.String()) }()
			select {
			case wr := <-done:
				wafResult = &wr
				logging.LogfAPI("[unblock.waf] ip=%s found=%t cleared=%q err=%q",
					ip.String(), wr.Found, wr.Summary(), wr.Err)
			case <-time.After(700 * time.Millisecond):
				logging.LogfAPI("[unblock.waf] ip=%s clear still running after 700ms; responding without findings", ip.String())
			}
		}

		// ── 4. Immediate JSON response ─────────────────────────────────────
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"ip":          ip.String(),
			"hostname":    localNodeID(),
			"was_blocked": wasBlocked,
			"waf":         wafResult,
			"duration_ms": time.Since(start).Milliseconds(),
			"bg_cleanup":  true,
		})

		// ── 5. Fire-and-forget cleanup ─────────────────────────────────────
		go func(ip net.IP, requester string, wasBlocked bool) {
			bgStart := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Where-&-why search before the cross-layer cleanup. The nft
			// entry was already removed in the fast path above, so when
			// wasBlocked we reinstate it in the report synthetically.
			lctx, lcancel := context.WithTimeout(ctx, 10*time.Second)
			locRes, lerr := locateFind(lctx, ip.String(), locate.Options{BE: be, ConfigDir: cfgDir})
			lcancel()
			if lerr == nil && locRes != nil {
				if wasBlocked {
					set := "block_v4"
					if ip.To4() == nil {
						set = "block_v6"
					}
					locRes.Locations = append([]locate.Location{
						{Source: "nft", List: set, Action: locate.ActionBlock, Match: ip.String()},
					}, locRes.Locations...)
				}
				for _, l := range locRes.Locations {
					logging.LogfAPI("[unblock.found] ip=%s source=%s list=%s action=%s match=%s reason=%q",
						ip.String(), l.Source, l.List, l.Action, l.Match, l.Reason)
				}
			}

			ttl := 24 * time.Hour
			whiteTTL := time.Hour // imunify grace window, mirrors cfm-web's 1h greylist
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
				ImunifyWhiteTTL: &whiteTTL,
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
		}(ip, requester, wasBlocked)
	}
}
