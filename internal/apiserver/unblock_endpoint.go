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
// Manual IP unblock is admin-only: it removes the IP from every blocking plane
// (nft, cfm.deny, csf, fail2ban, imunify360, OpenResty/Lua WAF), allows it in
// nft for 24h when a feed lists it and gives it a 1h imunify360 white grace
// entry (unblock.DoMany says when not). That is a host-wide state change with
// no per-vhost meaning, so a scoped (cPanel/DA) token must
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

		// ── 2. Capture requester identity for the audit log ───────────────
		// Done first, on the handler goroutine, since it reads the request.
		requester := realIPFromRequest(r)

		// ── 3. Bounded fast path ──────────────────────────────────────────
		// The nft check+remove and the WAF clear both run in goroutines under a
		// SINGLE response budget, well under cfm-web's ~1.2s node-call deadline.
		// Whatever finishes in time is folded into the response; whatever doesn't
		// is completed by the fire-and-forget cleanup below.
		//
		// This is the backend-agnostic fix for the incident where exec-engine nft
		// lock contention on a busy node stalled the synchronous HasElem/RemoveBlock
		// for several seconds, so cfm-web timed out and reported a healthy node
		// "unreachable" even though the unblock had actually succeeded. It is safe
		// to abandon the nft work early because unblock.Do in the cleanup goroutine
		// ALSO calls be.RemoveBlock(ip) (idempotent) — a slow backend can never
		// leave the IP blocked, it only defers the removal by a moment.
		const fastPathBudget = 800 * time.Millisecond
		budget := time.NewTimer(fastPathBudget)
		defer budget.Stop()

		// nft: point-lookup (O(1)) whether it was blocked, then remove.
		nftDone := make(chan bool, 1) // carries wasBlocked
		go func() {
			wb := false
			if found, _ := be.HasElem("block_v4", ip.String()); found {
				wb = true
			} else if found, _ := be.HasElem("block_v6", ip.String()); found {
				wb = true
			}
			rs := time.Now()
			logging.LogfAPI("[unblock.exec] engine=%s backend_type=%s batch_size=%d method=RemoveBlock ip=%s", engine, backendType, 1, ip.String())
			_ = be.RemoveBlock(ip) // idempotent
			logging.LogfAPI("[unblock.exec.done] engine=%s backend_type=%s batch_size=%d method=RemoveBlock ip=%s duration=%s", engine, backendType, 1, ip.String(), time.Since(rs))
			nftDone <- wb
		}()

		// WAF planes (OpenResty/Lua): clear the per-IP enforcement state
		// (challenge/block + shared-dict throttle/decision caches). These live
		// outside the firewall/blocklist, so without this a user can stay stuck
		// behind a challenge/throttle while every blocklist search comes back
		// empty. The clear always runs to completion in its own goroutine (the
		// buffered channel means it never blocks even if we stop waiting); the
		// findings double as the "was this IP actually being enforced, and why".
		var wafCh chan unblock.WAFResult // nil when no WAF cleaner is registered
		if c := unblock.WAFCleanerHook(); c != nil {
			wafCh = make(chan unblock.WAFResult, 1)
			go func() { wafCh <- c.ForceUnblock(ip.String()) }()
		}

		// Collect whatever completes before the shared budget expires.
		//
		// "Still waiting" is tracked with plain bools, NOT by nil-ing the channel
		// variables. The goroutines above close over nftDone/wafCh and perform
		// their final send on them; if we set the variable to nil, that send would
		// become `nil <- x`, which blocks forever (goroutine leak) AND races the
		// write. Leaving the variables stable means an abandoned send lands in the
		// cap-1 buffer harmlessly. A receive from a nil channel in a select is
		// simply never-ready, so a nil wafCh (no hook) needs no special-casing.
		var (
			wasBlocked  bool
			nftComplete bool
			wafResult   *unblock.WAFResult
		)
		nftPending := true
		wafPending := wafCh != nil
		for nftPending || wafPending {
			select {
			case wb := <-nftDone:
				wasBlocked, nftComplete, nftPending = wb, true, false
			case wr := <-wafCh:
				w := wr
				wafResult, wafPending = &w, false
				logging.LogfAPI("[unblock.waf] ip=%s found=%t cleared=%q err=%q", ip.String(), w.Found, w.Summary(), w.Err)
			case <-budget.C:
				logging.LogfAPI("[unblock.fastpath] ip=%s budget %s exhausted; responding now, background cleanup finishes the rest", ip.String(), fastPathBudget)
				nftPending, wafPending = false, false // stop waiting; goroutines run to completion, sending into their buffered channels
			}
		}

		// ── 4. Immediate JSON response ─────────────────────────────────────
		// fastpath_done=false means the nft check/remove was still running at the
		// budget, so was_blocked/waf aren't authoritative yet — the cleanup
		// goroutine below still guarantees the removal.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":            true,
			"ip":            ip.String(),
			"hostname":      localNodeID(),
			"was_blocked":   wasBlocked,
			"waf":           wafResult,
			"duration_ms":   time.Since(start).Milliseconds(),
			"bg_cleanup":    true,
			"fastpath_done": nftComplete,
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
