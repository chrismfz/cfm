package agent

import (
	"context"
	"net"
	"strings"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/locate"
	"cfm/internal/logging"
	"cfm/internal/unblock"
)

// ProcessUnblocks unblocks a batch of pending requests — one unblock.DoMany
// for all their IPs (nft, cfm.deny, csf, fail2ban, imunify, feeds allow, WAF
// planes) — then confirms each request to the API, success=true always so the
// queue never sticks. found holds each request's pre-removal locate result
// (where & why), keyed by request ID; it rides back on the confirm so cfm-web
// can aggregate fleet-wide findings. cfgDir, when set, has cfm.deny cleaned
// too (best-effort).
func (c *APIClient) ProcessUnblocks(ctx context.Context, be firewall.Backend, cfgDir string, reqs []PendingUnblock, found map[int]*locate.Result) {
	var ips []net.IP
	for _, it := range reqs {
		if ip := net.ParseIP(it.IP); ip != nil {
			ips = append(ips, ip)
		}
	}

	var results map[string]*unblock.Result
	if be == nil {
		logging.LogfAPI("[unblock] no backend available for %d IPs", len(ips))
	} else if len(ips) > 0 {
		ttl := 4 * time.Hour  // covers max feed sync interval
		whiteTTL := time.Hour // imunify grace window, mirrors cfm-web's 1h greylist
		start := time.Now()
		results = unblock.DoMany(ctx, ips, unblock.Options{
			BE:              be,
			ConfigDir:       cfgDir,
			TempWhitelist:   true, // whitelist override if from feeds
			AllowTTL:        &ttl,
			Reporter:        c, // θα στείλει reason "feeds:..." ή "manual"
			ReportWhy:       "agent",
			SendAPI:         false,
			ImunifyWhiteTTL: &whiteTTL,
			WAF:             unblock.WAFCleanerHook(), // clear OpenResty/Lua WAF planes too (nil in DNAT mode)
		})
		logging.LogfAPI("[unblock] unblocked %d IPs in %s", len(ips), time.Since(start).Round(time.Millisecond))
	}

	for _, it := range reqs {
		var res *unblock.Result
		if ip := net.ParseIP(it.IP); ip == nil {
			logging.LogfAPI("[unblock] invalid IP in request id=%d ip=%q", it.ID, it.IP)
		} else if results != nil {
			res = results[ip.String()]
		}
		c.confirmUnblock(it.ID, it.IP, found[it.ID], res)
	}
}

// confirmUnblock logs the unblock's steps, folds its WAF-plane findings into
// the request's locate result and confirms the request to the API.
func (c *APIClient) confirmUnblock(id int, ipStr string, found *locate.Result, res *unblock.Result) {
	if res != nil {
		for _, s := range res.Steps {
			if s.Err != "" {
				logging.LogfAPI("[unblock] %s %-9s via %-10s ERR=%s %s", ipStr, s.Action, s.Source, s.Err, strings.TrimSpace(s.Detail))
			} else {
				logging.LogfAPI("[unblock] %s %-9s via %-10s %s", ipStr, s.Action, s.Source, strings.TrimSpace(s.Detail))
			}
		}

		// Fold any WAF-plane findings into the locate result so they ride back
		// on the unblock-confirm call. This is how the OpenResty/Lua enforcement
		// planes (challenge/block/throttle) surface in cfm-web's fleet-wide
		// "Found On (where & why)" summary — they never appear in a blocklist
		// search. Each Location carries an Action (ALLOW/BLOCK/CHALLENGE/MATCH)
		// so cfm-web can label it correctly rather than assuming every finding
		// is a block.
		if res.WAF != nil && len(res.WAF.Cleared) > 0 {
			if found == nil {
				found = &locate.Result{Query: ipStr}
			}
			for _, f := range res.WAF.Cleared {
				action := locate.ActionMatch
				switch f.Plane {
				case "block":
					action = locate.ActionBlock
				case "challenge":
					action = locate.ActionChallenge
				}
				found.Locations = append(found.Locations, locate.Location{
					Source: string(unblock.SrcWAF),
					List:   f.Plane,
					Action: action,
					Match:  ipStr,
					Reason: f.Detail,
				})
			}
		}
	}

	// Confirm back to API (always success=true, to avoid stuck queue)
	logging.LogfAPI("[unblock] Confirming unblock to API id=%d ip=%s ...", id, ipStr)
	if err := c.ConfirmUnblock(id, ipStr, true, found); err != nil {
		logging.LogfAPI("[api] unblock-confirm FAILED id=%d ip=%s: %v", id, ipStr, err)
		return
	}
	logging.LogfAPI("[api] unblock-confirm OK id=%d ip=%s", id, ipStr)
}
