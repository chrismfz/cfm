package webdetector

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ── Clearance revocation (a malpath challenge on a cleared client) ──────────
//
// cfm_clearance is a stateless HMAC cookie: the edge honours it at cfm.lua
// Step 2b before it asks the bridge anything, so a per-IP challenge imposed
// AFTER a client solved never reached it. A scanner that solved once (or
// solved at v1 before the malpath challenge ran at v2) kept fetching /.env,
// backups and webshell names with its cookie for as long as the cookie
// lived, and the daemon's solved-ok state (okState) answered "allow" for it
// on the decision path too.
//
// A per-IP challenge whose reason revokes (clearanceRevokeArms: the malpath
// challenge, CHALLENGE_PATHS, while [webdetector] CHALLENGE_PATHS_REVOKE is
// on) therefore also:
//   - drops the IP's okState on every host, and refuses an ok-touch for it
//     while the revocation lives (a touch from a cookie the edge has not yet
//     learned to refuse would write it back);
//   - lists the IP on GET /nginx/clearance/revoked, which the edge polls
//     every few seconds (cfm_clearance.lua revoke_tick) into its decisions
//     dict. cfm.lua Step 1 does not honour a clearance cookie for a listed
//     IP, so the request takes the decision path and gets the challenge.
//
// The revocation lives as long as the challenge (it is extended with it) and
// ends with it: a solve (ClearIPScoped, the web-scope solve's release), an
// /nginx/ip/clear and a force unblock remove it. After a solve the client's
// new cookie is honoured again once the edge's next poll drops the IP; until
// then the decision path answers allow (the solve cleared the challenge).
// Per IP, like the challenge: the cookie is per host, the challenge is not.
//
// Residuals (HONEST LIMITS in challenge_v2.go): the edge learns of a
// revocation on its next poll (~5 s, plus the log-driven detector's own lag),
// and a challenge that expires unsolved ends the revocation with it — the
// cookie works again after CHALLENGE_PATHS_TTL (repeat offenders: the
// v2_reject escalation, not this).

// clearanceRevokeOn is [webdetector] CHALLENGE_PATHS_REVOKE (default on).
var clearanceRevokeOn atomic.Bool

func init() { clearanceRevokeOn.Store(true) }

// ConfigureClearanceRevoke applies [webdetector] CHALLENGE_PATHS_REVOKE
// (every reload). Off, a malpath challenge leaves an existing clearance
// alone (the old behaviour); revocations already recorded run out with
// their challenges.
func ConfigureClearanceRevoke(on bool) { clearanceRevokeOn.Store(on) }

// clearanceRevokeArms reports whether a per-IP bridge challenge with this
// reason revokes the IP's clearance.
func clearanceRevokeArms(reason string) bool {
	return reason == challengeV2PathsReason && clearanceRevokeOn.Load()
}

// clearanceRevokeMax caps the list (the edge writes one dict key per entry).
// A malpath challenge lives minutes; a node holds tens at a time. At the cap
// a new revocation is not recorded (fails toward the old behaviour).
const clearanceRevokeMax = 4096

// clearanceRevokeEpoch tells one daemon run's list versions from another's,
// so an edge holding version N from before a restart never matches N again.
var clearanceRevokeEpoch = strconv.FormatInt(time.Now().UnixNano(), 36)

// revokeClearanceLocked records (or extends) ip's revocation until `until`
// and drops its okState. Caller holds b.mu.
func (b *NginxBridge) revokeClearanceLocked(ip string, until, now time.Time) {
	if ip == "" {
		return
	}
	if b.clrRevoked == nil {
		b.clrRevoked = make(map[string]time.Time)
	}
	cur, had := b.clrRevoked[ip]
	if !had && len(b.clrRevoked) >= clearanceRevokeMax {
		for k, u := range b.clrRevoked {
			if !u.After(now) {
				delete(b.clrRevoked, k)
			}
		}
		if len(b.clrRevoked) >= clearanceRevokeMax {
			return
		}
	}
	if !had || until.After(cur) {
		b.clrRevoked[ip] = until
		b.clrRevokeVer++
	}
	for k := range b.okState {
		if k.IP == ip {
			delete(b.okState, k)
		}
	}
}

// unrevokeClearanceLocked ends ip's revocation. Caller holds b.mu.
func (b *NginxBridge) unrevokeClearanceLocked(ip string) {
	if _, ok := b.clrRevoked[ip]; ok {
		delete(b.clrRevoked, ip)
		b.clrRevokeVer++
	}
}

// clearanceRevokedLocked reports whether ip's clearance is revoked now.
// Caller holds b.mu (read or write).
func (b *NginxBridge) clearanceRevokedLocked(ip string, now time.Time) bool {
	u, ok := b.clrRevoked[ip]
	return ok && u.After(now)
}

// ClearanceRevoked reports whether ip's clearance is revoked now.
func (b *NginxBridge) ClearanceRevoked(ip string) bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.clearanceRevokedLocked(strings.TrimSpace(ip), time.Now())
}

// handleClearanceRevoked serves GET /nginx/clearance/revoked to the edge
// (cfm_clearance.lua revoke_tick).
//
//	?v=<version>   the version the edge holds
//
// Replies:
//
//	{"v":"<version>","same":true}                 nothing changed
//	{"v":"<version>","ips":{"203.0.113.5":540}}   the whole list, seconds left
//
// An entry that runs out with no write is dropped by its TTL at the edge.
func (b *NginxBridge) handleClearanceRevoked(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now()
	b.mu.RLock()
	ver := clearanceRevokeEpoch + ":" + strconv.FormatUint(b.clrRevokeVer, 10)
	out := map[string]any{"v": ver}
	if r.URL.Query().Get("v") == ver {
		out["same"] = true
	} else {
		ips := make(map[string]int, len(b.clrRevoked))
		for ip, u := range b.clrRevoked {
			if left := u.Sub(now); left > 0 {
				ips[ip] = int((left + time.Second - 1) / time.Second)
			}
		}
		out["ips"] = ips
	}
	b.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
