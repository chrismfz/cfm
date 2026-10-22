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
//   - stops its web okState from answering (handleDecision skips the
//     solved-ok check for a revoked IP; deleting it scanned all of okState
//     under the write lock for every newly revoked IP), and refuses a web
//     ok-touch for it while the revocation lives;
//   - lists the IP on GET /nginx/clearance/revoked, which the edge polls
//     every few seconds (cfm_clearance.lua revoke_tick) into its decisions
//     dict. cfm.lua Step 1 does not honour a clearance cookie for a listed
//     IP, so the request takes the decision path and gets the challenge.
//
// The revocation lives as long as the challenge (it is extended with it,
// and with the v2-reject hold: up to an hour after the last reject) and
// ends with it: a solve (ClearIPScoped, the web-scope solve's release), an
// /nginx/ip/clear and a force unblock remove it. After a solve the client's
// new cookie is honoured again once the edge's next poll drops the IP; until
// then the decision path answers allow (the solve cleared the challenge) —
// and under a vhost-wide challenge that request is sent through the
// challenge page once more, which waves the now unrevoked cookie back to
// next (one extra round trip, accepted).
// Per IP, like the challenge: the cookie is per host, the challenge is not.
//
// The challenge page (challenge_server.go) does not count a revoked web
// cookie as cleared, and every full decision answers "clrrv" (0/1) so an edge
// still listing a solved client drops its copy on the spot. Web scope only:
// panel okState and panel touches are untouched (the malpath challenge is
// web-only). A config reload builds a new bridge with an empty list and a new
// epoch (newClearanceRevokeEpoch), like the rest of the bridge state; the
// v2-reject holds are restored on it (RestoreMalpathHolds) with their
// revocations, a plain malpath challenge is not (no per-IP challenge is).
// All of it is in memory: a daemon restart (`systemctl reload cfm` is one)
// drops the list, the holds and the marks, failing open.
//
// Residuals (HONEST LIMITS in challenge_v2.go): the edge learns of a
// revocation on its next poll (~5 s, plus the log-driven detector's own lag),
// and a challenge that expires unsolved ends the revocation with it — the
// cookie works again after CHALLENGE_PATHS_TTL (a client that fails a verify
// gets the hour-long hold of challenge_v2_paths_ban.go).

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

// newClearanceRevokeEpoch names one bridge's list (NewNginxBridge): a
// restart AND a config reload (a new Engine builds a new bridge, with an
// empty list and its version back at 0) start a new epoch, so an edge
// holding version N of the old list never matches N of the new one.
var clearanceRevokeEpochSeq atomic.Uint64

func newClearanceRevokeEpoch() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36) + "." + strconv.FormatUint(clearanceRevokeEpochSeq.Add(1), 36)
}

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
				delete(b.clrPublished, k)
			}
		}
		if len(b.clrRevoked) >= clearanceRevokeMax {
			return
		}
	}
	wasLive := had && cur.After(now)
	if !wasLive || until.After(cur) {
		b.clrRevoked[ip] = until
		// The edge list carries seconds left, so an extension changes
		// nothing it acts on until the time it was last told nears: only a
		// new entry, or one more than a minute past what the edge was last
		// sent, makes every edge refetch the list (every reject of a held
		// client extends it). Compared with the last PUBLISHED until, not
		// the last extension, or extensions under a minute added up unseen.
		if b.clrPublished == nil {
			b.clrPublished = make(map[string]time.Time)
		}
		if pub, ok := b.clrPublished[ip]; !wasLive || !ok || until.Sub(pub) > time.Minute {
			b.clrRevokeVer++
			b.clrPublished[ip] = until
		}
	}
	// okState is not scanned here (O(okState) under the write lock, once per
	// newly revoked IP — a botnet sweep is thousands): handleDecision skips
	// it for a revoked IP, and no touch writes it while the revocation lives.
}

// unrevokeClearanceLocked ends ip's revocation. Caller holds b.mu.
func (b *NginxBridge) unrevokeClearanceLocked(ip string) {
	delete(b.clrPublished, ip)
	if _, ok := b.clrRevoked[ip]; ok {
		delete(b.clrRevoked, ip)
		b.clrRevokeVer++
	}
}

// clearanceRevokedLocked reports whether ip's (web) clearance is revoked
// now. Caller holds b.mu (read or write).
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
	ver := b.clrRevokeEpoch + ":" + strconv.FormatUint(b.clrRevokeVer, 10)
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
