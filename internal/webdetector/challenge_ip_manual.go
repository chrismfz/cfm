package webdetector

// Manual per-IP challenge: the operator challenges a list of client IPs, not a
// whole vhost.
//
// Why: on titan (2026-11-24) a facet scraper on Greek residential IPs was the
// load, and the only operator lever was a manual challenge of the WHOLE
// vhost, which every shop visitor then saw (the shop owners' complaint). Its
// top 50 IPs made 98% of its origin pages. The Web Traffic page lists a
// client's top IPs (traffic_mix.go) and challenges exactly those.
//
// It is ChallengeIPWithReason, the same per-IP challenge the detectors set,
// plus a clearance revocation for its length (a client that already solved
// sees it too; a person re-solves once); a live challenge is only extended,
// never shortened, and keeps its own reason:
// anyone on such an address who can solve gets a clearance and passes (a solve
// releases the IP, ClearIPScoped), and with CHALLENGE_UNSOLVED_HOLD = enforce a
// client that loads the page again and again without solving is held. Never a
// ban (D1: residential addresses are never banned on a label). Admin-only: it
// acts across tenants.

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"cfm/internal/logging"
)

const (
	manualIPChallengeReason = "manual_ip"
	manualIPChallengeMax    = 500
	manualIPChallengeMinTTL = 5 * time.Minute
	manualIPChallengeMaxTTL = 24 * time.Hour
	manualIPChallengeDefTTL = time.Hour
)

type manualIPChallengeBody struct {
	IPs        []string `json:"ips"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
	Reason     string   `json:"reason,omitempty"`
}

type manualIPChallengeSkip struct {
	IP  string `json:"ip"`
	Why string `json:"why"`
}

type manualIPChallengeResult struct {
	Action string   `json:"action"`
	Done   []string `json:"done"` // newly challenged (add) or lifted (remove): what an undo reverses
	// Extended (add only): IPs that already had a shorter live challenge,
	// now extended. Not in Done: an undo must not lift a challenge the
	// operator did not set (a WAF or malpath one, with its holds and marks).
	Extended   []string                `json:"extended,omitempty"`
	Skipped    []manualIPChallengeSkip `json:"skipped,omitempty"`
	TTLSeconds int                     `json:"ttl_seconds,omitempty"`
}

// readManualIPChallenge decodes and validates the body (a list of IPs, at most
// manualIPChallengeMax, each a literal address). It writes the error itself.
func readManualIPChallenge(w http.ResponseWriter, r *http.Request) (manualIPChallengeBody, []string, []manualIPChallengeSkip, bool) {
	var body manualIPChallengeBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body: {\"ips\": [...], \"ttl_seconds\": n, \"reason\": \"...\"}"})
		return body, nil, nil, false
	}
	if len(body.IPs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ips: at least one IP"})
		return body, nil, nil, false
	}
	if len(body.IPs) > manualIPChallengeMax {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ips: at most 500 per call"})
		return body, nil, nil, false
	}
	var ok []string
	var skipped []manualIPChallengeSkip
	seen := map[string]bool{}
	for _, raw := range body.IPs {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			skipped = append(skipped, manualIPChallengeSkip{IP: truncateForLog(raw, 64), Why: "not an IP address"})
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		ok = append(ok, s)
	}
	return body, ok, skipped, true
}

// handleChallengeIPAdd serves POST /api/v1/challenge/ip/add
// {"ips": [...], "ttl_seconds": 3600, "reason": "..."}: a per-IP challenge on
// each (TTL 5m..24h, default 1h). An address the node never challenges
// (IGNORE_IPS / IGNORE_NETS) or that is blocked is skipped, with the reason.
func (e *Engine) handleChallengeIPAdd(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	b := e.nginxBridge
	if b == nil || !b.cfg.Enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the edge bridge is not enabled on this node"})
		return
	}
	body, ips, skipped, ok := readManualIPChallenge(w, r)
	if !ok {
		return
	}
	ttl := time.Duration(body.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = manualIPChallengeDefTTL
	}
	if ttl < manualIPChallengeMinTTL {
		ttl = manualIPChallengeMinTTL
	}
	if ttl > manualIPChallengeMaxTTL {
		ttl = manualIPChallengeMaxTTL
	}
	reason := strings.TrimSpace(body.Reason)
	now := time.Now()
	out := manualIPChallengeResult{Action: "challenge", Done: []string{}, Skipped: skipped, TTLSeconds: int(ttl / time.Second)}
	for _, ip := range ips {
		if b.bypassFunc != nil && b.bypassFunc(ip) {
			out.Skipped = append(out.Skipped, manualIPChallengeSkip{IP: ip, Why: "never challenged on this node (IGNORE_IPS / IGNORE_NETS)"})
			continue
		}
		b.mu.RLock()
		cur, live := b.ipState[ip]
		b.mu.RUnlock()
		live = live && cur.Expires.After(now)
		if live && cur.Action == "block" {
			out.Skipped = append(out.Skipped, manualIPChallengeSkip{IP: ip, Why: "blocked (a block is stronger than a challenge)"})
			continue
		}
		// Never shorten a live challenge, and keep what challenged it (its
		// reason and WAF rule: the solved hook and history read them): a
		// live one only ever gets extended, with no reason of ours.
		why := manualIPChallengeReason
		extended := false
		if live && cur.Action == "challenge" {
			if !cur.Expires.Before(now.Add(ttl)) {
				// Its challenge already outlasts ours; the operator still
				// wants a client that had solved to face it.
				b.mu.Lock()
				b.revokeClearanceLocked(ip, now.Add(ttl), now)
				b.mu.Unlock()
				out.Skipped = append(out.Skipped, manualIPChallengeSkip{IP: ip, Why: "already challenged until " + cur.Expires.UTC().Format(time.RFC3339) + "; clearance revoked for the chosen time"})
				continue
			}
			why, extended = "", true
		}
		b.ChallengeIPWithReason(ip, ttl, why)
		// The edge passes a valid clearance cookie before it asks the daemon
		// (cfm.lua Step 2b), so without this a client that already solved
		// (a solving farm) would never see the challenge. A person on the
		// address re-solves once; a solve or a remove lifts it (ClearIPScoped).
		b.mu.Lock()
		b.revokeClearanceLocked(ip, now.Add(ttl), now)
		b.mu.Unlock()
		if extended {
			out.Extended = append(out.Extended, ip)
		} else {
			out.Done = append(out.Done, ip)
		}
	}
	logging.LogfCHALLENGES("[challenge] manual_ip action=challenge ips=%d extended=%d skipped=%d ttl=%s reason=%q first=%s",
		len(out.Done), len(out.Extended), len(out.Skipped), ttl, truncateForLog(reason, 160), strings.Join(firstN(out.Done, 5), ","))
	writeJSON(w, http.StatusOK, out)
}

// handleChallengeIPRemove serves POST /api/v1/challenge/ip/remove
// {"ips": [...]}: lifts each IP's per-IP challenge (and its holds), as a solve
// would. A block is left alone.
func (e *Engine) handleChallengeIPRemove(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	b := e.nginxBridge
	if b == nil || !b.cfg.Enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the edge bridge is not enabled on this node"})
		return
	}
	body, ips, skipped, ok := readManualIPChallenge(w, r)
	if !ok {
		return
	}
	now := time.Now()
	out := manualIPChallengeResult{Action: "remove", Done: []string{}, Skipped: skipped}
	for _, ip := range ips {
		b.mu.RLock()
		cur, live := b.ipState[ip]
		b.mu.RUnlock()
		if !live || !cur.Expires.After(now) {
			out.Skipped = append(out.Skipped, manualIPChallengeSkip{IP: ip, Why: "no challenge on it"})
			continue
		}
		if cur.Action != "challenge" {
			out.Skipped = append(out.Skipped, manualIPChallengeSkip{IP: ip, Why: "blocked, not challenged (unblock it instead)"})
			continue
		}
		b.ClearIPScoped(ip, "", "web")
		out.Done = append(out.Done, ip)
	}
	logging.LogfCHALLENGES("[challenge] manual_ip action=remove ips=%d skipped=%d reason=%q first=%s",
		len(out.Done), len(out.Skipped), truncateForLog(strings.TrimSpace(body.Reason), 160), strings.Join(firstN(out.Done, 5), ","))
	writeJSON(w, http.StatusOK, out)
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
