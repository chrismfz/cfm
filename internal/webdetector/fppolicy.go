package webdetector

// Fingerprint-policy enforcement (master plan E3, node slice — Phase C).
//
// cfm-web is the fleet's fingerprint-reputation store; an operator arms a
// per-fingerprint action there (challenge / challenge_v2 / deny) and the node
// pulls the ACTIVE, serve-time-gated list from
// GET /api/fingerprint-policies/fetch (internal/agent, the same Token-authed
// channel as the heartbeat). This file is the node-side half:
//
//   - a package-level replace-all store of the pulled policies (package-level
//     like the solverfarm marks, so it survives an engine reload), keyed by the
//     8-hex fingerprint id cfm-web uses (internal/tlsfp.Print.ID);
//   - the bridge lookup the edge calls per request (GET /nginx/fppolicy —
//     handleFpPolicy in this file): the edge sends the RAW handshake tuple it
//     stamped (cfm_tlsfp.value()), the daemon parses it with internal/tlsfp —
//     the ONLY place the id hash lives, so edge and store can never disagree —
//     and answers with the armed action. The edge caches the answer in a
//     shared dict (configs/lua/cfm_fppolicy.lua), so a lookup RPC happens once
//     per distinct fingerprint per cache TTL, not per request.
//
// Enforcement semantics (edge side, cfm.lua):
//   - deny         → 403 BEFORE the clearance fast-path (a solved farm client
//                    is still denied; the fp rides every request's handshake).
//   - challenge /
//     challenge_v2 → a challenge FLOOR: an uncleared client is challenged as if
//                    the vhost were challenge-armed; valid clearance still
//                    passes (the floor is satisfied by solving). challenge_v2
//                    behaves as challenge until the Rung-1 engine ships — the
//                    stored intent is preserved, only the rung is capped.
//
// Guardrails: FP_POLICY=0 ([webdetector]) disarms lookups node-wide (the
// store keeps pulling, answers go empty); FP_POLICY_ALLOW_FPS exempts ids
// (operator escape hatch, like the solver-farm ALLOW_FPS); expires_at is
// honoured HERE at lookup time, so an expired policy stops biting between
// pulls; unknown actions from a newer cfm-web are dropped at set time
// (fail-safe on mixed versions).

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
	"cfm/internal/tlsfp"
)

// FingerprintPolicy is one armed enforcement policy as pulled from cfm-web.
// A zero ExpiresAt means "until disarmed" (permanent).
type FingerprintPolicy struct {
	ID        string
	Action    string // "deny" | "challenge" | "challenge_v2"
	ExpiresAt time.Time
}

// fpPolicyEdgeCacheTTL is what the lookup response tells the edge to cache
// the answer for (seconds). Policy changes (arm/disarm centrally) propagate in
// at most pull-interval + this TTL — keep it small; the lookup is a local
// unix-socket call amortised per distinct fingerprint.
const fpPolicyEdgeCacheTTL = 30

var fpPolicyActions = map[string]bool{
	"deny":         true,
	"challenge":    true,
	"challenge_v2": true,
}

type fpPolicyState struct {
	mu       sync.RWMutex
	byID     map[string]FingerprintPolicy
	enabled  bool
	allow    map[string]bool // ids never enforced (operator escape hatch)
	lastSet  time.Time
	lastSize int
}

var fpPolicies = fpPolicyState{enabled: true}

// SetFingerprintPolicies replaces the whole policy set (the pull is a full
// snapshot, mirroring the blocklist feeds — a disarmed policy disappears from
// the feed and therefore from here on the next pull). Unknown actions are
// dropped with a log line rather than stored: a newer cfm-web must not make an
// older node enforce something it does not understand.
func SetFingerprintPolicies(ps []FingerprintPolicy) {
	byID := make(map[string]FingerprintPolicy, len(ps))
	dropped := 0
	for _, p := range ps {
		id := strings.ToLower(strings.TrimSpace(p.ID))
		if id == "" {
			continue
		}
		if !fpPolicyActions[p.Action] {
			dropped++
			continue
		}
		byID[id] = FingerprintPolicy{ID: id, Action: p.Action, ExpiresAt: p.ExpiresAt}
	}

	fpPolicies.mu.Lock()
	changed := len(byID) != fpPolicies.lastSize
	fpPolicies.byID = byID
	fpPolicies.lastSet = time.Now()
	fpPolicies.lastSize = len(byID)
	fpPolicies.mu.Unlock()

	if dropped > 0 {
		logging.Logf("[fppolicy] dropped %d policies with unknown action (newer cfm-web?)", dropped)
	}
	if changed {
		logging.Logf("[fppolicy] policy set updated: %d armed fingerprints", len(byID))
	}
}

// ConfigureFingerprintPolicyEnforcement applies the [webdetector] knobs
// (FP_POLICY master, FP_POLICY_ALLOW_FPS exemptions). Called on every
// detectors reload; ids are matched case-insensitively.
func ConfigureFingerprintPolicyEnforcement(enabled bool, allowIDs []string) {
	allow := make(map[string]bool, len(allowIDs))
	for _, id := range allowIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			allow[id] = true
		}
	}
	fpPolicies.mu.Lock()
	fpPolicies.enabled = enabled
	fpPolicies.allow = allow
	fpPolicies.mu.Unlock()
}

// FingerprintPolicyForID returns the armed action for a fingerprint id, or ""
// when nothing is armed, the policy expired, the id is operator-exempt, or
// enforcement is disabled. Cheap (one RLock + map read) — hot-path safe.
func FingerprintPolicyForID(id string) string {
	if id == "" {
		return ""
	}
	id = strings.ToLower(id)

	fpPolicies.mu.RLock()
	defer fpPolicies.mu.RUnlock()
	if !fpPolicies.enabled || fpPolicies.allow[id] {
		return ""
	}
	p, ok := fpPolicies.byID[id]
	if !ok {
		return ""
	}
	if !p.ExpiresAt.IsZero() && !p.ExpiresAt.After(time.Now()) {
		return ""
	}
	return p.Action
}

// handleFpPolicy answers the edge's per-fingerprint lookup:
//
//	GET /nginx/fppolicy?fp=<escaped raw cfm_tlsfp tuple>
//	→ {"action":"deny"|"challenge"|"challenge_v2"|"", "id":"<8hex>", "ttl":30}
//
// The tuple→id parse is internal/tlsfp — the single source of the hash. An
// absent/unparseable fp answers action:"" (fail-open: no fingerprint, no
// policy), never an error the edge would have to special-case.
func (b *NginxBridge) handleFpPolicy(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	action, id := "", ""
	if fp, ok := tlsfp.Parse(r.URL.Query().Get("fp")); ok && fp.ID != "" {
		id = fp.ID
		action = FingerprintPolicyForID(fp.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"action": action,
		"id":     id,
		"ttl":    fpPolicyEdgeCacheTTL,
	})
}
