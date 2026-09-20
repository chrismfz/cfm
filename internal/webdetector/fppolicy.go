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
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
	"cfm/internal/tlsfp"
)

// FingerprintPolicy is one armed enforcement policy as pulled from cfm-web.
// A zero ExpiresAt means "until disarmed" (permanent). Kind discriminates the
// target in ID (policy-kinds slice): "tls" (8-hex fingerprint id — the
// original grain, matched at the edge via /nginx/fppolicy), "country" (ISO-2,
// matched daemon-side on the per-IP decision path) or "asn" (AS number
// digits, likewise). An empty Kind reads as "tls" (older feed).
type FingerprintPolicy struct {
	ID        string
	Kind      string // "tls" (default) | "country" | "asn"
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
	mu        sync.RWMutex
	byID      map[string]FingerprintPolicy
	byCountry map[string]FingerprintPolicy // ISO-2 → challenge-tier policy
	byASN     map[uint64]FingerprintPolicy // AS number → challenge-tier policy
	enabled   bool
	allow     map[string]bool // ids never enforced (operator escape hatch)
	lastSet   time.Time
	lastSize  int
	// geoResolver maps an IP to (countryISO, asn) for the VERIFY-side v2
	// check (GeoPolicyActionForIP). Wired from the engine's enricher; nil
	// means geo policies simply can't influence verify (fail-open).
	geoResolver func(ip string) (string, uint64)
}

var fpPolicies = fpPolicyState{enabled: true}

// geoPolicyActions: the actions a country/asn policy may carry — CHALLENGE
// TIERS ONLY. cfm-web refuses a geo deny at arm time AND withholds it at
// serve time; this is the node's own third gate (doctrine: a whole country in
// 403 is the authoritarian failure mode — never enforceable here).
var geoPolicyActions = map[string]bool{
	"challenge":    true,
	"challenge_v2": true,
}

// SetFingerprintPolicies replaces the whole policy set (the pull is a full
// snapshot, mirroring the blocklist feeds — a disarmed policy disappears from
// the feed and therefore from here on the next pull). Unknown actions are
// dropped with a log line rather than stored: a newer cfm-web must not make an
// older node enforce something it does not understand.
func SetFingerprintPolicies(ps []FingerprintPolicy) {
	byID := make(map[string]FingerprintPolicy, len(ps))
	byCountry := map[string]FingerprintPolicy{}
	byASN := map[uint64]FingerprintPolicy{}
	dropped := 0
	for _, p := range ps {
		id := strings.ToLower(strings.TrimSpace(p.ID))
		if id == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(p.Kind)) {
		case "", "tls":
			if !fpPolicyActions[p.Action] {
				dropped++
				continue
			}
			byID[id] = FingerprintPolicy{ID: id, Kind: "tls", Action: p.Action, ExpiresAt: p.ExpiresAt}
		case "country":
			// Challenge tiers only (geoPolicyActions) — a deny here is a
			// doctrine violation upstream and is dropped, never enforced.
			cc := strings.ToUpper(id)
			if len(cc) != 2 || !geoPolicyActions[p.Action] {
				dropped++
				continue
			}
			byCountry[cc] = FingerprintPolicy{ID: cc, Kind: "country", Action: p.Action, ExpiresAt: p.ExpiresAt}
		case "asn":
			n, err := strconv.ParseUint(id, 10, 32)
			if err != nil || n == 0 || !geoPolicyActions[p.Action] {
				dropped++
				continue
			}
			byASN[n] = FingerprintPolicy{ID: id, Kind: "asn", Action: p.Action, ExpiresAt: p.ExpiresAt}
		default:
			// Unknown kind from a newer cfm-web: never enforce what this node
			// does not understand.
			dropped++
		}
	}

	total := len(byID) + len(byCountry) + len(byASN)
	fpPolicies.mu.Lock()
	changed := total != fpPolicies.lastSize
	fpPolicies.byID = byID
	fpPolicies.byCountry = byCountry
	fpPolicies.byASN = byASN
	fpPolicies.lastSet = time.Now()
	fpPolicies.lastSize = total
	fpPolicies.mu.Unlock()

	if dropped > 0 {
		logging.Logf("[fppolicy] dropped %d policies with unknown/ineligible kind or action (newer cfm-web, or a geo deny)", dropped)
	}
	if changed {
		logging.Logf("[fppolicy] policy set updated: %d armed (%d tls, %d country, %d asn)",
			total, len(byID), len(byCountry), len(byASN))
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

// SetFingerprintPolicyGeoResolver wires the IP→(countryISO, asn) resolver the
// VERIFY-side geo check uses (GeoPolicyActionForIP). Called once at engine
// start with the enricher's cached lookup; nil disables the verify-side check
// (fail-open — the decision-path floor still works from its own inputs).
func SetFingerprintPolicyGeoResolver(fn func(ip string) (string, uint64)) {
	fpPolicies.mu.Lock()
	fpPolicies.geoResolver = fn
	fpPolicies.mu.Unlock()
}

// geoPolicyLive re-checks expiry at lookup time (same contract as
// FingerprintPolicyForID: an expired policy stops biting between pulls).
// Caller holds at least RLock.
func geoPolicyLive(p FingerprintPolicy, ok bool) string {
	if !ok {
		return ""
	}
	if !p.ExpiresAt.IsZero() && !p.ExpiresAt.After(time.Now()) {
		return ""
	}
	return p.Action
}

// GeoPolicyAction returns the armed challenge-tier action for a request's
// country/ASN, or "". The country check is map-read cheap; asnFn is consulted
// ONLY when ASN policies exist and the country missed, so a fleet with no ASN
// policies pays nothing for the (potentially mmdb-backed) ASN resolution.
// Honours the FP_POLICY master knob like the fingerprint grain.
// PRECEDENCE: a country hit wins over an ASN hit — so with country=challenge
// AND asn=challenge_v2 both matching one client, the country's plain
// challenge is the answer and the Rung-1 verify gate does not bite. Arm the
// country itself at challenge_v2 if the teeth are wanted there.
func GeoPolicyAction(country string, asnFn func() uint64) string {
	fpPolicies.mu.RLock()
	defer fpPolicies.mu.RUnlock()
	if !fpPolicies.enabled || (len(fpPolicies.byCountry) == 0 && len(fpPolicies.byASN) == 0) {
		return ""
	}
	if country != "" {
		p, ok := fpPolicies.byCountry[strings.ToUpper(country)]
		if a := geoPolicyLive(p, ok); a != "" {
			return a
		}
	}
	if len(fpPolicies.byASN) > 0 && asnFn != nil {
		if n := asnFn(); n != 0 {
			p, ok := fpPolicies.byASN[n]
			if a := geoPolicyLive(p, ok); a != "" {
				return a
			}
		}
	}
	return ""
}

// GeoPolicyActionForIP resolves an IP's country/ASN via the wired resolver
// and returns the armed action (""). Verify-side use (the Rung-1 v2 gate on
// solves) — off the request hot path, so the resolver's cached-or-async
// lookup cost is fine.
func GeoPolicyActionForIP(ip string) string {
	fpPolicies.mu.RLock()
	resolver := fpPolicies.geoResolver
	empty := len(fpPolicies.byCountry) == 0 && len(fpPolicies.byASN) == 0
	fpPolicies.mu.RUnlock()
	if resolver == nil || empty || ip == "" {
		return ""
	}
	country, asn := resolver(ip)
	return GeoPolicyAction(country, func() uint64 { return asn })
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
