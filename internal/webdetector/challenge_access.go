// internal/webdetector/challenge_access.go
//
// Challenge Access-Control — an operator allow-list that EXEMPTS matching
// requests from the interactive challenge (challenge → allow) and nothing else.
//
// Why this exists (and how it differs from its neighbours):
//   - IGNORE_IPS / IGNORE_NETS (internal/detectors/ignore.go) bypass EVERYTHING
//     — WAF, challenge and autoblock — for an IP/CIDR. Too broad for "let this
//     crawler reach the product feed but keep the WAF armed".
//   - webdetector_challenge_exclude.txt (internal/detectors/challenge_exclude.go)
//     is a file-only, FCrDNS-crawler-oriented list (ua/asn/ptr/host); no path,
//     no country, no per-tenant API.
//   - The dynamic exclude store (exclude_store.go) is HOST-only for the
//     challenge (a `path` entry there feeds the WAF, never the challenge).
//   - A traffic-rule `allow` is NOT a challenge bypass (see cfm.lua OR-guards):
//     it only ends rule evaluation. docs/traffic-rules-ux-proposal.md §3
//     deliberately routes challenge exemption HERE instead.
//
// So this is the surgical, multi-dimension, per-vhost, API-managed companion to
// the coarse per-vhost `challenge on/off` toggle. It matches on country / URL
// path / user-agent / IP-CIDR / ASN / verified-crawler, reusing the traffic-rule
// match grammar (normalizeMatch + ruleMatchFilters) so operators learn ONE
// grammar (CLAUDE.md §5). It is a FLAT allow-list: any enabled entry that
// matches exempts the request — no priorities, no shadowing.
//
// Enforcement lives in the edge decision hot path (nginx_bridge.go
// handleDecision), where a match downgrades a would-be challenge to allow —
// exactly like goodBotDowngrade, and, like it, it NEVER softens a block and
// leaves the WAF / traffic-rule engine untouched. Fail-open on enrichment: an
// unresolved country or ASN never matches, so a geo/enrich hiccup can neither
// grant nor deny an exemption.

package webdetector

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxChallengeAccessEntries = 500

// challengeAccessMatch reuses the whole traffic-rule match grammar (embedded)
// and adds ASN, a dimension traffic rules do not carry yet. Embedding inlines
// the shared JSON keys (country_in, ip_any, ua_any, path_any, methods,
// verified_bot, has_qs, qs_not_rx) alongside asn_in.
type challengeAccessMatch struct {
	TrafficRuleMatch
	// AsnIn matches when the client IP's origin ASN (from the enrich cache;
	// e.g. 15169 for Google) is one of these. Cache-only on the hot path: an
	// ASN the enricher has not resolved (0) never matches — the same fail-open
	// contract as country. ASN is BGP-derived (not client-spoofable) but broad
	// (clouds host attackers too), so pair it with a path/UA for safety.
	AsnIn []uint32 `json:"asn_in,omitempty"`
}

// ChallengeAccessEntry is one exemption. A flat allow-list entry: when it
// matches, the request is exempted from the challenge (never from the WAF or an
// IP block). Scope.Vhosts is the host dimension (required); Match carries the
// rest. Shape mirrors TrafficRule so the cfm-admin builder can be reused.
type ChallengeAccessEntry struct {
	ID        string               `json:"id"`
	Enabled   bool                 `json:"enabled"`
	Scope     TrafficRuleScope     `json:"scope"`
	Match     challengeAccessMatch `json:"match"`
	Note      string               `json:"note,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
	// Unsupported is an in-memory marker only: the stored entry carries match/
	// scope keys THIS build does not understand (written by a newer cfm). Such
	// an entry is NEVER enforced (dropping the unknown key would WIDEN the
	// exemption — a narrowing condition the newer cfm meant to apply would be
	// lost), cannot be edited or enabled here, and is written back to disk
	// verbatim so nothing is lost for the upgrade. Same contract as TrafficRule.
	Unsupported bool `json:"unsupported,omitempty"`
}

// ChallengeAccessInput is the per-request shape MatchExempt evaluates. The
// origin ASN is resolved lazily via a callback (see MatchExempt) so a cold-IP
// mmdb read happens only when a matching entry actually uses asn_in.
type ChallengeAccessInput struct {
	Host        string
	IP          string
	UA          string
	Path        string
	Method      string
	Country     string
	QueryString string
	// VerifiedBot is the FCrDNS good-bot name for the IP ("" = none). Unlike a
	// traffic-rule allow, a challenge exemption KEEPS the generic "google"
	// verdict (Translate/AMP/Feedfetcher proxies): they cannot solve a
	// challenge and exempting them is safe — see verifiedBotForRules' comment.
	VerifiedBot string
}

// ChallengeAccessSimInput is the /api/v1/challenge/access/simulate request: a
// request shape to test against the allow-list. Country/ASN are resolved from IP
// when left empty/0; verified_bot is resolved inline (FCrDNS) or accepted as an
// override ("treat as a verified crawler").
type ChallengeAccessSimInput struct {
	Host        string `json:"host"`
	IP          string `json:"ip,omitempty"`
	UA          string `json:"ua,omitempty"`
	Path        string `json:"path,omitempty"`
	Method      string `json:"method,omitempty"`
	Country     string `json:"country,omitempty"`
	QueryString string `json:"qs,omitempty"`
	ASN         uint32 `json:"asn,omitempty"`
	VerifiedBot string `json:"verified_bot,omitempty"`
}

// ChallengeAccessSimResult is the verdict: whether the request is exempted from
// the challenge, and by which entry. Country/ASN/VerifiedBot echo what the
// evaluation resolved (so the UI can show "we treated this IP as GR / AS15169 /
// googlebot"). VerifiedBotInconclusive says why an FCrDNS check did not complete.
type ChallengeAccessSimResult struct {
	Exempted                bool                  `json:"exempted"`
	Entry                   *ChallengeAccessEntry `json:"entry,omitempty"`
	Country                 string                `json:"country,omitempty"`
	ASN                     uint32                `json:"asn,omitempty"`
	VerifiedBot             string                `json:"verified_bot,omitempty"`
	VerifiedBotInconclusive string                `json:"verified_bot_inconclusive,omitempty"`
}

type challengeAccessStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]ChallengeAccessEntry // key=id
	// frozen holds the verbatim JSON of entries this build cannot fully decode
	// (unknown match/scope keys). They are persisted back byte-for-byte so a
	// downgrade never rewrites — and thereby widens — a newer entry.
	frozen map[string]json.RawMessage
	// enabledCount is the lock-free-ish fast-path gate: MatchExempt returns
	// immediately when zero, so the hot path costs one RLock + one int read
	// when no exemptions exist.
	enabledCount int
	// verifiedBotScopes lists the vhost scopes of ENABLED entries using
	// verified_bot, so the bridge spends a good-bot cache lookup only for a host
	// such an entry can apply to (same pattern as trafficRuleStore).
	verifiedBotScopes [][]string
}

func newChallengeAccessStore(path string) *challengeAccessStore {
	s := &challengeAccessStore{
		path:    strings.TrimSpace(path),
		entries: make(map[string]ChallengeAccessEntry),
		frozen:  make(map[string]json.RawMessage),
	}
	s.load()
	return s
}

// recountLocked refreshes derived indexes after a mutation (caller holds mu).
func (s *challengeAccessStore) recountLocked() {
	scopes := make([][]string, 0, 4)
	n := 0
	for _, e := range s.entries {
		if !e.Enabled {
			continue
		}
		n++
		if e.Match.VerifiedBot {
			scopes = append(scopes, e.Scope.Vhosts)
		}
	}
	s.enabledCount = n
	s.verifiedBotScopes = scopes
}

func (s *challengeAccessStore) Add(in ChallengeAccessEntry) (ChallengeAccessEntry, error) {
	in.Unsupported = false // in-memory marker only; never client-settable
	norm, err := normalizeChallengeAccess(in, true)
	if err != nil {
		return ChallengeAccessEntry{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Frozen (newer-cfm) entries the operator cannot edit here must not count
	// toward the cap, or a downgrade full of unsupported entries would lock the
	// operator out of adding any working exemption.
	if len(s.entries)-len(s.frozen) >= maxChallengeAccessEntries {
		return ChallengeAccessEntry{}, fmt.Errorf("too many challenge-access entries (max %d)", maxChallengeAccessEntries)
	}
	if _, exists := s.entries[norm.ID]; exists {
		return ChallengeAccessEntry{}, errors.New("entry id already exists")
	}
	s.entries[norm.ID] = norm
	s.recountLocked()
	if err := s.saveLocked(); err != nil {
		return ChallengeAccessEntry{}, err
	}
	return norm, nil
}

func (s *challengeAccessStore) Update(id string, in ChallengeAccessEntry) (ChallengeAccessEntry, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return ChallengeAccessEntry{}, errors.New("id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.entries[id]
	if !ok {
		return ChallengeAccessEntry{}, errors.New("entry not found")
	}
	if cur.Unsupported {
		return ChallengeAccessEntry{}, errors.New("entry uses match fields this cfm build does not understand; upgrade cfm to edit or enable it")
	}
	in.Unsupported = false
	in.ID = id
	if in.CreatedAt.IsZero() {
		in.CreatedAt = cur.CreatedAt
	}
	norm, err := normalizeChallengeAccess(in, false)
	if err != nil {
		return ChallengeAccessEntry{}, err
	}
	s.entries[id] = norm
	s.recountLocked()
	if err := s.saveLocked(); err != nil {
		return ChallengeAccessEntry{}, err
	}
	return norm, nil
}

func (s *challengeAccessStore) Remove(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[id]; !ok {
		return false
	}
	delete(s.entries, id)
	delete(s.frozen, id)
	s.recountLocked()
	_ = s.saveLocked()
	return true
}

func (s *challengeAccessStore) Get(id string) (ChallengeAccessEntry, bool) {
	id = strings.TrimSpace(id)
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[id]
	return e, ok
}

func (s *challengeAccessStore) List() []ChallengeAccessEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ChallengeAccessEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		// Group by vhost scope, then by id — stable, UI-friendly ordering.
		si := strings.Join(out[i].Scope.Vhosts, ",")
		sj := strings.Join(out[j].Scope.Vhosts, ",")
		if si != sj {
			return si < sj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// NeedsVerifiedBotFor reports whether an ENABLED entry using verified_bot is
// scoped to host — the bridge's per-decision gate so a good-bot cache lookup is
// spent only when an entry for THIS host can use it.
func (s *challengeAccessStore) NeedsVerifiedBotFor(host string) bool {
	if s == nil {
		return false
	}
	host = normalizeControlHost(host)
	if host == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, vhosts := range s.verifiedBotScopes {
		if ruleHostMatch(vhosts, host) {
			return true
		}
	}
	return false
}

// MatchExempt reports whether any ENABLED entry exempts this request from the
// challenge (the bridge hot-path caller). See matchExemptEntry for the asnFn
// contract.
func (s *challengeAccessStore) MatchExempt(in ChallengeAccessInput, asnFn func() uint32) bool {
	_, ok := s.matchExemptEntry(in, asnFn)
	return ok
}

// matchExemptEntry returns the first ENABLED entry that exempts this request
// from the challenge (the simulate API wants the winning entry, not just a
// bool). Fast-paths on the enabled-count gate. asnFn lazily resolves the
// client's origin ASN and is invoked (at most once, memoized) ONLY when a
// candidate entry uses asn_in, so a cold-IP mmdb read is spent only when it can
// change the outcome; nil asnFn (or a 0 return) means "unresolved" and never
// matches an asn_in entry (fail-open).
func (s *challengeAccessStore) matchExemptEntry(in ChallengeAccessInput, asnFn func() uint32) (ChallengeAccessEntry, bool) {
	if s == nil {
		return ChallengeAccessEntry{}, false
	}
	host := normalizeControlHost(in.Host)
	if host == "" {
		return ChallengeAccessEntry{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.enabledCount == 0 {
		return ChallengeAccessEntry{}, false
	}

	path := strings.TrimSpace(in.Path)
	if path != "" && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	ua := strings.ToLower(strings.TrimSpace(in.UA))
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	country := strings.ToUpper(strings.TrimSpace(in.Country))
	ipAddr, ipErr := netip.ParseAddr(strings.Trim(strings.TrimSpace(in.IP), "[]"))
	ipOK := ipErr == nil
	if ipOK {
		ipAddr = ipAddr.Unmap()
	}
	// A challenge exemption keeps the generic "google" verdict (unlike a rule
	// allow): trim/lower only, do NOT run verifiedBotForRules.
	verifiedBot := strings.ToLower(strings.TrimSpace(in.VerifiedBot))

	asnResolved := false
	var asn uint32
	getASN := func() uint32 {
		if !asnResolved {
			if asnFn != nil {
				asn = asnFn()
			}
			asnResolved = true
		}
		return asn
	}

	for _, e := range s.entries {
		if !e.Enabled || e.Unsupported {
			continue // Unsupported entries are always disabled; belt-and-suspenders
		}
		if !ruleHostMatch(e.Scope.Vhosts, host) {
			continue
		}
		if len(e.Match.AsnIn) > 0 {
			reqASN := getASN()
			if reqASN == 0 {
				continue // fail-open: unresolved ASN never matches
			}
			hit := false
			for _, a := range e.Match.AsnIn {
				if a == reqASN {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		if !ruleMatchFilters(e.Match.TrafficRuleMatch, ipAddr, ipOK, country, ua, path, method, in.QueryString, verifiedBot) {
			continue
		}
		return e, true
	}
	return ChallengeAccessEntry{}, false
}

func normalizeChallengeAccess(in ChallengeAccessEntry, generateID bool) (ChallengeAccessEntry, error) {
	now := time.Now().UTC()
	r := in

	if generateID && strings.TrimSpace(r.ID) == "" {
		r.ID = newChallengeAccessID()
	}
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		return ChallengeAccessEntry{}, errors.New("id is required")
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	if strings.TrimSpace(r.Note) != "" {
		r.Note = strings.TrimSpace(r.Note)
		if len(r.Note) > maxRuleNoteLen {
			return ChallengeAccessEntry{}, fmt.Errorf("note too long (max %d)", maxRuleNoteLen)
		}
	}

	scope, err := normalizeScopeVhosts(r.Scope)
	if err != nil {
		return ChallengeAccessEntry{}, err
	}
	r.Scope = scope

	m, err := normalizeMatch(r.Match.TrafficRuleMatch)
	if err != nil {
		return ChallengeAccessEntry{}, err
	}
	r.Match.TrafficRuleMatch = m

	asns, err := normalizeASNList(r.Match.AsnIn, maxPatternsPerField)
	if err != nil {
		return ChallengeAccessEntry{}, fmt.Errorf("asn_in: %w", err)
	}
	r.Match.AsnIn = asns

	return r, nil
}

// normalizeASNList de-duplicates and caps a list of ASNs. ASN 0 is rejected: it
// is the enricher's "unresolved" sentinel and would silently exempt every
// IP the mmdb cannot place (fail-open would become fail-open-to-allow).
func normalizeASNList(in []uint32, max int) ([]uint32, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > max {
		return nil, fmt.Errorf("too many values (max %d)", max)
	}
	seen := map[uint32]struct{}{}
	out := make([]uint32, 0, len(in))
	for _, a := range in {
		if a == 0 {
			return nil, errors.New("invalid ASN 0")
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out, nil
}

func (s *challengeAccessStore) load() {
	if s == nil || s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(b, &raws); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range raws {
		e, unknown := decodeStoredCA(raw)
		if e == nil || strings.TrimSpace(e.ID) == "" {
			continue
		}
		if unknown {
			// Written by a newer cfm: it carries a match/scope key this build
			// cannot decode. Dropping the key would WIDEN the exemption (a
			// narrowing condition the newer cfm meant to apply is lost), so keep
			// the ORIGINAL bytes (re-emitted verbatim by saveLocked), list it as
			// disabled + unsupported, never enforce it, and refuse Update on it.
			// We do NOT normalize it here — a newer version may relax a field
			// this build still requires, and a normalize failure must not drop
			// (and thereby delete on next save) a frozen entry.
			log.Printf("[webdet][challenge-access] entry %s uses fields this cfm build does not understand; kept on disk verbatim, not enforced, not editable here (upgrade cfm)", strings.TrimSpace(e.ID))
			stub := *e
			stub.ID = strings.TrimSpace(stub.ID) // key consistently with Get/Update/Remove (which trim)
			stub.Enabled = false
			stub.Unsupported = true
			if stub.CreatedAt.IsZero() {
				stub.CreatedAt = time.Now().UTC()
			}
			s.entries[stub.ID] = stub
			s.frozen[stub.ID] = append(json.RawMessage(nil), raw...)
			continue
		}
		norm, err := normalizeChallengeAccess(*e, false)
		if err != nil {
			continue
		}
		if norm.CreatedAt.IsZero() {
			norm.CreatedAt = time.Now().UTC()
		}
		s.entries[norm.ID] = norm
	}
	s.recountLocked()
}

// decodeStoredCA decodes one persisted entry and reports unknown=true when the
// stored JSON carries ANY key this build does not define — a future selector, a
// nested match/scope key, OR a top-level field (metadata like hit counters, or a
// whole new selector block). An entry that fails to decode at all returns nil.
//
// This deliberately diverges from decodeStoredRule (traffic_rules.go), which
// probes only the match/scope blocks so harmless future metadata does not freeze
// a rule. For an ALLOW-LIST the trade-off inverts: freezing an entry means NOT
// enforcing it, which fails CLOSED (the request is challenged, not exempted) —
// the safe direction — whereas a partial decode that silently drops an unknown
// key would WIDEN the exemption into a challenge bypass. So we probe the WHOLE
// entry: a whole-entry re-marshal would also destroy unrecognised top-level
// bytes, so anything we cannot fully model is frozen and re-emitted verbatim.
// The cost — a benign metadata field a newer cfm adds freezes every entry on a
// downgrade, disabling exemptions until upgrade — is acceptable because it fails
// safe (over-challenge) and a downgrade is rare and operator-driven.
func decodeStoredCA(raw json.RawMessage) (*ChallengeAccessEntry, bool) {
	var e ChallengeAccessEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var strict ChallengeAccessEntry
	if err := dec.Decode(&strict); err != nil {
		return &e, true // any unknown key (top-level or nested) → freeze
	}
	return &e, false
}

func (s *challengeAccessStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	type stored struct {
		scope string
		id    string
		raw   json.RawMessage
	}
	arr := make([]stored, 0, len(s.entries))
	for id, e := range s.entries {
		key := stored{scope: strings.Join(e.Scope.Vhosts, ","), id: id}
		if raw, ok := s.frozen[id]; ok {
			// Written by a newer cfm: persist the ORIGINAL bytes so the selectors
			// this build cannot decode survive until the upgrade.
			key.raw = raw
		} else {
			b, err := json.Marshal(e)
			if err != nil {
				return err
			}
			key.raw = b
		}
		arr = append(arr, key)
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].scope != arr[j].scope {
			return arr[i].scope < arr[j].scope
		}
		return arr[i].id < arr[j].id
	})
	raws := make([]json.RawMessage, 0, len(arr))
	for _, e := range arr {
		raws = append(raws, e.raw)
	}
	b, err := json.MarshalIndent(raws, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}

func newChallengeAccessID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ca_%d", time.Now().UnixNano())
	}
	return "ca_" + hex.EncodeToString(b[:])
}
