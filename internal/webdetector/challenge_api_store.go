package webdetector

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type ChallengeVhostState struct {
	Host      string    `json:"host"`
	Status    string    `json:"status"` // active|inactive
	Mode      string    `json:"mode"`   // auto|manual
	Since     time.Time `json:"since"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// TTLSec is the window an operator granted for a MANUAL challenge, in
	// seconds — the "total" next to the remaining time (ExpiresAt - now).
	// It cannot be derived from the row: Since is the start of the challenge,
	// not of the current window, so a refreshed manual challenge would report
	// a total longer than the one granted.
	//
	// Zero (and omitted from the JSON) for an auto challenge — those have no
	// stored expiry, they live and die by the scorer — including when a lapsed
	// manual row is flipped to Mode=="auto", which clears TTLSec. ExpiresAt is
	// NOT cleared on that flip (vhostEffectivelyActive depends on it), so a
	// reader still has to gate the remaining time on Mode=="manual".
	TTLSec int `json:"ttl_sec,omitempty"`

	Score     float64  `json:"score"`
	OnThresh  float64  `json:"on_threshold"`
	OffThresh float64  `json:"off_threshold"`
	UniqIP    int      `json:"uniq_ip"`
	RPS       float64  `json:"rps"`
	Reasons   []string `json:"reasons,omitempty"`

	LastAction  string    `json:"last_action"`
	LastChanged time.Time `json:"last_changed"`

	// SolverFarm is true while challenge_solver_farm currently sees a
	// distributed solver farm on this vhost. Stamped by the handler, not stored:
	// the mark lives in solverfarm_marks.go with its own TTL, and copying it
	// into this store would leave two things to expire instead of one.
	SolverFarm bool `json:"solver_farm"`

	// ShadowOutliers is the live abuse_shadow rate-outlier count for this vhost.
	// Stamped by the handler, not stored (the mark lives in abuse_shadow_marks.go
	// with its own TTL). 0 when none/expired.
	ShadowOutliers int `json:"shadow_outliers"`

	// State is the vhost's position on the escalation ladder
	// (normal|suspicious|challenged|under_attack). Stamped by the handler via the
	// single deriveVhostState() helper (like SolverFarm, not stored): the
	// under_attack rung lives in the under-attack tracker with its own lifecycle.
	// Omitted from JSON when empty so older readers are unaffected.
	State string `json:"state,omitempty"`

	// manualUntil tracks an active operator manual challenge on this host,
	// independent of the auto scorer. Unexported on purpose: it is NOT part of
	// the API JSON (the status list keeps its single Status/Mode shape) — it
	// exists so RecordVhostAuto can tell that a manual challenge still covers
	// the host and must not be masked by an auto_off. Zero = no manual coverage.
	//
	// Without it the list lied: a manual challenge is recorded on the apex key
	// only, but the bridge enforces it on apex AND www (vhostVariantsForBridge);
	// the www row therefore carried only auto records, so when the auto scorer
	// cooled, RecordVhostAuto(false) flipped www to Status=inactive/Mode=auto
	// while the challenge was still being served — the vhost "dropped from the
	// list" though enforcement was intact.
	manualUntil time.Time
}

type ChallengeIPState struct {
	IP         string    `json:"ip"`
	State      string    `json:"state"` // challenge|block|ok
	Host       string    `json:"host,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Fails      int       `json:"fails"`
	Solves     int       `json:"solves"`
	LastURI    string    `json:"last_uri,omitempty"`
	LastMethod string    `json:"last_method,omitempty"`
	LastStatus int       `json:"last_status,omitempty"`
}

type ChallengeEvent struct {
	Ts     time.Time `json:"ts"`
	Type   string    `json:"type"`
	Host   string    `json:"host,omitempty"`
	IP     string    `json:"ip,omitempty"`
	Rule   string    `json:"rule,omitempty"`
	Score  float64   `json:"score,omitempty"`
	UniqIP int       `json:"uniq_ip,omitempty"`
	RPS    float64   `json:"rps,omitempty"`
}

type ChallengeSummary struct {
	Now          time.Time `json:"now"`
	ActiveVhosts int       `json:"active_vhosts"`
	ActiveIPs    int       `json:"active_ips"`

	// Under-Attack Mode status (stamped by the handler, not stored): whether the
	// detector is enabled and how many vhosts are currently in UNDER_ATTACK.
	UnderAttackEnabled bool `json:"under_attack_enabled"`
	UnderAttackVhosts  int  `json:"under_attack_vhosts"`
}

type ChallengeAPIStore struct {
	mu     sync.RWMutex
	vhosts map[string]*ChallengeVhostState
	ips    map[string]*ChallengeIPState

	events []ChallengeEvent
	head   int
	size   int
}

func NewChallengeAPIStore(maxEvents int) *ChallengeAPIStore {
	if maxEvents <= 0 {
		maxEvents = 50000
	}
	return &ChallengeAPIStore{
		vhosts: make(map[string]*ChallengeVhostState),
		ips:    make(map[string]*ChallengeIPState),
		events: make([]ChallengeEvent, maxEvents),
	}
}

func (s *ChallengeAPIStore) addEvent(e ChallengeEvent) {
	if len(s.events) == 0 {
		return
	}
	// Store the host canonically (trim+lower+strip :port) so a normalized
	// ?host= event filter matches regardless of the writer's casing. Idempotent
	// for the manual path, which already passes normalized variants.
	e.Host = normalizeHost(e.Host)
	s.events[s.head] = e
	s.head = (s.head + 1) % len(s.events)
	if s.size < len(s.events) {
		s.size++
	}
}

func (s *ChallengeAPIStore) RecordVhostAuto(host string, active bool, row SuspiciousRow, on, off float64, hold time.Duration) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.vhosts[host]
	if !ok {
		st = &ChallengeVhostState{Host: host}
		s.vhosts[host] = st
	}

	// An operator manual challenge outranks the auto scorer in the list: while
	// one is active on this host, neither an auto_on nor (critically) an
	// auto_off may overwrite Status/Mode/ExpiresAt — the auto cool-down must not
	// make a manually-challenged, still-enforced vhost read as inactive. Record
	// the auto score/metrics as evidence, but keep the manual top-line. The auto
	// action is surfaced through LastAction so the reason is still visible.
	manualActive := !st.manualUntil.IsZero() && st.manualUntil.After(now)
	if manualActive {
		st.Mode = "manual"
		st.Status = "active"
		st.ExpiresAt = st.manualUntil
		if active {
			st.LastAction = "auto_on_under_manual"
		} else {
			st.LastAction = "auto_off_keep_manual"
		}
	} else {
		st.Mode = "auto"
		// No manual challenge covers this row any more, so the granted TTL it
		// may still carry from a lapsed one is meaningless — drop it rather
		// than serve a stale window to API consumers that read the JSON raw
		// (WebUI, MCP). ExpiresAt is deliberately NOT cleared here: see
		// vhostEffectivelyActive, whose Mode check depends on it surviving.
		st.TTLSec = 0
		if active {
			st.Status = "active"
			if st.Since.IsZero() {
				st.Since = now
			}
			st.LastAction = "auto_on"
		} else {
			st.Status = "inactive"
			st.LastAction = "auto_off"
			st.Since = now
		}
	}
	st.LastChanged = now
	st.Score = row.Score
	st.OnThresh = on
	st.OffThresh = off
	st.UniqIP = row.UniqueIPs
	st.RPS = row.RPS
	// Don't overwrite the manual reason with auto scanner reasons while manual
	// owns the row; the auto score/uniqIP/rps above are still recorded as evidence.
	if !manualActive {
		st.Reasons = append([]string(nil), row.Reasons...)
	}

	s.addEvent(ChallengeEvent{
		Ts:     now,
		Type:   st.LastAction,
		Host:   host,
		Score:  row.Score,
		UniqIP: row.UniqueIPs,
		RPS:    row.RPS,
	})
}

// RecordVhostManual records an operator manual challenge whose TTL starts now:
// ttl is both the remaining window and the granted total.
func (s *ChallengeAPIStore) RecordVhostManual(host string, active bool, ttl time.Duration, reason string) {
	s.recordVhostManual(host, active, ttl, ttl, reason)
}

// RecordVhostManualRestored re-records a manual challenge that outlived a
// daemon restart. remaining is what is left of the window (it drives
// ExpiresAt); total is the TTL the operator originally granted (it drives
// TTLSec). Passing remaining for both would shrink the reported "total" on
// every restart, so a 24h challenge would read as e.g. "18h" after one.
// total <= 0 (an entry restored from a snapshot written before TTLs were
// persisted) falls back to remaining.
func (s *ChallengeAPIStore) RecordVhostManualRestored(host string, remaining, total time.Duration, reason string) {
	if total <= 0 {
		total = remaining
	}
	s.recordVhostManual(host, true, remaining, total, reason)
}

// recordVhostManual is the shared body: window drives ExpiresAt, total drives
// the reported TTL.
func (s *ChallengeAPIStore) recordVhostManual(host string, active bool, window, total time.Duration, reason string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	// Mirror the bridge's apex→www expansion (vhostVariantsForBridge): a manual
	// challenge on the apex is enforced on apex AND www, so the status list must
	// carry a manual record for BOTH — otherwise the www row shows only auto
	// state and an auto_off masks the still-active manual challenge.
	for _, h := range vhostVariantsForBridge(host) {
		st, ok := s.vhosts[h]
		if !ok {
			st = &ChallengeVhostState{Host: h}
			s.vhosts[h] = st
		}
		st.Mode = "manual"
		if active {
			st.Status = "active"
			st.LastAction = "manual_on"
			if st.Since.IsZero() {
				st.Since = now
			}
			if window > 0 {
				st.ExpiresAt = now.Add(window)
				st.manualUntil = st.ExpiresAt
				st.TTLSec = int(total.Round(time.Second) / time.Second)
			}
		} else {
			st.Status = "inactive"
			st.LastAction = "manual_off"
			st.Since = now
			st.ExpiresAt = time.Time{}
			st.manualUntil = time.Time{}
			st.TTLSec = 0
		}
		st.LastChanged = now
		if len(st.Reasons) == 0 || st.Reasons[0] != reason {
			st.Reasons = []string{reason}
		}

		s.addEvent(ChallengeEvent{
			Ts:   now,
			Type: st.LastAction,
			Host: h,
			Rule: reason,
		})
	}
}

// RecordIPChallenge records/refreshes an active challenge for ip and reports
// whether this is a NEW issuance (isNew). "New" = the IP was not already sitting
// in an active (unexpired) challenge for the same rule. The subnet/path emitters
// re-fire every detector cycle while a host stays flagged, so refreshes of a
// live challenge return false — letting callers log the issuance once per window
// instead of once per tick.
func (s *ChallengeAPIStore) RecordIPChallenge(ip, host, rule, uri, method string, status int, ttl time.Duration) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.ips[ip]
	// Capture prior liveness BEFORE we overwrite st below. A zero ExpiresAt with
	// State=="challenge" means "no expiry set" → still active.
	wasActive := ok && st.State == "challenge" && st.Rule == rule &&
		(st.ExpiresAt.IsZero() || st.ExpiresAt.After(now))
	if !ok {
		st = &ChallengeIPState{IP: ip, FirstSeen: now}
		s.ips[ip] = st
	}
	st.State = "challenge"
	st.Host = host
	st.Rule = rule
	st.LastSeen = now
	if ttl > 0 {
		st.ExpiresAt = now.Add(ttl)
	}
	if uri != "" {
		st.LastURI = uri
	}
	if method != "" {
		st.LastMethod = method
	}
	if status != 0 {
		st.LastStatus = status
	}

	s.addEvent(ChallengeEvent{
		Ts:   now,
		Type: "ip_challenge",
		Host: host,
		IP:   ip,
		Rule: rule,
	})
	return !wasActive
}

func (s *ChallengeAPIStore) RecordSolved(ip, host, uri string, diff int, ms int64) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.ips[ip]
	if !ok {
		st = &ChallengeIPState{IP: ip, FirstSeen: now}
		s.ips[ip] = st
	}
	st.Solves++
	st.LastSeen = now
	st.Host = host
	if uri != "" {
		st.LastURI = uri
	}
	// keep State as-is; solved doesn't necessarily mean "not challenged" (bridge/fw clears it)

	s.addEvent(ChallengeEvent{
		Ts:   now,
		Type: "solved",
		Host: host,
		IP:   ip,
	})
}

// vhostEffectivelyActive reports whether a vhost row counts as active right
// now. A MANUAL row can carry Status=="active" with an ExpiresAt already in the
// past — a manual (or manual-kept) challenge whose TTL lapsed without any later
// event rewriting the row, since the store has no TTL sweeper. Such a stale
// manual row must not be counted or listed as active.
//
// AUTO rows are governed by the tick loop, not a stored expiry, so they are
// active whenever Status=="active" regardless of ExpiresAt. This Mode check is
// load-bearing, not cosmetic: when a manual challenge lapses (leaving a past
// ExpiresAt on the row) and the host is still hot, the next auto_on flips the
// row to Mode=="auto" via RecordVhostAuto but does NOT clear that stale
// ExpiresAt — so keying purely on ExpiresAt would hide a genuinely-active auto
// challenge for its whole lifetime.
func vhostEffectivelyActive(v *ChallengeVhostState, now time.Time) bool {
	if v == nil || v.Status != "active" {
		return false
	}
	if v.Mode == "auto" {
		return true
	}
	return v.ExpiresAt.IsZero() || v.ExpiresAt.After(now)
}

func (s *ChallengeAPIStore) Summary() ChallengeSummary {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	av := 0
	for _, v := range s.vhosts {
		if vhostEffectivelyActive(v, now) {
			av++
		}
	}
	ai := 0
	for _, ip := range s.ips {
		if ip != nil && ip.State == "challenge" {
			ai++
		}
	}
	return ChallengeSummary{Now: now, ActiveVhosts: av, ActiveIPs: ai}
}

func (s *ChallengeAPIStore) ListVhosts(status, mode string, limit int) []ChallengeVhostState {
	if limit <= 0 {
		limit = 200
	}
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ChallengeVhostState, 0, len(s.vhosts))
	for _, v := range s.vhosts {
		if v == nil {
			continue
		}
		// Filter on the EFFECTIVE status so a stale active row (Status=="active"
		// but ExpiresAt already past — a lapsed manual challenge) is treated as
		// inactive, matching Summary(). Otherwise a status=active view would list
		// challenges that are no longer in force.
		eff := "inactive"
		if vhostEffectivelyActive(v, now) {
			eff = "active"
		}
		if status != "" && status != "all" && eff != status {
			continue
		}
		if mode != "" && mode != "all" && v.Mode != mode {
			continue
		}
		// Return the EFFECTIVE status, not the raw stored one: a lapsed manual
		// row keeps Status=="active" with a past ExpiresAt, and status=all would
		// otherwise report it active (and sort it among the live rows), while
		// the single-vhost endpoint folds it to inactive. Copy first so the
		// stored row is untouched.
		row := *v
		row.Status = eff
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		// active first, then score desc, then uniq desc
		if out[i].Status != out[j].Status {
			return out[i].Status == "active"
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].UniqIP > out[j].UniqIP
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *ChallengeAPIStore) GetVhost(host string) (ChallengeVhostState, bool) {
	host = strings.TrimSpace(host)
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.vhosts[host]
	if !ok || v == nil {
		return ChallengeVhostState{}, false
	}
	return *v, true
}

func (s *ChallengeAPIStore) ListIPs(host, state string, limit int) []ChallengeIPState {
	if limit <= 0 {
		limit = 500
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ChallengeIPState, 0, len(s.ips))
	for _, v := range s.ips {
		if v == nil {
			continue
		}
		if host != "" && v.Host != host {
			continue
		}
		if state != "" && state != "all" && v.State != state {
			continue
		}
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *ChallengeAPIStore) GetIP(ip string) (ChallengeIPState, bool) {
	ip = strings.TrimSpace(ip)
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.ips[ip]
	if !ok || v == nil {
		return ChallengeIPState{}, false
	}
	return *v, true
}

func (s *ChallengeAPIStore) Events(host, ip, rule, typ string, limit int) []ChallengeEvent {
	limit = clampChallengeEventsLimit(limit)
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ChallengeEvent, 0, limit)
	// read ring newest->oldest
	for i := 0; i < s.size && len(out) < limit; i++ {
		idx := s.head - 1 - i
		if idx < 0 {
			idx += len(s.events)
		}
		e := s.events[idx]
		if e.Ts.IsZero() {
			continue
		}
		if host != "" && e.Host != host {
			continue
		}
		if ip != "" && e.IP != ip {
			continue
		}
		if rule != "" && e.Rule != rule {
			continue
		}
		if typ != "" && e.Type != typ {
			continue
		}
		out = append(out, e)
	}
	return out
}
