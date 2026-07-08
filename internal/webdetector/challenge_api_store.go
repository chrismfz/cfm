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

	Score     float64  `json:"score"`
	OnThresh  float64  `json:"on_threshold"`
	OffThresh float64  `json:"off_threshold"`
	UniqIP    int      `json:"uniq_ip"`
	RPS       float64  `json:"rps"`
	Reasons   []string `json:"reasons,omitempty"`

	LastAction  string    `json:"last_action"`
	LastChanged time.Time `json:"last_changed"`
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
	st.Mode = "auto"
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
	st.LastChanged = now
	st.Score = row.Score
	st.OnThresh = on
	st.OffThresh = off
	st.UniqIP = row.UniqueIPs
	st.RPS = row.RPS
	st.Reasons = append([]string(nil), row.Reasons...)

	s.addEvent(ChallengeEvent{
		Ts:     now,
		Type:   st.LastAction,
		Host:   host,
		Score:  row.Score,
		UniqIP: row.UniqueIPs,
		RPS:    row.RPS,
	})
}

func (s *ChallengeAPIStore) RecordVhostManual(host string, active bool, ttl time.Duration, reason string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.vhosts[host]
	if !ok {
		st = &ChallengeVhostState{Host: host}
		s.vhosts[host] = st
	}
	st.Mode = "manual"
	if active {
		st.Status = "active"
		st.LastAction = "manual_on"
		if st.Since.IsZero() {
			st.Since = now
		}
		if ttl > 0 {
			st.ExpiresAt = now.Add(ttl)
		}
	} else {
		st.Status = "inactive"
		st.LastAction = "manual_off"
		st.Since = now
		st.ExpiresAt = time.Time{}
	}
	st.LastChanged = now
	if len(st.Reasons) == 0 || st.Reasons[0] != reason {
		st.Reasons = []string{reason}
	}

	s.addEvent(ChallengeEvent{
		Ts:   now,
		Type: st.LastAction,
		Host: host,
		Rule: reason,
	})
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

func (s *ChallengeAPIStore) Summary() ChallengeSummary {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	av := 0
	for _, v := range s.vhosts {
		if v != nil && v.Status == "active" {
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ChallengeVhostState, 0, len(s.vhosts))
	for _, v := range s.vhosts {
		if v == nil {
			continue
		}
		if status != "" && status != "all" && v.Status != status {
			continue
		}
		if mode != "" && mode != "all" && v.Mode != mode {
			continue
		}
		out = append(out, *v)
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
