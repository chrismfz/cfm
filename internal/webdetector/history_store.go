package webdetector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type HistoryEvent struct {
	ID      int64                  `json:"id"`
	TsUnix  int64                  `json:"ts_unix"`
	Type    string                 `json:"event_type"`
	Host    string                 `json:"host,omitempty"`
	IP      string                 `json:"ip,omitempty"`
	Mode    string                 `json:"mode,omitempty"`
	Reason  string                 `json:"reason,omitempty"`
	Score   float64                `json:"score,omitempty"`
	UniqIP  int                    `json:"uniq_ip,omitempty"`
	RPS     float64                `json:"rps,omitempty"`
	Status  int                    `json:"status_code,omitempty"`
	TTLSec  int                    `json:"ttl_sec,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

type HistoryStats struct {
	Path        string `json:"path"`
	Events      int    `json:"events"`
	UniqueHosts int    `json:"unique_hosts"`
	UniqueIPs   int    `json:"unique_ips"`
	SizeBytes   int64  `json:"size_bytes"`
}

type HistorySummary struct {
	FromUnix int64 `json:"from_unix"`
	ToUnix   int64 `json:"to_unix"`

	TotalEvents int `json:"total_events"`

	ChallengeIssued          int `json:"challenge_issued"`
	ChallengeSolved          int `json:"challenge_solved"`
	ChallengeExpiredUnsolved int `json:"challenge_expired_unsolved"`
	ChallengeEscalated       int `json:"challenge_escalated_block"`

	BlockTriggers int `json:"block_triggers"`
	WAFObserved   int `json:"waf_observed"`
	Suspicious    int `json:"suspicious"`
}

type HistoryStore struct {
	mu sync.Mutex

	path          string
	retentionDays int
	pruneEvery    time.Duration
	lastPrune     time.Time
	nextID        int64
}

func NewHistoryStore(path string, retentionDays int, pruneEvery time.Duration) (*HistoryStore, error) {
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/cfm/webdetector-history.jsonl"
	}
	if pruneEvery <= 0 {
		pruneEvery = time.Hour
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	s := &HistoryStore{path: path, retentionDays: retentionDays, pruneEvery: pruneEvery}
	_ = s.bootstrapID()
	return s, nil
}

func (s *HistoryStore) bootstrapID() error {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	var last int64
	for scan.Scan() {
		var ev HistoryEvent
		if err := json.Unmarshal(scan.Bytes(), &ev); err == nil && ev.ID > last {
			last = ev.ID
		}
	}
	s.nextID = last
	return nil
}

func (s *HistoryStore) Close() {}

func (s *HistoryStore) Append(ev HistoryEvent) {
	if s == nil || strings.TrimSpace(ev.Type) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.TsUnix <= 0 {
		ev.TsUnix = time.Now().Unix()
	}
	s.nextID++
	ev.ID = s.nextID
	ev.Host = cleanHost(ev.Host)
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
	s.pruneIfNeededLocked(time.Now())
}

func (s *HistoryStore) pruneIfNeededLocked(now time.Time) {
	if s.retentionDays <= 0 {
		return
	}
	if !s.lastPrune.IsZero() && now.Sub(s.lastPrune) < s.pruneEvery {
		return
	}
	s.lastPrune = now
	_, _ = s.pruneLocked(s.retentionDays)
}

func (s *HistoryStore) readAllLocked() ([]HistoryEvent, error) {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	out := make([]HistoryEvent, 0, 1024)
	for scan.Scan() {
		var ev HistoryEvent
		if err := json.Unmarshal(scan.Bytes(), &ev); err == nil {
			out = append(out, ev)
		}
	}
	return out, nil
}

func matchEv(ev HistoryEvent, host, ip, typ string) bool {
	if host != "" && cleanHost(ev.Host) != host {
		return false
	}
	if ip != "" && strings.TrimSpace(ev.IP) != ip {
		return false
	}
	if typ != "" && strings.TrimSpace(ev.Type) != typ {
		return false
	}
	return true
}

func (s *HistoryStore) QueryEvents(host, ip, typ string, limit int) ([]HistoryEvent, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	host = cleanHost(host)
	ip = strings.TrimSpace(ip)
	typ = strings.TrimSpace(typ)
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAllLocked()
	if err != nil {
		return nil, err
	}
	out := make([]HistoryEvent, 0, limit)
	for i := len(all) - 1; i >= 0; i-- {
		ev := all[i]
		if !matchEv(ev, host, ip, typ) {
			continue
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *HistoryStore) Summarize(host, ip string, hours int) (HistorySummary, error) {
	res := HistorySummary{}
	if s == nil {
		return res, nil
	}
	if hours <= 0 {
		hours = 24
	}
	to := time.Now()
	from := to.Add(-time.Duration(hours) * time.Hour)
	res.FromUnix = from.Unix()
	res.ToUnix = to.Unix()
	host = cleanHost(host)
	ip = strings.TrimSpace(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAllLocked()
	if err != nil {
		return res, err
	}
	for _, ev := range all {
		if ev.TsUnix < res.FromUnix || ev.TsUnix > res.ToUnix {
			continue
		}
		if !matchEv(ev, host, ip, "") {
			continue
		}
		res.TotalEvents++
		switch ev.Type {
		case "challenge_issued":
			res.ChallengeIssued++
		case "challenge_solved":
			res.ChallengeSolved++
		case "challenge_expired_unsolved":
			res.ChallengeExpiredUnsolved++
		case "challenge_escalated_block":
			res.ChallengeEscalated++
		case "block_trigger":
			res.BlockTriggers++
		case "waf_observe":
			res.WAFObserved++
		case "suspicious_snapshot":
			res.Suspicious++
		}
	}
	return res, nil
}

func (s *HistoryStore) pruneLocked(days int) (int64, error) {
	all, err := s.readAllLocked()
	if err != nil {
		return 0, err
	}
	cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	keep := make([]HistoryEvent, 0, len(all))
	var removed int64
	for _, ev := range all {
		if ev.TsUnix < cut {
			removed++
			continue
		}
		keep = append(keep, ev)
	}
	if err := s.rewriteLocked(keep); err != nil {
		return 0, err
	}
	return removed, nil
}

func (s *HistoryStore) rewriteLocked(events []HistoryEvent) error {
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	for _, ev := range events {
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		if _, err := f.Write(append(b, '\n')); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	var maxID int64
	for _, ev := range events {
		if ev.ID > maxID {
			maxID = ev.ID
		}
	}
	s.nextID = maxID
	return nil
}

func (s *HistoryStore) Prune(days int) (int64, error) {
	if s == nil || days <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneLocked(days)
}

func (s *HistoryStore) Truncate() (int64, error) {
	if s == nil {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAllLocked()
	if err != nil {
		return 0, err
	}
	removed := int64(len(all))
	if err := s.rewriteLocked(nil); err != nil {
		return 0, err
	}
	return removed, nil
}

func (s *HistoryStore) Stats() (HistoryStats, error) {
	st := HistoryStats{}
	if s == nil {
		return st, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.readAllLocked()
	if err != nil {
		return st, err
	}
	st.Path = s.path
	st.Events = len(all)
	hosts := map[string]struct{}{}
	ips := map[string]struct{}{}
	for _, ev := range all {
		if h := cleanHost(ev.Host); h != "" {
			hosts[h] = struct{}{}
		}
		if ip := strings.TrimSpace(ev.IP); ip != "" {
			ips[ip] = struct{}{}
		}
	}
	st.UniqueHosts = len(hosts)
	st.UniqueIPs = len(ips)
	if fi, err := os.Stat(s.path); err == nil {
		st.SizeBytes = fi.Size()
	}
	return st, nil
}

func (s *HistoryStore) String() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%s", s.path)
}
