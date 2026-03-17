//go:build !cgo

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
	TsUTC   string                 `json:"ts_utc,omitempty"`
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
	Path          string `json:"path"`
	Events        int    `json:"events"`
	UniqueHosts   int    `json:"unique_hosts"`
	UniqueIPs     int    `json:"unique_ips"`
	SizeBytes     int64  `json:"size_bytes"`
	RetentionDays int    `json:"retention_days"`
	PruneEverySec int64  `json:"prune_every_sec"`
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
	events        []HistoryEvent
	nextID        int64
}

func NewHistoryStore(path string, retentionDays int, pruneEvery time.Duration) (*HistoryStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("history path required")
	}
	if retentionDays <= 0 {
		retentionDays = 30
	}
	if pruneEvery <= 0 {
		pruneEvery = 10 * time.Minute
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	s := &HistoryStore{path: path, retentionDays: retentionDays, pruneEvery: pruneEvery, nextID: 1}
	_ = s.reloadLocked()
	_, _ = os.OpenFile(path, os.O_CREATE, 0o644)
	return s, nil
}

func (s *HistoryStore) Close() {}

func (s *HistoryStore) reloadLocked() error {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.events = nil
			s.nextID = 1
			return nil
		}
		return err
	}
	defer f.Close()
	var rows []HistoryEvent
	var maxID int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev HistoryEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.ID > maxID {
			maxID = ev.ID
		}
		rows = append(rows, ev)
	}
	s.events = rows
	s.nextID = maxID + 1
	if s.nextID <= 0 {
		s.nextID = 1
	}
	return nil
}

func (s *HistoryStore) appendLocked(ev HistoryEvent) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func (s *HistoryStore) Append(ev HistoryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.TsUnix == 0 {
		ev.TsUnix = time.Now().Unix()
	}
	if ev.ID == 0 {
		ev.ID = s.nextID
		s.nextID++
	}
	s.events = append(s.events, ev)
	s.appendLocked(ev)
	s.pruneIfNeededLocked(time.Now())
}

func (s *HistoryStore) pruneIfNeededLocked(now time.Time) {
	if now.Sub(s.lastPrune) < s.pruneEvery {
		return
	}
	s.lastPrune = now
	_, _ = s.pruneLocked(s.retentionDays)
}

func (s *HistoryStore) readAllLocked() ([]HistoryEvent, error) {
	out := make([]HistoryEvent, len(s.events))
	copy(out, s.events)
	return out, nil
}

func (s *HistoryStore) QueryEvents(host, ip, typ string, limit int) ([]HistoryEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	out := make([]HistoryEvent, 0, limit)
	for i := len(s.events) - 1; i >= 0; i-- {
		ev := s.events[i]
		if host != "" && ev.Host != host {
			continue
		}
		if ip != "" && ev.IP != ip {
			continue
		}
		if typ != "" && ev.Type != typ {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if hours <= 0 {
		hours = 24
	}
	to := time.Now().Unix()
	from := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	r := HistorySummary{FromUnix: from, ToUnix: to}
	for _, ev := range s.events {
		if ev.TsUnix < from || ev.TsUnix > to {
			continue
		}
		if host != "" && ev.Host != host {
			continue
		}
		if ip != "" && ev.IP != ip {
			continue
		}
		r.TotalEvents++
		switch ev.Type {
		case "challenge_issued":
			r.ChallengeIssued++
		case "challenge_solved":
			r.ChallengeSolved++
		case "challenge_expired_unsolved":
			r.ChallengeExpiredUnsolved++
		case "challenge_escalated_block":
			r.ChallengeEscalated++
		case "block_trigger", "waf_block_trigger":
			r.BlockTriggers++
		case "waf_observed":
			r.WAFObserved++
		case "suspicious":
			r.Suspicious++
		}
	}
	return r, nil
}

func (s *HistoryStore) persistAllLocked() error {
	tmp := s.path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, ev := range s.events {
		b, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			_ = f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *HistoryStore) pruneLocked(days int) (int64, error) {
	if days <= 0 {
		days = s.retentionDays
	}
	cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	keep := s.events[:0]
	removed := 0
	for _, ev := range s.events {
		if ev.TsUnix > 0 && ev.TsUnix < cut {
			removed++
			continue
		}
		keep = append(keep, ev)
	}
	s.events = keep
	if err := s.persistAllLocked(); err != nil {
		return 0, err
	}
	return int64(removed), nil
}

func (s *HistoryStore) Prune(days int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneLocked(days)
}

func (s *HistoryStore) Truncate() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int64(len(s.events))
	s.events = nil
	s.nextID = 1
	if err := s.persistAllLocked(); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *HistoryStore) Stats() (HistoryStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := map[string]struct{}{}
	i := map[string]struct{}{}
	for _, ev := range s.events {
		if ev.Host != "" {
			h[ev.Host] = struct{}{}
		}
		if ev.IP != "" {
			i[ev.IP] = struct{}{}
		}
	}
	fi, _ := os.Stat(s.path)
	sz := int64(0)
	if fi != nil {
		sz = fi.Size()
	}
	return HistoryStats{Path: s.path, Events: len(s.events), UniqueHosts: len(h), UniqueIPs: len(i), SizeBytes: sz, RetentionDays: s.retentionDays, PruneEverySec: int64(s.pruneEvery.Seconds())}, nil
}

func (s *HistoryStore) String() string {
	return fmt.Sprintf("history(path=%s retention_days=%d prune_every=%s)", s.path, s.retentionDays, s.pruneEvery)
}
