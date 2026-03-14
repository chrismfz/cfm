package webdetector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type excludeEntry struct {
	Type      string    `json:"type"` // host | path
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
}

type excludeStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]excludeEntry // key = type:value
}

func newExcludeStore(path string) *excludeStore {
	s := &excludeStore{
		path:    strings.TrimSpace(path),
		entries: make(map[string]excludeEntry),
	}
	s.load()
	return s
}

func (s *excludeStore) normalize(t, v string) (string, string, bool) {
	t = strings.ToLower(strings.TrimSpace(t))
	v = strings.ToLower(strings.TrimSpace(v))
	if t != "host" && t != "path" {
		return "", "", false
	}
	if v == "" {
		return "", "", false
	}
	if t == "path" && !strings.HasPrefix(v, "/") {
		v = "/" + v
	}
	return t, v, true
}

func (s *excludeStore) key(t, v string) string { return t + ":" + v }

func (s *excludeStore) Add(t, v string) bool {
	t, v, ok := s.normalize(t, v)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(t, v)
	if _, exists := s.entries[k]; exists {
		return false
	}
	s.entries[k] = excludeEntry{Type: t, Value: v, CreatedAt: time.Now()}
	_ = s.saveLocked()
	return true
}

func (s *excludeStore) Remove(t, v string) bool {
	t, v, ok := s.normalize(t, v)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.key(t, v)
	if _, exists := s.entries[k]; !exists {
		return false
	}
	delete(s.entries, k)
	_ = s.saveLocked()
	return true
}

func (s *excludeStore) List() []excludeEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]excludeEntry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func (s *excludeStore) MatchHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.Type != "host" {
			continue
		}
		ok, err := filepath.Match(e.Value, host)
		if err == nil && ok {
			return true
		}
		if !strings.ContainsAny(e.Value, "*?") && strings.Contains(host, e.Value) {
			return true
		}
	}
	return false
}

func (s *excludeStore) MatchPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.Type != "path" {
			continue
		}
		ok, err := filepath.Match(e.Value, path)
		if err == nil && ok {
			return true
		}
		if !strings.ContainsAny(e.Value, "*?") && strings.Contains(path, e.Value) {
			return true
		}
	}
	return false
}

func (s *excludeStore) load() {
	if s == nil || s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var arr []excludeEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range arr {
		t, v, ok := s.normalize(e.Type, e.Value)
		if !ok {
			continue
		}
		if e.CreatedAt.IsZero() {
			e.CreatedAt = time.Now()
		}
		e.Type, e.Value = t, v
		s.entries[s.key(t, v)] = e
	}
}

func (s *excludeStore) saveLocked() error {
	if s == nil || s.path == "" {
		return nil
	}
	arr := make([]excludeEntry, 0, len(s.entries))
	for _, e := range s.entries {
		arr = append(arr, e)
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].Type != arr[j].Type {
			return arr[i].Type < arr[j].Type
		}
		return arr[i].Value < arr[j].Value
	})
	b, err := json.MarshalIndent(arr, "", "  ")
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
