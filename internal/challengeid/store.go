package challengeid

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

type Store struct {
	mu sync.Mutex
	m  map[string]entry // ip -> entry
}

type entry struct {
	cid string
	exp time.Time
}

func New() *Store {
	return &Store{m: make(map[string]entry)}
}

func (s *Store) clean(now time.Time) {
	for ip, e := range s.m {
		if now.After(e.exp) {
			delete(s.m, ip)
		}
	}
}

func (s *Store) Get(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clean(now)
	if e, ok := s.m[ip]; ok && now.Before(e.exp) {
		return e.cid
	}
	return ""
}

func (s *Store) GetOrNew(ip string, ttl time.Duration) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clean(now)
	if e, ok := s.m[ip]; ok && now.Before(e.exp) && e.cid != "" {
		return e.cid
	}

	// 12 bytes => short base64url CID
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	cid := base64.RawURLEncoding.EncodeToString(b)
	s.m[ip] = entry{cid: cid, exp: now.Add(ttl)}
	return cid
}

func (s *Store) Delete(ip string) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}
	s.mu.Lock()
	delete(s.m, ip)
	s.mu.Unlock()
}

// Verify returns true if the currently stored CID for ip matches cid.
// This ties "rule trigger" (sink created CID) <-> "solve" (browser posts CID).
func (s *Store) Verify(ip, cid string) bool {
    ip = strings.TrimSpace(ip)
    cid = strings.TrimSpace(cid)
    if ip == "" || cid == "" {
        return false
    }
    got := s.Get(ip)
    return got != "" && got == cid
}

// Solved consumes the CID for ip if it matches.
// Returns true if it was consumed, false if mismatch / missing.
func (s *Store) Solved(ip, cid string) bool {
    if !s.Verify(ip, cid) {
        return false
    }
    s.Delete(ip)
    return true
}
