package core

import (
	"sync"
	"time"
)

type SlidingCounter struct {
	mu     sync.Mutex
	win    time.Duration
	budget int // optional per-key cap for timestamps (0 = unlimited)
	m      map[string][]time.Time
}

func NewSlidingCounter(win time.Duration, perKeyCap int) *SlidingCounter {
	if win <= 0 {
		win = 10 * time.Minute
	}
	return &SlidingCounter{win: win, budget: perKeyCap, m: make(map[string][]time.Time)}
}

func (s *SlidingCounter) Add(key string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	arr := append(s.m[key], now)

	// drop old
	cut := now.Add(-s.win)
	i := 0
	for i < len(arr) && arr[i].Before(cut) {
		i++
	}
	if i > 0 {
		arr = arr[i:]
	}
	// cap size to bound memory
	if s.budget > 0 && len(arr) > s.budget {
		arr = arr[len(arr)-s.budget:]
	}
	s.m[key] = arr
	return len(arr)
}

func (s *SlidingCounter) Count(key string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	arr := s.m[key]
	cut := now.Add(-s.win)
	i := 0
	for i < len(arr) && arr[i].Before(cut) {
		i++
	}
	if i > 0 {
		arr = arr[i:]
		s.m[key] = arr
	}
	return len(arr)
}



// AlertGate centralizes cooldown + "no-replay" logic.
// It only allows an alert when: count >= limit, cooldown passed, and count grew vs last time.
type AlertGate struct {
	mu        sync.Mutex
	cooldown  time.Duration
	lastHit   map[string]time.Time
	lastCount map[string]int
}

func NewAlertGate(cooldown time.Duration) *AlertGate {
	return &AlertGate{
		cooldown:  cooldown,
		lastHit:   make(map[string]time.Time),
		lastCount: make(map[string]int),
	}
}

func (g *AlertGate) Allow(key string, now time.Time, count, limit int) bool {
	if limit <= 0 || count < limit {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if lh, ok := g.lastHit[key]; ok && now.Sub(lh) < g.cooldown {
		return false
	}
	if last := g.lastCount[key]; count <= last {
		return false
	}
	g.lastHit[key] = now
	g.lastCount[key] = count
	return true
}




type SampleRing struct {
	Cap int
	M   map[string][]string
}

func NewSampleRing(cap int) *SampleRing { return &SampleRing{Cap: cap, M: make(map[string][]string)} }
func (r *SampleRing) Add(key, line string) {
	a := append(r.M[key], line)
	if r.Cap > 0 && len(a) > r.Cap {
		a = a[len(a)-r.Cap:]
	}
	r.M[key] = a
}
func (r *SampleRing) GetAndClear(key string) []string {
	a := r.M[key]
	delete(r.M, key)
	return a
}
