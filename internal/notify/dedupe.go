package notify

import (
	"sync"
	"time"
)

type deduper struct {
	mu   sync.Mutex
	data map[string]time.Time
	ttl  time.Duration
}

func newDeduper(ttl time.Duration) *deduper { return &deduper{data: map[string]time.Time{}, ttl: ttl} }

func (d *deduper) allow(key string, ttl time.Duration) bool {
	d.mu.Lock(); defer d.mu.Unlock()
	now := time.Now()
	for k, exp := range d.data { if now.After(exp) { delete(d.data, k) } }
	if exp, ok := d.data[key]; ok && now.Before(exp) { return false }
	if ttl <= 0 { ttl = d.ttl }
	d.data[key] = now.Add(ttl)
	return true
}
