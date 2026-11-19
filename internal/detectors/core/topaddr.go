package core

import (
	"strings"
	"sync"
	"time"
)

// topAddrPerKey bounds the addresses tallied per key: past it, a new
// address replaces the stalest one.
const topAddrPerKey = 32

// topAddrMaxKeys bounds the keys tallied in all: past it the tally starts
// over (an alert then names the address it sees, as before the tally). A
// spray of distinct /64s costs at most this many entries, never a sweep.
var topAddrMaxKeys = 50000

type addrHits struct {
	n    int
	last time.Time
}

var topAddrs = struct {
	sync.Mutex
	m map[string]map[string]*addrHits
}{m: map[string]map[string]*addrHits{}}

// TopAddr notes one hit of addr at now on a grouped counter key (scope names
// the detector or section, key its window key, win its window) and returns
// the address with the most hits inside the window: the address an alert on
// an IPv6 client's /64 names (Extra["ip"]: the fleet report, the leniency
// and exclude checks, the notification). An address idle for a window
// starts again from zero, and a tie goes to addr (the one hitting now), so
// the alert never names an address that did nothing in the window, nor a
// neighbour whose one hit came last instead of the address that did the
// rest. A key that is no /64 (IPv4, a guarded or ungrouped address, a user)
// is addr itself and keeps no state.
func TopAddr(scope, key, addr string, now time.Time, win time.Duration) string {
	if !strings.HasSuffix(key, "/64") {
		return addr
	}
	if win <= 0 {
		win = 10 * time.Minute
	}
	k := scope + "\x00" + key
	cut := now.Add(-win)
	topAddrs.Lock()
	defer topAddrs.Unlock()
	t := topAddrs.m[k]
	if t == nil {
		if len(topAddrs.m) >= topAddrMaxKeys {
			topAddrs.m = map[string]map[string]*addrHits{}
		}
		t = map[string]*addrHits{}
		topAddrs.m[k] = t
	}
	h := t[addr]
	if h == nil {
		if len(t) >= topAddrPerKey {
			stale, at := "", now
			for a, o := range t {
				if !o.last.After(at) {
					stale, at = a, o.last
				}
			}
			delete(t, stale)
		}
		h = &addrHits{}
		t[addr] = h
	}
	if h.last.Before(cut) {
		h.n = 0 // idle a window: its old hits are not this window's
	}
	h.n++
	h.last = now
	best, bestN := addr, h.n
	for a, o := range t {
		if o.last.Before(cut) {
			continue
		}
		if o.n > bestN {
			best, bestN = a, o.n
		}
	}
	return best
}
