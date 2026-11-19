package core

import (
	"strings"
	"sync"
	"time"
)

// topAddrIdle is how long a grouped key's tally outlives its last hit
// (longer than any detector window shipped).
const topAddrIdle = 2 * time.Hour

// topAddrPerKey bounds the addresses tallied per key: past it, a new
// address replaces the one with the fewest hits.
const topAddrPerKey = 32

type addrTally struct {
	last time.Time
	n    map[string]int
}

var topAddrs = struct {
	sync.Mutex
	m     map[string]*addrTally
	calls int
}{m: map[string]*addrTally{}}

// TopAddr notes one hit of addr on a grouped counter key (scope names the
// detector, key its window key) and returns the address with the most hits
// on it: the address an alert on an IPv6 client's /64 names (Extra["ip"],
// the fleet report, the leniency and exclude checks), so a neighbour's one
// hit at the end never takes the blame for the address that did the rest.
// A key that is no /64 (IPv4, a guarded or ungrouped address, a user) is
// addr itself and keeps no state.
func TopAddr(scope, key, addr string, now time.Time) string {
	if !strings.Contains(key, "/") {
		return addr
	}
	k := scope + "\x00" + key
	topAddrs.Lock()
	defer topAddrs.Unlock()
	topAddrs.calls++
	if topAddrs.calls%4096 == 0 {
		for kk, t := range topAddrs.m {
			if now.Sub(t.last) > topAddrIdle {
				delete(topAddrs.m, kk)
			}
		}
	}
	t := topAddrs.m[k]
	if t == nil || now.Sub(t.last) > topAddrIdle {
		t = &addrTally{n: map[string]int{}}
		topAddrs.m[k] = t
	}
	t.last = now
	if _, ok := t.n[addr]; !ok && len(t.n) >= topAddrPerKey {
		low, lowN := "", 0
		for a, n := range t.n {
			if low == "" || n < lowN || (n == lowN && a > low) {
				low, lowN = a, n
			}
		}
		delete(t.n, low)
	}
	t.n[addr]++
	best, bestN := addr, 0
	for a, n := range t.n {
		if n > bestN || (n == bestN && a < best) {
			best, bestN = a, n
		}
	}
	return best
}
