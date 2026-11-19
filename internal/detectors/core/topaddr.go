package core

import (
	"math"
	"strings"
	"sync"
	"time"
)

// topAddrPerKey bounds the addresses tallied per key: past it, a new
// address replaces the one with the lowest weight now.
const topAddrPerKey = 8

// topAddrMaxKeys bounds the keys tallied in all scopes together: past it
// the largest scope (the one being sprayed) starts over, its alerts then
// naming the address they see, as before the tally, while the other scopes
// keep theirs. At most topAddrMaxKeys x topAddrPerKey entries (160000,
// ~17 MB), never a sweep.
var topAddrMaxKeys = 20000

type addrHits struct {
	w    float64 // hits, decayed with the window as time constant, at last
	last time.Time
}

var topAddrs = struct {
	sync.Mutex
	m map[string]map[string]map[string]*addrHits // scope -> key -> addr
}{m: map[string]map[string]map[string]*addrHits{}}

// weightAt is h's hit weight at now: every hit counts 1, decaying by e per
// window (a hit a window ago weighs 0.37, three windows ago 0.05).
func (h *addrHits) weightAt(now time.Time, win time.Duration) float64 {
	dt := now.Sub(h.last)
	if dt <= 0 {
		return h.w
	}
	return h.w * math.Exp(-float64(dt)/float64(win))
}

// TopAddr notes one hit of addr at now on a grouped counter key (scope names
// the detector or section, key its window key, win its window) and returns
// the address that weighs most now: the address an alert on an IPv6
// client's /64 names (Extra["ip"]: the fleet report, the leniency and
// exclude checks, the notification). Each hit weighs 1 and decays by e per
// window, so the address busy now outweighs one that trickled hits for hours
// or stopped a while ago, and a tie goes to addr (the one hitting now): the
// alert never names a neighbour whose one hit came last instead of the
// address doing the rest. A key that is no /64 (IPv4, a guarded or
// ungrouped address, a user) is addr itself and keeps no state.
func TopAddr(scope, key, addr string, now time.Time, win time.Duration) string {
	if !strings.HasSuffix(key, "/64") {
		return addr
	}
	if win <= 0 {
		win = 10 * time.Minute
	}
	topAddrs.Lock()
	defer topAddrs.Unlock()
	sc := topAddrs.m[scope]
	if sc == nil || sc[key] == nil {
		total, largest, largestN := 0, "", -1
		for name, s := range topAddrs.m {
			total += len(s)
			if len(s) > largestN {
				largest, largestN = name, len(s)
			}
		}
		if total >= topAddrMaxKeys {
			delete(topAddrs.m, largest)
		}
		if sc = topAddrs.m[scope]; sc == nil {
			sc = map[string]map[string]*addrHits{}
			topAddrs.m[scope] = sc
		}
	}
	t := sc[key]
	if t == nil {
		t = map[string]*addrHits{}
		sc[key] = t
	}
	h := t[addr]
	if h == nil {
		if len(t) >= topAddrPerKey {
			low, lowW := "", math.Inf(1)
			for a, o := range t {
				if w := o.weightAt(now, win); w < lowW {
					low, lowW = a, w
				}
			}
			delete(t, low)
		}
		h = &addrHits{last: now}
		t[addr] = h
	}
	h.w = h.weightAt(now, win) + 1
	if now.After(h.last) {
		h.last = now
	}
	best, bestW := addr, h.w
	for a, o := range t {
		if w := o.weightAt(now, win); w > bestW {
			best, bestW = a, w
		}
	}
	return best
}
