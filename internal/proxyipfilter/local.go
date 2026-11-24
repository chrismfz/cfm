package proxyipfilter

import (
	"context"
	"sync"
	"time"

	"cfm/internal/logging"
)

// localSets are the node's own sets of `inet cfm input` that drop or accept by
// source address (internal/firewall/nft/nft.go, the "early" rules), read by
// StartLocalRefresh. The feed sets (allow_ext_* / block_ext_*) come from the
// feeds themselves (SetFeed), which also names the list, and the ban sets
// (banSets) from the edge ban reconcile's read (SetLocalBans). Left out on
// purpose: self_v4/v6 (the node's own addresses, never a proxied visitor),
// ignore_v4* (detector state, no rule drops or accepts on it), ps_pairs_*,
// th_*, throttled_* (rate state, not a verdict on the address).
var localSets = []struct {
	set   string
	allow bool
}{
	{"allow_v4", true}, {"allow_v6", true},
	{"allow_dyn_v4", true}, {"allow_dyn_v6", true},
	{"allow_v4_nets", true}, {"allow_v6_nets", true},
	{"block_v4_nets", false}, {"block_v6_nets", false},
}

// banSets are the sets the bans land in: every automatic ban, cfm.deny, the
// TTL bans (ttlban.Sets, the same list the edge ban reconcile reads). They are
// the big ones (50 000 bans on the busiest node, 2026-11-24), so this filter
// does not read them itself every minute: the edge ban reconcile hands over
// the read it makes anyway (SetLocalBans, every BanFeedEvery), with each
// element's time left, and each refresh drops what expired since.
var banSets = []string{"block_v4", "block_v6", "block_v6_clients"}

// BanSets is banSets, for cmd/cfm's parity test against ttlban.Sets (this
// package cannot import ttlban: firewall imports this package).
func BanSets() []string { return append([]string(nil), banSets...) }

// LocalRefreshEvery is how often the local sets are re-read, and the ban
// sets' expired elements dropped. A TTL ban that expires is gone within it;
// one the CLI adds behind the daemon's back, or an allow, within it for the
// small sets and within BanFeedEvery for a ban.
const LocalRefreshEvery = time.Minute

// BanFeedEvery is how often SetLocalBans is called (cmd/cfm's edge ban
// reconcile, edgeBanReconcileEvery): a new ban reaches this filter within it.
// The daemon's web bans also reach the edge ban store at once, which the
// bridge checks first.
const BanFeedEvery = 2 * time.Minute

// BanElem is one element of a ban set as the reconcile read it: the element
// (an address, a network), and the time it had left then (0 = permanent).
type BanElem struct {
	Elem string
	Left time.Duration
}

type timedElem struct {
	elem  string
	until time.Time // zero = permanent
}

var (
	bansMu sync.Mutex
	bans   = map[string][]timedElem{} // set -> elements, from the last SetLocalBans
)

// SetLocalBans takes the ban sets as the edge ban reconcile read them at
// readAt (a complete read: a set it did not read is left as it was) and
// publishes them; the minute refresh drops their elements as they expire.
func SetLocalBans(readAt time.Time, bySet map[string][]BanElem) {
	bansMu.Lock()
	for _, set := range banSets {
		elems, ok := bySet[set]
		if !ok {
			continue
		}
		out := make([]timedElem, 0, len(elems))
		for _, e := range elems {
			te := timedElem{elem: e.Elem}
			if e.Left > 0 {
				te.until = readAt.Add(e.Left)
			}
			out = append(out, te)
		}
		bans[set] = out
	}
	bansMu.Unlock()
	publishBans()
}

// publishBans builds each ban set's source from the cached elements that
// have not expired, and drops the expired ones from the cache.
func publishBans() {
	t := now()
	bansMu.Lock()
	defer bansMu.Unlock()
	for set, elems := range bans {
		live := make([]string, 0, len(elems))
		kept := elems[:0]
		for _, e := range elems {
			if e.until.IsZero() || t.Before(e.until) {
				live = append(live, e.elem)
				kept = append(kept, e)
			}
		}
		bans[set] = kept
		setLocal(set, false, live)
	}
}

// StartLocalRefresh reads the local sets now and then every interval, until
// ctx ends; the returned channel closes when the goroutine has stopped (a
// test waits for it, or a refresh in flight would write into the next test).
// list is the firewall backend's ListSetElementsRaw. A set that cannot be
// read keeps what it had (a node without IPv6 sets, an nft hiccup), and the
// error is logged when it changes, not every minute.
func StartLocalRefresh(ctx context.Context, list func(set string) ([]string, error), every time.Duration) <-chan struct{} {
	done := make(chan struct{})
	lastErr := map[string]string{}
	refresh := func() {
		for _, ls := range localSets {
			elems, err := list(ls.set)
			if err != nil {
				if e := err.Error(); lastErr[ls.set] != e {
					lastErr[ls.set] = e
					logging.Logf("[proxied_ipfilter] cannot read %s (keeping what it had): %v", ls.set, err)
				}
				continue
			}
			if lastErr[ls.set] != "" {
				delete(lastErr, ls.set)
				logging.Logf("[proxied_ipfilter] %s readable again (%d entries)", ls.set, len(elems))
			}
			setLocal(ls.set, ls.allow, elems)
		}
		publishBans()
		pruneForgotten()
	}
	go func() {
		defer close(done)
		refresh()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
	return done
}
