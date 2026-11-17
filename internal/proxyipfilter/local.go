package proxyipfilter

import (
	"context"
	"time"

	"cfm/internal/logging"
)

// localSets are the node's own sets of `inet cfm input` that drop or accept by
// source address (internal/firewall/nft/nft.go, the "early" rules). The feed
// sets (allow_ext_* / block_ext_*) come from the feeds themselves (SetFeed),
// which also names the list. Left out on purpose: self_v4/v6 (the node's own
// addresses, never a proxied visitor), ignore_v4* (detector state, no rule
// drops or accepts on it), ps_pairs_*, th_*, throttled_* (rate state, not a
// verdict on the address).
var localSets = []struct {
	set   string
	allow bool
}{
	{"allow_v4", true}, {"allow_v6", true},
	{"allow_dyn_v4", true}, {"allow_dyn_v6", true},
	{"allow_v4_nets", true}, {"allow_v6_nets", true},
	{"block_v4", false}, {"block_v6", false},
	{"block_v4_nets", false}, {"block_v6_nets", false},
}

// LocalRefreshEvery is how often the local sets are re-read. A TTL ban that
// expires, or one the CLI adds behind the daemon's back, is seen within it.
const LocalRefreshEvery = time.Minute

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
