package firewall

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
)

// HostProbeMax is the largest batch, per address family, that a backend plans
// from per-address kernel gets (HostProbe) instead of a dump of the whole set.
// Every automatic ban is a one-address batch (ExtendBlock / ExtendClientBlock),
// and with the dump each one cost a read of every element of block_v4: with
// 50 000 bans on the EL8 nodes that read (and its GC) was a quarter to a third
// of the daemon's CPU (2026-11-24; `nft -j list set` + JSON parse on the exec
// backend, a netlink dump on nftlib). A get costs the same whatever the set's
// size; a fleet blocklist delta of thousands still reads the set once.
const HostProbeMax = 64

// HostProbe asks the kernel, for each address, whether the host set holds it
// (found) and the time it has left (expires: 0 = permanent; a timed element
// never reports 0). Any error means "could not answer": the caller dumps.
type HostProbe func(set string, ips []net.IP) (found []bool, expires []time.Duration, err error)

// ReadHostElems is what PlanBlockBatch reads for want in set: the elements
// of set that are among want, from probe when the batch is small enough and
// probe answers, else the whole set from dump. Both give PlanBlockBatch the
// same answer for want: it only looks up want's addresses.
func ReadHostElems(set string, want []BlockEntry, probe HostProbe, dump func() ([]SetElementTimed, error)) ([]SetElementTimed, error) {
	if probe != nil && len(want) > 0 && len(want) <= HostProbeMax {
		ips := make([]net.IP, len(want))
		for i, w := range want {
			ips[i] = w.IP
		}
		found, expires, err := probe(set, ips)
		if err == nil && (len(found) != len(want) || len(expires) != len(want)) {
			err = errProbeShape
		}
		if err == nil {
			probeStats.probed.Add(1)
			probeStats.addrs.Add(uint64(len(want)))
			return ProbedHosts(want, found, expires), nil
		}
		noteProbeFallback(set, err)
	} else if len(want) > HostProbeMax {
		probeStats.large.Add(1)
	}
	probeStats.dumps.Add(1)
	return dump()
}

// probeStats counts what ReadHostElems did since start, for
// /api/v1/firewall/selftest (both engines): a node whose bans keep falling
// back to the dump is back on the per-ban O(set) cost, and says so there.
var probeStats struct {
	probed, addrs, large, dumps, fallbacks atomic.Uint64
	mu                                     sync.Mutex
	last                                   *HostProbeFallback
}

// HostProbeStats is ReadHostElems' record since start.
type HostProbeStats struct {
	// Probed batches were planned from per-address gets (ProbedAddrs
	// addresses in all).
	Probed      uint64 `json:"probed"`
	ProbedAddrs uint64 `json:"probed_addrs"`
	// Dumps read the whole set: Large batches (over MaxAddrs), Fallbacks
	// (the probe failed), and the rest had no probe (a CLI or test backend).
	Dumps     uint64 `json:"dumps"`
	Large     uint64 `json:"large"`
	Fallbacks uint64 `json:"fallbacks"`
	MaxAddrs  int    `json:"max_addrs"`
	// LastFallback is the latest failed probe: when, which set, why.
	LastFallback *HostProbeFallback `json:"last_fallback,omitempty"`
}

// HostProbeFallback is one probe that failed and fell back to the dump.
type HostProbeFallback struct {
	At  string `json:"at"` // RFC3339
	Set string `json:"set"`
	Err string `json:"err"`
}

// HostProbeSnapshot returns ReadHostElems' counters.
func HostProbeSnapshot() HostProbeStats {
	out := HostProbeStats{
		Probed:      probeStats.probed.Load(),
		ProbedAddrs: probeStats.addrs.Load(),
		Dumps:       probeStats.dumps.Load(),
		Large:       probeStats.large.Load(),
		Fallbacks:   probeStats.fallbacks.Load(),
		MaxAddrs:    HostProbeMax,
	}
	probeStats.mu.Lock()
	if l := probeStats.last; l != nil {
		c := *l
		out.LastFallback = &c
	}
	probeStats.mu.Unlock()
	return out
}

var errProbeShape = errors.New("the probe answered for a different number of addresses")

// ProbedHosts turns per-address answers for want into the current elements
// PlanBlockBatch reads: one SetElementTimed per address the set holds.
func ProbedHosts(want []BlockEntry, found []bool, expires []time.Duration) []SetElementTimed {
	var out []SetElementTimed
	for i, w := range want {
		if found[i] {
			out = append(out, SetElementTimed{Elem: w.IP.String(), Expires: expires[i]})
		}
	}
	return out
}

// probeFallbackEvery bounds the fallback log line: once per set per interval,
// so a kernel that cannot answer gets says so without a line per ban.
const probeFallbackEvery = 10 * time.Minute

var probeFallbackLogged sync.Map // set name -> time.Time

func noteProbeFallback(set string, err error) {
	now := time.Now()
	probeStats.fallbacks.Add(1)
	probeStats.mu.Lock()
	probeStats.last = &HostProbeFallback{At: now.UTC().Format(time.RFC3339), Set: set, Err: err.Error()}
	probeStats.mu.Unlock()
	if v, ok := probeFallbackLogged.Load(set); ok && now.Sub(v.(time.Time)) < probeFallbackEvery {
		return
	}
	probeFallbackLogged.Store(set, now)
	logging.Logf("[firewall] %s: per-address read failed (%v); reading the whole set instead (counted in firewall_selftest host_probe; logged at most every 10 minutes)", set, err)
}
