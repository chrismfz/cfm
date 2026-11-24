package firewall

import (
	"errors"
	"net"
	"sync"
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
			return ProbedHosts(want, found, expires), nil
		}
		noteProbeFallback(set, err)
	}
	return dump()
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
	if v, ok := probeFallbackLogged.Load(set); ok && now.Sub(v.(time.Time)) < probeFallbackEvery {
		return
	}
	probeFallbackLogged.Store(set, now)
	logging.Logf("[firewall] %s: per-address read failed (%v); reading the whole set instead (logged once per %s)", set, err, probeFallbackEvery)
}
