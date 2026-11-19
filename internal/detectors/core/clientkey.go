package core

import (
	"net/netip"
	"strings"
	"sync"

	"cfm/internal/firewall"
)

// ClientKey is the counter key of a per-client kind ("…|ip"): an IPv6
// client counts as its /64 (firewall.CountKey; docs/edge-ipv6.md "IPv6 /64
// grouping"), so a client rotating its address inside the /64 fills one
// window instead of a fresh one per address; a /64 a guard keeps from being
// banned as a whole counts per address, as its ban is. Any other kind keeps
// key.
//
// Only the COUNT is grouped: the alert still carries a real address
// (Extra["ip"]), which the sink's allow / ignore / self checks read and
// which firewall.ExtendClientBlock widens to the /64 itself.
func ClientKey(kindKey, key string) string {
	if strings.HasSuffix(kindKey, "|ip") {
		return firewall.CountKey(key)
	}
	return key
}

// TagClient records the /64 an IPv6 address was counted as (Extra
// "client"), for the alert's reader; IPv4, ungrouped and guarded addresses
// add nothing.
func TagClient(extra map[string]string, ip string) {
	if c := firewall.CountKey(ip); strings.Contains(c, "/") && extra != nil {
		extra["client"] = c
	}
}

// GuardAllows registers a detector's own allow list (ALLOW_IPS /
// ALLOW_NETS: addresses or CIDRs) as a /64 guard under "allow:"+name: a /64
// that holds an allowed IPv6 address is then counted and banned per address
// (firewall.SetClientNetExempt), as a /64 holding an nft-allowed address is,
// by every section and at the edge, so its neighbours' hits can never ban
// the allowed address with their /64. Only entries narrower than a /64
// guard: a /64 or wider entry allows its whole /64s in that detector already
// (no neighbour there is counted), and would otherwise switch the grouping
// off for every /64 it covers.
//
// Called from the detector's constructor. Inside a manager sweep
// (BeginGuardSweep / EndGuardSweep) the sections of one type add up and a
// type no section built any more is dropped; outside one (tests) a call
// replaces the list.
func GuardAllows(name string, entries ...[]string) {
	var nets []netip.Prefix
	for _, list := range entries {
		for _, e := range list {
			e = strings.TrimSpace(e)
			p, err := netip.ParsePrefix(e)
			if err != nil {
				a, aerr := netip.ParseAddr(e)
				if aerr != nil {
					continue
				}
				p = netip.PrefixFrom(a, a.BitLen())
			}
			if a := p.Addr(); a.Is6() && !a.Is4In6() && p.Bits() > 64 {
				nets = append(nets, p.Masked())
			}
		}
	}
	guardMu.Lock()
	defer guardMu.Unlock()
	g := guards[name]
	if !guardSweeping || g.gen != guardGen {
		g = guardEntry{}
	}
	g.gen = guardGen
	g.nets = append(g.nets, nets...)
	guards[name] = g
	setGuardLocked(name, g.nets)
}

type guardEntry struct {
	gen  int
	nets []netip.Prefix
}

var (
	guardMu       sync.Mutex
	guards        = map[string]guardEntry{}
	guardGen      int
	guardSweeping bool
)

// BeginGuardSweep starts a detectors build sweep (manager.go): the
// GuardAllows calls until EndGuardSweep are the whole set.
func BeginGuardSweep() {
	guardMu.Lock()
	guardGen++
	guardSweeping = true
	guardMu.Unlock()
}

// EndGuardSweep drops the allow guards no section registered in the sweep
// (a section disabled, removed or failing its build).
func EndGuardSweep() {
	guardMu.Lock()
	defer guardMu.Unlock()
	guardSweeping = false
	for name, g := range guards {
		if g.gen != guardGen {
			delete(guards, name)
			setGuardLocked(name, nil)
		}
	}
}

func setGuardLocked(name string, nets []netip.Prefix) {
	if len(nets) == 0 {
		firewall.SetClientNetExempt("allow:"+name, nil)
		return
	}
	nets = append([]netip.Prefix(nil), nets...)
	firewall.SetClientNetExempt("allow:"+name, func(p netip.Prefix) bool {
		for _, n := range nets {
			if n.Overlaps(p) {
				return true
			}
		}
		return false
	})
}
