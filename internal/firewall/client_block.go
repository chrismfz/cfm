package firewall

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cfm/internal/ipkey"
	"cfm/internal/logging"
)

// Automatic L7 bans of an IPv6 client take its /64 (docs/edge-ipv6.md "IPv6
// /64 grouping"): a client rotating its address inside the /64 any VPS or ISP
// line hands it would otherwise walk past a ban on one address. The blockers
// that ban this way see a real session (an HTTP request, a login): the
// detector sinks, the challenge server, the admin API's login autoblock. The
// kernel flood / port-scan autoblock counts packets whose source can be
// spoofed and stays per address (ExtendBlockResult), as do manual bans.
//
// The /64s live in their own set, block_v6_clients (interval, timeout), with
// their own drops in `inet cfm input` right after block_v6_nets' (both
// backends' EnsureBase). In block_v6_nets they collided with the operator's
// own IPv6 CIDRs: nft refuses an element overlapping another, so a manual
// /48 (or a cfm.deny one after a reboot) failed over an automatic /64.
//
// A /64 is only ever added or extended, as ExtendBlock does for a host, and
// an extend replaces the element in one transaction (SetElemWriter). The
// address is banned instead when:
//   - the /64 holds an address of this node (its interfaces, and self_v6: a
//     provider handing one /64 to several customers' VPSes), an ignored
//     address or network (ignore_v6 / ignore_v6_nets, and IGNORE_IPS /
//     IGNORE_NETS), or a trusted proxy's range (Cloudflare's: a detector that
//     saw a proxy's own address must not ban the proxy's /64). The last two
//     come through SetClientNetExempt. nft has no accept for any of them
//     before its drops;
//   - the backend cannot write the set (no SetElemWriter, a read or write
//     error).
//   - the /64 holds an allowed address or network: nft would still accept
//     it (every allow set comes before the drops), but the edge ban store
//     never answers a /64 an allow touches and the TTL restore drops one, so
//     a /64 ban there would hold only for direct clients and not survive a
//     restart. The small manual allow sets are read here; the fleet's
//     (allow_ext_*) come from the edge ban store's snapshot, registered as
//     "allow_sets".

// BlockV6Clients is the set of automatic IPv6 client /64 bans.
const BlockV6Clients = "block_v6_clients"

// SetElemWriter writes one element of a set: both backends implement it.
type SetElemWriter interface {
	// WriteSetElem writes elem to set with ttl (nil: permanent). replace
	// deletes the element equal to elem first, in the same transaction, so
	// it is never absent in between.
	WriteSetElem(set, elem string, ttl *time.Duration, replace bool) error
	// DeleteSetElem deletes elem from set; an element the set does not hold
	// is not an error.
	DeleteSetElem(set, elem string) error
	// WriteSetElems is WriteSetElem for many elements in ONE transaction
	// (the TTL ban restore; the caller chunks): all written or none.
	WriteSetElems(set string, elems []SetElemWrite) error
}

// SetElemWrite is one element for WriteSetElems.
type SetElemWrite struct {
	Elem    string
	TTL     *time.Duration // nil: permanent
	Replace bool           // delete the element equal to Elem first
}

// NetBan is one /64 for ExtendBlockNets.
type NetBan struct {
	P   netip.Prefix
	TTL time.Duration
}

// netBatchChunk is how many elements one WriteSetElems transaction holds.
const netBatchChunk = 500

// ExtendBlockNets bans many /64s in block_v6_clients, never shortening a ban:
// the TTL ban restore. One guard read and one read of the set for the whole
// batch, then one transaction per netBatchChunk elements; a refused chunk is
// retried one element at a time, so one bad element costs only itself (one at
// a time, 1000 restored /64s took 34 s on exec, past the edge ban store's
// wait). guarded lists the /64s a guard refused (ErrClientNetGuarded's
// cases), failed the ones that could not be written.
func ExtendBlockNets(be Backend, bans []NetBan) (res BlockBatchResult, guarded []netip.Prefix, failed map[netip.Prefix]error) {
	failed = map[netip.Prefix]error{}
	failAll := func(err error) {
		for _, b := range bans {
			failed[b.P] = err
		}
	}
	w, ok := be.(SetElemWriter)
	if !ok {
		failAll(fmt.Errorf("this backend cannot write %s", BlockV6Clients))
		return res, nil, failed
	}
	view, err := newGuardView(be)
	if err != nil {
		failAll(fmt.Errorf("cannot check what the /64s hold: %w", err))
		return res, nil, failed
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	elems, err := be.ListSetElementsTimed(BlockV6Clients)
	if err != nil {
		failAll(fmt.Errorf("cannot read %s: %w", BlockV6Clients, err))
		return res, nil, failed
	}
	type held struct {
		permanent bool
		left      time.Duration
	}
	have := map[netip.Prefix]held{}
	for _, e := range elems {
		if p, err := netip.ParsePrefix(strings.TrimSpace(e.Elem)); err == nil {
			have[p.Masked()] = held{e.Expires <= 0, e.Expires}
		}
	}
	// One /64 once, at its longest TTL: one transaction must not add an
	// interval twice.
	longest := map[netip.Prefix]time.Duration{}
	var order []NetBan
	for _, b := range bans {
		if t, seen := longest[b.P]; seen {
			longest[b.P] = max(t, b.TTL)
			continue
		}
		longest[b.P] = b.TTL
		order = append(order, b)
	}
	var writes []SetElemWrite
	extended := map[string]bool{}
	for _, b := range order {
		b.TTL = longest[b.P]
		p := b.P.Masked()
		if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p != b.P {
			failed[b.P] = fmt.Errorf("not an IPv6 network: %v", b.P)
			continue
		}
		if why := view.refuses(p); why != "" {
			logging.Logf("[firewall] ban of %s: %s", p, why)
			guarded = append(guarded, p)
			continue
		}
		ttl := b.TTL
		if ttl < time.Second {
			ttl = time.Second
		}
		h, exists := have[p]
		if exists && (h.permanent || h.left >= ttl) {
			res.Kept++
			continue
		}
		t := ttl
		writes = append(writes, SetElemWrite{Elem: p.String(), TTL: &t, Replace: exists})
		extended[p.String()] = exists
	}
	count := func(e SetElemWrite) {
		if extended[e.Elem] {
			res.Extended++
		} else {
			res.Added++
		}
	}
	for i := 0; i < len(writes); i += netBatchChunk {
		chunk := writes[i:min(i+netBatchChunk, len(writes))]
		if err := w.WriteSetElems(BlockV6Clients, chunk); err == nil {
			for _, e := range chunk {
				count(e)
			}
			continue
		}
		for _, e := range chunk { // one at a time: the bad one costs only itself
			err := w.WriteSetElem(BlockV6Clients, e.Elem, e.TTL, e.Replace)
			if err != nil && e.Replace {
				// Expired since the read: its delete fails, a plain add stands.
				err = w.WriteSetElem(BlockV6Clients, e.Elem, e.TTL, false)
			}
			if err != nil {
				failed[netip.MustParsePrefix(e.Elem)] = err
				continue
			}
			count(e)
		}
	}
	return res, guarded, failed
}

// netBlockMu serialises the read-then-write of a /64 ban: two extends of one
// /64 racing would let the shorter write land last.
var netBlockMu sync.Mutex

// ErrClientNetGuarded is ExtendBlockNet's answer for a /64 a guard refuses
// (it holds this node's address, an ignored one, a trusted proxy's): the
// TTL ban restore counts it excluded, not failed.
var ErrClientNetGuarded = errors.New("the /64 holds an address it must not drop")

// clientNetExempt holds the daemon's checks for a /64, by name
// (SetClientNetExempt).
var (
	clientNetExemptMu sync.Mutex
	clientNetExempt   atomic.Pointer[map[string]func(netip.Prefix) bool]
)

// SetClientNetExempt registers f under name: a /64 for which it returns true
// is never banned as a whole (the address is). The detectors manager
// registers "ignore" ([global] IGNORE_IPS / IGNORE_NETS, on every config
// load), the edge ban store "trusted_proxies"; nil removes name.
func SetClientNetExempt(name string, f func(netip.Prefix) bool) {
	clientNetExemptMu.Lock()
	defer clientNetExemptMu.Unlock()
	next := map[string]func(netip.Prefix) bool{}
	if cur := clientNetExempt.Load(); cur != nil {
		for k, v := range *cur {
			next[k] = v
		}
	}
	if f == nil {
		delete(next, name)
	} else {
		next[name] = f
	}
	clientNetExempt.Store(&next)
	ResetCountKeyCache() // CountKey asks these: a new entry applies at once
}

// clientNetExemptRegistered reports whether a check is registered under name.
func clientNetExemptRegistered(name string) bool {
	cur := clientNetExempt.Load()
	if cur == nil {
		return false
	}
	_, ok := (*cur)[name]
	return ok
}

// ClientNetExempted reports which registered check refuses p ("" when none).
func ClientNetExempted(p netip.Prefix) string {
	cur := clientNetExempt.Load()
	if cur == nil {
		return ""
	}
	for name, f := range *cur {
		if f(p) {
			return name
		}
	}
	return ""
}

// localAddrs are this node's interface addresses (a var: tests replace it).
var localAddrs = net.InterfaceAddrs

// ClientNet is the /64 an automatic ban of ip takes; ok is false for IPv4 and
// for the IPv6 addresses ipkey does not group, which are banned as they are.
func ClientNet(ip net.IP) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	return ipkey.Prefix(a.Unmap())
}

// ExtendClientBlock is ExtendBlock for an automatic L7 blocker: an IPv6
// client is banned as its /64. elem is what was banned (the /64, or the
// address), which the caller hands to the edge ban store (edgeban.BanElem)
// so the edge answers for exactly what nft drops.
func ExtendClientBlock(be Backend, ip net.IP, ttl time.Duration) (elem string, kept bool, err error) {
	if p, ok := ClientNet(ip); ok {
		if res, done := extendClientNet(be, ip, p, ttl); done {
			return p.String(), res.Kept > 0, nil
		}
	}
	res, err := ExtendBlockResult(be, ip, ttl)
	if err != nil {
		return "", false, err
	}
	if res.Added+res.Extended+res.Kept+res.Present == 0 {
		return "", false, fmt.Errorf("not blockable: %v", ip)
	}
	return ip.String(), res.Kept > 0, nil
}

// BlockClientPermanent is an automatic L7 blocker's permanent ban: an IPv6
// client's /64 (a permanent element of block_v6_clients), else AddBlock of
// the address. elem as in ExtendClientBlock. Like a permanent host ban from a
// detector, it is not written to cfm.deny.
func BlockClientPermanent(be Backend, ip net.IP, comment string) (elem string, err error) {
	if p, ok := ClientNet(ip); ok {
		if _, done, _ := writeClientNet(be, ip, p, nil); done {
			return p.String(), nil
		}
	}
	if err := be.AddBlock(ip, comment, nil); err != nil {
		return "", err
	}
	return ip.String(), nil
}

// ExtendBlockNet bans p for ttl in block_v6_clients, never shortening a ban:
// the TTL ban restore (internal/ttlban). It runs the same guards as an
// automatic ban; with no address to fall back to, a p it cannot write is an
// error.
func ExtendBlockNet(be Backend, p netip.Prefix, ttl time.Duration) (BlockBatchResult, error) {
	if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() || p != p.Masked() {
		return BlockBatchResult{}, fmt.Errorf("not an IPv6 network: %v", p)
	}
	if ttl < time.Second {
		ttl = time.Second
	}
	res, done, guarded := writeClientNet(be, nil, p, &ttl)
	switch {
	case guarded != "":
		return BlockBatchResult{}, fmt.Errorf("%s: %s: %w", p, guarded, ErrClientNetGuarded)
	case !done:
		return res, fmt.Errorf("%s: not written to %s (see the log)", p, BlockV6Clients)
	}
	return res, nil
}

// RemoveClientNets is RemoveClientNet for many addresses (a mass unblock):
// the /64s deduplicated, block_v6_clients read once, only the /64s it holds
// deleted. The result maps each address whose /64 could not be checked or
// deleted to the error (an address not grouped, or whose /64 is not held,
// has none).
func RemoveClientNets(be Backend, ips []net.IP) map[string]error {
	byNet := map[netip.Prefix][]string{}
	for _, ip := range ips {
		if p, ok := ClientNet(ip); ok {
			byNet[p] = append(byNet[p], ip.String())
		}
	}
	if len(byNet) == 0 {
		return nil
	}
	w, ok := be.(SetElemWriter)
	if !ok {
		return nil // nothing can have written them
	}
	fail := func(nets []netip.Prefix, err error) map[string]error {
		out := map[string]error{}
		for _, p := range nets {
			for _, ip := range byNet[p] {
				out[ip] = err
			}
		}
		return out
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	elems, err := be.ListSetElementsTimed(BlockV6Clients)
	if err != nil {
		all := make([]netip.Prefix, 0, len(byNet))
		for p := range byNet {
			all = append(all, p)
		}
		if IsMissingSet(err) {
			return nil // a table from before the set: nothing to free
		}
		return fail(all, fmt.Errorf("read %s: %w", BlockV6Clients, err))
	}
	held := map[netip.Prefix]bool{}
	for p := range byNet {
		plo, phi := prefixRange(p)
		for _, e := range elems {
			if lo, hi, ok := ElemRange(e.Elem); ok && lo == plo && hi == phi {
				held[p] = true
				break
			}
		}
	}
	var out map[string]error
	for p := range byNet {
		if !held[p] {
			continue
		}
		if err := w.DeleteSetElem(BlockV6Clients, p.String()); err != nil {
			if out == nil {
				out = map[string]error{}
			}
			for k, v := range fail([]netip.Prefix{p}, err) {
				out[k] = v
			}
		}
	}
	return out
}

// IsMissingSet reports nft's (or nftlib's) error for a set or table that does
// not exist (a table an older daemon built): ENOENT, "No such file or
// directory". Not any "not found": a missing nft binary ("executable file
// not found") is a failure.
func IsMissingSet(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOENT) && !errors.Is(err, exec.ErrNotFound) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such file or directory")
}

// RemoveClientNet is the unblock side: it removes the /64 an automatic ban
// of ip's client took (unblocking an IPv6 address frees its client, the
// /64). net is "" when ip is not grouped; a /64 the set does not hold is no
// error.
func RemoveClientNet(be Backend, ip net.IP) (net string, err error) {
	p, ok := ClientNet(ip)
	if !ok {
		return "", nil
	}
	w, ok := be.(SetElemWriter)
	if !ok {
		return p.String(), nil // nothing can have written it
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	if err := w.DeleteSetElem(BlockV6Clients, p.String()); err != nil && !IsMissingSet(err) {
		return p.String(), err
	}
	return p.String(), nil // removed, not held, or a table from before the set
}

// RemoveClientPrefix removes the /64 ban p from block_v6_clients (the TTL ban
// restore's undo of an unblock that landed during it); not held is no error.
func RemoveClientPrefix(be Backend, p netip.Prefix) error {
	w, ok := be.(SetElemWriter)
	if !ok {
		return nil
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	return w.DeleteSetElem(BlockV6Clients, p.String())
}

// extendClientNet bans p for ttl, never shortening a ban. done is false when
// the /64 must not or could not be written (the caller bans the address).
func extendClientNet(be Backend, ip net.IP, p netip.Prefix, ttl time.Duration) (BlockBatchResult, bool) {
	if ttl < time.Second {
		ttl = time.Second // as SplitBlockEntries: "0s" would read as permanent
	}
	res, done, _ := writeClientNet(be, ip, p, &ttl)
	return res, done
}

// writeClientNet writes p to block_v6_clients for ttl (nil: permanent),
// never shortening what is there. guarded names why a guard refused p ("" when
// none did).
func writeClientNet(be Backend, ip net.IP, p netip.Prefix, ttl *time.Duration) (res BlockBatchResult, done bool, guarded string) {
	what := p.String()
	if ip != nil {
		what = fmt.Sprintf("%s as %s", ip, p)
	}
	fallback := func(why string) (BlockBatchResult, bool, string) {
		if ip == nil {
			logging.Logf("[firewall] ban of %s: %s", what, why)
		} else {
			logging.Logf("[firewall] ban of %s: %s; banning the address instead", what, why)
		}
		return BlockBatchResult{}, false, ""
	}
	w, ok := be.(SetElemWriter)
	if !ok {
		return fallback("this backend cannot write " + BlockV6Clients)
	}
	if why, err := clientNetGuard(be, p); err != nil {
		return fallback(fmt.Sprintf("cannot check what the /64 holds: %v", err))
	} else if why != "" {
		r, d, _ := fallback(why)
		return r, d, why
	}
	netBlockMu.Lock()
	defer netBlockMu.Unlock()
	elems, err := be.ListSetElementsTimed(BlockV6Clients)
	if err != nil {
		return fallback(fmt.Sprintf("cannot read %s: %v", BlockV6Clients, err))
	}
	exists, permanent, left := false, false, time.Duration(0)
	for _, e := range elems {
		lo, hi, ok := ElemRange(e.Elem)
		if !ok {
			continue
		}
		if plo, phi := prefixRange(p); lo == plo && hi == phi {
			exists, permanent, left = true, e.Expires <= 0, e.Expires
			break
		}
	}
	switch {
	case exists && permanent:
		return BlockBatchResult{Kept: 1, Net: p.String()}, true, ""
	case exists && ttl != nil && left >= *ttl:
		return BlockBatchResult{Kept: 1, Net: p.String()}, true, ""
	}
	if err := w.WriteSetElem(BlockV6Clients, p.String(), ttl, exists); err != nil {
		return fallback(fmt.Sprintf("cannot write %s: %v", BlockV6Clients, err))
	}
	if exists {
		return BlockBatchResult{Extended: 1, Net: p.String()}, true, ""
	}
	return BlockBatchResult{Added: 1, Net: p.String()}, true, ""
}

// clientNetGuardSets are the sets whose addresses a /64 ban must not cover:
// this node's, the ignored (nft accepts neither before its drops), and the
// small manual allow sets (the rest of the allows: "allow_sets").
var clientNetGuardSets = []string{"self_v6", "ignore_v6", "ignore_v6_nets", "allow_v6", "allow_dyn_v6", "allow_v6_nets"}

// clientNetFleetAllowSets are the fleet whitelist's IPv6 sets, read only while
// no "allow_sets" snapshot is registered.
var clientNetFleetAllowSets = []string{"allow_ext_v6_hosts", "allow_ext_v6_nets"}

// guardSpan is one element of a guard set, as its first and last address.
type guardSpan struct {
	lo, hi netip.Addr
	text   string // the element, or the address, as logged
	what   string // "this node's own address", the set's name
}

// guardView is what a /64 must not cover, read once: this node's interface
// addresses and default-route gateways, and the guard sets' elements. The
// registered checks (SetClientNetExempt) are asked live.
type guardView struct {
	spans []guardSpan
}

// refuses says why p must not be banned as a whole ("" when it may).
func (v *guardView) refuses(p netip.Prefix) string {
	if name := ClientNetExempted(p); name != "" {
		return fmt.Sprintf("the /64 is refused by the %s check", name)
	}
	plo, phi := prefixRange(p)
	for _, g := range v.spans {
		if !g.hi.Less(plo) && !phi.Less(g.lo) {
			return fmt.Sprintf("the /64 holds %s (%s)", g.what, g.text)
		}
	}
	return ""
}

// guardCacheTTL is how long a live ban reuses a guardView (each read is
// several nft runs on exec: an IPv6 ban storm must not pay them per ban).
// An allow, ignore or self address added since is seen within it. A var:
// tests set 0.
var guardCacheTTL = 10 * time.Second

var (
	guardCacheMu sync.Mutex
	guardCache   struct {
		be   Backend
		at   time.Time
		view *guardView
		err  error // a failed read, answered for guardErrTTL
		sets int   // the number of sets it read (the fleet allows or not)

		refreshing bool // a background refresh (staleGuardView) is running
		gen        int  // bumped by every write and reset: a refresh started
		// before one must not overwrite it
	}
)

// guardErrTTL is how long a failed guard read is answered from the cache: a
// counter (firewall.CountKey) asks per IPv6 event, and with nft failing each
// new /64 would otherwise run every guard set's read again, in turn.
var guardErrTTL = 5 * time.Second

// cachedGuardView is newGuardView, reused for guardCacheTTL on one backend.
func cachedGuardView(be Backend) (*guardView, error) {
	sets := len(guardSetsNow())
	guardCacheMu.Lock()
	c := &guardCache
	if guardCacheTTL > 0 && c.be == be && c.sets == sets {
		if c.view != nil && time.Since(c.at) < guardCacheTTL {
			v := c.view
			guardCacheMu.Unlock()
			return v, nil
		}
		if c.err != nil && time.Since(c.at) < guardErrTTL {
			err := c.err
			guardCacheMu.Unlock()
			return nil, err
		}
	}
	gen := c.gen
	guardCacheMu.Unlock()
	// The read runs unlocked: a counter (staleGuardView) never waits on a
	// ban's nft reads. Two readers at once both read; the later write wins
	// unless a reset came in between.
	v, err := newGuardView(be)
	guardCacheMu.Lock()
	if c.gen == gen || c.be != be {
		c.be, c.at, c.view, c.err, c.sets = be, time.Now(), v, err, sets
		c.gen++
	}
	guardCacheMu.Unlock()
	if err != nil {
		return nil, err
	}
	return v, nil
}

// staleGuardView is cachedGuardView for a hot path (firewall.CountKey, per
// IPv6 event): a stale view is answered at once while one background
// refresh replaces it, so no log tailer or HTTP handler waits on nft's reads.
// With no view at all it reads as cachedGuardView does.
func staleGuardView(be Backend) (*guardView, error) {
	sets := len(guardSetsNow())
	guardCacheMu.Lock()
	c := &guardCache
	if guardCacheTTL > 0 && c.be == be && c.sets == sets && c.view != nil {
		v := c.view
		if time.Since(c.at) >= guardCacheTTL && !c.refreshing {
			c.refreshing = true
			gen := c.gen
			go func() {
				nv, err := newGuardView(be)
				guardCacheMu.Lock()
				defer guardCacheMu.Unlock()
				c.refreshing = false
				if c.gen != gen || c.be != be || c.sets != sets {
					return // replaced or reset meanwhile
				}
				c.at, c.view, c.err = time.Now(), nv, err
				c.gen++
			}()
		}
		guardCacheMu.Unlock()
		return v, nil
	}
	guardCacheMu.Unlock()
	return cachedGuardView(be)
}

// ResetGuardCache drops the cached guard view: the next ban reads its guards
// afresh (a test that changes a guard set behind the backend's back).
func ResetGuardCache() {
	guardCacheMu.Lock()
	guardCache.view, guardCache.err = nil, nil
	guardCache.gen++
	guardCacheMu.Unlock()
}

// guardSetsNow are the sets a guardView reads now: the fleet whitelist's too
// while no "allow_sets" snapshot is registered (boot, before the edge ban
// store's first reconcile; or a store cleared after failed reads).
func guardSetsNow() []string {
	if clientNetExemptRegistered("allow_sets") {
		return clientNetGuardSets
	}
	return append(append([]string(nil), clientNetGuardSets...), clientNetFleetAllowSets...)
}

// procIPv6Route is the kernel's IPv6 routing table (a var: tests point it at
// a file).
var procIPv6Route = "/proc/net/ipv6_route"

// defaultGateways are the next hops of this node's IPv6 default routes: the
// provider's router, whose /64 a ban must not cover (dropping its
// neighbour discovery would cut the node's IPv6). A link-local one is
// ungrouped anyway.
func defaultGateways() []netip.Addr {
	raw, err := os.ReadFile(procIPv6Route) // #nosec G304 -- fixed kernel path
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != strings.Repeat("0", 32) || f[1] != "00" || f[4] == strings.Repeat("0", 32) {
			continue
		}
		b, err := hex.DecodeString(f[4])
		if err != nil || len(b) != 16 {
			continue
		}
		out = append(out, netip.AddrFrom16([16]byte(b)))
	}
	return out
}

// newGuardView reads what a /64 must not cover. A guard set it cannot read is
// an error (the caller bans the address).
func newGuardView(be Backend) (*guardView, error) {
	v := &guardView{}
	// This node's own addresses, from its interfaces: self_v6 below is
	// rewritten (flushed, then filled) on every refresh, and a read in
	// between would miss them.
	if addrs, err := localAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is6() {
					ip = ip.Unmap()
					v.spans = append(v.spans, guardSpan{lo: ip, hi: ip, text: ip.String(), what: "this node's own address"})
				}
			}
		}
	}
	for _, gw := range defaultGateways() {
		v.spans = append(v.spans, guardSpan{lo: gw, hi: gw, text: gw.String(), what: "this node's default gateway"})
	}
	for _, set := range guardSetsNow() {
		elems, err := be.ListSetElementsTimed(set)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", set, err)
		}
		what := set
		if set == "self_v6" {
			what = "this node's own address"
		}
		for _, e := range elems {
			if lo, hi, ok := ElemRange(e.Elem); ok && lo.Is6() {
				v.spans = append(v.spans, guardSpan{lo: lo, hi: hi, text: strings.TrimSpace(e.Elem), what: what})
			}
		}
	}
	return v, nil
}

// clientNetGuard says why p must not be banned as a whole ("" when it may),
// from the cached view.
func clientNetGuard(be Backend, p netip.Prefix) (string, error) {
	v, err := cachedGuardView(be)
	if err != nil {
		return "", err
	}
	return v.refuses(p), nil
}

// prefixRange is p's first and last address.
func prefixRange(p netip.Prefix) (netip.Addr, netip.Addr) {
	p = p.Masked()
	lo := p.Addr()
	b := lo.As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return lo, netip.AddrFrom16(b)
}

// ElemRange reads a set element as nft lists it (an address, a CIDR, or a
// first-last range) as its first and last address.
func ElemRange(s string) (lo, hi netip.Addr, ok bool) {
	s = strings.TrimSpace(s)
	if a, b, isRange := strings.Cut(s, "-"); isRange {
		lo, err1 := netip.ParseAddr(strings.TrimSpace(a))
		hi, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil || lo.Is4() != hi.Is4() || hi.Less(lo) {
			return netip.Addr{}, netip.Addr{}, false
		}
		return lo.Unmap(), hi.Unmap(), true
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false
		}
		if p.Addr().Is4() {
			lo := p.Masked().Addr()
			v := lo.As4()
			n := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
			if p.Bits() == 0 {
				n = ^uint32(0)
			} else {
				n |= uint32(1)<<(32-uint(p.Bits())) - 1
			}
			return lo, netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true
		}
		lo, hi := prefixRange(p)
		return lo, hi, true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	a = a.Unmap()
	return a, a, true
}

// ParseClientTarget reads an unblock target: an address, or an IPv6 client
// /64 as an automatic ban names it ("2001:db8:1:2::/64", the text of
// block_v6_clients and of the ban notification), which stands for any
// address of it. Anything else is nil.
func ParseClientTarget(s string) net.IP {
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != 64 {
		return nil
	}
	ip := net.IP(p.Masked().Addr().AsSlice())
	if cn, ok := ClientNet(ip); !ok || cn != p.Masked() {
		return nil // an ungrouped range: no client /64 to free
	}
	return ip
}
