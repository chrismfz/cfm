//go:build linux

package nftlib

// The backend's netlink handle: one socket per kernel call, and a deadline on
// every read.
//
// The backend used to hold ONE lasting netlink connection (AsLasting) for its
// whole life. Every firewall read and write in this package runs under b.mu,
// so two failure modes of that shared socket stalled or corrupted all of them:
//
//   - An operation that failed part-way could leave replies unread on the
//     socket. Flush returns early on ENOBUFS/EPERM with ACKs still queued, and
//     the next operation reads them as its own answer. GetRules and the set
//     dumps go through SendMessages + receiveAckAware, which don't check
//     sequence numbers, so that could be a silently wrong answer (e.g. "no
//     rules") rather than an error.
//   - Nothing bounded a receive, so a reply that never came held b.mu forever.
//
// Now each kernel call dials its own socket and closes it (a transient
// nftables.Conn, the library default), so no reply can outlive the call that
// asked for it. Measured on a real kernel, a 120,000-address feed write takes
// the same ~250ms as on the lasting socket.
//
// Reads — dumps and lookups — also get a deadline of nlOpTimeout. They change
// nothing, so a read that times out has lost nothing; its caller gets an
// error instead of holding b.mu indefinitely.
//
// Writes (Flush) deliberately get no deadline. The kernel applies a batch
// inside sendmsg, possibly after waiting for the nf_tables commit lock (e.g.
// behind another tool's `nft -f`). A socket deadline can't interrupt that
// wait; it only expires meanwhile, and then the ACK read fails at once — so
// a batch that WAS committed is reported as failed (reproduced in a netns: an
// AddBlock stuck 594ms behind a large `nft -f` returned "i/o timeout" with the
// address already in the set). Callers act on that error — an autoblock then
// skips its cfm.deny record and notification, EnsureBase skips invalidating
// its caches — so a false failure is worse than waiting.
//
// Messages queued for the next Flush (AddRule, SetAddElements, …) and the
// library's sticky marshal error still live on the one long-lived write Conn:
// a caller that queues and then returns before Flush still leaks those
// messages into the next Flush, as before.
//
// nlConn embeds the write Conn, so queueing calls and Flush go to it; the read
// methods are overridden to use the deadline-bounded read Conn. Every kernel
// call is timed for firewall_selftest; TestNLConnWrapsEveryKernelCall keeps
// the list complete.

import (
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	// nlOpTimeout bounds one netlink read (a dump or lookup). A healthy
	// 120,000-element set dump takes about a second; 30s leaves wide headroom
	// for a loaded or swapping host while still freeing b.mu long before
	// cfm-web's 3-minute offline threshold.
	nlOpTimeout = 30 * time.Second

	// nlSlowOp is the threshold for keeping a call in the slow ring. Above
	// the ~1s a healthy large dump takes, so routine big reads don't push out
	// the calls worth looking at.
	nlSlowOp = 5 * time.Second

	// nlDial opens the socket the startup probe checks; a var for tests.
	nlDial = func() (*netlink.Conn, error) { return netlink.Dial(unix.NETLINK_NETFILTER, nil) }
)

// nlSlowRingCap bounds the retained slow/timed-out calls.
const nlSlowRingCap = 16

// nlStats records every kernel call. It has its own mutex (never b.mu), like
// statMu, so recording can't add contention to the path it measures.
type nlStats struct {
	mu          sync.Mutex
	ops         uint64
	errs        uint64
	timeouts    uint64
	dials       uint64 // sockets opened; ≤ ops (an empty Flush sends nothing)
	slow        [nlSlowRingCap]nlSample
	slowN       int
	lastTimeout *nlSample
	deadlineErr string // non-empty if SetDeadline ever failed (reads then run unbounded)
}

type nlSample struct {
	at  time.Time
	op  string
	dur time.Duration
	err string
}

// countDial is the socket option for write sockets: no deadline (see above).
func (s *nlStats) countDial(*netlink.Conn) error {
	s.mu.Lock()
	s.dials++
	s.mu.Unlock()
	return nil
}

// readDeadline is the socket option for read sockets, applied at dial, i.e.
// at the start of every read.
func (s *nlStats) readDeadline(nl *netlink.Conn) error {
	_ = s.countDial(nl)
	if err := nl.SetDeadline(time.Now().Add(nlOpTimeout)); err != nil {
		s.mu.Lock()
		first := s.deadlineErr == ""
		if first {
			s.deadlineErr = err.Error()
		}
		s.mu.Unlock()
		if first {
			logging.Logf("[firewall] engine=nftlib netlink deadline unsupported, reads run unbounded: %v", err)
		}
	}
	// Fail open: an unbounded read is what the backend always had; refusing
	// the socket would take the whole firewall down instead.
	return nil
}

func (s *nlStats) record(op string, start time.Time, err error) {
	dur := time.Since(start)
	timedOut := isNLTimeout(err)
	s.mu.Lock()
	s.ops++
	if err != nil {
		s.errs++
	}
	if timedOut || dur >= nlSlowOp {
		smp := nlSample{at: start, op: op, dur: dur}
		if err != nil {
			smp.err = err.Error()
		}
		s.slow[s.slowN%nlSlowRingCap] = smp
		s.slowN++
		if timedOut {
			s.timeouts++
			s.lastTimeout = &smp
		}
	}
	s.mu.Unlock()
	if timedOut {
		logging.Logf("[firewall] engine=nftlib netlink %s timed out after %s; the read failed and changed nothing",
			op, dur.Round(time.Millisecond))
	}
}

// isNLTimeout reports whether err is a netlink deadline expiry. nftables
// wraps some receive errors with %v, which drops the error chain, so the
// message is checked too.
func isNLTimeout(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrDeadlineExceeded) || strings.Contains(err.Error(), "i/o timeout")
}

// nlConn is the write Conn (embedded: queueing calls + Flush) plus a
// deadline-bounded read Conn, with every kernel call timed.
type nlConn struct {
	*nftables.Conn
	read  *nftables.Conn
	stats *nlStats
}

// newNLConn returns the backend's transient connections. extra is applied to
// both (tests pass nftables.WithTestDial).
func newNLConn(stats *nlStats, extra ...nftables.ConnOption) (*nlConn, error) {
	// A transient Conn opens nothing until the first call. Dial once now so a
	// host without usable netlink still fails at startup, as the lasting dial
	// used to, rather than at the first firewall write.
	probe, err := nlDial()
	if err != nil {
		return nil, err
	}
	_ = probe.Close()
	opts := func(o nftables.ConnOption) []nftables.ConnOption {
		return append(append([]nftables.ConnOption{}, extra...), o) // fresh slice each time
	}
	w, err := nftables.New(opts(nftables.WithSockOptions(stats.countDial))...)
	if err != nil {
		return nil, err
	}
	r, err := nftables.New(opts(nftables.WithSockOptions(stats.readDeadline))...)
	if err != nil {
		return nil, err
	}
	return &nlConn{Conn: w, read: r, stats: stats}, nil
}

// timed runs one kernel call and records it.
func timed[T any](s *nlStats, op string, f func() (T, error)) (T, error) {
	start := time.Now()
	v, err := f()
	s.record(op, start, err)
	return v, err
}

// --- kernel calls (keep in sync with TestNLConnWrapsEveryKernelCall) ---

// Flush sends the queued batch on a write socket (no deadline).
func (c *nlConn) Flush() error {
	_, err := timed(c.stats, "Flush", func() (struct{}, error) { return struct{}{}, c.Conn.Flush() })
	return err
}

func (c *nlConn) GetRules(t *nftables.Table, ch *nftables.Chain) ([]*nftables.Rule, error) {
	return timed(c.stats, "GetRules", func() ([]*nftables.Rule, error) { return c.read.GetRules(t, ch) })
}

func (c *nlConn) GetSetElements(s *nftables.Set) ([]nftables.SetElement, error) {
	return timed(c.stats, "GetSetElements", func() ([]nftables.SetElement, error) { return c.read.GetSetElements(s) })
}

func (c *nlConn) GetSets(t *nftables.Table) ([]*nftables.Set, error) {
	return timed(c.stats, "GetSets", func() ([]*nftables.Set, error) { return c.read.GetSets(t) })
}

func (c *nlConn) GetSetByName(t *nftables.Table, name string) (*nftables.Set, error) {
	return timed(c.stats, "GetSetByName", func() (*nftables.Set, error) { return c.read.GetSetByName(t, name) })
}

func (c *nlConn) GetObjects(t *nftables.Table) ([]nftables.Obj, error) {
	return timed(c.stats, "GetObjects", func() ([]nftables.Obj, error) { return c.read.GetObjects(t) })
}

func (c *nlConn) ListChains() ([]*nftables.Chain, error) {
	return timed(c.stats, "ListChains", c.read.ListChains)
}

func (c *nlConn) ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error) {
	return timed(c.stats, "ListChainsOfTableFamily", func() ([]*nftables.Chain, error) { return c.read.ListChainsOfTableFamily(family) })
}

func (c *nlConn) ListTables() ([]*nftables.Table, error) {
	return timed(c.stats, "ListTables", c.read.ListTables)
}

func (c *nlConn) ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error) {
	return timed(c.stats, "ListTableOfFamily", func() (*nftables.Table, error) { return c.read.ListTableOfFamily(name, family) })
}
