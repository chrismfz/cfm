//go:build linux

package nftlib

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

func stubNLTimeouts(t *testing.T, op, slow time.Duration) {
	t.Helper()
	origOp, origSlow := nlOpTimeout, nlSlowOp
	t.Cleanup(func() { nlOpTimeout, nlSlowOp = origOp, origSlow })
	nlOpTimeout, nlSlowOp = op, slow
}

// The deadline option really bounds a receive on a real netfilter socket. No
// privileges needed: the socket is only opened and read, never sent to.
func TestNLDeadline_BoundsARealReceive(t *testing.T) {
	stubNLTimeouts(t, 100*time.Millisecond, time.Second)
	nl, err := nlDial()
	if err != nil {
		t.Skipf("no netfilter netlink socket here: %v", err)
	}
	defer nl.Close()

	var st nlStats
	if err := st.readDeadline(nl); err != nil {
		t.Fatalf("readDeadline: %v", err)
	}
	if st.deadlineErr != "" {
		t.Fatalf("a real netlink socket must accept a deadline: %s", st.deadlineErr)
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() { _, err := nl.Receive(); done <- err }()
	select {
	case err := <-done:
		if !isNLTimeout(err) {
			t.Fatalf("want an i/o timeout, got %v", err)
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Fatalf("deadline fired late: %s", el)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("receive with a 100ms deadline did not return")
	}
}

// Every operation must run on its own socket: that is what makes a stuck or
// half-read reply impossible to carry into the next operation. Reintroducing
// a lasting connection breaks this test.
func TestNewNLConn_OneSocketPerOperation(t *testing.T) {
	var st nlStats
	c, err := newNLConn(&st)
	if err != nil {
		t.Skipf("no netfilter netlink socket here: %v", err)
	}
	// Unprivileged these fail with EPERM; either way each is a round-trip.
	_, _ = c.ListTables()
	_, _ = c.ListTables()
	if st.dials != 2 || st.ops != 2 {
		t.Fatalf("want one socket per operation: dials=%d ops=%d", st.dials, st.ops)
	}
}

// nlTestConn builds an nlConn through the real constructor, with every socket
// (the startup probe included) going to fn. nltest sockets don't take
// deadlines, which also exercises the fail-open path.
func nlTestConn(t *testing.T, st *nlStats, fn nltest.Func) *nlConn {
	t.Helper()
	orig := nlDial
	nlDial = func() (*netlink.Conn, error) { return nltest.Dial(fn), nil }
	defer func() { nlDial = orig }()
	c, err := newNLConn(st, nftables.WithTestDial(fn))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The design's core property, pinned through the real constructor: a write
// (Flush) socket never gets a deadline, a read socket always does. nltest
// sockets refuse deadlines, so deadlineErr records the first socket that
// tried to set one.
func TestNewNLConn_WritesUnboundedReadsBounded(t *testing.T) {
	var st nlStats
	c := nlTestConn(t, &st, func([]netlink.Message) ([]netlink.Message, error) { return nil, io.EOF })

	c.AddTable(&nftables.Table{Name: "t", Family: nftables.TableFamilyINet})
	if err := c.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if st.deadlineErr != "" || st.dials != 1 {
		t.Fatalf("a write must dial its own socket without a deadline: dials=%d deadlineErr=%q", st.dials, st.deadlineErr)
	}
	if _, err := c.ListTables(); err != nil {
		t.Fatalf("read: %v", err)
	}
	if st.deadlineErr == "" || st.dials != 2 {
		t.Fatalf("a read must dial its own socket and set a deadline: dials=%d deadlineErr=%q", st.dials, st.deadlineErr)
	}
}

func TestNLConn_RecordsTimeoutsAndSlowOps(t *testing.T) {
	stubNLTimeouts(t, time.Second, 20*time.Millisecond)
	var st nlStats
	var mode string
	c := nlTestConn(t, &st, func([]netlink.Message) ([]netlink.Message, error) {
		switch mode {
		case "timeout":
			return nil, os.ErrDeadlineExceeded
		case "slow":
			time.Sleep(40 * time.Millisecond)
		}
		return nil, io.EOF // an empty, successful dump
	})

	mode = "ok"
	if _, err := c.ListTables(); err != nil {
		t.Fatalf("ok op: %v", err)
	}
	mode = "timeout"
	if _, err := c.ListTables(); !isNLTimeout(err) {
		t.Fatalf("want the timeout surfaced to the caller, got %v", err)
	}
	mode = "slow"
	if _, err := c.ListTables(); err != nil {
		t.Fatalf("slow op: %v", err)
	}

	if st.ops != 3 || st.errs != 1 || st.timeouts != 1 {
		t.Fatalf("counts: ops=%d errs=%d timeouts=%d", st.ops, st.errs, st.timeouts)
	}
	if st.deadlineErr == "" {
		t.Fatal("a socket without deadline support must be recorded (and still used)")
	}
	snap := st.snapshot()
	if snap.LastTimeout == nil || snap.LastTimeout.Op != "ListTables" || snap.LastTimeout.Err == "" {
		t.Fatalf("last timeout = %+v", snap.LastTimeout)
	}
	if len(snap.SlowRecent) != 2 || snap.SlowRecent[0].Err == "" || snap.SlowRecent[1].Err != "" {
		t.Fatalf("slow ring must hold the timeout then the slow op, oldest first: %+v", snap.SlowRecent)
	}
}

func TestNLStats_SlowRingKeepsNewestOldestFirst(t *testing.T) {
	stubNLTimeouts(t, time.Second, 0) // every op counts as slow
	b := &Backend{}
	n := nlSlowRingCap + 4
	base := time.Now().Add(-time.Duration(n) * time.Second) // starts in the past, increasing
	for i := 0; i < n; i++ {
		b.nl.record("op"+string(rune('a'+i)), base.Add(time.Duration(i)*time.Second), nil)
	}
	got := b.NftlibSelfTest().Netlink
	if got == nil || len(got.SlowRecent) != nlSlowRingCap {
		t.Fatalf("netlink stats missing or ring not capped: %+v", got)
	}
	if first, last := got.SlowRecent[0].Op, got.SlowRecent[nlSlowRingCap-1].Op; first != "ope" || last != "opt" {
		t.Fatalf("ring order: first=%s last=%s, want ope..opt", first, last)
	}
	if got.OpTimeoutMs != time.Second.Milliseconds() {
		t.Fatalf("op_timeout_ms = %d", got.OpTimeoutMs)
	}
}

// Calls on b.conn that only queue messages for the next Flush. Everything
// else talks to the kernel and must be overridden on nlConn so it is timed.
var nlQueueOnly = map[string]bool{
	"AddChain": true, "AddRule": true, "AddSet": true, "AddTable": true,
	"DelRule": true, "DelSet": true, "DelTable": true, "FlushChain": true,
	"FlushSet": true, "InsertRule": true, "SetAddElements": true,
	"SetDeleteElements": true,
}

func TestNLConnWrapsEveryKernelCall(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]string{} // method -> first file:line
	wrapped := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if x.Recv != nil && len(x.Recv.List) == 1 {
					if st, ok := x.Recv.List[0].Type.(*ast.StarExpr); ok {
						if id, ok := st.X.(*ast.Ident); ok && id.Name == "nlConn" {
							wrapped[x.Name.Name] = true
						}
					}
				}
			case *ast.SelectorExpr:
				inner, ok := x.X.(*ast.SelectorExpr)
				if !ok || inner.Sel.Name != "conn" {
					return true
				}
				if id, ok := inner.X.(*ast.Ident); ok && id.Name == "b" {
					if _, seen := used[x.Sel.Name]; !seen {
						used[x.Sel.Name] = fset.Position(x.Pos()).String()
					}
				}
			}
			return true
		})
	}
	if len(used) == 0 {
		t.Fatal("found no b.conn calls; the scan is broken")
	}
	var bad []string
	for m, pos := range used {
		if !wrapped[m] && !nlQueueOnly[m] {
			bad = append(bad, m+" ("+pos+")")
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Fatalf("b.conn calls that reach the kernel untimed — override them on nlConn in nlconn.go, or add to nlQueueOnly if they only queue messages: %s",
			strings.Join(bad, ", "))
	}
	for m := range nlQueueOnly {
		if wrapped[m] {
			t.Errorf("%s is both wrapped and listed as queue-only", m)
		}
	}
}

func TestIsNLTimeout(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{os.ErrDeadlineExceeded, true},
		{errors.New("receiveAckAware: netlink receive: i/o timeout"), true}, // %v-wrapped
		{errors.New("conn.Receive: no such file or directory"), false},
	} {
		if got := isNLTimeout(c.err); got != c.want {
			t.Errorf("isNLTimeout(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// Writes carry no deadline: a deadline can't stop a batch the kernel is
// applying inside sendmsg, it would only turn a committed write into a
// reported failure.
func TestNLWriteSocketHasNoDeadline(t *testing.T) {
	stubNLTimeouts(t, 50*time.Millisecond, time.Second)
	nl, err := nlDial()
	if err != nil {
		t.Skipf("no netfilter netlink socket here: %v", err)
	}
	var st nlStats
	_ = st.countDial(nl)
	done := make(chan error, 1)
	go func() { _, err := nl.Receive(); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("write socket must have no deadline, receive returned: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	_ = nl.Close() // unblocks the receive
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("receive did not return after close")
	}
}

func TestNew_FailsWhenNetlinkUnusable(t *testing.T) {
	orig := nlDial
	t.Cleanup(func() { nlDial = orig })
	nlDial = func() (*netlink.Conn, error) { return nil, errors.New("protocol not supported") }
	if b, err := New(); err == nil || b != nil || !strings.Contains(err.Error(), "open netlink conn") {
		t.Fatalf("New must fail at startup without netlink, got b=%v err=%v", b, err)
	}
}

// nlBackend is a Backend whose netlink calls all go to fn.
func nlBackend(t *testing.T, fn nltest.Func) *Backend {
	t.Helper()
	b := &Backend{namedSets: map[string]*nftables.Set{}, appliedHash: map[string]uint64{}}
	b.conn = nlTestConn(t, &b.nl, fn)
	return b
}

func TestShouldSkipAutoBlock_ReadErrorSkipsMissingSetDoesNot(t *testing.T) {
	failing := nlBackend(t, func([]netlink.Message) ([]netlink.Message, error) {
		return nil, os.ErrDeadlineExceeded
	})
	skip, why := failing.shouldSkipAutoBlock("203.0.113.9")
	if !skip || !strings.Contains(why, "could not check ignore_v4") {
		t.Fatalf("an unreadable allow/ignore set must skip the ban: skip=%v why=%q", skip, why)
	}

	missing := nlBackend(t, func([]netlink.Message) ([]netlink.Message, error) {
		return nil, unix.ENOENT
	})
	if skip, why := missing.shouldSkipAutoBlock("203.0.113.9"); skip {
		t.Fatalf("sets that don't exist list nobody, so the ban must go ahead: why=%q", why)
	}
}

func isBatch(msgs []netlink.Message) bool {
	for _, m := range msgs {
		if m.Header.Type == netlink.HeaderType(unix.NFNL_MSG_BATCH_BEGIN) {
			return true
		}
	}
	return false
}

func TestPanelDNATOn_LookupErrorChangesNothing(t *testing.T) {
	var sentBatch bool
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if isBatch(req) {
			sentBatch = true
			return nil, io.EOF
		}
		return nil, os.ErrDeadlineExceeded
	})
	if err := b.PanelDNATOn(-99); err == nil {
		t.Fatal("PanelDNATOn must fail when it can't tell whether its table exists")
	}
	if sentBatch {
		t.Fatal("no batch may be sent: rules added on top of a live table would be duplicated")
	}
}

// chainMsg is a NEWCHAIN reply naming table/chain in the inet family.
func chainMsg(table, chain string) netlink.Message {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.NFTA_CHAIN_TABLE, table)
	ae.String(unix.NFTA_CHAIN_NAME, chain)
	attrs, _ := ae.Encode()
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWCHAIN)},
		Data:   append([]byte{unix.NFPROTO_INET, 0, 0, 0}, attrs...),
	}
}

func nftMsgType(m netlink.Message) int { return int(m.Header.Type) & 0xff }

// DNATOn must read the live prerouting rules before it changes anything: a
// failed read returns at once, with nothing sent and the input-chain accepts
// (nft CLI, run after the read) untouched. Rebuilding from a failed read
// appended a second copy of the rules (3 became 6 on a real kernel).
func TestInstallDNATRules_ReadErrorChangesNothing(t *testing.T) {
	var sentBatch bool
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if isBatch(req) {
			sentBatch = true
			return nil, io.EOF
		}
		switch nftMsgType(req[0]) {
		case unix.NFT_MSG_GETCHAIN:
			m := chainMsg("cfm_redirect", "prerouting")
			m.Header.Sequence = req[0].Header.Sequence // replies echo the request's sequence
			return []netlink.Message{m}, nil
		case unix.NFT_MSG_GETRULE:
			return nil, os.ErrDeadlineExceeded
		}
		return nil, io.EOF
	})
	wanted := dnatUnscopedWantedSpecs(nftables.TableFamilyINet, 9080, 9043)
	err := b.installDNATRules("inet", "cfm_redirect", wanted, dnatRuleNamespaceEdge, true)
	if err == nil || !strings.Contains(err.Error(), "read inet cfm_redirect prerouting rules") {
		t.Fatalf("want the read error before any change, got %v", err)
	}
	if sentBatch {
		t.Fatal("no batch may be sent after a failed read")
	}
}

func TestIntervalContains(t *testing.T) {
	k := func(s string) []byte { return normalizeIP(net.ParseIP(s)) }
	// 10.9.0.0/24 and 10.9.2.0-10.9.2.255, stored as [start, end) boundaries,
	// in the kernel's dump order (ends before starts, descending).
	elems := []nftables.SetElement{
		{Key: k("10.9.3.0"), IntervalEnd: true}, {Key: k("10.9.2.0")},
		{Key: k("10.9.1.0"), IntervalEnd: true}, {Key: k("10.9.0.0")},
		{Key: k("0.0.0.0"), IntervalEnd: true},
	}
	for ip, want := range map[string]bool{
		"10.9.0.0": true, "10.9.0.5": true, "10.9.0.255": true,
		"10.9.1.0": false, "10.9.1.77": false,
		"10.9.2.0": true, "10.9.2.255": true, "10.9.3.0": false,
		"10.8.255.255": false, "1.2.3.4": false,
	} {
		if got := intervalContains(elems, k(ip)); got != want {
			t.Errorf("%s: got %v, want %v", ip, got, want)
		}
	}
	if intervalContains(elems, k("2001:db8::1")) {
		t.Error("a v6 key must never match v4 ranges")
	}
	// Adjacent ranges share a boundary: the start wins.
	adj := []nftables.SetElement{{Key: k("10.0.0.0")}, {Key: k("10.0.0.8"), IntervalEnd: true}, {Key: k("10.0.0.8")}, {Key: k("10.0.0.16"), IntervalEnd: true}}
	if !intervalContains(adj, k("10.0.0.8")) {
		t.Error("the shared boundary belongs to the next range")
	}
}

// A table lookup that fails (here: times out) is not a missing table: the
// port-scanner tick must skip, not run EnsureBase — which would invalidate
// the caches and flush-rewrite every feed set on a kernel that is already
// slow.
func TestLoadPortScanner_ReadErrorIsNotAMissingTable(t *testing.T) {
	var sentBatch bool
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if isBatch(req) {
			sentBatch = true
			return nil, io.EOF
		}
		return nil, os.ErrDeadlineExceeded
	})
	b.loadPortScannerOnce()
	if sentBatch {
		t.Fatal("a failed table read must not trigger EnsureBase")
	}
}
