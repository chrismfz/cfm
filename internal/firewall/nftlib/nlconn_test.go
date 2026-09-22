//go:build linux

package nftlib

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
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

// nlTestConn is an nlConn over nltest, built the same way newNLConn builds
// it except for the socket. nltest sockets don't take deadlines, which also
// exercises the fail-open path.
func nlTestConn(t *testing.T, st *nlStats, fn nltest.Func) *nlConn {
	t.Helper()
	w, err := nftables.New(nftables.WithTestDial(fn), nftables.WithSockOptions(st.countDial))
	if err != nil {
		t.Fatal(err)
	}
	r, err := nftables.New(nftables.WithTestDial(fn), nftables.WithSockOptions(st.readDeadline))
	if err != nil {
		t.Fatal(err)
	}
	return &nlConn{Conn: w, read: r, stats: st}
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
