package proxyipfilter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTableContains(t *testing.T) {
	tb := buildTable([]string{
		"20.43.87.186", "45.138.12.32", "45.138.12.32", // a duplicate
		"10.0.0.0/24", "10.0.1.0/24", // adjacent: merged
		"192.0.2.10-192.0.2.20", "198.51.100.7/32",
		"2001:db8::1", "2001:db8:1::/48", "2001:db8:2::5-2001:db8:2::9",
		"bogus", "1.2.3.4/99", "::ffff:1.2.3.0/120", "",
	})
	if tb.n != 10 || tb.bad != 3 || len(tb.v4) != 3 || len(tb.v4r) != 2 {
		t.Fatalf("n=%d bad=%d v4=%v v4r=%v", tb.n, tb.bad, tb.v4, tb.v4r)
	}
	in := []string{"20.43.87.186", "45.138.12.32", "10.0.0.0", "10.0.1.255", "192.0.2.10", "192.0.2.20",
		"198.51.100.7", "::ffff:20.43.87.186", "2001:db8::1", "2001:db8:1:ffff::1", "2001:db8:2::7"}
	out := []string{"20.43.87.185", "10.0.2.0", "9.255.255.255", "192.0.2.21", "192.0.2.9", "2001:db8::2",
		"2001:db8:2::a", "2001:db8:0:ffff::1", "0.0.0.0", "255.255.255.255"}
	for _, s := range in {
		if !tb.contains(netip.MustParseAddr(s)) {
			t.Errorf("%s not found", s)
		}
	}
	for _, s := range out {
		if tb.contains(netip.MustParseAddr(s)) {
			t.Errorf("%s found", s)
		}
	}
	// The top of the address space: a range ending at 255.255.255.255 does
	// not wrap the adjacency test.
	top := buildTable([]string{"255.255.255.0/24", "1.1.1.1"})
	if !top.contains(netip.MustParseAddr("255.255.255.255")) || top.contains(netip.MustParseAddr("1.1.1.2")) {
		t.Fatal("top of the space")
	}
}

// The fleet blacklist's size: 268 k IPv4 hosts on earth. A lookup must stay a
// binary search (no allocation).
func TestTableLargeAndAllocFree(t *testing.T) {
	elems := make([]string, 0, 270000)
	for i := 0; i < 270000; i++ {
		elems = append(elems, fmt.Sprintf("%d.%d.%d.%d", 11+i>>16, (i>>8)&255, i&255, 7))
	}
	tb := buildTable(elems)
	if len(tb.v4) != 270000 {
		t.Fatalf("v4=%d", len(tb.v4))
	}
	a := netip.MustParseAddr("12.3.4.7")
	if !tb.contains(a) || tb.contains(netip.MustParseAddr("12.3.4.8")) {
		t.Fatal("lookup")
	}
	if n := testing.AllocsPerRun(100, func() { tb.contains(a) }); n != 0 {
		t.Fatalf("allocs per lookup = %v", n)
	}
}

func TestVerdictOrderAndModes(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	SetFeed("MYBLOCK", false, []string{"20.43.87.186", "45.138.12.0/24"}, []string{"2001:db8::/32"})
	SetFeed("MYALLOW", true, []string{"45.138.12.99"}, nil)
	setLocal("block_v4", false, []string{"20.43.87.186", "5.6.7.8"})
	setLocal("allow_dyn_v4", true, []string{"5.6.7.8"})

	v := Check("20.43.87.186")
	if fmt.Sprint(v.Blocks) != "[block_v4 feed:myblock]" || v.Enforce || !v.Log {
		t.Fatalf("log mode: %+v", v)
	}
	// An allow cancels the block, and is named.
	if v := Check("45.138.12.99"); fmt.Sprint(v.Allows) != "[feed:myallow]" || v.Enforce {
		t.Fatalf("fleet allow: %+v", v)
	}
	if v := Check("5.6.7.8"); fmt.Sprint(v.Allows) != "[allow_dyn_v4]" || v.Enforce {
		t.Fatalf("dyndns allow: %+v", v)
	}
	if v := Check("2001:db8::9"); fmt.Sprint(v.Blocks) != "[feed:myblock]" {
		t.Fatalf("v6: %+v", v)
	}
	if v := Check("1.1.1.1"); v.Log || len(v.Blocks) != 0 {
		t.Fatalf("clean: %+v", v)
	}
	if v := Check("not-an-ip"); v.Log {
		t.Fatal("garbage")
	}

	SetModes("enforce", "log")
	if v := Check("45.138.12.1"); !v.Enforce {
		t.Fatalf("feed enforce: %+v", v)
	}
	if v := Check("5.6.7.9"); v.Log {
		t.Fatalf("not listed: %+v", v)
	}
	if v := Check("45.138.12.99"); v.Enforce {
		t.Fatal("an allow wins over enforce")
	}
	SetModes("off", "enforce")
	if v := Check("20.43.87.186"); fmt.Sprint(v.Blocks) != "[block_v4]" || !v.Enforce {
		t.Fatalf("feed off, local enforce: %+v", v)
	}
	SetModes("bogus", "")
	if modeFeed.Load() != ModeLog || modeLocal.Load() != ModeLog {
		t.Fatal("unknown and empty modes are log")
	}

	DropFeed("MYBLOCK")
	if v := Check("45.138.12.1"); v.Log {
		t.Fatalf("dropped feed still answers: %+v", v)
	}
}

func TestDecideLogsOncePerWindow(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	logNow = func() time.Time { return now }
	t.Cleanup(func() { logNow = time.Now })
	SetFeed("MYBLOCK", false, []string{"20.43.87.186"}, nil)

	if Decide("20.43.87.186", "shop.gr") {
		t.Fatal("log mode answered block")
	}
	for i := 0; i < 5; i++ {
		Decide("20.43.87.186", "shop.gr")
	}
	if n, due := logDue("20.43.87.186|would_block"); due || n != 0 {
		t.Fatal("a line inside the window")
	}
	now = now.Add(logEvery)
	if n, due := logDue("20.43.87.186|would_block"); !due || n != 7 {
		t.Fatalf("after the window: n=%d due=%v (5 decides + the probe + this one)", n, due)
	}
	SetModes("enforce", "log")
	if !Decide("20.43.87.186", "shop.gr") {
		t.Fatal("enforce mode")
	}
	st := Stats()
	if st["would_block"].(int64) != 6 || st["blocked"].(int64) != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestLocalRefreshKeepsASetItCannotRead(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	var calls atomic.Int32
	fail := atomic.Bool{}
	list := func(set string) ([]string, error) {
		calls.Add(1)
		if set == "block_v4" {
			if fail.Load() {
				return nil, errors.New("nft hiccup")
			}
			return []string{"9.9.9.9"}, nil
		}
		return nil, errors.New("no such set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartLocalRefresh(ctx, list, 20*time.Millisecond)
	waitFor(t, func() bool { return Check("9.9.9.9").Log })
	fail.Store(true)
	n := calls.Load()
	waitFor(t, func() bool { return calls.Load() > n+int32(len(localSets)) })
	if !Check("9.9.9.9").Log {
		t.Fatal("an unreadable set lost what it had")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOrDashKeepsALineALine(t *testing.T) {
	if got := orDash("a.gr block=x\nfake"); got != "a.gr_block=x_fake" {
		t.Fatalf("%q", got)
	}
	if orDash("") != "-" || len(orDash(strings.Repeat("a", 400))) != 253 {
		t.Fatal("empty / length")
	}
}
