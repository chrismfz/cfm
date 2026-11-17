package proxyipfilter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
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
	if fmt.Sprint(v.Blocks) != "[block_v4 feed:MYBLOCK]" || v.Enforce || !v.Listed() {
		t.Fatalf("log mode: %+v", v)
	}
	// An allow cancels the block, and is named.
	if v := Check("45.138.12.99"); fmt.Sprint(v.Allows) != "[feed:MYALLOW]" || v.Enforce {
		t.Fatalf("fleet allow: %+v", v)
	}
	if v := Check("5.6.7.8"); fmt.Sprint(v.Allows) != "[allow_dyn_v4]" || v.Enforce {
		t.Fatalf("dyndns allow: %+v", v)
	}
	if v := Check("2001:db8::9"); fmt.Sprint(v.Blocks) != "[feed:MYBLOCK]" {
		t.Fatalf("v6: %+v", v)
	}
	if v := Check("1.1.1.1"); v.Listed() {
		t.Fatalf("clean: %+v", v)
	}
	if v := Check("not-an-ip"); v.Listed() {
		t.Fatal("garbage")
	}

	SetModes("enforce", "log")
	if v := Check("45.138.12.1"); !v.Enforce {
		t.Fatalf("feed enforce: %+v", v)
	}
	if v := Check("5.6.7.9"); v.Listed() {
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
	if v := Check("45.138.12.1"); v.Listed() {
		t.Fatalf("dropped feed still answers: %+v", v)
	}
}

func TestDecideLogsOncePerWindow(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	setClock(func() time.Time { return now })
	SetFeed("MYBLOCK", false, []string{"20.43.87.186"}, nil)

	if enf, listed := Decide("20.43.87.186", "shop.gr"); enf || !listed {
		t.Fatal("log mode: listed, not enforced")
	}
	SetFeed("MYALLOW", true, []string{"20.43.87.187"}, nil)
	SetFeed("MYBLOCK2", false, []string{"20.43.87.187"}, nil)
	if enf, listed := Decide("20.43.87.187", "shop.gr"); enf || listed {
		t.Fatal("an allow-cancelled block is neither enforced nor listed (its allow stays cacheable)")
	}
	if enf, listed := Decide("1.1.1.1", "shop.gr"); enf || listed {
		t.Fatal("a clean client is neither")
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
	if enf, _ := Decide("20.43.87.186", "shop.gr"); !enf {
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
	done := StartLocalRefresh(ctx, list, 20*time.Millisecond)
	// Before ResetForTest (cleanups run last-in first-out): a refresh still
	// in flight would write into the next test's state.
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, func() bool { return Check("9.9.9.9").Listed() })
	fail.Store(true)
	n := calls.Load()
	waitFor(t, func() bool { return calls.Load() > n+int32(len(localSets)) })
	if !Check("9.9.9.9").Listed() {
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

// An unblock (edgeban.Unban -> Forget) clears the address at once, from feed
// and local sources alike, until the sets read next can show it.
func TestForget(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	setClock(func() time.Time { return clock })
	SetFeed("MYBLOCK", false, []string{"20.43.87.186"}, nil)
	setLocal("block_v4", false, []string{"20.43.87.186", "5.6.7.8"})
	Forget("20.43.87.186")
	Forget("20.43.87.186") // again: one override
	Forget("garbage")
	if Check("20.43.87.186").Listed() || !Check("5.6.7.8").Listed() {
		t.Fatal("forget")
	}
	if Check("::ffff:20.43.87.186").Listed() {
		t.Fatal("a v4-mapped form of a forgotten address")
	}
	if Stats()["forgotten"].(int64) != 1 {
		t.Fatalf("forgotten = %v", Stats()["forgotten"])
	}
	clock = clock.Add(forgetFor)
	if !Check("20.43.87.186").Listed() {
		t.Fatal("still on the lists after the override: listed again")
	}
	if Stats()["forgotten"].(int64) != 0 {
		t.Fatal("an expired override a request met is dropped")
	}
	Forget("5.6.7.8")
	clock = clock.Add(forgetFor)
	pruneForgotten()
	if Stats()["forgotten"].(int64) != 0 {
		t.Fatal("the refresh prunes expired overrides nobody asked about")
	}
}

// A mass unblock: Forget is a map store, not a snapshot copy per address.
func TestForgetMassIsCheap(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	start := time.Now()
	for i := 0; i < 20000; i++ {
		Forget(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("20 000 Forgets took %v", d)
	}
	if Stats()["forgotten"].(int64) != 20000 {
		t.Fatal("count")
	}
}

// A feed's per-element TTL is not part of nft's verdict (the base rules drop
// on the union sets, rebuilt without a TTL): the feed answers until its next
// apply, there as here.
func TestFeedHoldsUntilNextApply(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	setClock(func() time.Time { return clock })
	SetFeed("SHORT", false, []string{"198.51.100.1"}, nil)
	clock = clock.Add(48 * time.Hour)
	if !Check("198.51.100.1").Listed() {
		t.Fatal("a feed stopped answering before its next apply")
	}
	SetFeed("SHORT", false, nil, nil)
	if Check("198.51.100.1").Listed() {
		t.Fatal("the next apply replaces it")
	}
}

// A network allow (`cfm allow 203.0.113.0/24`) lifts every address in it at
// once, like nft's accept.
func TestForgetNetwork(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	setClock(func() time.Time { return clock })
	SetFeed("MYBLOCK", false, []string{"203.0.113.7", "203.0.114.7"}, nil)
	Forget("203.0.113.9/24")
	Forget("not/a/cidr")
	if Check("203.0.113.7").Listed() || !Check("203.0.114.7").Listed() {
		t.Fatal("network forget")
	}
	clock = clock.Add(forgetFor)
	if !Check("203.0.113.7").Listed() {
		t.Fatal("after the override")
	}
	pruneForgotten()
	if l := forgottenNets.Load(); l != nil && len(*l) != 0 {
		t.Fatal("pruned")
	}
}

// Two feeds whose names differ only in case are two lists in the log.
func TestFeedLabelKeepsTheName(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	SetFeed("MyList", false, []string{"192.0.2.1"}, nil)
	SetFeed("MYLIST", false, []string{"192.0.2.1"}, nil)
	if v := Check("192.0.2.1"); fmt.Sprint(v.Blocks) != "[feed:MYLIST feed:MyList]" {
		t.Fatalf("%v", v.Blocks)
	}
}

// The log de-dup under concurrent decisions for one listed client: one line,
// and the next window's line counts every occurrence.
func TestLogDueConcurrent(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	setClock(func() time.Time { return clock })
	var lines atomic.Int32
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if _, due := logDue("k"); due {
					lines.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if lines.Load() != 1 {
		t.Fatalf("lines in one window = %d", lines.Load())
	}
	clock = clock.Add(logEvery)
	if n, due := logDue("k"); !due || n != 4000 {
		t.Fatalf("next window: n=%d due=%v (3 999 counted + this one)", n, due)
	}
}

func TestGeoFields(t *testing.T) {
	t.Cleanup(func() { SetGeo(nil) })
	if got := geoFields("20.43.87.186"); got != "cc=- asn=- asn_name=-" {
		t.Fatalf("no resolver: %q", got)
	}
	SetGeo(func(ip string) (string, uint, string) {
		if ip == "69.63.184.14" {
			return "us", 32934, "Facebook, Inc."
		}
		return "", 0, ""
	})
	if got := geoFields("69.63.184.14"); got != "cc=US asn=32934 asn_name=Facebook,_Inc." {
		t.Fatalf("resolved: %q", got)
	}
	if got := geoFields("192.0.2.1"); got != "cc=- asn=- asn_name=-" {
		t.Fatalf("unknown to the database: %q", got)
	}
	// A name the database holds cannot fake another field.
	SetGeo(func(string) (string, uint, string) { return "GR", 1, "x cc=US\n" })
	if got := geoFields("192.0.2.1"); got != "cc=GR asn=1 asn_name=x_cc=US_" {
		t.Fatalf("sanitised: %q", got)
	}
}

// The line Decide writes ends with the geo fields, and Stats says whether a
// resolver is set.
func TestDecideLineCarriesGeo(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	var lines []string
	orig := logf
	logf = func(f string, a ...interface{}) { lines = append(lines, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() { logf = orig; SetGeo(nil) })
	SetFeed("MYBLOCK", false, []string{"69.63.184.14"}, nil)

	SetGeo(nil)
	if Stats()["geo"] != false {
		t.Fatal("no resolver: geo=false")
	}
	SetGeo(func(string) (string, uint, string) { return "US", 32934, "Facebook, Inc." })
	if Stats()["geo"] != true {
		t.Fatal("resolver set: geo=true")
	}
	Decide("69.63.184.14", "infonews24.gr")
	want := "[proxied_ipfilter] would_block ip=69.63.184.14 host=infonews24.gr block=feed:MYBLOCK allow=- " +
		"mode=feed:log,local:log n=1 cc=US asn=32934 asn_name=Facebook,_Inc."
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("line:\n got %q\nwant %q", lines, want)
	}
}
