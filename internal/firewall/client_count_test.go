package firewall

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// CountKey groups an IPv6 client on its /64 only where a ban could take the
// /64: a /64 a registered check or the backend's guard sets refuse counts
// per address, as its ban does.
func TestCountKey(t *testing.T) {
	old := countKeyTTL
	countKeyTTL = 0
	t.Cleanup(func() {
		countKeyTTL = old
		SetCountBackend(nil)
		SetClientNetExempt("count-test", nil)
		ResetCountKeyCache()
	})

	if got := CountKey("2001:db8:1:2::a"); got != "2001:db8:1:2::/64" {
		t.Fatalf("no backend, no check: %q", got)
	}
	if got := CountKey("203.0.113.7"); got != "203.0.113.7" {
		t.Fatalf("IPv4: %q", got)
	}
	if got := CountKey("fe80::1"); got != "fe80::1" {
		t.Fatalf("ungrouped: %q", got)
	}
	// A registered check (IGNORE_IPS, trusted proxies, the fleet allows).
	SetClientNetExempt("count-test", func(p netip.Prefix) bool { return p.String() == "2001:db8:1:2::/64" })
	if got := CountKey("2001:db8:1:2::A"); got != "2001:db8:1:2::a" {
		t.Fatalf("a refused /64: %q, want the canonical address", got)
	}
	if got := CountKey("2001:db8:1:3::a"); got != "2001:db8:1:3::/64" {
		t.Fatalf("another /64: %q", got)
	}
	SetClientNetExempt("count-test", nil)
	// The backend's guard sets (self, ignore, allow).
	f := newNetFake()
	f.set("allow_v6")["2001:db8:5:5::1"] = 0
	SetCountBackend(f)
	if got := CountKey("2001:db8:5:5::9"); got != "2001:db8:5:5::9" {
		t.Fatalf("a /64 holding an allowed address: %q", got)
	}
	if got := CountKey("2001:db8:5:6::9"); got != "2001:db8:5:6::/64" {
		t.Fatalf("an unguarded /64: %q", got)
	}
	// nft cannot tell: the address, as the ban would.
	f.readErr = map[string]error{"self_v6": errors.New("nft: busy")}
	if got := CountKey("2001:db8:5:7::9"); got != "2001:db8:5:7::9" {
		t.Fatalf("unreadable guards: %q", got)
	}
}

// The answer for a /64 is reused within countKeyTTL.
func TestCountKeyCaches(t *testing.T) {
	old := countKeyTTL
	countKeyTTL = time.Minute
	t.Cleanup(func() { countKeyTTL = old; SetCountBackend(nil); ResetCountKeyCache() })
	ResetCountKeyCache()
	f := newNetFake()
	SetCountBackend(f)
	_ = CountKey("2001:db8:8:8::1")
	_ = CountKey("2001:db8:8:8::2")
	if f.reads["self_v6"] != 1 {
		t.Fatalf("self_v6 read %d times, want once", f.reads["self_v6"])
	}
}

// A failed guard read is answered from the cache for guardErrTTL: a spray of
// new /64s while nft fails must not run the guard reads per /64.
func TestCountKeyCachesAFailedGuardRead(t *testing.T) {
	oldG, oldC := guardCacheTTL, countKeyTTL
	guardCacheTTL, countKeyTTL = 10*time.Second, 10*time.Second
	t.Cleanup(func() {
		guardCacheTTL, countKeyTTL = oldG, oldC
		SetCountBackend(nil)
		ResetCountKeyCache()
		ResetGuardCache()
	})
	ResetCountKeyCache()
	ResetGuardCache()
	f := newNetFake()
	f.readErr = map[string]error{"allow_v6": errors.New("nft: busy")}
	SetCountBackend(f)
	for i := 0; i < 1000; i++ {
		ip := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 7, byte(i >> 8), byte(i), 0, 0, 0, 0, 0, 0, 0, 1}).String()
		if got := CountKey(ip); got != ip {
			t.Fatalf("unreadable guards: %q, want the address", got)
		}
	}
	if f.reads["self_v6"] != 1 {
		t.Fatalf("self_v6 read %d times for 1000 /64s, want once", f.reads["self_v6"])
	}
}

// A backend that cannot write block_v6_clients bans the address alone: its
// counters count per address too.
func TestCountKeyWithoutASetElemWriter(t *testing.T) {
	t.Cleanup(func() { SetCountBackend(nil); ResetCountKeyCache() })
	ResetCountKeyCache()
	SetCountBackend(struct{ Backend }{})
	if got := CountKey("2001:db8:1:2::a"); got != "2001:db8:1:2::a" {
		t.Fatalf("%q, want the address", got)
	}
}

// Once warm, CountKey never waits on nft: a stale guard view is answered
// while one background refresh replaces it.
func TestCountKeyServesAStaleGuardView(t *testing.T) {
	oldG, oldC := guardCacheTTL, countKeyTTL
	guardCacheTTL, countKeyTTL = 20*time.Millisecond, 0
	t.Cleanup(func() {
		guardCacheTTL, countKeyTTL = oldG, oldC
		SetCountBackend(nil)
		ResetCountKeyCache()
		ResetGuardCache()
	})
	ResetGuardCache()
	f := &lockedNetFake{netFake: newNetFake()}
	SetCountBackend(f)
	_ = CountKey("2001:db8:a:1::1") // the first read is synchronous
	if f.readsOf("self_v6") != 1 {
		t.Fatalf("first read: %d", f.readsOf("self_v6"))
	}
	time.Sleep(30 * time.Millisecond)
	f.block = make(chan struct{})
	start := time.Now()
	if got := CountKey("2001:db8:a:2::1"); got != "2001:db8:a:2::/64" || time.Since(start) > 10*time.Millisecond {
		t.Fatalf("stale view: %q after %s", got, time.Since(start))
	}
	close(f.block)
	deadline := time.Now().Add(2 * time.Second)
	for f.readsOf("self_v6") < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no background refresh")
		}
		time.Sleep(time.Millisecond)
	}
}

// lockedNetFake is netFake safe for the background refresh, whose reads can
// be held (block).
type lockedNetFake struct {
	*netFake
	mu    sync.Mutex
	block chan struct{}
}

func (f *lockedNetFake) ListSetElementsTimed(set string) ([]SetElementTimed, error) {
	f.mu.Lock()
	b := f.block
	f.mu.Unlock()
	if b != nil {
		<-b
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.netFake.ListSetElementsTimed(set)
}

func (f *lockedNetFake) readsOf(set string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads[set]
}

// A check registered (an IGNORE_IPS reload, a detector allow) applies to
// CountKey at once, not after its cache.
func TestCountKeyFollowsANewCheckAtOnce(t *testing.T) {
	old := countKeyTTL
	countKeyTTL = time.Minute
	t.Cleanup(func() { countKeyTTL = old; SetClientNetExempt("count-new", nil); ResetCountKeyCache() })
	ResetCountKeyCache()
	if got := CountKey("2001:db8:b:1::9"); got != "2001:db8:b:1::/64" {
		t.Fatalf("before: %q", got)
	}
	SetClientNetExempt("count-new", func(p netip.Prefix) bool { return p.String() == "2001:db8:b:1::/64" })
	if got := CountKey("2001:db8:b:1::9"); got != "2001:db8:b:1::9" {
		t.Fatalf("after the check: %q", got)
	}
}

// A background refresh that started before a reset does not write its view
// back over it.
func TestStaleGuardRefreshLosesToAReset(t *testing.T) {
	oldG := guardCacheTTL
	guardCacheTTL = 20 * time.Millisecond
	t.Cleanup(func() { guardCacheTTL = oldG; ResetGuardCache() })
	ResetGuardCache()
	f := &lockedNetFake{netFake: newNetFake()}
	if _, err := staleGuardView(f); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	f.mu.Lock()
	f.block = make(chan struct{})
	f.mu.Unlock()
	if _, err := staleGuardView(f); err != nil { // starts the refresh, held
		t.Fatal(err)
	}
	ResetGuardCache()
	close(f.block)
	deadline := time.Now().Add(2 * time.Second)
	for {
		guardCacheMu.Lock()
		done, view := !guardCache.refreshing, guardCache.view
		guardCacheMu.Unlock()
		if done {
			if view != nil {
				t.Fatal("the refresh wrote its view over the reset")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh never finished")
		}
		time.Sleep(time.Millisecond)
	}
}
