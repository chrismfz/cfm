package proxyipfilter

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// earth's sizes: MYBLOCK 267 782 hosts + 339 nets, block_v4 13 794, MYALLOW
// 885 + 72 nets, allow_dyn 1.
func loadEarthSized(tb testing.TB) {
	ResetForTest()
	feed := make([]string, 0, 268200)
	for i := 0; i < 267782; i++ {
		feed = append(feed, fmt.Sprintf("%d.%d.%d.%d", 11+i>>16, (i>>8)&255, i&255, 9))
	}
	for i := 0; i < 339; i++ {
		feed = append(feed, fmt.Sprintf("100.%d.%d.0/24", i>>8, i&255))
	}
	SetFeed("MYBLOCK", false, feed, nil)
	local := make([]string, 0, 13794)
	for i := 0; i < 13794; i++ {
		local = append(local, fmt.Sprintf("150.%d.%d.%d", i>>16, (i>>8)&255, i&255))
	}
	setLocal("block_v4", false, local)
	allow := make([]string, 0, 960)
	for i := 0; i < 885; i++ {
		allow = append(allow, fmt.Sprintf("160.0.%d.%d", i>>8, i&255))
	}
	SetFeed("MYALLOW", true, allow, nil)
	setLocal("allow_dyn_v4", true, []string{"170.0.0.1"})
}

// The hot path for the common case: a proxied visitor on no list.
func BenchmarkDecideClean(b *testing.B) {
	loadEarthSized(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Decide("203.0.113.77", "shop.gr")
	}
}

// A listed scanner (log mode): the lookup plus the de-duplicated log check.
func BenchmarkDecideListed(b *testing.B) {
	loadEarthSized(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Decide("12.3.4.9", "shop.gr")
	}
}

func TestBuildCostEarthSized(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	t0 := time.Now()
	loadEarthSized(t)
	d := time.Since(t0)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	t.Logf("build (incl. generating the strings): %v, retained heap +%.2f MB", d, float64(m1.HeapAlloc-m0.HeapAlloc)/(1<<20))
	ResetForTest()
}
