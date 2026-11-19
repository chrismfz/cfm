package core

import (
	"fmt"
	"testing"
	"time"
)

func TestTopAddr(t *testing.T) {
	const win = 10 * time.Minute
	now := time.Now()
	if got := TopAddr("t", "AUTHFAIL|ip:203.0.113.7", "203.0.113.7", now, win); got != "203.0.113.7" {
		t.Fatalf("ungrouped key: %q", got)
	}
	if got := TopAddr("t", "AUTHFAIL|userip:203.0.113.7/bob", "203.0.113.7/bob", now, win); got != "203.0.113.7/bob" {
		t.Fatalf("a userip key: %q", got)
	}
	k := "AUTHFAIL|ip:2001:db8:1:2::/64"
	TopAddr("t", k, "2001:db8:1:2::a", now, win)
	TopAddr("t", k, "2001:db8:1:2::a", now, win)
	if got := TopAddr("t", k, "2001:db8:1:2::b", now, win); got != "2001:db8:1:2::a" {
		t.Fatalf("busiest: %q", got)
	}
	if got := TopAddr("other", k, "2001:db8:1:2::b", now, win); got != "2001:db8:1:2::b" {
		t.Fatalf("scopes share a tally: %q", got)
	}
	if got := TopAddr("t", k, "2001:db8:1:2::b", now, win); got != "2001:db8:1:2::b" {
		t.Fatalf("a tie goes to the address hitting now: %q", got)
	}
}

// An address trickling one hit just inside every window for hours never
// outweighs one busy now (the decay is per window, not "since it was last
// idle"), nor does one that stopped a while ago.
func TestTopAddrFavoursTheAddressBusyNow(t *testing.T) {
	const win = 10 * time.Minute
	k := "x:2001:db8:3:3::/64"
	at := time.Now()
	for i := 0; i < 100; i++ {
		TopAddr("trickle", k, "2001:db8:3:3::a", at, win)
		at = at.Add(9 * time.Minute)
	}
	var got string
	for i := 0; i < 20; i++ {
		got = TopAddr("trickle", k, "2001:db8:3:3::b", at.Add(time.Duration(i)*time.Second), win)
	}
	if got != "2001:db8:3:3::b" {
		t.Fatalf("the trickler named: %q", got)
	}
	// 100 hits that stopped three windows ago weigh ~5: less than 6 now.
	k2 := "x:2001:db8:4:4::/64"
	t0 := time.Now()
	for i := 0; i < 100; i++ {
		TopAddr("old", k2, "2001:db8:4:4::c", t0, win)
	}
	later := t0.Add(3 * win)
	for i := 0; i < 6; i++ {
		got = TopAddr("old", k2, "2001:db8:4:4::d", later, win)
	}
	if got != "2001:db8:4:4::d" {
		t.Fatalf("an address that stopped three windows ago named: %q", got)
	}
}

// Bounded: per key, and in all (a spray on one scope resets that scope,
// never another's tally).
func TestTopAddrBounded(t *testing.T) {
	old := topAddrMaxKeys
	topAddrMaxKeys = 100
	t.Cleanup(func() { topAddrMaxKeys = old })
	now := time.Now()
	k := "x:2001:db8:9:9::/64"
	for i := 0; i < 1000; i++ {
		TopAddr("cap", k, fmt.Sprintf("2001:db8:9:9::%x", i+1), now, time.Minute)
	}
	topAddrs.Lock()
	n := len(topAddrs.m["cap"][k])
	topAddrs.Unlock()
	if n > topAddrPerKey {
		t.Fatalf("%d addresses on one key, cap %d", n, topAddrPerKey)
	}
	keep := "x:2001:db8:5:5::/64"
	TopAddr("kept", keep, "2001:db8:5:5::1", now, time.Minute)
	TopAddr("kept", keep, "2001:db8:5:5::1", now, time.Minute)
	for i := 0; i < 1000; i++ {
		TopAddr("spray", fmt.Sprintf("k:2001:db8:%x::/64", i), fmt.Sprintf("2001:db8:%x::1", i), now, time.Minute)
	}
	topAddrs.Lock()
	n = 0
	for _, s := range topAddrs.m {
		n += len(s)
	}
	topAddrs.Unlock()
	if n > 100 {
		t.Fatalf("%d keys in all, cap 100", n)
	}
	if got := TopAddr("kept", keep, "2001:db8:5:5::2", now, time.Minute); got != "2001:db8:5:5::1" {
		t.Fatalf("a spray on another scope wiped this one: %q", got)
	}
}

// A tie goes to the address hitting now, whatever the map order.
func TestTopAddrTieGoesToTheCurrentAddress(t *testing.T) {
	now := time.Now()
	for i := 0; i < 200; i++ {
		k := fmt.Sprintf("tie:2001:db8:%x::/64", i)
		TopAddr("tie", k, fmt.Sprintf("2001:db8:%x::a", i), now, time.Minute)
		TopAddr("tie", k, fmt.Sprintf("2001:db8:%x::c", i), now, time.Minute)
		if got := TopAddr("tie", k, fmt.Sprintf("2001:db8:%x::b", i), now, time.Minute); got != fmt.Sprintf("2001:db8:%x::b", i) {
			t.Fatalf("tie named %q", got)
		}
	}
}
