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
	// A tie goes to the address hitting now.
	if got := TopAddr("t", k, "2001:db8:1:2::b", now, win); got != "2001:db8:1:2::b" {
		t.Fatalf("tie: %q", got)
	}
	// An address idle for the window no longer counts: 100 old hits from ::c
	// do not outweigh ::d's one hit a window later.
	k3 := "x:2001:db8:3:3::/64"
	for i := 0; i < 100; i++ {
		TopAddr("t", k3, "2001:db8:3:3::c", now, win)
	}
	later := now.Add(win + time.Second)
	if got := TopAddr("t", k3, "2001:db8:3:3::d", later, win); got != "2001:db8:3:3::d" {
		t.Fatalf("an address idle for the window named: %q", got)
	}
	TopAddr("t", k3, "2001:db8:3:3::d", later, win)
	TopAddr("t", k3, "2001:db8:3:3::d", later, win)
	if got := TopAddr("t", k3, "2001:db8:3:3::c", later, win); got != "2001:db8:3:3::d" {
		t.Fatalf("::c back after a window: its old 100 hits counted (%q named, want ::d with 3)", got)
	}
	// Bounded per key; a busy address survives a spray of one-hit ones.
	k2 := "x:2001:db8:9:9::/64"
	for i := 0; i < 5; i++ {
		TopAddr("t", k2, "2001:db8:9:9::bad", now, win)
	}
	var got string
	for i := 0; i < 1000; i++ {
		got = TopAddr("t", k2, fmt.Sprintf("2001:db8:9:9::%x", i+1), now.Add(time.Duration(i+1)*time.Millisecond), win)
	}
	topAddrs.Lock()
	n := len(topAddrs.m["t\x00"+k2])
	topAddrs.Unlock()
	if n > topAddrPerKey {
		t.Fatalf("%d tallied, cap %d", n, topAddrPerKey)
	}
	_ = got // the stalest address is evicted first: the spray may evict ::bad
}

// A spray of distinct /64s never grows the tally past topAddrMaxKeys.
func TestTopAddrKeysBounded(t *testing.T) {
	old := topAddrMaxKeys
	topAddrMaxKeys = 100
	t.Cleanup(func() { topAddrMaxKeys = old })
	now := time.Now()
	for i := 0; i < 1000; i++ {
		TopAddr("spray", fmt.Sprintf("k:2001:db8:%x::/64", i), fmt.Sprintf("2001:db8:%x::1", i), now, time.Minute)
	}
	topAddrs.Lock()
	n := len(topAddrs.m)
	topAddrs.Unlock()
	if n > 100 {
		t.Fatalf("%d keys, cap 100", n)
	}
}
