package core

import (
	"fmt"
	"testing"
	"time"
)

func TestTopAddr(t *testing.T) {
	now := time.Now()
	if got := TopAddr("t", "AUTHFAIL|ip:203.0.113.7", "203.0.113.7", now); got != "203.0.113.7" {
		t.Fatalf("ungrouped key: %q", got)
	}
	k := "AUTHFAIL|ip:2001:db8:1:2::/64"
	TopAddr("t", k, "2001:db8:1:2::a", now)
	TopAddr("t", k, "2001:db8:1:2::a", now)
	if got := TopAddr("t", k, "2001:db8:1:2::b", now); got != "2001:db8:1:2::a" {
		t.Fatalf("busiest: %q", got)
	}
	if got := TopAddr("other", k, "2001:db8:1:2::b", now); got != "2001:db8:1:2::b" {
		t.Fatalf("scopes share a tally: %q", got)
	}
	// Idle past topAddrIdle: a fresh tally.
	if got := TopAddr("t", k, "2001:db8:1:2::c", now.Add(topAddrIdle+time.Second)); got != "2001:db8:1:2::c" {
		t.Fatalf("after idle: %q", got)
	}
	// Bounded per key; a busy address survives a spray of one-hit ones.
	k2 := "x:2001:db8:9:9::/64"
	for i := 0; i < 5; i++ {
		TopAddr("t", k2, "2001:db8:9:9::bad", now)
	}
	var got string
	for i := 0; i < 1000; i++ {
		got = TopAddr("t", k2, fmt.Sprintf("2001:db8:9:9::%x", i+1), now)
	}
	topAddrs.Lock()
	n := len(topAddrs.m["t\x00"+k2].n)
	topAddrs.Unlock()
	if got != "2001:db8:9:9::bad" || n > topAddrPerKey {
		t.Fatalf("after a spray: top %q, %d tallied", got, n)
	}
}
