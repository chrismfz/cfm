package webdetector

import (
	"testing"
	"time"
)

// A manual (or manual-kept) vhost row can sit at Status=="active" with an
// ExpiresAt already in the past — the store has no TTL sweeper, so nothing
// rewrites the row once the challenge lapses unless a later event touches that
// exact key. Summary()/ListVhosts() must treat such a stale row as inactive so
// the admin view and active-count reflect what is actually in force.
func TestChallengeAPIStore_ExpiredManualNotCountedActive(t *testing.T) {
	s := NewChallengeAPIStore(100)
	s.RecordVhostManual("shop.gr", true, time.Hour, "manual") // apex + www

	if got := s.Summary().ActiveVhosts; got != 2 {
		t.Fatalf("fresh manual: expected 2 active vhosts, got %d", got)
	}
	if got := s.ListVhosts("active", "", 100); len(got) != 2 {
		t.Fatalf("fresh manual: expected 2 in active list, got %d", len(got))
	}

	// Force both rows past their expiry (simulates the TTL lapsing with no
	// further event on those keys).
	s.mu.Lock()
	for _, v := range s.vhosts {
		v.ExpiresAt = time.Now().Add(-time.Minute)
	}
	s.mu.Unlock()

	if got := s.Summary().ActiveVhosts; got != 0 {
		t.Fatalf("expired manual still counted active: %d", got)
	}
	if got := s.ListVhosts("active", "", 100); len(got) != 0 {
		t.Fatalf("expired manual still in active list: %d", len(got))
	}
	// "all" still shows the raw rows; the "inactive" filter now includes them.
	if got := s.ListVhosts("all", "", 100); len(got) != 2 {
		t.Fatalf("all view should still show 2 rows, got %d", len(got))
	}
	if got := s.ListVhosts("inactive", "", 100); len(got) != 2 {
		t.Fatalf("inactive view should show the 2 expired rows, got %d", len(got))
	}
}

// An auto-challenge active row carries a ZERO ExpiresAt (its lifetime is the
// tick loop's, not a stored expiry) and must never be hidden by the expiry
// filter.
func TestChallengeAPIStore_AutoActiveNotHiddenByZeroExpiry(t *testing.T) {
	s := NewChallengeAPIStore(100)
	s.RecordVhostAuto("a.gr", true, SuspiciousRow{Host: "a.gr", Score: 0.8, UniqueIPs: 100}, 0.7, 0.6, 0)

	if got := s.Summary().ActiveVhosts; got != 1 {
		t.Fatalf("auto active (zero ExpiresAt) should count active, got %d", got)
	}
	if got := s.ListVhosts("active", "", 100); len(got) != 1 {
		t.Fatalf("auto active should be listed, got %d", len(got))
	}
}
