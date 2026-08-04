package webdetector

import (
	"testing"
	"time"
)

// Regression coverage for the manual-vhost-challenge stomp (2026-08-04):
// the suspicious-vhost auto cool-down cleared the bridge entry of an active
// 24h manual challenge, and the same-tick manual re-push recreated it with
// the hardcoded 60m tick TTL — so the operator's 24h challenge silently
// became 1h and then vanished. The fix keys both decisions (keep the bridge
// entry on auto_off, push the remaining manual window) on
// manualChallengeCovering, tested here.
func TestManualChallengeCovering(t *testing.T) {
	e := &Engine{}
	e.manualChal.init()

	ttl := 24 * time.Hour
	e.manualChal.set("example.com", ttl, "manual")
	e.manualChal.set("www.wwwonly.com", ttl, "manual")

	t.Run("exact host matches", func(t *testing.T) {
		ok, exp, reason := e.manualChallengeCovering("example.com")
		if !ok {
			t.Fatal("expected exact host to be covered")
		}
		if reason != "manual" {
			t.Fatalf("expected reason=manual, got %q", reason)
		}
		if rem := time.Until(exp); rem < 23*time.Hour {
			t.Fatalf("expected ~24h remaining, got %s", rem)
		}
	})

	t.Run("www variant is covered by apex manual challenge", func(t *testing.T) {
		// The bridge expands an apex manual challenge to apex+www
		// (vhostVariantsForBridge), so lifecycle decisions for the www
		// host must see the apex entry.
		ok, exp, reason := e.manualChallengeCovering("www.example.com")
		if !ok {
			t.Fatal("expected www host to be covered by apex manual challenge")
		}
		if reason != "manual" {
			t.Fatalf("expected reason=manual, got %q", reason)
		}
		if rem := time.Until(exp); rem < 23*time.Hour {
			t.Fatalf("expected ~24h remaining, got %s", rem)
		}
	})

	t.Run("www-only manual challenge does not cover the apex", func(t *testing.T) {
		// vhostVariantsForBridge does NOT expand www→apex, so covering
		// must not either.
		if ok, _, _ := e.manualChallengeCovering("wwwonly.com"); ok {
			t.Fatal("apex must not be covered by a www-only manual challenge")
		}
	})

	t.Run("unrelated subdomain is not covered", func(t *testing.T) {
		if ok, _, _ := e.manualChallengeCovering("sub.example.com"); ok {
			t.Fatal("sub.example.com must not be covered")
		}
	})

	t.Run("expired entry does not cover", func(t *testing.T) {
		e.manualChal.set("expired.com", time.Nanosecond, "manual")
		time.Sleep(2 * time.Millisecond)
		if ok, _, _ := e.manualChallengeCovering("expired.com"); ok {
			t.Fatal("expired manual challenge must not cover")
		}
		if ok, _, _ := e.manualChallengeCovering("www.expired.com"); ok {
			t.Fatal("expired manual challenge must not cover the www variant")
		}
	})

	t.Run("no entry", func(t *testing.T) {
		if ok, _, _ := e.manualChallengeCovering("other.com"); ok {
			t.Fatal("host without manual challenge must not be covered")
		}
	})
}
