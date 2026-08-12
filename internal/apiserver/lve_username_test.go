package apiserver

import (
	"testing"
	"time"
)

func TestResolveLVEUsername(t *testing.T) {
	// Save/restore the package globals this test mutates.
	origLookup := uidLookup
	origCache := uidCache
	t.Cleanup(func() { uidLookup = origLookup; uidCache = origCache })

	calls := map[int64]int{}
	uidCache = map[int64]uidCacheEntry{}
	uidLookup = func(uid int64) (string, bool) {
		calls[uid]++
		switch uid {
		case 1513:
			return "acmecorp", true
		default:
			return "", false // no passwd entry
		}
	}

	now := time.Unix(1_000_000, 0)

	// The default/aggregate LVE is labelled, never looked up.
	if got := resolveLVEUsername(lveDefaultUID, now); got != "(default LVE / outside)" {
		t.Fatalf("default LVE = %q", got)
	}
	if calls[lveDefaultUID] != 0 {
		t.Fatalf("default LVE must not hit passwd (calls=%d)", calls[lveDefaultUID])
	}

	// Known uid resolves to the login/account.
	if got := resolveLVEUsername(1513, now); got != "acmecorp" {
		t.Fatalf("uid 1513 = %q, want acmecorp", got)
	}
	// Cached within the TTL — no second passwd read.
	if got := resolveLVEUsername(1513, now.Add(1*time.Minute)); got != "acmecorp" {
		t.Fatalf("cached uid 1513 = %q", got)
	}
	if calls[1513] != 1 {
		t.Fatalf("uid 1513 looked up %d times within TTL, want 1", calls[1513])
	}
	// After the TTL it is re-resolved (a newly-created account can appear).
	if got := resolveLVEUsername(1513, now.Add(uidCacheTTL+time.Second)); got != "acmecorp" {
		t.Fatalf("post-TTL uid 1513 = %q", got)
	}
	if calls[1513] != 2 {
		t.Fatalf("uid 1513 looked up %d times across TTL boundary, want 2", calls[1513])
	}

	// A uid with no passwd entry resolves to "" (caller shows the bare uid), and
	// the miss is cached too (bounded cost under repeated polls).
	if got := resolveLVEUsername(9999, now); got != "" {
		t.Fatalf("unknown uid = %q, want empty", got)
	}
	_ = resolveLVEUsername(9999, now.Add(1*time.Minute))
	if calls[9999] != 1 {
		t.Fatalf("unknown uid looked up %d times within TTL, want 1 (miss cached)", calls[9999])
	}
}
