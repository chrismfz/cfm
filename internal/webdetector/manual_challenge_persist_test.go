package webdetector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestManualChalPersist_RoundTrip asserts a manual challenge survives a restart:
// set() writes the entry to disk and a fresh store loads it back with its expiry
// intact (this is the whole point — a 34h manual challenge must not vanish on a
// daemon restart).
func TestManualChalPersist_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual.json")

	var s1 manualChalState
	s1.init(path)
	s1.set("example.gr", 10*time.Hour, "operator")

	// Fresh store, same path → simulates a daemon restart.
	var s2 manualChalState
	s2.init(path)
	ok, exp, reason := s2.active("example.gr")
	if !ok {
		t.Fatalf("manual challenge not restored after reload")
	}
	if reason != "operator" {
		t.Errorf("reason = %q, want %q", reason, "operator")
	}
	// Remaining window should still be ~10h (a couple seconds of slack for the
	// test wall clock), NOT reset and NOT lost.
	if rem := time.Until(exp); rem < 9*time.Hour+59*time.Minute || rem > 10*time.Hour {
		t.Errorf("remaining window = %s, want ~10h", rem)
	}
}

// TestManualChalPersist_DropsExpired asserts a stale (already-expired) entry on
// disk is filtered on load rather than resurrected. load() and saveLocked() both
// time-filter, so a crash that left an expired entry behind is inert.
func TestManualChalPersist_DropsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual.json")
	// Hand-write a file with one expired and one live entry.
	arr := []manualChalPersistEntry{
		{Host: "expired.gr", ExpiresAt: time.Now().Add(-time.Hour), Reason: "old"},
		{Host: "live.gr", ExpiresAt: time.Now().Add(time.Hour), Reason: "manual"},
	}
	b, _ := json.MarshalIndent(arr, "", "  ")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	var s manualChalState
	s.init(path)
	if ok, _, _ := s.active("expired.gr"); ok {
		t.Errorf("expired entry was restored, want dropped")
	}
	if ok, _, _ := s.active("live.gr"); !ok {
		t.Errorf("live entry was not restored")
	}
}

// TestManualChalPersist_ClearRemoves asserts clear() persists the removal so a
// subsequent restart does not bring the challenge back.
func TestManualChalPersist_ClearRemoves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual.json")

	var s1 manualChalState
	s1.init(path)
	s1.set("gone.gr", time.Hour, "manual")
	if !s1.clear("gone.gr") {
		t.Fatalf("clear reported entry absent, want present")
	}

	var s2 manualChalState
	s2.init(path)
	if ok, _, _ := s2.active("gone.gr"); ok {
		t.Errorf("cleared entry came back after reload")
	}
}

// TestManualChalPersist_FileMode asserts the snapshot is written 0600 (it names
// operator-targeted vhosts; keep it owner-only like the other webdetector stores).
func TestManualChalPersist_FileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual.json")
	var s manualChalState
	s.init(path)
	s.set("perm.gr", time.Hour, "manual")

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}
}

// TestManualChalPersist_EmptyPathNoop asserts an empty path keeps the store
// purely in-memory and never touches the filesystem (the test constructor path).
func TestManualChalPersist_EmptyPathNoop(t *testing.T) {
	var s manualChalState
	s.init("")
	s.set("mem.gr", time.Hour, "manual")
	if ok, _, _ := s.active("mem.gr"); !ok {
		t.Errorf("in-memory set did not take effect")
	}
	// No path → nothing to assert on disk; the point is set()/clear() must not panic.
	s.clear("mem.gr")
}
