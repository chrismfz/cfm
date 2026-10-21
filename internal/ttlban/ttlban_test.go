package ttlban

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// batchFake records AddBlockBatch and RemoveBlock; every other Backend
// method panics.
type batchFake struct {
	firewall.Backend
	got     []firewall.BlockEntry
	calls   int
	err     error // returned by the first failN calls (every call when failN is 0)
	failN   int
	during  func() // runs inside AddBlockBatch
	removed []string
}

func (f *batchFake) AddBlockBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	f.calls++
	f.got = append(f.got, entries...)
	if f.during != nil {
		f.during()
	}
	if f.err != nil && (f.failN == 0 || f.calls <= f.failN) {
		return firewall.BlockBatchResult{}, f.err
	}
	return firewall.BlockBatchResult{Added: len(entries)}, nil
}

func (f *batchFake) RemoveBlock(ip net.IP) error {
	f.removed = append(f.removed, ip.String())
	return nil
}

var t0 = time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ttlbans.json")
	s := New(path)
	s.now = func() time.Time { return t0 }
	s.sleep = func(time.Duration) {}
	return s, path
}

func writeFile(t *testing.T, path string, bans map[string]Entry) {
	t.Helper()
	raw, err := json.Marshal(fileFormat{Version: 1, SavedAt: t0, Bans: bans})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) map[string]Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Bans
}

// The incident: bans stored before a restart come back for the time they
// have left; an expired one is dropped, and so is one an allow / ignore
// covers (never re-added, and gone from the file).
func TestRestoreKeepsRemainingTTLSkipsExpiredAndExcluded(t *testing.T) {
	s, path := newStore(t)
	writeFile(t, path, map[string]Entry{
		"34.73.15.51":        {Set: "block_v4", Expires: t0.Add(168*time.Hour - 20*time.Minute)},
		"2a11:6102:0:50cd::": {Set: "block_v6", Expires: t0.Add(90*time.Minute + 500*time.Millisecond)},
		"198.51.100.7":       {Set: "block_v4", Expires: t0.Add(-time.Minute)},           // expired while down
		"198.51.100.8":       {Set: "block_v4", Expires: t0.Add(400 * time.Millisecond)}, // last second
		"203.0.113.9":        {Set: "block_v4", Expires: t0.Add(time.Hour)},              // allowed since
	})
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	be := &batchFake{}
	exclude := func(ip net.IP) bool { return ip.String() == "203.0.113.9" }
	res, err := s.Restore(be, exclude)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stored != 5 || res.Expired != 2 || res.Excluded != 1 || res.Batch.Added != 2 {
		t.Fatalf("result %+v", res)
	}
	want := map[string]time.Duration{
		"34.73.15.51":        168*time.Hour - 20*time.Minute,
		"2a11:6102:0:50cd::": 90 * time.Minute, // truncated to whole seconds
	}
	if len(be.got) != len(want) {
		t.Fatalf("restored %v, want %v", be.got, want)
	}
	for _, e := range be.got {
		if e.Permanent {
			t.Fatalf("%s restored permanent", e.IP)
		}
		if w, ok := want[e.IP.String()]; !ok || e.TTL != w {
			t.Fatalf("%s restored for %s, want %s", e.IP, e.TTL, w)
		}
	}
	got := readFile(t, path)
	if len(got) != 2 {
		t.Fatalf("file after restore holds %v, want only the two live bans", got)
	}
	if _, ok := got["203.0.113.9"]; ok {
		t.Fatal("an excluded ban stayed in the file")
	}
}

// An unblock landing while the restore batch writes must not leave the
// address banned: the batch may re-add it after the unblock removed it.
func TestRestoreUndoesAnUnblockDuringTheBatch(t *testing.T) {
	s, path := newStore(t)
	writeFile(t, path, map[string]Entry{
		"192.0.2.1": {Expires: t0.Add(time.Hour)},
		"192.0.2.2": {Expires: t0.Add(time.Hour)},
	})
	_ = s.Load()
	be := &batchFake{}
	be.during = func() { _ = s.Forget("192.0.2.1") }
	if _, err := s.Restore(be, nil); err != nil {
		t.Fatal(err)
	}
	if len(be.removed) != 1 || be.removed[0] != "192.0.2.1" {
		t.Fatalf("removed %v, want the address unblocked during the batch", be.removed)
	}
	if e := s.Entries(); len(e) != 1 {
		t.Fatalf("store %v, want only 192.0.2.2", e)
	}
}

// A batch failing at boot (nft busy) is retried.
func TestRestoreRetriesTheBatch(t *testing.T) {
	s, path := newStore(t)
	writeFile(t, path, map[string]Entry{"192.0.2.1": {Expires: t0.Add(time.Hour)}})
	_ = s.Load()
	be := &batchFake{err: errors.New("nft: busy"), failN: 2}
	if _, err := s.Restore(be, nil); err != nil || be.calls != 3 {
		t.Fatalf("calls=%d err=%v, want success on the third try", be.calls, err)
	}
}

// A batch that keeps failing arms the store all the same (or it would never
// persist again) and carries the bans: the first snapshot must not drop them
// from the file, so the next start retries. Once nft holds a carried ban,
// nft is the truth again; an expired or forgotten one leaves the carry.
func TestRestoreFailureCarriesTheBans(t *testing.T) {
	s, path := newStore(t)
	writeFile(t, path, map[string]Entry{
		"192.0.2.1": {Expires: t0.Add(time.Hour)},
		"192.0.2.3": {Expires: t0.Add(time.Hour)},
		"192.0.2.4": {Expires: t0.Add(2 * time.Minute)},
	})
	_ = s.Load()
	if _, err := s.Restore(&batchFake{err: errors.New("nft: busy")}, nil); err == nil {
		t.Fatal("batch error not reported")
	}
	if err := s.Snapshot(t0, []firewall.SetElementTimed{{Elem: "192.0.2.2", Expires: time.Hour}}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"} {
		if _, ok := got[ip]; !ok {
			t.Fatalf("%s missing from %v after a failed restore", ip, got)
		}
	}
	_ = s.Forget("192.0.2.3")
	// 192.0.2.1 now in nft (gone from the carry); .4 expired; .3 forgotten.
	_ = s.Snapshot(t0.Add(5*time.Minute), []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: 55 * time.Minute}})
	if got := readFile(t, path); len(got) != 1 || len(s.carry) != 0 {
		t.Fatalf("carry outlived nft / expiry / unblock: file %v carry %v", got, s.carry)
	}
}

// A clock behind at boot must not stretch a ban past what it had when the
// file was saved.
func TestRestoreCapsTTLAtWhatWasLeftWhenSaved(t *testing.T) {
	s, path := newStore(t)
	saved := t0.Add(24 * time.Hour) // the clock now reads a day earlier than at save
	raw, _ := json.Marshal(fileFormat{Version: 1, SavedAt: saved, Bans: map[string]Entry{
		"192.0.2.1": {Expires: saved.Add(6 * time.Hour)},
	}})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = s.Load()
	be := &batchFake{}
	if _, err := s.Restore(be, nil); err != nil {
		t.Fatal(err)
	}
	if len(be.got) != 1 || be.got[0].TTL != 6*time.Hour {
		t.Fatalf("restored %+v, want 6h (not 30h)", be.got)
	}
}

// A slow read finishing after a newer one (the periodic read landing after
// the shutdown snapshot) must not replace it.
func TestSnapshotIgnoresAnOlderRead(t *testing.T) {
	s, path := newStore(t)
	_, _ = s.Restore(nil, nil)
	_ = s.Snapshot(t0.Add(time.Minute), []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour}, {Elem: "192.0.2.2", Expires: time.Hour}})
	_ = s.Snapshot(t0, []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour}})
	if got := readFile(t, path); len(got) != 2 {
		t.Fatalf("an older read replaced a newer one: %v", got)
	}
}

// A snapshot before Restore must not save the fresh table's empty sets over
// the bans still waiting to be restored.
func TestSnapshotBeforeRestoreIsANoop(t *testing.T) {
	s, path := newStore(t)
	writeFile(t, path, map[string]Entry{"192.0.2.1": {Set: "block_v4", Expires: t0.Add(time.Hour)}})
	_ = s.Load()
	if err := s.Snapshot(t0, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := readFile(t, path)["192.0.2.1"]; !ok {
		t.Fatal("an unarmed snapshot overwrote the stored bans")
	}
}

// A snapshot mirrors the timed host elements nft holds: permanent elements
// (cfm.deny's) and non-hosts stay out, an element nft no longer holds
// (expired, unblocked from the CLI, flushed) leaves the store, and expiry is
// the read time plus what nft reports left. Load reads it back.
func TestSnapshotMirrorsTimedHostElements(t *testing.T) {
	s, path := newStore(t)
	if _, err := s.Restore(nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = s.Snapshot(t0, []firewall.SetElementTimed{
		{Elem: "192.0.2.1", Expires: time.Hour},
		{Elem: "192.0.2.2", Expires: 2 * time.Hour},
	})
	readAt := t0.Add(time.Minute)
	if err := s.Snapshot(readAt, []firewall.SetElementTimed{
		{Elem: "192.0.2.1", Expires: 59 * time.Minute},
		{Elem: "198.51.100.1"},                        // permanent
		{Elem: "198.51.100.0/24", Expires: time.Hour}, // not a host
		{Elem: "2001:DB8::1", Expires: 6 * time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	want := map[string]Entry{
		"192.0.2.1":   {Set: "block_v4", Expires: t0.Add(time.Hour)},
		"2001:db8::1": {Set: "block_v6", Expires: readAt.Add(6 * time.Hour)},
	}
	if len(got) != len(want) {
		t.Fatalf("file %v, want %v", got, want)
	}
	for k, w := range want {
		if g := got[k]; g.Set != w.Set || !g.Expires.Equal(w.Expires) {
			t.Fatalf("%s: %+v, want %+v", k, g, w)
		}
	}
	l := New(path)
	if err := l.Load(); err != nil || l.Len() != 2 {
		t.Fatalf("load: len=%d err=%v", l.Len(), err)
	}
}

// An unchanged read (expiry moved only by nft's whole-second rounding) does
// not rewrite the file; a longer ban (an extension) does.
func TestSnapshotRewritesOnlyOnChange(t *testing.T) {
	s, path := newStore(t)
	_, _ = s.Restore(nil, nil)
	_ = s.Snapshot(t0, []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour}})
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_ = s.Snapshot(t0.Add(2*time.Minute), []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: 58*time.Minute - time.Second}})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("an unchanged read rewrote the file")
	}
	_ = s.Snapshot(t0.Add(3*time.Minute), []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: 6 * time.Hour}})
	if got := readFile(t, path)["192.0.2.1"]; !got.Expires.Equal(t0.Add(3*time.Minute + 6*time.Hour)) {
		t.Fatalf("extension not saved: %+v", got)
	}
}

// An unblock drops the entry at once, and a read begun before it (which
// still saw the element) must not put it back: a restart would otherwise
// resurrect an unblocked address. A read begun after it is the truth again
// (a fresh ban of the same address).
func TestForgetHonoursUnblockAgainstStaleRead(t *testing.T) {
	s, path := newStore(t)
	_, _ = s.Restore(nil, nil)
	_ = s.Snapshot(t0, []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour}, {Elem: "192.0.2.2", Expires: time.Hour}})

	readStart := t0.Add(time.Minute) // a reconcile's read begins…
	s.now = func() time.Time { return t0.Add(time.Minute + time.Second) }
	if err := s.Forget("192.0.2.1"); err != nil { // …the unblock lands during it
		t.Fatal(err)
	}
	if _, ok := readFile(t, path)["192.0.2.1"]; ok {
		t.Fatal("Forget left the entry in the file")
	}
	_ = s.Snapshot(readStart, []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: 59 * time.Minute}, {Elem: "192.0.2.2", Expires: 59 * time.Minute}})
	got := readFile(t, path)
	if _, ok := got["192.0.2.1"]; ok {
		t.Fatal("a read begun before the unblock resurrected it")
	}
	if _, ok := got["192.0.2.2"]; !ok {
		t.Fatal("the stale-read guard dropped an unrelated ban")
	}
	// Banned again later: a read begun after the unblock keeps it.
	_ = s.Snapshot(t0.Add(5*time.Minute), []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour}})
	if _, ok := readFile(t, path)["192.0.2.1"]; !ok {
		t.Fatal("a re-ban after the unblock was not persisted")
	}
	if len(s.forgot) != 0 {
		t.Fatalf("tombstones not pruned: %v", s.forgot)
	}
}

// Outside the daemon there is no store: Forget does nothing.
func TestForgetWithoutDefault(t *testing.T) {
	SetDefault(nil)
	Forget("192.0.2.1") // must not panic
	s, path := newStore(t)
	_, _ = s.Restore(nil, nil)
	_ = s.Snapshot(t0, []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour}})
	SetDefault(s)
	defer SetDefault(nil)
	Forget("192.0.2.1")
	if len(readFile(t, path)) != 0 {
		t.Fatal("package Forget did not reach the default store")
	}
}

// A corrupt file is reported and the store starts empty (the next snapshot
// rewrites it); a missing one is simply empty.
func TestLoadMissingAndCorrupt(t *testing.T) {
	s, path := newStore(t)
	if err := s.Load(); err != nil || s.Len() != 0 {
		t.Fatalf("missing: len=%d err=%v", s.Len(), err)
	}
	if err := os.WriteFile(path, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Load(); err == nil || s.Len() != 0 {
		t.Fatalf("corrupt: len=%d err=%v", s.Len(), err)
	}
}

// The live path stays a redirectable var (CLAUDE.md §5).
func TestDefaultPathIsRedirectable(t *testing.T) {
	restore := SetPathForTest("/tmp/x.json")
	if DefaultPath != "/tmp/x.json" {
		t.Fatal("SetPathForTest did not redirect")
	}
	restore()
	if DefaultPath != "/var/lib/cfm/ttlbans.json" {
		t.Fatalf("DefaultPath = %q", DefaultPath)
	}
}

// A read that lost at least three stored live bans, and more than half, is
// a table recreated empty under the daemon (`cfm disable`, then a CLI command
// running EnsureBase): those bans stay for the next start, a new ban beside
// them is added, and an expired one still goes.
func TestSnapshotKeepsBansARecreatedTableLost(t *testing.T) {
	s, path := newStore(t)
	_, _ = s.Restore(nil, nil)
	_ = s.Snapshot(t0, []firewall.SetElementTimed{
		{Elem: "192.0.2.1", Expires: time.Hour},
		{Elem: "192.0.2.2", Expires: time.Hour},
		{Elem: "192.0.2.3", Expires: time.Hour},
		{Elem: "192.0.2.4", Expires: 2 * time.Minute},
	})
	_ = s.Snapshot(t0.Add(5*time.Minute), []firewall.SetElementTimed{{Elem: "192.0.2.9", Expires: time.Hour}})
	got := readFile(t, path)
	if len(got) != 4 {
		t.Fatalf("after a recreated table: %v, want .1-.3 kept and .9 added (.4 expired)", got)
	}
}

// Losing one or two bans, or a few of many, is ordinary churn (an AddBlock
// that replaced a ban, a hand-run `nft delete element`): taken as it is, or
// a node with one ban would keep a removed ban until it expired.
func TestSnapshotTakesOrdinaryChurn(t *testing.T) {
	s, path := newStore(t)
	_, _ = s.Restore(nil, nil)
	_ = s.Snapshot(t0, []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: 6 * time.Hour}})
	_ = s.Snapshot(t0.Add(time.Minute), nil) // the one ban removed
	if got := readFile(t, path); len(got) != 0 {
		t.Fatalf("1 of 1 lost: %v, want it gone", got)
	}
	var many []firewall.SetElementTimed
	for i := 10; i < 30; i++ {
		many = append(many, firewall.SetElementTimed{Elem: net.IPv4(198, 51, 100, byte(i)).String(), Expires: time.Hour})
	}
	_ = s.Snapshot(t0.Add(2*time.Minute), many)
	_ = s.Snapshot(t0.Add(3*time.Minute), many[3:])
	if got := readFile(t, path); len(got) != 17 {
		t.Fatalf("3 of 20 lost: %d entries, want 17", len(got))
	}
}

// `cfm flush` leaves a marker: a read begun after it is the truth (even with
// the file rewritten by a save that raced the flush, and over a failed
// restore's carry); a read begun before it is not.
func TestSnapshotAfterDiscardTakesTheRead(t *testing.T) {
	s, path := newStore(t)
	base := time.Now()
	s.now = func() time.Time { return base }
	writeFile(t, path, map[string]Entry{"192.0.2.7": {Expires: base.Add(time.Hour)}})
	_ = s.Load()
	_, _ = s.Restore(&batchFake{err: errors.New("nft: busy")}, nil) // .7 carried
	var three []firewall.SetElementTimed
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		three = append(three, firewall.SetElementTimed{Elem: ip, Expires: time.Hour})
	}
	_ = s.Snapshot(base.Add(-time.Minute), three)
	if err := Discard(path); err != nil {
		t.Fatal(err)
	}
	_ = s.Snapshot(base.Add(-30*time.Second), three) // began before the flush, saved after it
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the racing save did not rewrite the file; the test proves nothing")
	}
	_ = s.Snapshot(time.Now().Add(time.Second), []firewall.SetElementTimed{{Elem: "192.0.2.5", Expires: time.Hour}})
	if got := readFile(t, path); len(got) != 1 || got["192.0.2.5"].Expires.IsZero() {
		t.Fatalf("after cfm flush: %v, want only the new ban", got)
	}
	if _, err := os.Stat(flushMarker(path)); !os.IsNotExist(err) {
		t.Fatal("the marker outlived the read that acted on it")
	}
}

// A flush while the daemon was down: the next start restores nothing.
func TestRestoreAfterDiscardRestoresNothing(t *testing.T) {
	s, path := newStore(t)
	writeFile(t, path, map[string]Entry{"192.0.2.1": {Expires: t0.Add(time.Hour)}})
	if err := Discard(path); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, map[string]Entry{"192.0.2.1": {Expires: t0.Add(time.Hour)}}) // a save that raced it
	_ = s.Load()
	be := &batchFake{}
	res, err := s.Restore(be, nil)
	if err != nil || len(be.got) != 0 || res.Flushed != 1 {
		t.Fatalf("restored %v (res %+v, err %v), want nothing after a flush", be.got, res, err)
	}
	if len(readFile(t, path)) != 0 {
		t.Fatal("the flushed bans stayed in the file")
	}
}

// `cfm unblock` with the daemon stopped edits the file itself.
func TestForgetInFile(t *testing.T) {
	_, path := newStore(t)
	writeFile(t, path, map[string]Entry{
		"192.0.2.1":   {Expires: t0.Add(time.Hour)},
		"2001:db8::1": {Expires: t0.Add(time.Hour)},
	})
	if err := ForgetInFile(path, "2001:DB8::1", "not-an-ip"); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if _, ok := got["2001:db8::1"]; ok || len(got) != 1 {
		t.Fatalf("file %v, want only 192.0.2.1", got)
	}
	if err := ForgetInFile(filepath.Join(t.TempDir(), "none.json"), "192.0.2.1"); err != nil {
		t.Fatalf("missing file: %v", err)
	}
}

// Expiry moves below the tolerance on each read must not pile up unsaved:
// the comparison is against the file.
func TestSnapshotDriftIsBoundedByTheFile(t *testing.T) {
	s, path := newStore(t)
	_, _ = s.Restore(nil, nil)
	_ = s.Snapshot(t0, []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour}})
	for i := 1; i <= 4; i++ { // +3s on each read: 12s in all
		_ = s.Snapshot(t0.Add(time.Duration(i)*time.Minute), []firewall.SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour - time.Duration(i)*time.Minute + time.Duration(3*i)*time.Second}})
	}
	if got := readFile(t, path)["192.0.2.1"].Expires; got.Sub(t0.Add(time.Hour)) <= expiryTolerance {
		t.Fatalf("file expiry %s: 12s of drift never saved", got)
	}
}
