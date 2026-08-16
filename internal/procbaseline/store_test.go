package procbaseline

import (
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "processbaseline.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRecordAndFamilySeriesDistinguishZeroFromMissingTelemetry(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Unix(1_700_000_000, 0).Truncate(time.Minute)

	if err := st.Record(t0, Sample{
		TotalProcesses: 15,
		Families:       map[string]int{"exim": 10, "php-fpm": 5},
	}); err != nil {
		t.Fatal(err)
	}
	// No sample at t0+1m: this must remain a gap, not turn into an exim=0 point.
	if err := st.Record(t0.Add(2*time.Minute), Sample{
		TotalProcesses: 7,
		Families:       map[string]int{"php-fpm": 7},
	}); err != nil {
		t.Fatal(err)
	}

	exim, err := st.FamilySeries("exim", t0, t0.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(exim) != 2 {
		t.Fatalf("exim points = %d, want 2: %+v", len(exim), exim)
	}
	if exim[0].Count != 10 || exim[0].TotalProcesses != 15 {
		t.Fatalf("first exim point = %+v", exim[0])
	}
	if exim[1].Count != 0 || exim[1].TotalProcesses != 7 {
		t.Fatalf("family absence in a valid sample must be explicit zero: %+v", exim[1])
	}
	if !exim[1].At.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("missing minute must remain a gap; second point at %s", exim[1].At)
	}
}

func TestRecordSameMinuteReplacesWholeSnapshot(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Unix(1_700_010_000, 0).Truncate(time.Minute)

	if err := st.Record(t0, Sample{
		TotalProcesses: 10,
		Families:       map[string]int{"exim": 6, "php-fpm": 4},
	}); err != nil {
		t.Fatal(err)
	}
	// A retry later in the same minute is a replacement, not an increment. The
	// old php-fpm row must disappear rather than surviving as stale baseline data.
	if err := st.Record(t0.Add(25*time.Second), Sample{
		TotalProcesses: 12,
		Families:       map[string]int{"exim": 12},
	}); err != nil {
		t.Fatal(err)
	}

	exim, err := st.FamilySeries("exim", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(exim) != 1 || exim[0].Count != 12 || exim[0].TotalProcesses != 12 {
		t.Fatalf("replacement exim series = %+v", exim)
	}
	php, err := st.FamilySeries("php-fpm", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(php) != 1 || php[0].Count != 0 {
		t.Fatalf("stale family survived same-minute replacement: %+v", php)
	}
}

func TestRecordRejectsInconsistentSnapshotWithoutClobberingData(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Unix(1_700_020_000, 0).Truncate(time.Minute)
	good := Sample{TotalProcesses: 5, Families: map[string]int{"exim": 5}}
	if err := st.Record(t0, good); err != nil {
		t.Fatal(err)
	}

	bad := Sample{TotalProcesses: 99, Families: map[string]int{"exim": 3}}
	if err := st.Record(t0.Add(10*time.Second), bad); err == nil {
		t.Fatal("inconsistent sample unexpectedly accepted")
	}
	got, err := st.FamilySeries("exim", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Count != 5 || got[0].TotalProcesses != 5 {
		t.Fatalf("invalid replacement clobbered prior valid sample: %+v", got)
	}
}

func TestRecordPrunesExpiredSamplesAndFamilyRows(t *testing.T) {
	st := openTestStore(t)
	st.retention = 2 * time.Minute
	t0 := time.Unix(1_700_030_000, 0).Truncate(time.Minute)
	one := Sample{TotalProcesses: 1, Families: map[string]int{"exim": 1}}

	if err := st.Record(t0, one); err != nil {
		t.Fatal(err)
	}
	if err := st.Record(t0.Add(time.Minute), one); err != nil {
		t.Fatal(err)
	}
	// cutoff = t0+1m, so t0 is expired while the cutoff bucket itself remains.
	if err := st.Record(t0.Add(3*time.Minute), one); err != nil {
		t.Fatal(err)
	}

	got, err := st.FamilySeries("exim", t0, t0.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("retained points = %d, want 2: %+v", len(got), got)
	}
	if !got[0].At.Equal(t0.Add(time.Minute)) || !got[1].At.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("unexpected retained buckets: %+v", got)
	}

	var oldFamilyRows int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM process_family_counts WHERE bucket < ?`, bucketOf(t0.Add(time.Minute))).Scan(&oldFamilyRows); err != nil {
		t.Fatal(err)
	}
	if oldFamilyRows != 0 {
		t.Fatalf("expired family rows = %d, want 0", oldFamilyRows)
	}
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "processbaseline.db")
	t0 := time.Unix(1_700_040_000, 0).Truncate(time.Minute)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Record(t0, Sample{TotalProcesses: 3, Families: map[string]int{"spamd": 3}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.FamilySeries("spamd", t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Count != 3 || got[0].TotalProcesses != 3 {
		t.Fatalf("reopened series = %+v", got)
	}
}
