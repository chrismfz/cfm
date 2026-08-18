package procbaseline

import (
	"math"
	"testing"
	"time"
)

func TestSummarizeFamilyStatsIncludesValidZeroes(t *testing.T) {
	t0 := time.Unix(1_700_100_000, 0).Truncate(time.Minute)
	points := []Point{
		{At: t0, Count: 2},
		{At: t0.Add(time.Minute), Count: 0},
		{At: t0.Add(2 * time.Minute), Count: 4},
		{At: t0.Add(3 * time.Minute), Count: 10},
	}

	got := summarizeFamilyStats("exim", t0, t0.Add(4*time.Minute), points)
	if got.Samples != 4 || got.ExpectedSamples != 4 || got.Coverage != 1 {
		t.Fatalf("sample accounting = %+v", got)
	}
	if got.PresentSamples != 3 {
		t.Fatalf("present samples = %d, want 3", got.PresentSamples)
	}
	if got.Median != 3 {
		t.Fatalf("median = %v, want 3", got.Median)
	}
	if got.P95 != 10 || got.Max != 10 {
		t.Fatalf("tail stats = p95=%d max=%d, want 10/10", got.P95, got.Max)
	}
}

func TestSummarizeFamilyStatsTreatsMissingMinutesAsCoverageGaps(t *testing.T) {
	t0 := time.Unix(1_700_110_000, 0).Truncate(time.Minute)
	points := []Point{
		{At: t0, Count: 1},
		{At: t0.Add(2 * time.Minute), Count: 0},
		{At: t0.Add(4 * time.Minute), Count: 3},
	}

	got := summarizeFamilyStats("worker", t0, t0.Add(5*time.Minute), points)
	if got.Samples != 3 || got.ExpectedSamples != 5 {
		t.Fatalf("sample accounting = %+v", got)
	}
	if math.Abs(got.Coverage-0.6) > 1e-9 {
		t.Fatalf("coverage = %v, want 0.6", got.Coverage)
	}
	if got.Median != 1 || got.P95 != 3 || got.Max != 3 {
		t.Fatalf("distribution = median=%v p95=%d max=%d", got.Median, got.P95, got.Max)
	}
}

func TestExpectedMinuteBucketsHonorsStoreWindowBoundaries(t *testing.T) {
	t0 := time.Unix(1_700_120_000, 0).Truncate(time.Minute)
	tests := []struct {
		name       string
		start, end time.Time
		want       int
	}{
		{"aligned", t0, t0.Add(3 * time.Minute), 3},
		{"partial_start", t0.Add(30 * time.Second), t0.Add(3 * time.Minute), 2},
		{"partial_end", t0, t0.Add(3*time.Minute + 10*time.Second), 4},
		{"both_partial", t0.Add(30 * time.Second), t0.Add(3*time.Minute + 10*time.Second), 3},
		{"subminute_without_bucket", t0.Add(time.Second), t0.Add(30 * time.Second), 0},
		// FamilySeries passes Unix seconds to SQLite. A sub-second offset inside
		// the same second therefore has the same lower bound as the aligned time.
		{"subsecond_matches_store_precision", t0.Add(500 * time.Millisecond), t0.Add(time.Minute), 1},
		{"same_second_subsecond_window", t0.Add(100 * time.Millisecond), t0.Add(900 * time.Millisecond), 0},
		{"empty", t0, t0, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := expectedMinuteBuckets(tc.start, tc.end); got != tc.want {
				t.Fatalf("expectedMinuteBuckets(%s,%s) = %d, want %d", tc.start, tc.end, got, tc.want)
			}
		})
	}
}

func TestSummarizeFamilyStatsEmptyHistory(t *testing.T) {
	t0 := time.Unix(1_700_130_000, 0).Truncate(time.Minute)
	got := summarizeFamilyStats("spamd", t0, t0.Add(5*time.Minute), nil)
	if got.Samples != 0 || got.ExpectedSamples != 5 || got.Coverage != 0 {
		t.Fatalf("empty sample accounting = %+v", got)
	}
	if got.PresentSamples != 0 || got.Median != 0 || got.P95 != 0 || got.Max != 0 {
		t.Fatalf("empty distribution must remain zero-valued with Samples=0: %+v", got)
	}
}

func TestFamilyStatsPreservesZeroVsTelemetryGapFromStore(t *testing.T) {
	st := openTestStore(t)
	t0 := time.Unix(1_700_140_000, 0).Truncate(time.Minute)

	if err := st.Record(t0, Sample{
		TotalProcesses: 15,
		Families:       map[string]int{"exim": 10, "php-fpm": 5},
	}); err != nil {
		t.Fatal(err)
	}
	// No host sample at t0+1m: telemetry gap.
	if err := st.Record(t0.Add(2*time.Minute), Sample{
		TotalProcesses: 7,
		Families:       map[string]int{"php-fpm": 7},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.FamilyStats("exim", t0, t0.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got.Samples != 2 || got.ExpectedSamples != 4 || got.Coverage != 0.5 {
		t.Fatalf("sample accounting = %+v", got)
	}
	if got.PresentSamples != 1 {
		t.Fatalf("present samples = %d, want 1", got.PresentSamples)
	}
	// Stored exim values are [10,0]. The missing t0+1m and t0+3m minutes do
	// not enter the distribution.
	if got.Median != 5 || got.P95 != 10 || got.Max != 10 {
		t.Fatalf("distribution = median=%v p95=%d max=%d", got.Median, got.P95, got.Max)
	}
}
