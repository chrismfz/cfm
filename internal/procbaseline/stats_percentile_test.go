package procbaseline

import (
	"testing"
	"time"
)

func TestSummarizeFamilyStatsUsesNearestRankP95(t *testing.T) {
	t0 := time.Unix(1_700_150_000, 0).Truncate(time.Minute)
	points := make([]Point, 0, 20)
	for i := 1; i <= 20; i++ {
		points = append(points, Point{At: t0.Add(time.Duration(i-1) * time.Minute), Count: i})
	}

	got := summarizeFamilyStats("worker", t0, t0.Add(20*time.Minute), points)
	if got.Median != 10.5 {
		t.Fatalf("median = %v, want 10.5", got.Median)
	}
	if got.P95 != 19 {
		t.Fatalf("p95 = %d, want nearest-rank 19", got.P95)
	}
	if got.Max != 20 {
		t.Fatalf("max = %d, want 20", got.Max)
	}
}
