package procbaseline

import (
	"math"
	"sort"
	"time"
)

// FamilyStats is a descriptive summary of one COMM family's stored history over
// an explicit half-open [Start, End) window. It intentionally contains no
// anomaly verdict or minimum-history policy; callers can inspect Samples and
// Coverage before deciding whether the history is sufficient for a later rule.
type FamilyStats struct {
	Comm            string
	Start           time.Time
	End             time.Time
	Samples         int
	ExpectedSamples int
	Coverage        float64
	PresentSamples  int
	Median          float64
	P95             int
	Max             int
}

// FamilyStats returns descriptive statistics for one exact COMM family. Valid
// host samples where the family was absent remain explicit zeroes and therefore
// participate in the distribution. Missing host samples remain telemetry gaps:
// they reduce Coverage but are not inserted as zero-valued observations.
func (s *Store) FamilyStats(comm string, start, end time.Time) (FamilyStats, error) {
	points, err := s.FamilySeries(comm, start, end)
	if err != nil {
		return FamilyStats{}, err
	}
	return summarizeFamilyStats(comm, start, end, points), nil
}

func summarizeFamilyStats(comm string, start, end time.Time, points []Point) FamilyStats {
	out := FamilyStats{
		Comm:            comm,
		Start:           start,
		End:             end,
		Samples:         len(points),
		ExpectedSamples: expectedMinuteBuckets(start, end),
	}
	if out.ExpectedSamples > 0 {
		out.Coverage = float64(out.Samples) / float64(out.ExpectedSamples)
	}
	if len(points) == 0 {
		return out
	}

	counts := make([]int, 0, len(points))
	for _, p := range points {
		counts = append(counts, p.Count)
		if p.Count > 0 {
			out.PresentSamples++
		}
	}
	sort.Ints(counts)

	n := len(counts)
	if n%2 == 1 {
		out.Median = float64(counts[n/2])
	} else {
		out.Median = (float64(counts[n/2-1]) + float64(counts[n/2])) / 2
	}

	// P95 uses the nearest-rank definition so it always remains an observed
	// integer process count. Minimum sample/coverage requirements belong to the
	// later policy layer, not this descriptive calculation.
	rank := int(math.Ceil(0.95 * float64(n)))
	out.P95 = counts[rank-1]
	out.Max = counts[n-1]
	return out
}

// expectedMinuteBuckets counts the minute-aligned bucket timestamps that fall
// inside the same second-precision [start.Unix(), end.Unix()) window used by
// FamilySeries. Matching the store query exactly prevents coverage drift at
// sub-second boundaries.
func expectedMinuteBuckets(start, end time.Time) int {
	if !end.After(start) {
		return 0
	}
	lo, hi := start.Unix(), end.Unix()
	if hi <= lo {
		return 0
	}

	first := lo
	if rem := first % bucketSeconds; rem != 0 {
		if rem > 0 {
			first += bucketSeconds - rem
		} else {
			first -= rem
		}
	}
	if first >= hi {
		return 0
	}
	return int((hi-1-first)/bucketSeconds) + 1
}
