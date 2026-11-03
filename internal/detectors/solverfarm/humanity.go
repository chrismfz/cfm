package solverfarm

import (
	"fmt"
	"sort"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
)

// Humanity context on a finding (abuse-defense master plan §5 candidate 3,
// docs/roadmaps/challenge-engine.md §8.3 leg 1): the ChallengeV2 Rung-1
// humanity distribution and country split of the PASSED solves of the cluster
// a finding is about.
//
// EVIDENCE ONLY. Nothing here is read by a threshold, a track or a mark: the
// readings ride the evidence records (solveRec, xhRec) under the caps those
// already have, and are folded only while an alert is being built. A
// fingerprint is a population, so a finding on a coarse TLS bucket can sit on
// real visitors (read 5: half of www.e-vafeiadis.gr's c28caa00 solves were a
// Greek audience at hs 0); this lets the operator see that on the alert
// instead of acting on the fingerprint blind.
//
// PASSED SOLVES ONLY. The detector is fed from the solve event stream, and a
// Rung-1 reject returns before that event is published, so under a
// challenge_v2 arm the failing population never reaches it. The rejected side
// is detection_history type=challenge_v2_reject.

// hsBucket is a solve's humanity bucket. The zero value is hsUnscored, so a
// record built without a reading can never claim a score.
type hsBucket uint8

const (
	hsUnscored hsBucket = iota // no reading: the rung was off
	hsNone                     // scored, no report: the solve line's hs=-
	hs0                        // scored clean
	hs1to59
	hs60to99
	hs100up
	hsBucketCount
)

// hsBucketNames are the bucket keys of HumanitySummary.Buckets and of the
// history payload's humanity.hs object.
var hsBucketNames = [hsBucketCount]string{
	hsUnscored: "unscored",
	hsNone:     "none",
	hs0:        "0",
	hs1to59:    "1-59",
	hs60to99:   "60-99",
	hs100up:    "100+",
}

// hsBucketOrder is the order buckets are rendered in (the bucket NAMES are
// the contract; the enum values are not).
var hsBucketOrder = [hsBucketCount]hsBucket{hsNone, hsUnscored, hs0, hs1to59, hs60to99, hs100up}

// humanityTopN is how many tells strings and countries a summary lists.
const humanityTopN = 5

// maxInternedTells bounds the tells-string intern table. The scorer has a
// handful of tells, so the distinct comma-joined combinations seen in
// practice are far below this; past it a record keeps its own string.
const maxInternedTells = 512

// bucketOf maps an event's reading to its bucket. nil is the only unscored
// (never 0). hs=- is core.Humanity.NoReport, the same predicate the solve
// line renders with, so a no-payload solve that a UA-borne opener scored is
// bucketed by its score, as the line shows it.
func bucketOf(h *core.Humanity) hsBucket {
	switch {
	case h == nil:
		return hsUnscored
	case h.NoReport():
		return hsNone
	case h.Score <= 0:
		return hs0
	case h.Score < 60:
		return hs1to59
	case h.Score < 100:
		return hs60to99
	default:
		return hs100up
	}
}

// BucketName is the hs bucket name ("none", "unscored", "0", "1-59",
// "60-99", "100+") a reading lands in — exported so the challenge server's
// tests can pin the buckets to its solve line (HumanitySuffix).
func BucketName(h *core.Humanity) string { return hsBucketNames[bucketOf(h)] }

// tellsOf is the exact tells string a record keeps: none for an unscored or
// no-report (hs=-) reading, which the solve line renders without tells.
func tellsOf(h *core.Humanity) string {
	if h == nil || h.NoReport() {
		return ""
	}
	return strings.TrimSpace(h.Tells)
}

// internTells returns a shared copy of s, so a record retains the table's
// string rather than the per-solve allocation the event carried. Bounded at
// maxInternedTells distinct values; past that, s itself is returned. Owned by
// RunOnce (serial), like hosts.
func (d *Detector) internTells(s string) string {
	if s == "" {
		return ""
	}
	if v, ok := d.tellsIntern[s]; ok {
		return v
	}
	if len(d.tellsIntern) >= maxInternedTells {
		return s
	}
	v := strings.Clone(s)
	d.tellsIntern[v] = v
	return v
}

// KeyCount is one ranked entry (a tells string, a country, a UA) with the
// number of solves carrying it.
type KeyCount struct {
	Key string
	N   int
}

// HumanitySummary is the humanity distribution of the PASSED solves of the
// cluster a finding is about (a Rung-1 reject never reaches this detector;
// see detection_history type=challenge_v2_reject for those). Which cluster
// is named by Cluster, always on the finding's vhost:
//
//   - "cross_host": the cross-host fingerprint's solves ON THIS VHOST over
//     XHWindow (from the cross-host record buffer). A combined finding that
//     includes cross_host uses this one, because the finding's Fingerprint is
//     the cross-host fp. Note the finding's own solves / distinct_* are
//     node-wide on a cross-host finding; this summary is not.
//   - "fp_concentration": the per-host fingerprint's solves over Window.
//   - "subnet_spread": every solve of the vhost over Window (no fingerprint
//     convicted, so the whole vhost is the cluster).
//
// N is the number of solves the summary covers (the evidence records). When
// Truncated is set, an evidence cap dropped a record inside the window, so
// the counts are of a sample and N is a lower bound on the cluster's solves.
type HumanitySummary struct {
	Cluster     string
	Fingerprint string
	Window      time.Duration
	N           int
	Truncated   bool
	// Buckets counts solves per hs bucket, keyed by hsBucketNames ("none",
	// "unscored", "0", "1-59", "60-99", "100+"); every key is present.
	Buckets map[string]int
	// Tells is the top tells strings (exact, comma-joined as on the solve
	// line) of scored solves with at least one tell, by count then key.
	Tells []KeyCount
	// Countries is the top ISO-2 countries by count then key; solves with no
	// country are counted in N only.
	Countries []KeyCount
}

// humanityAcc folds evidence records into a summary.
type humanityAcc struct {
	n         int
	buckets   [hsBucketCount]int
	tells     map[string]int
	countries map[string]int
}

func newHumanityAcc() *humanityAcc {
	return &humanityAcc{tells: map[string]int{}, countries: map[string]int{}}
}

func (a *humanityAcc) add(b hsBucket, tells, cc string) {
	a.n++
	a.buckets[b]++
	if tells != "" {
		a.tells[tells]++
	}
	if cc != "" {
		a.countries[cc]++
	}
}

// summary returns nil when no record was folded: an empty cluster has no
// distribution to report.
func (a *humanityAcc) summary(cluster, fp string, window time.Duration, truncated bool) *HumanitySummary {
	if a.n == 0 {
		return nil
	}
	b := make(map[string]int, hsBucketCount)
	for i, name := range hsBucketNames {
		b[name] = a.buckets[i]
	}
	return &HumanitySummary{
		Cluster: cluster, Fingerprint: fp, Window: window,
		N: a.n, Truncated: truncated, Buckets: b,
		Tells:     topKeys(a.tells, humanityTopN),
		Countries: topKeys(a.countries, humanityTopN),
	}
}

// topKeys ranks m by count (descending) then key (ascending), so equal counts
// come out in the same order on every pass, and keeps the first n (all when
// n <= 0).
func topKeys(m map[string]int, n int) []KeyCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]KeyCount, 0, len(m))
	for k, v := range m {
		out = append(out, KeyCount{Key: k, N: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Line renders the summary for the alert text (one Samples line), e.g.
//
//	[challenge] humanity of passed solves of fp c28caa00 on this vhost (fp_concentration, 3m0s, n=967): hs none ×3, 0 ×812, 60-99 ×140, 100+ ×12; tells: "sw_renderer,no_input" ×120; countries: GR ×590, US ×88; rejects not included (detection_history type=challenge_v2_reject)
//
// Empty buckets are left out; countries are counts (a solve with no country
// is in n only).
func (h *HumanitySummary) Line() string {
	if h == nil {
		return ""
	}
	subject := "passed solves on this vhost"
	if h.Fingerprint != "" {
		subject = "passed solves of fp " + h.Fingerprint + " on this vhost"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[challenge] humanity of %s (%s, %s, n=%d): hs", subject, h.Cluster, h.Window, h.N)
	first := true
	for _, k := range hsBucketOrder {
		name := hsBucketNames[k]
		if c := h.Buckets[name]; c > 0 {
			if !first {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, " %s ×%d", name, c)
			first = false
		}
	}
	b.WriteString("; tells:")
	if len(h.Tells) == 0 {
		b.WriteString(" none")
	}
	for i, t := range h.Tells {
		if i > 0 {
			b.WriteString(",")
		}
		// %q: tells are scorer-produced names, but quoting keeps a comma-joined
		// list readable as ONE entry.
		fmt.Fprintf(&b, " %q ×%d", t.Key, t.N)
	}
	b.WriteString("; countries:")
	if len(h.Countries) == 0 {
		b.WriteString(" unknown")
	}
	for i, c := range h.Countries {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, " %s ×%d", c.Key, c.N)
	}
	if h.Truncated {
		b.WriteString(" (evidence cap hit in this window: counts are of a sample)")
	}
	b.WriteString("; rejects not included (detection_history type=challenge_v2_reject)")
	return b.String()
}
