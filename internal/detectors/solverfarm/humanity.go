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
// humanity distribution and country split of the cluster a finding is about.
//
// EVIDENCE ONLY. Nothing here is read by a threshold, a track or a mark: the
// readings ride the evidence records (solveRec, xhRec) under the caps those
// already have, and are folded only while an alert is being built. A
// fingerprint is a population, so a finding on a coarse TLS bucket can sit on
// real visitors (read 5: half of www.e-vafeiadis.gr's c28caa00 solves were a
// Greek audience at hs 0); this lets the operator see that on the alert
// instead of acting on the fingerprint blind.

// hsBucket is a solve's humanity bucket. The zero value is hsUnscored, so a
// record built without a reading can never claim a score.
type hsBucket uint8

const (
	hsUnscored hsBucket = iota // no reading: the rung was off, or not a scored solve
	hsNone                     // scored, but the verify carried no payload (hs=-)
	hs0                        // scored clean
	hs1to59
	hs60to99
	hs100up
	hsBucketCount
)

// hsBucketNames are the bucket keys of HumanitySummary.Buckets and of the
// history payload's humanity.hs object, in display order.
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

// bucketOf maps an event's reading to its bucket. A nil reading (or one that
// says it was not scored) is unscored, never 0. hs=- mirrors the solve line
// (HumanitySuffix): a no-payload solve renders hs=- only while its score is 0
// — a UA-borne opener can still score one, and the line then shows that
// score, so the bucket does too.
func bucketOf(h *core.Humanity) hsBucket {
	if h == nil || !h.Scored {
		return hsUnscored
	}
	switch {
	case h.NoPayload && h.Score == 0:
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

// tellsOf is the exact tells string a record keeps: only a scored reading has
// one.
func tellsOf(h *core.Humanity) string {
	if h == nil || !h.Scored {
		return ""
	}
	return strings.TrimSpace(h.Tells)
}

// KeyCount is one ranked entry of a humanity summary (a tells string or a
// country) with the number of solves carrying it.
type KeyCount struct {
	Key string
	N   int
}

// HumanitySummary is the humanity distribution of the cluster a finding is
// about. Which cluster is named by Cluster:
//
//   - "cross_host": the cross-host fingerprint's solves ON THIS VHOST over
//     XHWindow (from the cross-host record buffer). A combined finding that
//     includes cross_host uses this one, because the finding's Fingerprint is
//     the cross-host fp.
//   - "fp_concentration": the per-host fingerprint's solves on this vhost over
//     Window.
//   - "subnet_spread": every solve of the vhost over Window (no fingerprint
//     convicted, so the whole vhost is the cluster).
//
// N is the number of solves the summary covers (the evidence records). When
// Truncated is set, an evidence cap dropped records inside the window, so the
// counts are of a sample and N is a lower bound on the cluster's solves.
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
	if b < hsBucketCount {
		a.buckets[b]++
	}
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
// come out in the same order on every pass, and keeps the first n.
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
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Payload renders the summary as the detection_history solver_farm row's
// `humanity` object. The keys are a contract (the abuse-defense reads and
// cfm-web parse them): cluster, fingerprint (omitted when empty), window,
// n, truncated, hs {bucket: count, all six keys}, tells [{tells, n}],
// countries [{cc, n}].
func (h *HumanitySummary) Payload() map[string]interface{} {
	if h == nil {
		return nil
	}
	hs := make(map[string]interface{}, len(h.Buckets))
	for k, v := range h.Buckets {
		hs[k] = v
	}
	tells := make([]map[string]interface{}, 0, len(h.Tells))
	for _, t := range h.Tells {
		tells = append(tells, map[string]interface{}{"tells": t.Key, "n": t.N})
	}
	ccs := make([]map[string]interface{}, 0, len(h.Countries))
	for _, c := range h.Countries {
		ccs = append(ccs, map[string]interface{}{"cc": c.Key, "n": c.N})
	}
	p := map[string]interface{}{
		"cluster":   h.Cluster,
		"window":    h.Window.String(),
		"n":         h.N,
		"truncated": h.Truncated,
		"hs":        hs,
		"tells":     tells,
		"countries": ccs,
	}
	if h.Fingerprint != "" {
		p["fingerprint"] = h.Fingerprint
	}
	return p
}

// Line renders the summary for the alert text (one Samples line), e.g.
//
//	[challenge] humanity of fp c28caa00 on this vhost (fp_concentration, 3m0s, n=967): hs none ×3, 0 ×812, 60-99 ×140, 100+ ×12; tells: sw_renderer,no_input ×120; countries: GR 61%, US 9%
//
// Empty buckets are left out; shares are of n.
func (h *HumanitySummary) Line() string {
	if h == nil {
		return ""
	}
	subject := "all solves on this vhost"
	if h.Fingerprint != "" {
		subject = "fp " + h.Fingerprint + " on this vhost"
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
		fmt.Fprintf(&b, " %s %d%%", c.Key, c.N*100/h.N)
	}
	if h.Truncated {
		b.WriteString(" (evidence cap hit in this window: counts are of a sample)")
	}
	return b.String()
}
