package lvestat

import (
	"sort"
	"time"
)

// CPUSample is one tenant's CPU rate between two /proc/lve/list snapshots.
type CPUSample struct {
	Reseller int64 `json:"reseller"`
	UID      int64 `json:"uid"`
	// CPURate is the change in the raw CPU-usage counter per second between the
	// two snapshots. It is a RELATIVE signal for ranking tenants against each
	// other — the counter's absolute unit is not yet confirmed, so this is NOT
	// normalized to a percentage of a core. (Normalizing to a %-of-limit against
	// LimitCPU needs that unit; a later slice adds it once calibrated.)
	CPURate  float64 `json:"cpu_rate"`
	LimitCPU int64   `json:"limit_cpu"` // lCPU passthrough (hundredths of a %; 0 = unlimited)
	NumCPU   int64   `json:"num_cpu"`   // nCPU passthrough
	EP       int64   `json:"ep"`        // current entry procs (from cur)
	NProc    int64   `json:"nproc"`     // current procs (from cur)
}

// Diff computes per-tenant CPU rates between prev and cur (cur is the newer
// snapshot, taken `elapsed` after prev). Tenants in cur are matched to prev by
// (reseller,uid). A tenant absent from prev, or whose CPU counter went backwards
// (LVE recreated / counter reset), yields rate 0 rather than a bogus spike — a
// newly-seen or reset tenant simply reads 0 until the next interval. The result
// is sorted by CPURate descending (hottest first), uid ascending on ties.
// Returns nil if elapsed <= 0.
func Diff(prev, cur Snapshot, elapsed time.Duration) []CPUSample {
	secs := elapsed.Seconds()
	if secs <= 0 {
		return nil
	}

	prevCPU := make(map[[2]int64]int64, len(prev.Entries))
	for _, e := range prev.Entries {
		prevCPU[[2]int64{e.Reseller, e.UID}] = e.CPUUsage
	}

	out := make([]CPUSample, 0, len(cur.Entries))
	for _, e := range cur.Entries {
		rate := 0.0
		if p, ok := prevCPU[[2]int64{e.Reseller, e.UID}]; ok && e.CPUUsage >= p {
			rate = float64(e.CPUUsage-p) / secs
		}
		out = append(out, CPUSample{
			Reseller: e.Reseller,
			UID:      e.UID,
			CPURate:  rate,
			LimitCPU: e.LimitCPU,
			NumCPU:   e.NumCPU,
			EP:       e.EP,
			NProc:    e.NProc,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].CPURate != out[j].CPURate {
			return out[i].CPURate > out[j].CPURate
		}
		return out[i].UID < out[j].UID
	})
	return out
}
