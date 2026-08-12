package lvestat

import (
	"sort"
	"time"
)

// cpuNsPerSecPerCore is the CPU-usage counter's rate for one fully-busy core.
// The /proc/lve/list CPU column is cumulative NANOSECONDS of CPU time — verified
// empirically against two live snapshots ~22s apart (titan, CL9): the busiest
// tenant's ΔCPU/Δt came to ~0.93 cores against a 6-core limit and the whole-box
// non-LVE aggregate to ~10 cores, i.e. every value bounded sanely by nCPU. So a
// rate of 1e9 counter-units/sec == one core fully consumed.
const cpuNsPerSecPerCore = 1e9

// cpuLimitUnitsPerCore is the lCPU limit unit: 10000 == 100% of one core.
const cpuLimitUnitsPerCore = 10000.0

// LimitCores converts an lCPU cap (hundredths of a %-of-one-core; 10000 == one
// core) to whole cores. Returns 0 for an unlimited/zero cap. Exported so the
// CLI/UI render the cap from one source of truth rather than re-hardcoding the
// 10000 unit.
func LimitCores(limitCPU int64) float64 {
	if limitCPU <= 0 {
		return 0
	}
	return float64(limitCPU) / cpuLimitUnitsPerCore
}

// CPUSample is one tenant's CPU rate between two /proc/lve/list snapshots.
type CPUSample struct {
	Reseller int64 `json:"reseller"`
	UID      int64 `json:"uid"`
	// CPURate is the change in the CPU-usage counter (nanoseconds of CPU time)
	// per second between the two snapshots — the raw signal Cores/PctOfLimit are
	// derived from. Kept for debugging; consumers usually want Cores.
	CPURate float64 `json:"cpu_rate"`
	// Cores is CPU cores consumed = CPURate / 1e9 (e.g. 0.93 = 93% of one core,
	// 2.4 = 2.4 cores). The human-facing "how hot is this tenant" number.
	Cores float64 `json:"cores"`
	// PctOfLimit is Cores as a percentage of the tenant's lCPU limit (100 = at
	// its cap → throttling). 0 when the tenant is unlimited (lCPU == 0).
	PctOfLimit float64 `json:"pct_of_limit"`
	LimitCPU   int64   `json:"limit_cpu"` // lCPU passthrough (hundredths of a %; 0 = unlimited)
	NumCPU     int64   `json:"num_cpu"`   // nCPU passthrough
	EP         int64   `json:"ep"`        // current entry procs (from cur)
	NProc      int64   `json:"nproc"`     // current procs (from cur)
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
		cores := rate / cpuNsPerSecPerCore
		pct := 0.0
		if e.LimitCPU > 0 { // lCPU == 0 means unlimited → no meaningful %
			limitCores := float64(e.LimitCPU) / cpuLimitUnitsPerCore
			if limitCores > 0 {
				pct = cores / limitCores * 100
			}
		}
		out = append(out, CPUSample{
			Reseller:   e.Reseller,
			UID:        e.UID,
			CPURate:    rate,
			Cores:      cores,
			PctOfLimit: pct,
			LimitCPU:   e.LimitCPU,
			NumCPU:     e.NumCPU,
			EP:         e.EP,
			NProc:      e.NProc,
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
