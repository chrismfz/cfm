package health

// edac.go collects memory ECC (error-correcting code) error counters — the
// "is a DIMM going bad?" signal the health snapshot was previously blind to.
//
// Primary source is the kernel EDAC subsystem under /sys/devices/system/edac/mc
// (cheap file reads, per-controller and per-DIMM cumulative counters). When EDAC
// is not populated (e.g. amd64_edac not loaded) but the CPU's machine-check
// decoder still logs "[Hardware Error] ... ECC" lines to the kernel ring, a
// best-effort fallback counts those instead so the signal is not lost.
//
// Counts are cumulative since boot. A single corrected error is benign ("no
// action required"), but a rising corrected count — or ANY uncorrected error —
// is a pre-failure / data-integrity signal, which is why whats_wrong surfaces
// them (corrected → warning, uncorrected → critical).

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bounds on directory traversal so a pathological sysfs can't blow up the scan.
const (
	maxECCControllers = 64
	maxECCDimms       = 128
)

// ECCReport summarizes memory ECC error counters. All counts are cumulative
// since boot. Present is false when no ECC information could be read at all
// (neither EDAC sysfs nor the kernel-ring fallback) — reported honestly rather
// than as "healthy".
type ECCReport struct {
	Present          bool           `json:"present"`
	Source           string         `json:"source,omitempty"` // "edac_sysfs" | "kernel_ring"
	CorrectedTotal   uint64         `json:"corrected_total"`
	UncorrectedTotal uint64         `json:"uncorrected_total"`
	Controllers      []ECCController `json:"controllers,omitempty"`
	DIMMs            []ECCDimm      `json:"dimms,omitempty"` // only DIMMs with non-zero counts
	Note             string         `json:"note,omitempty"`
}

// ECCController is one memory controller's cumulative counters.
type ECCController struct {
	Name             string `json:"name"`              // e.g. "mc0"
	MCName           string `json:"mc_name,omitempty"` // driver name, e.g. "amd64"
	CorrectedCount   uint64 `json:"corrected_count"`
	UncorrectedCount uint64 `json:"uncorrected_count"`
}

// ECCDimm is one DIMM/rank with a non-zero error count (the offending module).
type ECCDimm struct {
	ID               string `json:"id"`                 // e.g. "mc0/dimm1"
	Label            string `json:"label,omitempty"`    // operator/BIOS label
	Location         string `json:"location,omitempty"` // e.g. "mc#0channel#0slot#1"
	CorrectedCount   uint64 `json:"corrected_count"`
	UncorrectedCount uint64 `json:"uncorrected_count"`
}

// readECC reads ECC counters, preferring EDAC sysfs under edacRoot. When EDAC
// exposes no controllers and mceFallback is non-nil, it falls back to that
// (kernel-ring-derived) counter source so an AMD box whose corrected errors
// only reach the machine-check log is still covered.
func readECC(edacRoot string, mceFallback func() (corrected, uncorrected uint64, ok bool)) ECCReport {
	rep := readEDACSysfs(edacRoot)
	if rep.Present {
		return rep
	}
	if mceFallback != nil {
		if ce, ue, ok := mceFallback(); ok {
			return ECCReport{
				Present:          true,
				Source:           "kernel_ring",
				CorrectedTotal:   ce,
				UncorrectedTotal: ue,
				Note:             "counts derived from the kernel ring buffer (EDAC sysfs unavailable); values reflect only machine-check messages still in the ring",
			}
		}
	}
	return ECCReport{Present: false, Note: "no EDAC memory-controller sysfs and no machine-check counters available"}
}

// readEDACSysfs walks /sys/devices/system/edac/mc/mc*/ summing corrected and
// uncorrected counters and collecting the DIMMs that carry a non-zero count.
func readEDACSysfs(root string) ECCReport {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ECCReport{Present: false}
	}
	rep := ECCReport{Source: "edac_sysfs"}
	nctl := 0
	for _, e := range entries {
		name := e.Name()
		if !isMCDir(name) {
			continue
		}
		if nctl >= maxECCControllers {
			break
		}
		nctl++
		mcPath := filepath.Join(root, name)

		ctl := ECCController{Name: name, MCName: readTrimFile(filepath.Join(mcPath, "mc_name"))}
		ctl.CorrectedCount, _ = readUintFile(filepath.Join(mcPath, "ce_count"))
		ctl.UncorrectedCount, _ = readUintFile(filepath.Join(mcPath, "ue_count"))
		rep.Controllers = append(rep.Controllers, ctl)
		rep.CorrectedTotal += ctl.CorrectedCount
		rep.UncorrectedTotal += ctl.UncorrectedCount

		rep.DIMMs = append(rep.DIMMs, readEDACDimms(mcPath, name, len(rep.DIMMs))...)
	}
	rep.Present = nctl > 0
	if !rep.Present {
		return ECCReport{Present: false}
	}
	sort.Slice(rep.Controllers, func(i, j int) bool { return rep.Controllers[i].Name < rep.Controllers[j].Name })
	sort.Slice(rep.DIMMs, func(i, j int) bool { return rep.DIMMs[i].ID < rep.DIMMs[j].ID })
	return rep
}

// readEDACDimms collects the per-DIMM/rank entries under one controller that
// carry a non-zero error count. alreadyHave is the running DIMM total so the
// overall cap (maxECCDimms) is honoured across controllers.
func readEDACDimms(mcPath, mcName string, alreadyHave int) []ECCDimm {
	subs, err := os.ReadDir(mcPath)
	if err != nil {
		return nil
	}
	var out []ECCDimm
	for _, s := range subs {
		dn := s.Name()
		if !isDimmDir(dn) {
			continue
		}
		if alreadyHave+len(out) >= maxECCDimms {
			break
		}
		dPath := filepath.Join(mcPath, dn)
		ce, _ := readUintFile(filepath.Join(dPath, "dimm_ce_count"))
		ue, _ := readUintFile(filepath.Join(dPath, "dimm_ue_count"))
		if ce == 0 && ue == 0 {
			continue
		}
		out = append(out, ECCDimm{
			ID:               mcName + "/" + dn,
			Label:            readTrimFile(filepath.Join(dPath, "dimm_label")),
			Location:         readTrimFile(filepath.Join(dPath, "dimm_location")),
			CorrectedCount:   ce,
			UncorrectedCount: ue,
		})
	}
	return out
}

// parseECCFromKmsg counts corrected MEMORY ECC events in kernel-ring lines, as a
// best-effort fallback for boxes with no EDAC sysfs. It keys ONLY on the AMD
// mce_amd decoder's memory-specific "DRAM ECC error" line — exactly one per
// memory machine-check — deliberately NOT on:
//   - the generic "Corrected error, no action required." summary the decoder
//     also emits for cache/bus/other banks (would misattribute a non-memory MCE
//     as memory), nor
//   - a bare "uncorrect" substring, which also appears on PCIe AER / GHES events
//     (would raise a false "imminent DIMM failure" critical for a non-memory
//     fault), nor
//   - the co-printed "Unified Memory Controller …" line (would double-count).
//
// Uncorrected memory errors are intentionally not inferred from the ring: they
// usually panic (so they aren't sitting in the ring on a later triage) and are
// reported authoritatively by EDAC sysfs when it is present. The ring fallback
// therefore biases to the SAFE direction — a real memory error shows at worst as
// a corrected (warning), never a false uncorrected (critical) for a non-memory
// machine-check. Returns uncorrected=0 by construction.
func parseECCFromKmsg(lines []string) (corrected, uncorrected uint64) {
	for _, ln := range lines {
		low := strings.ToLower(ln)
		if strings.Contains(low, "hardware error") && strings.Contains(low, "dram ecc") {
			corrected++
		}
	}
	return corrected, 0
}

func isMCDir(name string) bool {
	if !strings.HasPrefix(name, "mc") {
		return false
	}
	suffix := name[len("mc"):]
	if suffix == "" {
		return false
	}
	_, err := strconv.Atoi(suffix)
	return err == nil
}

// isDimmDir matches the modern "dimmN"/"rankN" per-module directories. (Legacy
// csrow layout is intentionally not walked for per-module counts; controller
// totals above still capture its errors via ce_count/ue_count.)
func isDimmDir(name string) bool {
	for _, pfx := range []string{"dimm", "rank"} {
		if strings.HasPrefix(name, pfx) {
			if _, err := strconv.Atoi(name[len(pfx):]); err == nil {
				return true
			}
		}
	}
	return false
}

// ECCEvent is a durable memory-ECC observation published by the health detector
// so it survives what the live counters cannot: a reboot (EDAC resets to 0) or a
// dmesg ring wrap. A subscriber (webdetector's history store) persists it, making
// the event queryable from a later session via detection_history.
type ECCEvent struct {
	Kind             string    // "baseline" | "corrected" | "uncorrected"
	Host             string    //
	When             time.Time //
	Corrected        uint64    // cumulative corrected total at observation
	Uncorrected      uint64    // cumulative uncorrected total at observation
	DeltaCorrected   uint64    // new corrected since the previous observation
	DeltaUncorrected uint64    // new uncorrected since the previous observation
	WorstDIMM        string    // best-attributed offending DIMM label/location/id, if any
	Source           string    // "edac_sysfs" | "kernel_ring"
}

var (
	eccSinkMu sync.RWMutex
	eccSink   func(ECCEvent)
)

// SetECCEventSink registers (replacing any prior) the consumer of ECC events.
// Mirrors clam.SetScanEventSink: the health detector is a leaf package, so the
// persister (webdetector) subscribes rather than being called directly. nil
// detaches. Safe for concurrent use.
func SetECCEventSink(fn func(ECCEvent)) {
	eccSinkMu.Lock()
	eccSink = fn
	eccSinkMu.Unlock()
}

// publishECCEvent delivers ev to the sink if one is set; a misbehaving sink must
// never take down the detector loop, so panics are contained.
func publishECCEvent(ev ECCEvent) {
	eccSinkMu.RLock()
	fn := eccSink
	eccSinkMu.RUnlock()
	if fn == nil {
		return
	}
	defer func() { _ = recover() }()
	fn(ev)
}

// worstECCDimm returns a label for the DIMM carrying the most errors (uncorrected
// preferred over corrected), or "" when the controller attributed none (AMD
// "noinfo" errors it cannot pin to a module).
func worstECCDimm(rep ECCReport) string {
	best, bestKey := "", [2]uint64{}
	for _, d := range rep.DIMMs {
		key := [2]uint64{d.UncorrectedCount, d.CorrectedCount}
		if key[0] > bestKey[0] || (key[0] == bestKey[0] && key[1] > bestKey[1]) {
			bestKey = key
			switch {
			case strings.TrimSpace(d.Label) != "":
				best = d.Label
			case strings.TrimSpace(d.Location) != "":
				best = d.Location
			default:
				best = d.ID
			}
		}
	}
	return best
}

func readUintFile(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func readTrimFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
