// Package cputhrottle answers "the box load is high — is the CPU being
// throttled, or is this genuine demand?" It reads instantaneous CPU-frequency,
// thermal, and utilization signals and classifies the root cause, so "high
// load" stops being a dead end: thermal throttling, a frequency cap (powersave
// governor / policy limit), or real work saturating the cores.
//
// Getting the verdict right needed three deliberate choices, each guarding a
// classic misdiagnosis:
//
//   - Gate on real CPU busy% (a short /proc/stat sample, EXCLUDING iowait), not
//     loadavg. loadavg counts uninterruptible I/O-blocked tasks, so an I/O-bound
//     box shows high load with idle, downclocked CPUs — that must NOT read as
//     throttling. Busy% (excluding iowait) is the honest "are the cores actually
//     working" gate.
//   - Reference the BASE frequency, not the turbo ceiling. cpuinfo_max_freq is
//     the (often unsustainable) turbo max; under sustained all-core load a
//     healthy CPU settles near its base clock. Judging against turbo would call
//     that genuine demand "throttled". We only call it slow when it drops below
//     the guaranteed base clock. Where base_frequency isn't exposed we fall back
//     conservatively to the turbo ratio and lean toward genuine_demand.
//   - Thermal-throttle counters are cumulative since boot, so a throttle event
//     weeks ago would pin the verdict forever. They are a summary hint only, not
//     a cause determinant; the live temperature (CPU thermal zones only) decides
//     thermal.
//
// Read() gathers the signals (paths/sample interval are package vars so tests
// point them at a fabricated tree); Classify() is pure so the decision matrix is
// unit-tested without the filesystem. Availability is explicit: on a VM cpufreq/
// thermal are usually absent and the honest answer is "can't tell from here —
// check host CPU steal", not a false verdict.
package cputhrottle

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Paths + sample interval (package vars so tests can override).
var (
	SysCPUBase     = "/sys/devices/system/cpu"
	ThermalBase    = "/sys/class/thermal"
	LoadAvgPath    = "/proc/loadavg"
	ProcStatPath   = "/proc/stat"
	sampleInterval = 250 * time.Millisecond
	sleepFn        = time.Sleep
)

// cpuThermalZoneTypes are the thermal_zone `type` substrings we treat as CPU
// temperature. A box exposes zones for NVMe/WiFi/battery/etc too; picking the
// hottest of ALL of them would let a hot SSD masquerade as CPU thermal
// throttling, so we only consider CPU-package sensors.
var cpuThermalZoneTypes = []string{"x86_pkg_temp", "coretemp", "cpu", "soc"}

// CPUFreq is one logical CPU's cpufreq state (kHz). MaxKHz is the hardware/turbo
// ceiling (cpuinfo_max_freq); BaseKHz is the guaranteed sustained clock
// (base_frequency, intel_pstate — may be 0 if not exposed); PolicyMaxKHz is the
// governor/policy ceiling (scaling_max_freq).
type CPUFreq struct {
	CurKHz       int64  `json:"cur_khz"`
	MaxKHz       int64  `json:"max_khz"`
	BaseKHz      int64  `json:"base_khz,omitempty"`
	PolicyMaxKHz int64  `json:"policy_max_khz"`
	Governor     string `json:"governor"`
}

// Reading is the gathered instantaneous signal set.
type Reading struct {
	NumCPU               int       `json:"num_cpu"`
	Load1                float64   `json:"load1"`
	Load5                float64   `json:"load5"`
	Load15               float64   `json:"load15"`
	BusyPct              float64   `json:"busy_pct"` // CPU utilization over the sample, excluding iowait
	Freqs                []CPUFreq `json:"-"`        // per-CPU with cpufreq data
	CoreThrottleCount    int64     `json:"core_throttle_count"`
	PackageThrottleCount int64     `json:"package_throttle_count"`
	MaxTempC             float64   `json:"max_temp_c"`
	HaveFreq             bool      `json:"have_freq"`
	HaveBusy             bool      `json:"have_busy"`
	HaveThrottleCounts   bool      `json:"have_throttle_counts"`
	HaveTemp             bool      `json:"have_temp"`
}

// Params tunes the classifier thresholds. Zero values fall back to defaults.
type Params struct {
	// BusyThreshold is the CPU busy fraction (0..1, iowait excluded) at/above
	// which the cores are considered actually working — the gate for any
	// throttle judgement. 0.75.
	BusyThreshold float64
	// LoadPerCoreThreshold is the fallback gate (loadavg per core) used only when
	// busy% couldn't be sampled. 0.9.
	LoadPerCoreThreshold float64
	// BaseFreqRatio is the fraction of the BASE clock at/above which the CPU is
	// "meeting its guaranteed clock" (not throttled). 0.9.
	BaseFreqRatio float64
	// TurboFreqRatio is the conservative cur/turbo-max ratio used only when base
	// frequency isn't exposed; below it (and busy) the CPU is judged slow. 0.65.
	TurboFreqRatio float64
	// ThermalWarnC is the CPU temperature (°C) at/above which a slow-under-load
	// CPU is attributed to thermal throttling. 80.
	ThermalWarnC float64
}

func (p Params) withDefaults() Params {
	if p.BusyThreshold <= 0 {
		p.BusyThreshold = 0.75
	}
	if p.LoadPerCoreThreshold <= 0 {
		p.LoadPerCoreThreshold = 0.9
	}
	if p.BaseFreqRatio <= 0 {
		p.BaseFreqRatio = 0.9
	}
	if p.TurboFreqRatio <= 0 {
		p.TurboFreqRatio = 0.65
	}
	if p.ThermalWarnC <= 0 {
		p.ThermalWarnC = 80
	}
	return p
}

// Cause classifications (the headline root-cause flag).
const (
	CauseThermalThrottling = "thermal_throttling" // busy + slow + hot
	CauseFrequencyCapped   = "frequency_capped"   // busy + slow, cool: powersave governor / policy cap
	CauseFrequencyReduced  = "frequency_reduced"  // busy + slow, cool, cause unclear (BIOS/host cap)
	CauseGenuineDemand     = "genuine_demand"     // busy + meeting clock = real work, not throttling
	CauseLowLoad           = "low_load"           // cores not actually busy; reduced freq is normal idle downclock
	CauseNoCPUFreqData     = "no_cpufreq_data"    // cpufreq not exposed (virtualized?) — check host CPU steal
)

// Assessment is the classified result.
type Assessment struct {
	Cause                string  `json:"cause"`
	Summary              string  `json:"summary"`
	BusyPct              float64 `json:"busy_pct"`
	CPUBound             bool    `json:"cpu_bound"`
	LoadPerCore          float64 `json:"load_per_core"`
	FreqRefKind          string  `json:"freq_ref_kind,omitempty"` // "base" or "turbo_max" — what the ratio is against
	FreqRatio            float64 `json:"freq_ratio,omitempty"`    // avg cur / reference clock
	Governor             string  `json:"governor,omitempty"`
	PolicyCapped         bool    `json:"policy_capped,omitempty"`
	MaxTempC             float64 `json:"max_temp_c,omitempty"`
	CoreThrottleCount    int64   `json:"core_throttle_count,omitempty"`
	PackageThrottleCount int64   `json:"package_throttle_count,omitempty"`
	NumCPU               int     `json:"num_cpu"`
	Load1                float64 `json:"load1"`

	BusyAvailable           bool `json:"busy_available"`
	FreqAvailable           bool `json:"freq_available"`
	BaseFreqAvailable       bool `json:"base_freq_available"`
	TempAvailable           bool `json:"temp_available"`
	ThrottleCountsAvailable bool `json:"throttle_counts_available"`
}

// dominantGovernor returns the most common governor across the per-CPU freqs.
func dominantGovernor(freqs []CPUFreq) string {
	counts := map[string]int{}
	for _, f := range freqs {
		if f.Governor != "" {
			counts[f.Governor]++
		}
	}
	best, bestN := "", 0
	for g, n := range counts {
		if n > bestN || (n == bestN && g < best) {
			best, bestN = g, n
		}
	}
	return best
}

// Classify turns a Reading into a root-cause Assessment. Pure.
func Classify(r Reading, params Params) Assessment {
	p := params.withDefaults()

	a := Assessment{
		BusyPct:                 r.BusyPct,
		NumCPU:                  r.NumCPU,
		Load1:                   r.Load1,
		MaxTempC:                r.MaxTempC,
		CoreThrottleCount:       r.CoreThrottleCount,
		PackageThrottleCount:    r.PackageThrottleCount,
		BusyAvailable:           r.HaveBusy,
		FreqAvailable:           r.HaveFreq,
		TempAvailable:           r.HaveTemp,
		ThrottleCountsAvailable: r.HaveThrottleCounts,
	}
	if r.NumCPU > 0 {
		a.LoadPerCore = r.Load1 / float64(r.NumCPU)
	}

	// "Are the cores actually working?" — busy% (iowait excluded) if we have it,
	// else fall back to loadavg per core. This is what stops an I/O-bound box (or
	// an idle box that happens to downclock) reading as throttled.
	if r.HaveBusy {
		a.CPUBound = r.BusyPct >= p.BusyThreshold*100
	} else {
		a.CPUBound = r.NumCPU > 0 && a.LoadPerCore >= p.LoadPerCoreThreshold
	}

	// Frequency reference: prefer the guaranteed BASE clock (turbo is never
	// guaranteed, so falling short of turbo is not throttling). Fall back to the
	// turbo ceiling with a looser ratio only when base isn't exposed.
	var sumCur, sumBase, sumMax, sumPolicy float64
	var nCur, nBase, nMax, nPolicy int
	for _, f := range r.Freqs {
		if f.CurKHz > 0 {
			sumCur += float64(f.CurKHz)
			nCur++
		}
		if f.BaseKHz > 0 {
			sumBase += float64(f.BaseKHz)
			nBase++
		}
		if f.MaxKHz > 0 {
			sumMax += float64(f.MaxKHz)
			nMax++
		}
		if f.PolicyMaxKHz > 0 {
			sumPolicy += float64(f.PolicyMaxKHz)
			nPolicy++
		}
		if f.PolicyMaxKHz > 0 && f.MaxKHz > 0 && f.PolicyMaxKHz < f.MaxKHz {
			a.PolicyCapped = true
		}
	}
	a.Governor = dominantGovernor(r.Freqs)
	a.BaseFreqAvailable = nBase > 0

	// meetingClock is true when the CPU is running at/above the fraction of its
	// reference clock we consider healthy. Prefer the guaranteed base clock;
	// fall back to the turbo ceiling, then the policy ceiling (scaling_max) —
	// both with the looser turbo ratio since neither is a guaranteed floor.
	// haveRef is false when no usable frequency reference exists at all.
	meetingClock, haveRef := false, false
	if nCur > 0 {
		avgCur := sumCur / float64(nCur)
		switch {
		case nBase > 0:
			ref := sumBase / float64(nBase)
			a.FreqRefKind, a.FreqRatio, haveRef = "base", avgCur/ref, true
			meetingClock = a.FreqRatio >= p.BaseFreqRatio
		case nMax > 0:
			ref := sumMax / float64(nMax)
			a.FreqRefKind, a.FreqRatio, haveRef = "turbo_max", avgCur/ref, true
			meetingClock = a.FreqRatio >= p.TurboFreqRatio
		case nPolicy > 0:
			ref := sumPolicy / float64(nPolicy)
			a.FreqRefKind, a.FreqRatio, haveRef = "policy_max", avgCur/ref, true
			meetingClock = a.FreqRatio >= p.TurboFreqRatio
		}
	}

	switch {
	case !r.HaveFreq || !haveRef:
		a.Cause = CauseNoCPUFreqData
		a.Summary = "CPU frequency data not exposed (common on VMs). Can't judge throttling from inside the guest — if load is high, check the hypervisor's CPU steal (noisy neighbour / overcommitted host)."
	case !a.CPUBound:
		a.Cause = CauseLowLoad
		a.Summary = lowLoadSummary(r)
	case meetingClock:
		a.Cause = CauseGenuineDemand
		a.Summary = "Cores are busy and running at/near their " + refWord(a.FreqRefKind) + " clock — this is genuine CPU demand, not throttling. Find the workload (top processes / heavy tenants), not a thermal fault."
	case r.HaveTemp && r.MaxTempC >= p.ThermalWarnC:
		a.Cause = CauseThermalThrottling
		a.Summary = "Cores are busy but running below their " + refWord(a.FreqRefKind) + " clock while hot — thermal throttling. Check cooling/airflow/dust." + throttleCounterHint(r)
	case a.Governor == "powersave" || a.Governor == "conservative" || a.PolicyCapped:
		a.Cause = CauseFrequencyCapped
		a.Summary = "Cores are busy and capped below their " + refWord(a.FreqRefKind) + " clock but NOT hot — a frequency cap, not thermal: scaling governor is '" + a.Governor + "'" + policyCapNote(a.PolicyCapped) + ". Switch to the 'performance' governor (or lift the policy cap) to release the headroom." + throttleCounterHint(r)
	default:
		a.Cause = CauseFrequencyReduced
		a.Summary = "Cores are busy and running below their " + refWord(a.FreqRefKind) + " clock, but it's not hot and the governor isn't a power-saving one — cause unclear (BIOS/host frequency policy, aggressive turbo limits). Investigate firmware/host settings." + throttleCounterHint(r)
	}
	return a
}

func refWord(kind string) string {
	if kind == "turbo_max" {
		return "maximum"
	}
	return "base"
}

func lowLoadSummary(r Reading) string {
	if r.HaveBusy {
		s := "Cores are not actually busy (CPU utilization below threshold, iowait excluded); a reduced clock here is normal idle downclocking, not throttling."
		if r.NumCPU > 0 && r.Load1/float64(r.NumCPU) >= 0.9 {
			s += " Note: loadavg per core is high while CPU busy% is low — this looks I/O-bound (uninterruptible tasks), not CPU-bound."
		}
		return s
	}
	return "Cores are not under sustained load (loadavg per core below threshold; CPU busy% unavailable); a reduced clock here is normal idle downclocking."
}

func throttleCounterHint(r Reading) string {
	if r.HaveThrottleCounts && (r.CoreThrottleCount+r.PackageThrottleCount) > 0 {
		return " (kernel thermal-throttle counters are non-zero — cumulative since boot, so this may reflect a past episode; watch the temperature to confirm it's current.)"
	}
	return ""
}

func policyCapNote(capped bool) string {
	if capped {
		return " and a policy cap (scaling_max_freq < hardware max) is in effect"
	}
	return ""
}

// Read gathers the instantaneous signals. Missing pieces set the matching
// Have* flag false rather than erroring — a VM with no cpufreq is a valid,
// classifiable state.
func Read() Reading {
	var r Reading
	r.Load1, r.Load5, r.Load15 = readLoadAvg(LoadAvgPath)

	// CPU busy% over a short sample, iowait excluded.
	if prev, ok := readCPUTimes(ProcStatPath); ok {
		sleepFn(sampleInterval)
		if cur, ok2 := readCPUTimes(ProcStatPath); ok2 {
			if pct, ok3 := busyPct(prev, cur); ok3 {
				r.BusyPct, r.HaveBusy = pct, true
			}
		}
	}

	cpus := listCPUs(SysCPUBase)
	r.NumCPU = len(cpus)
	for _, cpu := range cpus {
		base := filepath.Join(SysCPUBase, cpu)
		cf := readCPUFreq(filepath.Join(base, "cpufreq"))
		if cf.CurKHz > 0 || cf.MaxKHz > 0 || cf.Governor != "" {
			r.Freqs = append(r.Freqs, cf)
			r.HaveFreq = true
		}
		if c, ok := readInt(filepath.Join(base, "thermal_throttle", "core_throttle_count")); ok {
			r.CoreThrottleCount += c
			r.HaveThrottleCounts = true
		}
		if c, ok := readInt(filepath.Join(base, "thermal_throttle", "package_throttle_count")); ok {
			r.PackageThrottleCount += c
			r.HaveThrottleCounts = true
		}
	}

	if t, ok := readMaxCPUThermalZoneC(ThermalBase); ok {
		r.MaxTempC = t
		r.HaveTemp = true
	}
	return r
}

// ReadAndClassify is the convenience one-shot for the endpoint.
func ReadAndClassify(params Params) Assessment { return Classify(Read(), params) }

func readLoadAvg(path string) (l1, l5, l15 float64) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(b))
	if len(fields) >= 3 {
		l1, _ = strconv.ParseFloat(fields[0], 64)
		l5, _ = strconv.ParseFloat(fields[1], 64)
		l15, _ = strconv.ParseFloat(fields[2], 64)
	}
	return
}

// cpuTimes is the aggregate "cpu " line of /proc/stat, reduced to what busyPct
// needs: total jiffies, and the not-working portion (idle + iowait).
type cpuTimes struct {
	total   uint64
	notBusy uint64 // idle + iowait
}

// readCPUTimes parses the aggregate "cpu " line of /proc/stat.
// Fields: user nice system idle iowait irq softirq steal guest guest_nice.
func readCPUTimes(path string) (cpuTimes, bool) {
	f, err := os.Open(path)
	if err != nil {
		return cpuTimes{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:] // drop "cpu"
		var ct cpuTimes
		for i, fld := range fields {
			v, err := strconv.ParseUint(fld, 10, 64)
			if err != nil {
				return cpuTimes{}, false
			}
			ct.total += v
			if i == 3 || i == 4 { // idle, iowait
				ct.notBusy += v
			}
		}
		return ct, true
	}
	return cpuTimes{}, false
}

// busyPct is the fraction (0..100) of CPU time spent working between two
// samples, iowait counted as NOT working. Returns ok=false on a zero/negative
// delta (counter reset or too-fast sample).
func busyPct(prev, cur cpuTimes) (float64, bool) {
	if cur.total <= prev.total {
		return 0, false
	}
	dTotal := cur.total - prev.total
	var dIdle uint64
	if cur.notBusy >= prev.notBusy {
		dIdle = cur.notBusy - prev.notBusy
	}
	if dIdle > dTotal {
		dIdle = dTotal
	}
	return float64(dTotal-dIdle) / float64(dTotal) * 100, true
}

// listCPUs returns the cpuN directory names (cpu0, cpu1, …), sorted.
func listCPUs(base string) []string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if len(name) <= 3 || !strings.HasPrefix(name, "cpu") {
			continue
		}
		if _, err := strconv.Atoi(name[3:]); err != nil {
			continue // skip cpufreq/cpuidle/… non-core entries
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func readCPUFreq(dir string) CPUFreq {
	var cf CPUFreq
	cf.CurKHz, _ = readInt(filepath.Join(dir, "scaling_cur_freq"))
	cf.MaxKHz, _ = readInt(filepath.Join(dir, "cpuinfo_max_freq"))
	cf.BaseKHz, _ = readInt(filepath.Join(dir, "base_frequency"))
	cf.PolicyMaxKHz, _ = readInt(filepath.Join(dir, "scaling_max_freq"))
	if b, err := os.ReadFile(filepath.Join(dir, "scaling_governor")); err == nil {
		cf.Governor = strings.TrimSpace(string(b))
	}
	return cf
}

// readMaxCPUThermalZoneC returns the hottest CPU thermal_zone*/temp in °C,
// considering only zones whose `type` names a CPU sensor (so a hot NVMe/GPU/
// battery zone can't masquerade as CPU thermal throttling).
func readMaxCPUThermalZoneC(base string) (float64, bool) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return 0, false
	}
	var maxC float64
	found := false
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "thermal_zone") {
			continue
		}
		zdir := filepath.Join(base, e.Name())
		typ := ""
		if b, err := os.ReadFile(filepath.Join(zdir, "type")); err == nil {
			typ = strings.ToLower(strings.TrimSpace(string(b)))
		}
		if !isCPUThermalZone(typ) {
			continue
		}
		milli, ok := readInt(filepath.Join(zdir, "temp"))
		if !ok {
			continue
		}
		c := float64(milli) / 1000.0
		if !found || c > maxC {
			maxC = c
			found = true
		}
	}
	return maxC, found
}

func isCPUThermalZone(typ string) bool {
	for _, t := range cpuThermalZoneTypes {
		if strings.Contains(typ, t) {
			return true
		}
	}
	return false
}

func readInt(path string) (int64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(sc.Text()), 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
