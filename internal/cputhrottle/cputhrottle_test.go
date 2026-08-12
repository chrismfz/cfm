package cputhrottle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freq(cur, base, max, policyMax int64, gov string) CPUFreq {
	return CPUFreq{CurKHz: cur, BaseKHz: base, MaxKHz: max, PolicyMaxKHz: policyMax, Governor: gov}
}

// busy marks a Reading as CPU-bound (busy% sampled and high).
func busy(r Reading, pct float64) Reading {
	r.BusyPct, r.HaveBusy = pct, true
	if r.NumCPU == 0 {
		r.NumCPU = 4
	}
	return r
}

func TestClassify_NoCPUFreq(t *testing.T) {
	r := busy(Reading{NumCPU: 8, HaveFreq: false}, 99)
	a := Classify(r, Params{})
	if a.Cause != CauseNoCPUFreqData {
		t.Fatalf("cause = %q, want %q", a.Cause, CauseNoCPUFreqData)
	}
}

func TestClassify_NotBusyIsNotThrottle(t *testing.T) {
	// Downclocked deep, but CPUs aren't actually busy → must be low_load.
	r := Reading{
		NumCPU: 4, BusyPct: 12, HaveBusy: true, HaveFreq: true,
		Freqs: []CPUFreq{freq(800000, 2400000, 3000000, 3000000, "powersave")},
	}
	a := Classify(r, Params{})
	if a.Cause != CauseLowLoad {
		t.Fatalf("cause = %q, want %q", a.Cause, CauseLowLoad)
	}
}

func TestClassify_IOBoundNoteWhenLoadHighButBusyLow(t *testing.T) {
	// High loadavg (I/O wait) but low CPU busy% → low_load with an I/O-bound note.
	r := Reading{
		NumCPU: 4, Load1: 8.0, BusyPct: 10, HaveBusy: true, HaveFreq: true,
		Freqs: []CPUFreq{freq(800000, 2400000, 3000000, 3000000, "performance")},
	}
	a := Classify(r, Params{})
	if a.Cause != CauseLowLoad {
		t.Fatalf("cause = %q, want %q", a.Cause, CauseLowLoad)
	}
	if !strings.Contains(a.Summary, "I/O-bound") {
		t.Errorf("expected an I/O-bound note in summary, got %q", a.Summary)
	}
}

func TestClassify_GenuineDemand_AtBaseNotThrottled(t *testing.T) {
	// The turbo trap: cur sits at base (2.4) well below turbo max (3.5) under
	// sustained all-core load. That is genuine demand, NOT throttling.
	r := busy(Reading{
		NumCPU: 8, HaveFreq: true,
		Freqs: []CPUFreq{freq(2400000, 2400000, 3500000, 3500000, "performance")},
	}, 96)
	a := Classify(r, Params{})
	if a.Cause != CauseGenuineDemand {
		t.Fatalf("cause = %q, want %q (at base = genuine, turbo miss is not throttle)", a.Cause, CauseGenuineDemand)
	}
	if a.FreqRefKind != "base" {
		t.Errorf("FreqRefKind = %q, want base", a.FreqRefKind)
	}
}

func TestClassify_ThermalByTemp(t *testing.T) {
	r := busy(Reading{
		NumCPU: 4, HaveFreq: true, HaveTemp: true, MaxTempC: 92,
		Freqs: []CPUFreq{freq(1200000, 2400000, 3000000, 3000000, "performance")},
	}, 95)
	a := Classify(r, Params{})
	if a.Cause != CauseThermalThrottling {
		t.Fatalf("cause = %q, want %q", a.Cause, CauseThermalThrottling)
	}
}

func TestClassify_StaleThrottleCountersDoNotForceThermal(t *testing.T) {
	// Cool, powersave, slow, but cumulative throttle counters are set from a past
	// episode. Must be frequency_capped (governor), NOT thermal — counters are
	// only a summary hint.
	r := busy(Reading{
		NumCPU: 4, HaveFreq: true, HaveTemp: true, MaxTempC: 52,
		HaveThrottleCounts: true, CoreThrottleCount: 9,
		Freqs: []CPUFreq{freq(1200000, 2400000, 3000000, 3000000, "powersave")},
	}, 95)
	a := Classify(r, Params{})
	if a.Cause != CauseFrequencyCapped {
		t.Fatalf("cause = %q, want %q (stale counters must not force thermal)", a.Cause, CauseFrequencyCapped)
	}
	if !strings.Contains(a.Summary, "cumulative since boot") {
		t.Errorf("expected a cumulative-counter hint in summary, got %q", a.Summary)
	}
}

func TestClassify_FrequencyCappedPolicy(t *testing.T) {
	r := busy(Reading{
		NumCPU: 4, HaveFreq: true, HaveTemp: true, MaxTempC: 50,
		Freqs: []CPUFreq{freq(1500000, 2400000, 3000000, 1600000, "performance")},
	}, 95)
	a := Classify(r, Params{})
	if a.Cause != CauseFrequencyCapped {
		t.Fatalf("cause = %q, want %q", a.Cause, CauseFrequencyCapped)
	}
	if !a.PolicyCapped {
		t.Error("PolicyCapped should be true")
	}
}

func TestClassify_FrequencyReducedUnknown(t *testing.T) {
	r := busy(Reading{
		NumCPU: 4, HaveFreq: true, HaveTemp: true, MaxTempC: 50,
		Freqs: []CPUFreq{freq(1200000, 2400000, 3000000, 3000000, "performance")},
	}, 95)
	a := Classify(r, Params{})
	if a.Cause != CauseFrequencyReduced {
		t.Fatalf("cause = %q, want %q", a.Cause, CauseFrequencyReduced)
	}
}

func TestClassify_TurboFallbackWhenNoBase(t *testing.T) {
	// No base_frequency exposed → reference the turbo ceiling with the looser
	// ratio. cur/turbo = 0.9 ≥ 0.65 → genuine demand.
	r := busy(Reading{
		NumCPU: 4, HaveFreq: true,
		Freqs: []CPUFreq{freq(2700000, 0, 3000000, 3000000, "performance")},
	}, 96)
	a := Classify(r, Params{})
	if a.Cause != CauseGenuineDemand || a.FreqRefKind != "turbo_max" {
		t.Fatalf("cause=%q ref=%q, want genuine_demand/turbo_max", a.Cause, a.FreqRefKind)
	}
	// Deeply below turbo with no base → judged slow.
	r2 := busy(Reading{
		NumCPU: 4, HaveFreq: true, HaveTemp: true, MaxTempC: 50,
		Freqs: []CPUFreq{freq(1200000, 0, 3000000, 3000000, "performance")},
	}, 96)
	if a2 := Classify(r2, Params{}); a2.Cause != CauseFrequencyReduced {
		t.Fatalf("deep turbo miss no-base: cause = %q, want %q", a2.Cause, CauseFrequencyReduced)
	}
}

func TestClassify_PolicyMaxFallbackWhenNoBaseOrTurbo(t *testing.T) {
	// Only scaling_cur + scaling_max exposed (no base, no cpuinfo_max) — must
	// still be judged, not degrade to no_cpufreq_data (finding 4).
	r := busy(Reading{
		NumCPU: 4, HaveFreq: true,
		Freqs: []CPUFreq{freq(2700000, 0, 0, 3000000, "performance")},
	}, 96)
	a := Classify(r, Params{})
	if a.Cause != CauseGenuineDemand || a.FreqRefKind != "policy_max" {
		t.Fatalf("cause=%q ref=%q, want genuine_demand/policy_max", a.Cause, a.FreqRefKind)
	}
}

func TestClassify_LoadavgFallbackWhenNoBusy(t *testing.T) {
	// busy% not sampled → fall back to loadavg-per-core gate.
	r := Reading{
		NumCPU: 4, Load1: 8.0, HaveBusy: false, HaveFreq: true, HaveTemp: true, MaxTempC: 95,
		Freqs: []CPUFreq{freq(1200000, 2400000, 3000000, 3000000, "performance")},
	}
	a := Classify(r, Params{})
	if a.CPUBound != true {
		t.Fatalf("loadavg 2.0/core should read CPU-bound in the fallback")
	}
	if a.Cause != CauseThermalThrottling {
		t.Fatalf("cause = %q, want %q", a.Cause, CauseThermalThrottling)
	}
}

func TestBusyPct(t *testing.T) {
	// dTotal=400, dIdle=0 → 100% busy.
	if p, ok := busyPct(cpuTimes{total: 1000, notBusy: 800}, cpuTimes{total: 1400, notBusy: 800}); !ok || p != 100 {
		t.Errorf("busyPct all-busy = %v,%v want 100,true", p, ok)
	}
	// dTotal=400, dIdle=400 → 0% busy.
	if p, ok := busyPct(cpuTimes{total: 1000, notBusy: 800}, cpuTimes{total: 1400, notBusy: 1200}); !ok || p != 0 {
		t.Errorf("busyPct idle = %v,%v want 0,true", p, ok)
	}
	// dTotal=400, dIdle=200 → 50%.
	if p, ok := busyPct(cpuTimes{total: 1000, notBusy: 800}, cpuTimes{total: 1400, notBusy: 1000}); !ok || p != 50 {
		t.Errorf("busyPct half = %v,%v want 50,true", p, ok)
	}
	// No progress → not ok.
	if _, ok := busyPct(cpuTimes{total: 1000}, cpuTimes{total: 1000}); ok {
		t.Error("zero delta should be ok=false")
	}
}

// ── Read against a fabricated sysfs/proc tree ───────────────────────────────

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRead_FabricatedTree(t *testing.T) {
	root := t.TempDir()
	cpuBase := filepath.Join(root, "cpu")
	thermalBase := filepath.Join(root, "thermal")
	statPath := filepath.Join(root, "stat")
	loadPath := filepath.Join(root, "loadavg")

	for _, c := range []string{"cpu0", "cpu1"} {
		fq := filepath.Join(cpuBase, c, "cpufreq")
		writeFile(t, filepath.Join(fq, "scaling_cur_freq"), "1200000\n")
		writeFile(t, filepath.Join(fq, "cpuinfo_max_freq"), "3500000\n")
		writeFile(t, filepath.Join(fq, "base_frequency"), "2400000\n")
		writeFile(t, filepath.Join(fq, "scaling_max_freq"), "3500000\n")
		writeFile(t, filepath.Join(fq, "scaling_governor"), "performance\n")
		tt := filepath.Join(cpuBase, c, "thermal_throttle")
		writeFile(t, filepath.Join(tt, "core_throttle_count"), "3\n")
		writeFile(t, filepath.Join(tt, "package_throttle_count"), "1\n")
	}
	// Non-core sysfs entry under cpu/ — must be ignored by listCPUs.
	writeFile(t, filepath.Join(cpuBase, "cpufreq", "boost"), "1\n")

	// Thermal zones: a hot NVMe (must be ignored) + a CPU package zone (88°C).
	writeFile(t, filepath.Join(thermalBase, "thermal_zone0", "type"), "nvme\n")
	writeFile(t, filepath.Join(thermalBase, "thermal_zone0", "temp"), "95000\n")
	writeFile(t, filepath.Join(thermalBase, "thermal_zone1", "type"), "x86_pkg_temp\n")
	writeFile(t, filepath.Join(thermalBase, "thermal_zone1", "temp"), "88000\n")

	writeFile(t, loadPath, "8.00 6.00 4.00 2/1234 5678\n")
	// First /proc/stat snapshot; sleepFn swaps in the second (all-busy delta).
	writeFile(t, statPath, "cpu  100 0 100 700 100 0 0 0\ncpu0 50 0 50 350 50 0 0 0\n")

	oldCPU, oldTherm, oldLoad, oldStat, oldSleep := SysCPUBase, ThermalBase, LoadAvgPath, ProcStatPath, sleepFn
	SysCPUBase, ThermalBase, LoadAvgPath, ProcStatPath = cpuBase, thermalBase, loadPath, statPath
	t.Cleanup(func() {
		SysCPUBase, ThermalBase, LoadAvgPath, ProcStatPath, sleepFn = oldCPU, oldTherm, oldLoad, oldStat, oldSleep
	})
	// Between the two /proc/stat reads, swap in the second snapshot:
	// dTotal=400, dIdle(idle+iowait)=800→800 (unchanged) → 100% busy.
	sleepFn = func(_ time.Duration) {
		writeFile(t, statPath, "cpu  300 0 300 700 100 0 0 0\ncpu0 150 0 150 350 50 0 0 0\n")
	}

	r := Read()
	if r.NumCPU != 2 {
		t.Errorf("NumCPU = %d, want 2", r.NumCPU)
	}
	if !r.HaveBusy || r.BusyPct != 100 {
		t.Errorf("busy = have %v pct %v, want true/100", r.HaveBusy, r.BusyPct)
	}
	if !r.HaveFreq || len(r.Freqs) != 2 || r.Freqs[0].BaseKHz != 2400000 {
		t.Errorf("freq gather wrong: %+v", r.Freqs)
	}
	if r.CoreThrottleCount != 6 || r.PackageThrottleCount != 2 {
		t.Errorf("throttle counts = %d/%d, want 6/2", r.CoreThrottleCount, r.PackageThrottleCount)
	}
	if !r.HaveTemp || r.MaxTempC != 88 {
		t.Errorf("temp = have %v max %.0f, want true/88 (nvme zone ignored)", r.HaveTemp, r.MaxTempC)
	}

	// Full pipeline: busy 100%, cur 1.2 < 0.9*base(2.4), hot 88 → thermal.
	if a := Classify(r, Params{}); a.Cause != CauseThermalThrottling {
		t.Errorf("classify(read) = %q, want %q", a.Cause, CauseThermalThrottling)
	}
}

func TestRead_MissingTreeIsGraceful(t *testing.T) {
	root := t.TempDir()
	oldCPU, oldTherm, oldLoad, oldStat := SysCPUBase, ThermalBase, LoadAvgPath, ProcStatPath
	SysCPUBase = filepath.Join(root, "nope-cpu")
	ThermalBase = filepath.Join(root, "nope-thermal")
	LoadAvgPath = filepath.Join(root, "nope-load")
	ProcStatPath = filepath.Join(root, "nope-stat")
	t.Cleanup(func() { SysCPUBase, ThermalBase, LoadAvgPath, ProcStatPath = oldCPU, oldTherm, oldLoad, oldStat })

	r := Read()
	if r.HaveFreq || r.HaveTemp || r.HaveThrottleCounts || r.HaveBusy || r.NumCPU != 0 {
		t.Errorf("missing tree should yield empty reading, got %+v", r)
	}
	if a := Classify(r, Params{}); a.Cause != CauseNoCPUFreqData {
		t.Errorf("empty reading → cause %q, want %q", a.Cause, CauseNoCPUFreqData)
	}
}
