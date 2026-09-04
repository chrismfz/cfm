package health

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The detector loop tracks cumulative-since-boot ECC counters across cycles and
// publishes a durable event only on growth: a baseline at first sight, a delta on
// each increase, nothing when unchanged, and a silent re-seed (no bogus negative
// delta) when counters go backwards after a reboot / ring wrap.
func TestDetectorECCDeltaPublish(t *testing.T) {
	var events []ECCEvent
	SetECCEventSink(func(ev ECCEvent) { events = append(events, ev) })
	defer SetECCEventSink(nil)

	d := New(Config{ECCAlert: true, Cooldown: time.Millisecond})
	base := time.Now()
	step := func(sec int, ce, ue uint64) {
		d.evaluate(Snapshot{Time: base.Add(time.Duration(sec) * time.Second), Host: "h",
			ECC: ECCReport{Present: true, Source: "edac_sysfs", CorrectedTotal: ce, UncorrectedTotal: ue}})
	}
	step(0, 2, 0) // seed with 2 pre-existing corrected → baseline
	step(1, 2, 0) // unchanged → no event
	step(2, 5, 0) // +3 corrected
	step(3, 5, 1) // +1 uncorrected
	step(4, 0, 0) // reboot: counters reset → re-seed, no event
	step(5, 1, 0) // +1 corrected after reboot

	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d: %+v", len(events), events)
	}
	if events[0].Kind != "baseline" || events[0].Corrected != 2 {
		t.Errorf("baseline: %+v", events[0])
	}
	if events[1].Kind != "corrected" || events[1].DeltaCorrected != 3 || events[1].Corrected != 5 {
		t.Errorf("delta corrected: %+v", events[1])
	}
	if events[2].Kind != "uncorrected" || events[2].DeltaUncorrected != 1 {
		t.Errorf("uncorrected: %+v", events[2])
	}
	if events[3].Kind != "corrected" || events[3].DeltaCorrected != 1 || events[3].Corrected != 1 {
		t.Errorf("post-reboot corrected: %+v", events[3])
	}
}

// When a cycle grows BOTH corrected and uncorrected, only the critical
// (uncorrected) alert fires — the corrected alert is subsumed — while the durable
// event records the cycle as uncorrected and still carries both deltas.
func TestDetectorECCCombinedCycleAlertsExclusive(t *testing.T) {
	var last ECCEvent
	var n int
	SetECCEventSink(func(ev ECCEvent) { last = ev; n++ })
	defer SetECCEventSink(nil)

	d := New(Config{ECCAlert: true, Cooldown: time.Millisecond})
	base := time.Now()
	d.evaluate(Snapshot{Time: base, Host: "h", ECC: ECCReport{Present: true, CorrectedTotal: 1}})
	alerts := d.evaluate(Snapshot{Time: base.Add(time.Second), Host: "h",
		ECC: ECCReport{Present: true, CorrectedTotal: 3, UncorrectedTotal: 1}})

	var ce, ue int
	for _, a := range alerts {
		switch string(a.Kind) {
		case "HEALTH/ECC_CORRECTED":
			ce++
		case "HEALTH/ECC_UNCORRECTED":
			ue++
		}
	}
	if ue != 1 || ce != 0 {
		t.Fatalf("combined-growth cycle must emit only the uncorrected alert: ue=%d ce=%d", ue, ce)
	}
	if last.Kind != "uncorrected" || last.DeltaCorrected != 2 || last.DeltaUncorrected != 1 {
		t.Fatalf("event should record uncorrected with both deltas: %+v", last)
	}
	_ = n
}

// A clean box (ECC present, zero counts) never seeds a baseline event.
func TestDetectorECCNoBaselineWhenClean(t *testing.T) {
	var n int
	SetECCEventSink(func(ECCEvent) { n++ })
	defer SetECCEventSink(nil)
	d := New(Config{ECCAlert: true, Cooldown: time.Millisecond})
	d.evaluate(Snapshot{Time: time.Now(), Host: "h", ECC: ECCReport{Present: true}})
	if n != 0 {
		t.Fatalf("clean box must not publish, got %d", n)
	}
}

// worstECCDimm prefers uncorrected, then corrected, and falls back label→location→id.
func TestWorstECCDimm(t *testing.T) {
	rep := ECCReport{DIMMs: []ECCDimm{
		{ID: "mc0/dimm0", Label: "A1", CorrectedCount: 10},
		{ID: "mc0/dimm1", Location: "mc#0ch#1", CorrectedCount: 3, UncorrectedCount: 1},
	}}
	if got := worstECCDimm(rep); got != "mc#0ch#1" {
		t.Errorf("worst = %q, want the uncorrected DIMM's location", got)
	}
	if got := worstECCDimm(ECCReport{}); got != "" {
		t.Errorf("no dimms → empty, got %q", got)
	}
}

// writeFile is a tiny fixture helper.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// mkController lays out a mcN controller with the given counts and, optionally,
// one attributed DIMM.
func mkController(t *testing.T, root, mc, mcName, ce, ue string) string {
	t.Helper()
	base := filepath.Join(root, mc)
	writeFile(t, filepath.Join(base, "mc_name"), mcName+"\n")
	writeFile(t, filepath.Join(base, "ce_count"), ce+"\n")
	writeFile(t, filepath.Join(base, "ue_count"), ue+"\n")
	return base
}

func TestReadEDACSysfs_Absent(t *testing.T) {
	rep := readEDACSysfs(filepath.Join(t.TempDir(), "nope"))
	if rep.Present {
		t.Fatalf("expected Present=false for missing root, got %+v", rep)
	}
}

func TestReadEDACSysfs_CorrectedWithDimm(t *testing.T) {
	root := t.TempDir()
	base := mkController(t, root, "mc0", "amd64", "7", "0")
	// one DIMM carries all 7 corrected; a second DIMM is clean (must be skipped).
	writeFile(t, filepath.Join(base, "dimm0", "dimm_ce_count"), "7\n")
	writeFile(t, filepath.Join(base, "dimm0", "dimm_ue_count"), "0\n")
	writeFile(t, filepath.Join(base, "dimm0", "dimm_label"), "CPU0_DIMM_A1\n")
	writeFile(t, filepath.Join(base, "dimm0", "dimm_location"), "mc#0channel#0slot#0\n")
	writeFile(t, filepath.Join(base, "dimm1", "dimm_ce_count"), "0\n")
	writeFile(t, filepath.Join(base, "dimm1", "dimm_ue_count"), "0\n")

	rep := readEDACSysfs(root)
	if !rep.Present || rep.Source != "edac_sysfs" {
		t.Fatalf("present/source wrong: %+v", rep)
	}
	if rep.CorrectedTotal != 7 || rep.UncorrectedTotal != 0 {
		t.Fatalf("totals: ce=%d ue=%d", rep.CorrectedTotal, rep.UncorrectedTotal)
	}
	if len(rep.Controllers) != 1 || rep.Controllers[0].MCName != "amd64" {
		t.Fatalf("controllers: %+v", rep.Controllers)
	}
	if len(rep.DIMMs) != 1 {
		t.Fatalf("expected only the non-zero DIMM, got %+v", rep.DIMMs)
	}
	if rep.DIMMs[0].Label != "CPU0_DIMM_A1" || rep.DIMMs[0].ID != "mc0/dimm0" {
		t.Fatalf("dimm attribution wrong: %+v", rep.DIMMs[0])
	}
}

func TestReadEDACSysfs_MultiControllerSummedAndSorted(t *testing.T) {
	root := t.TempDir()
	// Deliberately create mc1 before mc0 on disk to prove sorting.
	mkController(t, root, "mc1", "amd64", "3", "2")
	mkController(t, root, "mc0", "amd64", "1", "0")
	// A non-mc dir must be ignored.
	writeFile(t, filepath.Join(root, "readme"), "ignore me\n")

	rep := readEDACSysfs(root)
	if rep.CorrectedTotal != 4 || rep.UncorrectedTotal != 2 {
		t.Fatalf("totals: ce=%d ue=%d", rep.CorrectedTotal, rep.UncorrectedTotal)
	}
	if len(rep.Controllers) != 2 || rep.Controllers[0].Name != "mc0" || rep.Controllers[1].Name != "mc1" {
		t.Fatalf("controllers not sorted: %+v", rep.Controllers)
	}
}

func TestReadECC_FallbackWhenEDACAbsent(t *testing.T) {
	called := false
	fb := func() (uint64, uint64, bool) {
		called = true
		return 5, 1, true
	}
	rep := readECC(filepath.Join(t.TempDir(), "nope"), fb)
	if !called {
		t.Fatal("fallback not consulted when EDAC absent")
	}
	if !rep.Present || rep.Source != "kernel_ring" {
		t.Fatalf("fallback report wrong: %+v", rep)
	}
	if rep.CorrectedTotal != 5 || rep.UncorrectedTotal != 1 {
		t.Fatalf("fallback totals: %+v", rep)
	}
}

func TestReadECC_EDACWinsOverFallback(t *testing.T) {
	root := t.TempDir()
	mkController(t, root, "mc0", "amd64", "2", "0")
	fb := func() (uint64, uint64, bool) {
		t.Fatal("fallback must not run when EDAC is present")
		return 0, 0, false
	}
	rep := readECC(root, fb)
	if rep.Source != "edac_sysfs" || rep.CorrectedTotal != 2 {
		t.Fatalf("edac should win: %+v", rep)
	}
}

func TestReadECC_NeitherSource(t *testing.T) {
	rep := readECC(filepath.Join(t.TempDir(), "nope"), func() (uint64, uint64, bool) { return 0, 0, false })
	if rep.Present {
		t.Fatalf("expected Present=false, got %+v", rep)
	}
}

func TestParseECCFromKmsg(t *testing.T) {
	// The real orion capture: each memory event prints one "DRAM ECC error." line
	// (the memory-specific marker) alongside the generic "Corrected error" summary
	// and the "Unified Memory Controller …" line. We key ONLY on "DRAM ECC error",
	// so two memory events → corrected=2, with no double-count from the co-printed
	// lines and no miscount from the generic summary.
	lines := []string{
		"[Fri Sep  4 16:19:56 2026] core: [Hardware Error]: Machine check events logged",
		"[Fri Sep  4 16:19:56 2026] [Hardware Error]: Corrected error, no action required.",
		"[Fri Sep  4 16:19:56 2026] [Hardware Error]: Unified Memory Controller Ext. Error Code: 0, DRAM ECC error.",
		"[Fri Sep  4 16:23:08 2026] [Hardware Error]: Corrected error, no action required.",
		"[Fri Sep  4 16:23:08 2026] [Hardware Error]: Unified Memory Controller Ext. Error Code: 0, DRAM ECC error.",
		"some unrelated kernel line",
		// A NON-memory machine-check (cache) and a PCIe AER event must NOT be
		// counted as memory ECC — this is the false-attribution guard: both carry
		// "corrected"/"uncorrect" but neither carries the "dram ecc" marker.
		"[Hardware Error]: Corrected error, no action required.",
		"[Hardware Error]: cache level: L2, tx: DATA, mem-tx: EV",
		"[Hardware Error]: Uncorrected, software restartable error. (PCIe Bus Error)",
		// An inline uncorrected DRAM line IS memory-scoped → counts as uncorrected.
		"[Hardware Error]: Uncorrectable DRAM ECC error on memory read",
	}
	ce, ue := parseECCFromKmsg(lines)
	if ce != 2 {
		t.Errorf("corrected = %d, want 2 (DRAM ECC lines without an uncorrected marker)", ce)
	}
	if ue != 1 {
		t.Errorf("uncorrected = %d, want 1 (inline uncorrected DRAM line; PCIe uncorrected excluded)", ue)
	}
}

func TestIsMCDirAndDimmDir(t *testing.T) {
	for _, tc := range []struct {
		name string
		mc   bool
		dimm bool
	}{
		{"mc0", true, false},
		{"mc12", true, false},
		{"mcelog", false, false},
		{"mc", false, false},
		{"dimm0", false, true},
		{"rank3", false, true},
		{"csrow0", false, false},
		{"dimm_label", false, false},
	} {
		if got := isMCDir(tc.name); got != tc.mc {
			t.Errorf("isMCDir(%q)=%v want %v", tc.name, got, tc.mc)
		}
		if got := isDimmDir(tc.name); got != tc.dimm {
			t.Errorf("isDimmDir(%q)=%v want %v", tc.name, got, tc.dimm)
		}
	}
}
