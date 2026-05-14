package kernsec

import (
	"strings"
	"testing"
)

// This file carries the tests for the kernel-hardening knobs borrowed
// from the afflicted.sh "every kernel mitigation on Resolute" writeup
// that we actually shipped. The three held-back candidates
// (io_uring_disabled, vsyscall=none, debugfs=off) are documented in
// docs/kernsec.md under "Considered but not shipped"; the registry
// absence below is the regression guard that keeps them out until
// the probe / managed-key issues called out in that section are fixed.

// ---------------------------------------------------------------------
// AcceptValues coverage for the relaxed audit rules
// ---------------------------------------------------------------------

func TestAcceptValues_PerfEventParanoid(t *testing.T) {
	var rule *SysctlRule
	for i, r := range KSPPSysctls {
		if r.ID == "KSEC-SCT-kspp.kernel-005" {
			rule = &KSPPSysctls[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("KSEC-SCT-kspp.kernel-005 (perf_event_paranoid) not found in KSPPSysctls")
	}
	if rule.Value != "3" {
		t.Errorf("canonical perf_event_paranoid value = %q, want 3", rule.Value)
	}
	wantAccept := map[string]bool{"2": false, "4": false}
	for _, v := range rule.AcceptValues {
		if _, ok := wantAccept[v]; ok {
			wantAccept[v] = true
		}
	}
	for v, found := range wantAccept {
		if !found {
			t.Errorf("AcceptValues missing %q (should be also-green)", v)
		}
	}
}

func TestAcceptValues_MmapMinAddr(t *testing.T) {
	var rule *SysctlRule
	for i, r := range KSPPSysctls {
		if r.ID == "KSEC-SCT-kspp.kernel-007" {
			rule = &KSPPSysctls[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("KSEC-SCT-kspp.kernel-007 (vm.mmap_min_addr) not found in KSPPSysctls")
	}
	if rule.Key != "vm.mmap_min_addr" {
		t.Errorf("KSEC-SCT-kspp.kernel-007 Key = %q, want vm.mmap_min_addr", rule.Key)
	}
	if rule.Value != "65536" {
		t.Errorf("canonical mmap_min_addr value = %q, want 65536", rule.Value)
	}
	wantAccept := map[string]bool{"131072": false, "262144": false}
	for _, v := range rule.AcceptValues {
		if _, ok := wantAccept[v]; ok {
			wantAccept[v] = true
		}
	}
	for v, found := range wantAccept {
		if !found {
			t.Errorf("AcceptValues missing %q (stricter live value should be also-green)", v)
		}
	}
}

// ---------------------------------------------------------------------
// Held-back rule guards — keep io_uring_disabled, vsyscall=none, and
// debugfs=off out of the registry until docs/kernsec.md "Considered
// but not shipped" gets resolved.
// ---------------------------------------------------------------------

func TestHeldBackRules_NotInSysctlRegistry(t *testing.T) {
	heldKeys := map[string]string{
		"kernel.io_uring_disabled": "see docs/kernsec.md \"Considered but not shipped\" — probe cost",
	}
	heldIDs := map[string]string{
		"KSEC-SCT-tier2.iouring-001": "see docs/kernsec.md \"Considered but not shipped\"",
	}
	for _, r := range AllSysctls() {
		if reason, held := heldKeys[r.Key]; held {
			t.Errorf("held-back sysctl key %q is registered as %s — %s", r.Key, r.ID, reason)
		}
		if reason, held := heldIDs[r.ID]; held {
			t.Errorf("held-back sysctl ID %q is registered — %s", r.ID, reason)
		}
	}
}

func TestHeldBackRules_NotInBootArgRegistry(t *testing.T) {
	heldKeys := map[string]string{
		"vsyscall": "see docs/kernsec.md \"Considered but not shipped\" — probe needs Elf_Verneed parsing",
		"debugfs":  "see docs/kernsec.md \"Considered but not shipped\" — ManagedBootArgKeys regression",
	}
	heldIDs := map[string]string{
		"KSEC-BOOT-tier3.legacycompat-001":   "see docs/kernsec.md \"Considered but not shipped\"",
		"KSEC-BOOT-tier3.observability-001": "see docs/kernsec.md \"Considered but not shipped\"",
	}
	for _, a := range AllBootArgs() {
		if reason, held := heldKeys[a.Key]; held {
			t.Errorf("held-back boot arg key %q is registered as %s — %s", a.Key, a.ID, reason)
		}
		if reason, held := heldIDs[a.ID]; held {
			t.Errorf("held-back boot arg ID %q is registered — %s", a.ID, reason)
		}
	}
	// And the managed-key list must not regrow the held entries
	// either, since their presence there is what causes the
	// operator-set-value clobber regression.
	for _, k := range ManagedBootArgKeys {
		if _, held := heldKeys[k]; held {
			t.Errorf("held-back boot arg key %q is still in ManagedBootArgKeys — kernsec would strip operator-set values", k)
		}
	}
}

// ---------------------------------------------------------------------
// init_on_free=1 preflight notice surfaces the stacked perf-cost
// language so operators opting in at Tier 3 see the combined ceiling
// rather than the bare per-arg overhead.
// ---------------------------------------------------------------------

func TestBootImpactingRisks_InitOnFreeStackedNote(t *testing.T) {
	risks := boot_impacting_risks(
		[]BootArg{{Key: "init_on_free", Value: "1"}},
		nil,
		HostProfile{},
	)
	var found string
	for _, r := range risks {
		if strings.Contains(r, "init_on_free") {
			found = r
			break
		}
	}
	if found == "" {
		t.Fatalf("init_on_free=1 should surface a preflight risk note, got: %v", risks)
	}
	if !strings.Contains(found, "stacked") {
		t.Errorf("init_on_free preflight note should call out the stacked perf cost, got: %q", found)
	}
	if !strings.Contains(found, "init_on_alloc") {
		t.Errorf("init_on_free preflight note should reference the Tier 1 init_on_alloc pair, got: %q", found)
	}
}

func TestBootImpactingRisks_InitOnAllocBareNote(t *testing.T) {
	risks := boot_impacting_risks(
		[]BootArg{{Key: "init_on_alloc", Value: "1"}},
		nil,
		HostProfile{},
	)
	var found string
	for _, r := range risks {
		if strings.Contains(r, "init_on_alloc") {
			found = r
			break
		}
	}
	if found == "" {
		t.Fatalf("init_on_alloc=1 should surface a preflight risk note, got: %v", risks)
	}
	// init_on_alloc on its own should NOT carry the stacked-with-init_on_free
	// language — that's reserved for the Tier 3 entry so the operator's
	// Tier 1 audit doesn't double-count.
	if strings.Contains(found, "stacked") {
		t.Errorf("bare init_on_alloc note should not use stacked language, got: %q", found)
	}
}
