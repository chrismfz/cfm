//go:build linux

package lsm

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestEmitProbeText_SkippedWhenPreflightFails verifies the text
// output path for the most common case — a host whose preflight
// says it cannot accept BPF LSM programs. We do not need to load
// anything for this; the formatter is purely a function of the
// ProbeResult struct.
func TestEmitProbeText_SkippedWhenPreflightFails(t *testing.T) {
	var buf bytes.Buffer
	emitProbeText(&buf, ProbeResult{PreflightOK: false}, false)

	out := buf.String()
	if !strings.Contains(out, "SKIPPED") {
		t.Errorf("expected SKIPPED in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Preflight failed") {
		t.Errorf("expected 'Preflight failed' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "cfm lsm status") {
		t.Errorf("expected pointer to `cfm lsm status` for remediation, got:\n%s", out)
	}
}

// TestEmitProbeText_VerboseShowsDriftPicks confirms that --verbose
// surfaces the BTF-probed LSM hook variant selections in a stable,
// sorted order and that the section is silent in non-verbose mode.
func TestEmitProbeText_VerboseShowsDriftPicks(t *testing.T) {
	res := ProbeResult{
		PreflightOK:     true,
		AttachAttempted: true,
		Attached:        []PolicyID{PolicyMemfdExec},
		DriftPicks: map[string]string{
			"bpf_lsm_inode_setattr":  "cfm_fs005_setattr_idmap",
			"bpf_lsm_inode_setxattr": "cfm_fs005_setxattr_idmap",
		},
	}

	var quiet bytes.Buffer
	emitProbeText(&quiet, res, false)
	if strings.Contains(quiet.String(), "BTF probe") {
		t.Errorf("non-verbose probe output leaked the BTF-probe section:\n%s", quiet.String())
	}

	var loud bytes.Buffer
	emitProbeText(&loud, res, true)
	out := loud.String()
	if !strings.Contains(out, "[BTF probe — LSM hook variant picks]") {
		t.Errorf("verbose probe output missing the BTF-probe section:\n%s", out)
	}
	if !strings.Contains(out, "bpf_lsm_inode_setattr → cfm_fs005_setattr_idmap") {
		t.Errorf("verbose probe output missing setattr pick:\n%s", out)
	}
	if !strings.Contains(out, "bpf_lsm_inode_setxattr → cfm_fs005_setxattr_idmap") {
		t.Errorf("verbose probe output missing setxattr pick:\n%s", out)
	}
	// Sort stability: setattr line must appear before setxattr line
	// because the section iterates keys via sort.Strings.
	if idxA, idxB := strings.Index(out, "bpf_lsm_inode_setattr"), strings.Index(out, "bpf_lsm_inode_setxattr"); idxA < 0 || idxB < 0 || idxA > idxB {
		t.Errorf("verbose probe output picks not sorted: setattr=%d setxattr=%d\n%s", idxA, idxB, out)
	}
}

// TestEmitProbeText_VerboseSilentWhenNoPicks confirms the verbose
// section is omitted when DriftPicks is empty — e.g. on a kernel
// without any drifting hooks in scope, or in AdoptPinned mode.
func TestEmitProbeText_VerboseSilentWhenNoPicks(t *testing.T) {
	var buf bytes.Buffer
	emitProbeText(&buf, ProbeResult{
		PreflightOK:     true,
		AttachAttempted: true,
		Attached:        []PolicyID{PolicyMemfdExec},
	}, true)
	if strings.Contains(buf.String(), "BTF probe") {
		t.Errorf("verbose probe with empty picks should omit the section:\n%s", buf.String())
	}
}

func TestEmitProbeText_SkippedWhenEveryPolicyDisabled(t *testing.T) {
	var buf bytes.Buffer
	emitProbeText(&buf, ProbeResult{
		PreflightOK:     true,
		AttachAttempted: false,
	}, false)

	out := buf.String()
	if !strings.Contains(out, "SKIPPED") {
		t.Errorf("expected SKIPPED, got:\n%s", out)
	}
	if !strings.Contains(out, "mode=disabled") {
		t.Errorf("expected explanation about mode=disabled, got:\n%s", out)
	}
}

func TestEmitProbeText_PassWithAttached(t *testing.T) {
	var buf bytes.Buffer
	emitProbeText(&buf, ProbeResult{
		PreflightOK:     true,
		AttachAttempted: true,
		Attached:        []PolicyID{PolicyMemfdExec, PolicyReverseShell},
	}, false)

	out := buf.String()
	if !strings.Contains(out, "Result: PASS") {
		t.Errorf("expected Result: PASS, got:\n%s", out)
	}
	if !strings.Contains(out, "CFML-EXEC-001") {
		t.Errorf("expected EXEC-001 listed, got:\n%s", out)
	}
	if !strings.Contains(out, "CFML-EXEC-003") {
		t.Errorf("expected EXEC-003 listed, got:\n%s", out)
	}
}

func TestEmitProbeText_PartialMode(t *testing.T) {
	var buf bytes.Buffer
	emitProbeText(&buf, ProbeResult{
		PreflightOK:     true,
		AttachAttempted: true,
		Attached:        []PolicyID{PolicyMemfdExec},
		Failed: map[PolicyID]error{
			PolicyReverseShell: errVerifierStub{},
		},
	}, false)

	out := buf.String()
	if !strings.Contains(out, "Result: PARTIAL") {
		t.Errorf("expected PARTIAL, got:\n%s", out)
	}
	if !strings.Contains(out, "CFML-EXEC-001") || !strings.Contains(out, "[Attached]") {
		t.Errorf("expected attached list to mention EXEC-001, got:\n%s", out)
	}
	if !strings.Contains(out, "CFML-EXEC-003") || !strings.Contains(out, "[Failed]") {
		t.Errorf("expected failed list to mention EXEC-003, got:\n%s", out)
	}
}

func TestEmitProbeText_UnavailablePolicyDoesNotFailAttachedProbe(t *testing.T) {
	var buf bytes.Buffer
	emitProbeText(&buf, ProbeResult{
		PreflightOK:     true,
		AttachAttempted: true,
		Attached:        []PolicyID{PolicyMemfdExec},
		Unavailable: map[PolicyID]string{
			PolicyDirectCredInstall: "commit_creds is not visible",
		},
	}, false)

	out := buf.String()
	if !strings.Contains(out, "Result: PASS") {
		t.Errorf("expected unavailable optional policy to keep probe PASS, got:\n%s", out)
	}
	if !strings.Contains(out, "[Unavailable]") || !strings.Contains(out, "CFML-CRED-003") {
		t.Errorf("expected unavailable list to mention CRED-003, got:\n%s", out)
	}
	if strings.Contains(out, "[Failed]") {
		t.Errorf("optional unavailability should not be reported as failure, got:\n%s", out)
	}
}

func TestEmitProbeText_SkippedWhenOnlyEnabledPoliciesUnavailable(t *testing.T) {
	var buf bytes.Buffer
	emitProbeText(&buf, ProbeResult{
		PreflightOK:     true,
		AttachAttempted: false,
		Unavailable: map[PolicyID]string{
			PolicyDirectCredInstall: "commit_creds is not visible",
		},
	}, false)

	out := buf.String()
	if !strings.Contains(out, "Result: SKIPPED") {
		t.Errorf("expected skipped result, got:\n%s", out)
	}
	if !strings.Contains(out, "Every enabled policy is unavailable") {
		t.Errorf("expected unavailable explanation, got:\n%s", out)
	}
	if !strings.Contains(out, "[Unavailable]") || !strings.Contains(out, "CFML-CRED-003") {
		t.Errorf("expected unavailable policy listing, got:\n%s", out)
	}
}

func TestEmitProbeText_SpontaneousEventReported(t *testing.T) {
	var buf bytes.Buffer
	ev := Event{
		PolicyID: PolicyMemfdExec,
		PID:      12345,
		Comm:     "php-fpm",
		Filename: "memfd:payload",
	}
	emitProbeText(&buf, ProbeResult{
		PreflightOK:       true,
		AttachAttempted:   true,
		Attached:          []PolicyID{PolicyMemfdExec},
		SpontaneousEvents: 1,
		FirstEvent:        &ev,
	}, false)

	out := buf.String()
	if !strings.Contains(out, "Spontaneous events observed: 1") {
		t.Errorf("expected event count, got:\n%s", out)
	}
	if !strings.Contains(out, "pid=12345") {
		t.Errorf("expected pid in first-event line, got:\n%s", out)
	}
	if !strings.Contains(out, "php-fpm") {
		t.Errorf("expected comm in first-event line, got:\n%s", out)
	}
	if !strings.Contains(out, "investigate") {
		t.Errorf("expected guidance to investigate spontaneous events, got:\n%s", out)
	}
}

// errVerifierStub stands in for a real attach error in formatter tests.
// Wrapping ErrBPFLSMUnavailable would couple the test to the exact
// loader error path; this stub keeps the formatter test isolated.
type errVerifierStub struct{}

func (errVerifierStub) Error() string { return "stub verifier rejection" }

// TestRunProbeOnce_SkipsCleanlyOnUnsupportedHost is the live counterpart:
// it actually calls RunProbeOnce on the test host. On any runner that
// fails preflight the result must come back with PreflightOK=false
// and AttachAttempted=false — confirming the early-exit path works.
func TestRunProbeOnce_SkipsCleanlyOnUnsupportedHost(t *testing.T) {
	if RunPreflight().OK {
		t.Skip("host actually supports BPF LSM; this test is for the unsupported-host code path")
	}

	res := RunProbeOnce(10 * time.Millisecond)
	if res.PreflightOK {
		t.Fatal("RunPreflight reported NOT OK above but ProbeResult.PreflightOK is true")
	}
	if res.AttachAttempted {
		t.Errorf("AttachAttempted should be false when preflight fails, got true")
	}
	if res.LoadError != nil {
		t.Errorf("LoadError should be nil when preflight fails (we never tried to load), got: %v", res.LoadError)
	}
	if len(res.Attached) != 0 {
		t.Errorf("Attached should be empty when preflight fails, got: %v", res.Attached)
	}
}
