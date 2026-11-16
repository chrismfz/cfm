package lsm

import (
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// TestTracepointPoliciesMatchProgramsFor keeps tracepointPolicies honest
// without a loaded BPF object: it reads programsFor's switch out of
// loader.go and collects every case whose body builds a tracepoint
// entry. A new tracepoint-backed policy missing from the list would be
// attached on a kernel without perf links and fail the pin.
func TestTracepointPoliciesMatchProgramsFor(t *testing.T) {
	src, err := os.ReadFile("loader.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "func (l *Loader) programsFor(")
	if start < 0 {
		t.Fatal("programsFor not found in loader.go")
	}
	body = body[start:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	caseRe := regexp.MustCompile(`(?m)^\s*case (Policy\w+(?:,\s*Policy\w+)*):`)
	idx := caseRe.FindAllStringSubmatchIndex(body, -1)
	if len(idx) == 0 {
		t.Fatal("no cases parsed from programsFor")
	}
	consts := map[string]PolicyID{
		"PolicyUnexpectedBPF":    PolicyUnexpectedBPF,
		"PolicyKernelModuleLoad": PolicyKernelModuleLoad,
		"PolicyKexecLoad":        PolicyKexecLoad,
	}
	var got []string
	for i, m := range idx {
		end := len(body)
		if i+1 < len(idx) {
			end = idx[i+1][0]
		}
		if strings.Contains(body[m[1]:end], "tracepointProgramEntry") {
			for _, name := range strings.Split(body[m[2]:m[3]], ",") {
				got = append(got, strings.TrimSpace(name))
			}
		}
	}
	var want []string
	for _, id := range tracepointPolicies {
		for name, v := range consts {
			if v == id {
				want = append(want, name)
			}
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("tracepoint-backed cases in programsFor = %v, tracepointPolicies = %v; update tracepointPolicies (and the consts map here)", got, want)
	}
}

func TestMemoPerfLinkProbe_CachesOnlyDefiniteAnswers(t *testing.T) {
	reset := func() { perfLinkProbeDone, perfLinkProbeErr = false, nil }
	reset()
	t.Cleanup(reset)

	// A definite answer is cached: a second call must not re-probe.
	perfLinkProbeDone, perfLinkProbeErr = true, ebpf.ErrNotSupported
	if err := memoPerfLinkProbe(); !errors.Is(err, ebpf.ErrNotSupported) {
		t.Fatalf("cached answer not returned: %v", err)
	}
}

// An OBS-004 attach is never hidden by the comm allowlist, compiled-in
// or operator-supplied; a read by the same comm still is.
func TestEventFilter_OBS004AttachNotHiddenByComm(t *testing.T) {
	c := DefaultConf()
	c.AllowComm[PolicyPtraceAccess] = []string{"my-orchestrator"}
	f := BuildEventFilter(c)
	for _, comm := range []string{"pgrep", "ps", "my-orchestrator"} {
		read := Event{PolicyID: PolicyPtraceAccess, Comm: comm, Flags: EventFlagPtraceRead | EventFlagPtraceSameUid}
		if !f.Match(read) {
			t.Errorf("comm=%q read should be suppressed", comm)
		}
		for _, fl := range []uint8{EventFlagPtraceAttach, EventFlagPtraceAttach | EventFlagPtraceRead} {
			ev := Event{PolicyID: PolicyPtraceAccess, Comm: comm, Flags: fl | EventFlagPtraceSameUid}
			if f.Match(ev) {
				t.Errorf("comm=%q attach (flags=%#x) must still report", comm, fl)
			}
		}
	}
	// Other policies' flag bits are unrelated: a CRED-002 comm match is
	// unaffected by bit 5.
	if !f.Match(Event{PolicyID: PolicyCredEscal, Comm: "runc", Flags: EventFlagPtraceAttach}) {
		t.Error("CRED-002 comm allowlist must ignore OBS-004 flag bits")
	}
}
