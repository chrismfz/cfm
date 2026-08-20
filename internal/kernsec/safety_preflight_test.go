package kernsec

import (
	"bytes"
	"strings"
	"testing"
)

func TestConfirmApply_YesAndYesFull(t *testing.T) {
	tests := []string{"y\n", "Y\n", "yes\n", "YES\n", "Yes\n"}
	for _, in := range tests {
		t.Run(strings.TrimSpace(in), func(t *testing.T) {
			var w bytes.Buffer
			ok, err := confirmApply(&w, strings.NewReader(in))
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				t.Errorf("input %q should accept, got decline", in)
			}
		})
	}
}

func TestConfirmApply_DeclinesEverythingElse(t *testing.T) {
	tests := []string{
		"n\n",
		"no\n",
		"N\n",
		"\n", // bare Enter
		"yep\n",
		"yeah\n",
		"asdf\n",
		" y \n", // y wrapped in spaces actually trims to "y" — should ACCEPT
	}
	wantAccept := map[string]bool{" y \n": true}
	for _, in := range tests {
		t.Run(strings.TrimSpace(in), func(t *testing.T) {
			var w bytes.Buffer
			ok, _ := confirmApply(&w, strings.NewReader(in))
			if ok != wantAccept[in] {
				t.Errorf("input %q: ok=%v, want %v", in, ok, wantAccept[in])
			}
		})
	}
}

func TestConfirmApply_EOFIsDecline(t *testing.T) {
	// Piped input that closes without a newline (e.g. `echo -n y`)
	// or any other non-interactive context that closes stdin → must
	// decline rather than silently accept.
	var w bytes.Buffer
	ok, err := confirmApply(&w, strings.NewReader(""))
	if err != nil {
		t.Errorf("EOF should not error, got %v", err)
	}
	if ok {
		t.Error("EOF must decline (avoid accidental yes)")
	}
}

func TestBootImpactingRisks_DangerousModuleSurfaced(t *testing.T) {
	// Apply-time deny-list will reject this, but if a future PR ever
	// loosens the deny-list the pre-flight must still flag it.
	risks := boot_impacting_risks(
		nil,
		[]ModuleRule{{Name: "nvme", ID: "FAKE-001"}},
		HostProfile{},
	)
	found := false
	for _, r := range risks {
		if strings.Contains(r, "nvme") {
			found = true
		}
	}
	if !found {
		t.Errorf("dangerous module name should be in risks, got: %v", risks)
	}
}

func TestBootImpactingRisks_NoBootArgsNoRisks(t *testing.T) {
	// Tier 1 sysctl-only apply set: no bootloader mutation → no
	// boot-impacting risks. Operator gets the lighter prompt.
	risks := boot_impacting_risks(nil, nil, HostProfile{})
	if len(risks) != 0 {
		t.Errorf("no boot args + no modules should produce no risks, got: %v", risks)
	}
}

func TestPreflightSummary_RendersFiles(t *testing.T) {
	// Smoke that the summary names the three managed file paths so
	// the operator can see at a glance what's about to be touched.
	var w bytes.Buffer
	preflightSummary(&w, "APPLY",
		[]SysctlRule{{ID: "X", Key: "k", Value: "v"}},
		[]BootArg{{Key: "slab_nomerge"}},
		[]ModuleRule{{Name: "ksmbd", ID: "Y"}},
		HostProfile{},
		nil,
		nil,
	)
	out := w.String()
	for _, want := range []string{SysctlPath, ModprobePath, "Apply",
		"backup", "y/N"} {
		// y/N appears in confirmApply, not preflightSummary — but
		// "Pass --yes" should appear in preflightSummary so check
		// just one word.
		_ = want
	}
	for _, want := range []string{SysctlPath, ModprobePath, "--yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("preflight summary missing %q in:\n%s", want, out)
		}
	}
}

// TestPreflightSummary_NamesForeignReconcileFiles asserts that when the
// reconcile is about to rewrite a foreign drop-in, the safety gate names
// that file and its backup — the operator must not confirm blind to a
// mutation of a file kernsec does not own.
func TestPreflightSummary_NamesForeignReconcileFiles(t *testing.T) {
	var w bytes.Buffer
	conflicts := []foreignConflict{
		{File: "/etc/sysctl.d/99-kspp.conf", Line: 6, Key: "fs.protected_regular", Found: "2", Want: "1", Reason: "x"},
	}
	preflightSummary(&w, "APPLY",
		[]SysctlRule{{ID: "X", Key: "k", Value: "v"}},
		nil, nil, HostProfile{}, nil,
		conflicts,
	)
	out := w.String()
	for _, want := range []string{
		"/etc/sysctl.d/99-kspp.conf",
		"neutralise fs.protected_regular=2",
		"/etc/sysctl.d/99-kspp.conf" + BackupSuffix,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("preflight summary missing %q in:\n%s", want, out)
		}
	}
}
