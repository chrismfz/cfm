//go:build linux

package lsm

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnforceByte_Mapping(t *testing.T) {
	cases := []struct {
		mode Mode
		want uint8
	}{
		{ModeDisabled, 0},
		{ModeMonitor, 0},
		{ModeEnforce, 1},
	}
	for _, tc := range cases {
		if got := enforceByte(tc.mode); got != tc.want {
			t.Errorf("enforceByte(%v) = %d, want %d", tc.mode, got, tc.want)
		}
	}
}

func TestRewriteEnforceConstants_RealSpec(t *testing.T) {
	// loadCfmlsm is the bpf2go-generated spec loader. It works
	// without root because it just reads the embedded .o bytes;
	// no kernel-side operation is involved.
	spec, err := loadCfmlsm()
	if err != nil {
		t.Fatalf("loadCfmlsm: %v", err)
	}

	// Both globals should be present in the freshly-loaded spec.
	for _, name := range []string{"cfm_enforce_memfd_exec", "cfm_enforce_revshell"} {
		if _, ok := spec.Variables[name]; !ok {
			t.Errorf("spec.Variables missing %q — BPF C / Go names out of sync", name)
		}
	}

	// Rewrite: EXEC-001 enforce, EXEC-003 monitor.
	err = rewriteEnforceConstants(spec, map[PolicyID]Mode{
		PolicyMemfdExec:    ModeEnforce,
		PolicyReverseShell: ModeMonitor,
	})
	if err != nil {
		t.Fatalf("rewriteEnforceConstants: %v", err)
	}

	// Read back via VariableSpec.Get to verify the bytes landed.
	var memfd uint8
	if err := spec.Variables["cfm_enforce_memfd_exec"].Get(&memfd); err != nil {
		t.Fatalf("Get memfd: %v", err)
	}
	if memfd != 1 {
		t.Errorf("memfd_exec = %d after rewrite, want 1", memfd)
	}
	var revshell uint8
	if err := spec.Variables["cfm_enforce_revshell"].Get(&revshell); err != nil {
		t.Fatalf("Get revshell: %v", err)
	}
	if revshell != 0 {
		t.Errorf("revshell = %d after rewrite, want 0", revshell)
	}
}

func TestRewriteEnforceConstants_MissingVariableErrs(t *testing.T) {
	// Build a fake spec with no Variables. RewriteEnforceConstants
	// should report which name is missing rather than silently
	// succeeding.
	spec, err := loadCfmlsm()
	if err != nil {
		t.Fatalf("loadCfmlsm: %v", err)
	}
	// Strip one of the variables.
	delete(spec.Variables, "cfm_enforce_memfd_exec")

	err = rewriteEnforceConstants(spec, map[PolicyID]Mode{PolicyMemfdExec: ModeEnforce})
	if err == nil {
		t.Fatal("expected error when cfm_enforce_memfd_exec is missing")
	}
	if !strings.Contains(err.Error(), "cfm_enforce_memfd_exec") {
		t.Errorf("error %q should name the missing variable", err.Error())
	}
}

func TestConfirmEnforce_AcceptsY(t *testing.T) {
	for _, in := range []string{"y\n", "Y\n", "yes\n", "YES\n", "  yes  \n"} {
		t.Run(strings.TrimSpace(in), func(t *testing.T) {
			var w bytes.Buffer
			conf := DefaultConf()
			conf.Modes[PolicyMemfdExec] = ModeEnforce
			ok := confirmEnforce(&w, strings.NewReader(in), conf, []PolicyID{PolicyMemfdExec})
			if !ok {
				t.Errorf("input %q should confirm; got false", in)
			}
		})
	}
}

func TestConfirmEnforce_RejectsEverythingElse(t *testing.T) {
	// Anything that is not an explicit y/yes — including empty
	// input, "n", "no", random text, EOF — must be treated as no.
	cases := []string{
		"\n",      // bare Enter
		"n\n",     // explicit no
		"no\n",
		"abort\n",
		"sure why not\n",
		"", // EOF
	}
	for _, in := range cases {
		t.Run(strings.ReplaceAll(in, "\n", "\\n"), func(t *testing.T) {
			var w bytes.Buffer
			conf := DefaultConf()
			conf.Modes[PolicyMemfdExec] = ModeEnforce
			ok := confirmEnforce(&w, strings.NewReader(in), conf, []PolicyID{PolicyMemfdExec})
			if ok {
				t.Errorf("input %q should NOT confirm; got true", in)
			}
		})
	}
}

func TestConfirmEnforce_PromptListsEachEnforcePolicy(t *testing.T) {
	var w bytes.Buffer
	conf := DefaultConf()
	conf.Modes[PolicyMemfdExec] = ModeEnforce
	conf.Modes[PolicyReverseShell] = ModeEnforce
	_ = confirmEnforce(&w, strings.NewReader("n\n"), conf,
		[]PolicyID{PolicyMemfdExec, PolicyReverseShell})

	out := w.String()
	if !strings.Contains(out, "ENFORCE") {
		t.Errorf("prompt missing ENFORCE warning; got: %s", out)
	}
	for _, id := range []PolicyID{PolicyMemfdExec, PolicyReverseShell} {
		if !strings.Contains(out, string(id)) {
			t.Errorf("prompt missing policy %s; got: %s", id, out)
		}
	}
	if !strings.Contains(out, "cfm lsm disable") {
		t.Errorf("prompt should mention the recovery path; got: %s", out)
	}
	if !strings.Contains(out, "--yes") {
		t.Errorf("prompt should mention the --yes flag; got: %s", out)
	}
}

func TestConfirmEnforce_LabelsMonitorPoliciesToo(t *testing.T) {
	// EXEC-001 enforce, EXEC-003 monitor — the prompt should list
	// both so the operator sees the full picture.
	var w bytes.Buffer
	conf := DefaultConf()
	conf.Modes[PolicyMemfdExec] = ModeEnforce
	conf.Modes[PolicyReverseShell] = ModeMonitor
	_ = confirmEnforce(&w, strings.NewReader("n\n"), conf,
		[]PolicyID{PolicyMemfdExec})

	out := w.String()
	if !strings.Contains(out, "CFML-EXEC-001") {
		t.Error("prompt missing EXEC-001 (enforce)")
	}
	if !strings.Contains(out, "CFML-EXEC-003") {
		t.Error("prompt missing EXEC-003 (monitor) — operator needs the full picture")
	}
	if !strings.Contains(out, "mode=monitor") {
		t.Error("monitor entry should be tagged so operator sees the contrast")
	}
}
