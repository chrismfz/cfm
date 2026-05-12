package kernsec

import (
	"strings"
	"testing"
)

func TestMergeLSMBPF_AddsBPFWhenAbsent(t *testing.T) {
	in := []string{
		"BOOT_IMAGE=/vmlinuz",
		"root=UUID=abc",
		"lsm=lockdown,capability,yama,apparmor",
		"ro",
	}
	got := MergeLSMBPF(append([]string{}, in...))
	want := "lsm=lockdown,capability,yama,apparmor,bpf"

	found := false
	for _, tok := range got {
		if tok == want {
			found = true
		}
	}
	if !found {
		t.Errorf("MergeLSMBPF did not produce %q\ntokens: %v", want, got)
	}
	if len(got) != len(in) {
		t.Errorf("token count changed: in=%d out=%d", len(in), len(got))
	}
}

func TestMergeLSMBPF_IdempotentWhenBPFAlreadyThere(t *testing.T) {
	in := []string{"lsm=lockdown,capability,bpf,yama"}
	got := MergeLSMBPF(append([]string{}, in...))
	if got[0] != "lsm=lockdown,capability,bpf,yama" {
		t.Errorf("idempotent run mutated value: got %q", got[0])
	}
}

func TestMergeLSMBPF_PreservesOperatorOrder(t *testing.T) {
	// Operators may have ordered their LSM list deliberately; the
	// kernel applies LSMs in cmdline order. Preserve it; we only
	// append.
	in := []string{"lsm=integrity,lockdown,capability"}
	got := MergeLSMBPF(append([]string{}, in...))
	if got[0] != "lsm=integrity,lockdown,capability,bpf" {
		t.Errorf("operator order not preserved: got %q", got[0])
	}
}

func TestMergeLSMBPF_NoLSMTokenIsNoOp(t *testing.T) {
	// Conservative behaviour: when there is no `lsm=` token, we do
	// NOT synthesise one. The live LSM list reflects the running
	// kernel which may differ from the boot kernel, and guessing
	// is more dangerous than asking the operator to set lsm=
	// manually first.
	in := []string{"BOOT_IMAGE=/vmlinuz", "root=UUID=abc", "ro"}
	got := MergeLSMBPF(append([]string{}, in...))
	if strings.Join(got, " ") != strings.Join(in, " ") {
		t.Errorf("MergeLSMBPF synthesised an lsm= token when none was present\nin=%v\nout=%v", in, got)
	}
}

func TestMergeLSMBPF_EmptyLSMValueGetsBareBPF(t *testing.T) {
	in := []string{"lsm="}
	got := MergeLSMBPF(append([]string{}, in...))
	if got[0] != "lsm=bpf" {
		t.Errorf("`lsm=` with empty value should become `lsm=bpf`; got %q", got[0])
	}
}

func TestUnmergeLSMBPF_RemovesBPF(t *testing.T) {
	in := []string{"lsm=lockdown,capability,bpf,yama"}
	got := UnmergeLSMBPF(append([]string{}, in...))
	if got[0] != "lsm=lockdown,capability,yama" {
		t.Errorf("UnmergeLSMBPF should remove bpf preserving order; got %q", got[0])
	}
}

func TestUnmergeLSMBPF_RemovesLSMTokenWhenBPFWasOnly(t *testing.T) {
	in := []string{"BOOT_IMAGE=/vmlinuz", "lsm=bpf", "ro"}
	got := UnmergeLSMBPF(append([]string{}, in...))
	for _, tok := range got {
		if strings.HasPrefix(tok, "lsm=") {
			t.Errorf("UnmergeLSMBPF should drop the whole lsm= token when bpf was the only entry; got %v", got)
			return
		}
	}
	if len(got) != 2 {
		t.Errorf("expected exactly two tokens after unmerge; got %v", got)
	}
}

func TestUnmergeLSMBPF_NoOpWhenBPFAbsent(t *testing.T) {
	in := []string{"lsm=lockdown,capability,yama"}
	got := UnmergeLSMBPF(append([]string{}, in...))
	if got[0] != in[0] {
		t.Errorf("unmerge should be a no-op when bpf absent; got %q", got[0])
	}
}

func TestIsLSMBPFForced(t *testing.T) {
	cases := []struct {
		name string
		c    *Conf
		want bool
	}{
		{"nil conf", nil, false},
		{"no overrides", &Conf{Overrides: map[string]RuleOverride{}}, false},
		{
			"forced",
			&Conf{Overrides: map[string]RuleOverride{LSMBPFRuleID: OverrideForce}},
			true,
		},
		{
			"skipped",
			&Conf{Overrides: map[string]RuleOverride{LSMBPFRuleID: OverrideSkip}},
			false,
		},
		{
			"default",
			&Conf{Overrides: map[string]RuleOverride{LSMBPFRuleID: OverrideDefault}},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLSMBPFForced(tc.c); got != tc.want {
				t.Errorf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestLSMBPFStatus_NotForced(t *testing.T) {
	state, msg := LSMBPFStatus(&Conf{Overrides: map[string]RuleOverride{}})
	if state != LSMBPFNotForced {
		t.Errorf("state: got %v, want LSMBPFNotForced", state)
	}
	if !strings.Contains(msg, "force") {
		t.Errorf("message should mention how to force: %q", msg)
	}
}
