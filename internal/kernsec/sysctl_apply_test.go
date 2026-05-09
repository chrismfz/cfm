package kernsec

import (
	"strings"
	"testing"
)

func TestRenderSysctlFile_Empty(t *testing.T) {
	got := string(RenderSysctlFile(nil))
	if !strings.Contains(got, "# Managed by cfm kernsec") {
		t.Errorf("missing header in:\n%s", got)
	}
	if !strings.Contains(got, "no sysctl rules selected") {
		t.Errorf("missing empty-set marker in:\n%s", got)
	}
}

func TestRenderSysctlFile_HappyPath(t *testing.T) {
	rules := []SysctlRule{
		{Key: "kernel.kptr_restrict", Value: "2"},
		{Key: "fs.protected_hardlinks", Value: "1"},
	}
	got := string(RenderSysctlFile(rules))
	for _, want := range []string{
		"# Managed by cfm kernsec",
		"# Generated from /etc/cfm/kernsec.conf",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// At least one of the rules will exist on this host (kptr_restrict
	// has been mainline since 2.6.38). The rest depends on the runtime
	// kernel — we only assert the header structure.
}

func TestRenderSysctlFile_SkippedRulesAreCommented(t *testing.T) {
	rules := []SysctlRule{
		{Key: "kernel.this.does.not.exist.zzz", Value: "1"},
	}
	got := string(RenderSysctlFile(rules))
	if !strings.Contains(got, "# skipped") {
		t.Errorf("missing skip line for nonexistent key in:\n%s", got)
	}
	// No live (uncommented) line should set the key.
	for _, line := range strings.Split(got, "\n") {
		ln := strings.TrimSpace(line)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "kernel.this.does.not.exist.zzz") {
			t.Errorf("nonexistent key emitted as live rule line %q in:\n%s", ln, got)
		}
	}
}
