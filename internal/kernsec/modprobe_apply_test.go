package kernsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTempModprobePath redirects ModprobePath to a per-test temp file.
func withTempModprobePath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig := ModprobePath
	ModprobePath = filepath.Join(dir, "cfm-kernsec.conf")
	t.Cleanup(func() {
		ModprobePath = orig
	})
}

func TestRenderModprobeFile_Empty(t *testing.T) {
	got := string(RenderModprobeFile(nil))
	if !strings.Contains(got, "# Managed by cfm kernsec") {
		t.Errorf("missing header in:\n%s", got)
	}
	if !strings.Contains(got, "no module rules") {
		t.Errorf("missing empty-set marker in:\n%s", got)
	}
}

func TestRenderModprobeFile_HappyPath(t *testing.T) {
	rules := []ModuleRule{
		{Name: "ksmbd", Group: "modules.recent_cves"},
		{Name: "n_hdlc", Group: "modules.recent_cves"},
		{Name: "dccp", Group: "modules.net.legacy"},
	}
	got := string(RenderModprobeFile(rules))

	// Each rule emits both the blacklist line and the install /bin/false line.
	for _, name := range []string{"ksmbd", "n_hdlc", "dccp"} {
		if !strings.Contains(got, "blacklist "+name+"\n") {
			t.Errorf("missing `blacklist %s` line in:\n%s", name, got)
		}
		if !strings.Contains(got, "install "+name+" /bin/false\n") {
			t.Errorf("missing `install %s /bin/false` line in:\n%s", name, got)
		}
	}

	// Group separator comments appear when groups change.
	if !strings.Contains(got, "# Group: modules.recent_cves") {
		t.Errorf("missing group header for recent_cves in:\n%s", got)
	}
	if !strings.Contains(got, "# Group: modules.net.legacy") {
		t.Errorf("missing group header for net.legacy in:\n%s", got)
	}
}

func TestRenderModprobeFile_Idempotent(t *testing.T) {
	rules := Tier1Modules
	a := RenderModprobeFile(rules)
	b := RenderModprobeFile(rules)
	if string(a) != string(b) {
		t.Fatal("RenderModprobeFile not deterministic")
	}
}

func TestParseManagedBlacklist(t *testing.T) {
	withTempModprobePath(t)

	content := `# Managed by cfm kernsec — do not edit by hand.
# Group: modules.recent_cves
blacklist ksmbd
install ksmbd /bin/false
blacklist n_hdlc
install n_hdlc /bin/false

# Group: modules.net.legacy
blacklist dccp
install dccp /bin/false
`
	if err := os.WriteFile(ModprobePath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := ParseManagedBlacklist()
	for _, name := range []string{"ksmbd", "n_hdlc", "dccp"} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing %q in parsed blacklist: %v", name, got)
		}
	}
	// Install lines must NOT leak into the blacklist set.
	if _, ok := got["/bin/false"]; ok {
		t.Errorf("install line leaked into blacklist set: %v", got)
	}
	// Comments must NOT contribute to the set.
	if len(got) != 3 {
		t.Errorf("expected 3 entries, got %d: %v", len(got), got)
	}
}

func TestParseManagedBlacklist_MissingFile(t *testing.T) {
	withTempModprobePath(t)
	// Don't create the file; empty result expected.
	got := ParseManagedBlacklist()
	if len(got) != 0 {
		t.Errorf("expected empty set on missing file, got %v", got)
	}
}

func TestModuleRowState(t *testing.T) {
	tests := []struct {
		name                                 string
		blacklisted, loaded, presentOnKernel bool
		want                                 RuleState
	}{
		{name: "blacklist effective", blacklisted: true, loaded: false, presentOnKernel: true, want: StateOK},
		{name: "blacklist effective absent kernel", blacklisted: true, loaded: false, presentOnKernel: false, want: StateOK},
		{name: "blacklisted but loaded", blacklisted: true, loaded: true, presentOnKernel: true, want: StateLOADED},
		{name: "missing on this kernel", blacklisted: false, loaded: false, presentOnKernel: false, want: StateSKIP},
		{name: "not blacklisted yet", blacklisted: false, loaded: false, presentOnKernel: true, want: StateMISSING},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := moduleRowState(tc.blacklisted, tc.loaded, tc.presentOnKernel)
			if got != tc.want {
				t.Errorf("moduleRowState(%v,%v,%v) = %v, want %v",
					tc.blacklisted, tc.loaded, tc.presentOnKernel, got, tc.want)
			}
		})
	}
}

func TestWriteModprobeFile_AtomicWithBackup(t *testing.T) {
	withTempModprobePath(t)

	// First write — no .bak should be created (no prior file).
	first := []byte("# v1\nblacklist ksmbd\ninstall ksmbd /bin/false\n")
	if err := WriteModprobeFile(first); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(ModprobePath); string(got) != string(first) {
		t.Errorf("first write content mismatch")
	}
	if _, err := os.Stat(ModprobePath + BackupSuffix); !os.IsNotExist(err) {
		t.Errorf("backup created on first write — should not exist")
	}

	// Second write — .bak should now contain the v1 content.
	second := []byte("# v2\nblacklist n_hdlc\ninstall n_hdlc /bin/false\n")
	if err := WriteModprobeFile(second); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(ModprobePath); string(got) != string(second) {
		t.Errorf("second write content mismatch")
	}
	bak, err := os.ReadFile(ModprobePath + BackupSuffix)
	if err != nil {
		t.Fatalf("backup not created on second write: %v", err)
	}
	if string(bak) != string(first) {
		t.Errorf("backup has wrong content:\n  got:  %s\n  want: %s", bak, first)
	}

	// Third write — .bak must NOT be overwritten (one-shot).
	third := []byte("# v3\n")
	if err := WriteModprobeFile(third); err != nil {
		t.Fatal(err)
	}
	bak2, _ := os.ReadFile(ModprobePath + BackupSuffix)
	if string(bak2) != string(first) {
		t.Errorf("backup overwritten on third write — should be one-shot:\n  got:  %s\n  want: %s",
			bak2, first)
	}
}

func TestLoadedAndManaged_NoLoadedNoOutput(t *testing.T) {
	// Both modules set to clearly-not-real-loaded names so /proc/modules
	// won't ever match. Output should be empty.
	got := loadedAndManaged([]ModuleRule{
		{Name: "this_module_does_not_exist_zzz"},
		{Name: "another_fake_module_qqq"},
	})
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestModprobeDriftCheck_AbsentFileDiffers(t *testing.T) {
	withTempModprobePath(t)
	// File doesn't exist; any non-empty desired content is drift.
	differs, err := modprobeDriftCheck([]byte("# managed\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !differs {
		t.Error("expected drift on absent file")
	}
}

func TestModprobeDriftCheck_MatchingByteEqual(t *testing.T) {
	withTempModprobePath(t)
	content := []byte("# managed\nblacklist ksmbd\n")
	if err := os.WriteFile(ModprobePath, content, 0o644); err != nil {
		t.Fatal(err)
	}
	differs, err := modprobeDriftCheck(content)
	if err != nil {
		t.Fatal(err)
	}
	if differs {
		t.Error("byte-equal content reported as drift")
	}
}

func TestModprobeDriftCheck_DifferentBytesDiffer(t *testing.T) {
	withTempModprobePath(t)
	if err := os.WriteFile(ModprobePath, []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	differs, err := modprobeDriftCheck([]byte("# new\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !differs {
		t.Error("different content not detected as drift")
	}
}
