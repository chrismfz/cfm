package kernsec

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestModulePresentOnKernel_UsesCacheNotPerModuleWalk(t *testing.T) {
	// Build a fixture /lib/modules tree with exactly two modules, then
	// point the cache at it. ModulePresentOnKernel should hit the
	// cache after the first call, not re-walk per name.
	root := t.TempDir()
	for _, p := range []string{
		filepath.Join(root, "kernel/drivers/net/legacy/dccp.ko"),
		filepath.Join(root, "kernel/fs/cramfs/cramfs.ko.xz"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	origRoot := moduleFileCacheRoot
	moduleFileCacheRoot = func() string { return root }
	t.Cleanup(func() {
		moduleFileCacheRoot = origRoot
		ResetModuleFileCache()
	})
	ResetModuleFileCache()

	if !ModulePresentOnKernel("dccp") {
		t.Error("dccp.ko should be detected (lives at kernel/drivers/net/legacy/)")
	}
	if !ModulePresentOnKernel("cramfs") {
		t.Error("cramfs.ko.xz should be detected (lives at kernel/fs/cramfs/)")
	}
	if ModulePresentOnKernel("not_present") {
		t.Error("not_present should not be detected — fixture has only dccp + cramfs")
	}

	// Sanity: rebuild the cache with a different fixture and the
	// same calls must reflect the new state.
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "kernel/fs/cramfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Re-create cramfs only.
	if err := os.WriteFile(filepath.Join(root, "kernel/fs/cramfs/cramfs.ko.xz"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ResetModuleFileCache()
	if ModulePresentOnKernel("dccp") {
		t.Error("dccp removed from fixture; cache reset should reflect it")
	}
	if !ModulePresentOnKernel("cramfs") {
		t.Error("cramfs still in fixture")
	}
}

func TestWriteModprobeFile_PreservesOperatorEdits(t *testing.T) {
	withTempModprobePath(t)

	// First write produces a clean managed file.
	managed := []byte("# Managed by cfm kernsec — do not edit by hand.\nblacklist ksmbd\ninstall ksmbd /bin/false\n")
	if err := WriteModprobeFile(io.Discard, managed); err != nil {
		t.Fatal(err)
	}

	// Operator hand-edits the file: appends an extra `blacklist nfc`
	// (a real module rule, but added directly rather than via tier
	// upgrade) plus an unrelated comment.
	operatorEdit := append([]byte{}, managed...)
	operatorEdit = append(operatorEdit, []byte("# operator-added\nblacklist nfc\ninstall nfc /bin/false\n")...)
	if err := os.WriteFile(ModprobePath, operatorEdit, 0o644); err != nil {
		t.Fatal(err)
	}

	// Pin a deterministic timestamp so we can assert the backup name.
	origNow := nowFunc
	nowFunc = func() time.Time {
		return time.Date(2026, 5, 10, 14, 5, 30, 0, time.UTC)
	}
	t.Cleanup(func() { nowFunc = origNow })

	// Run apply with the same managed content. The audit must detect
	// the operator-added lines, write a per-run backup, and warn.
	var w bytes.Buffer
	if err := WriteModprobeFile(&w, managed); err != nil {
		t.Fatal(err)
	}

	// 1. Per-run backup file exists with the operator-edited content.
	wantBackup := ModprobePath + ".cfm-kernsec.bak.20260510T140530Z"
	bakContent, err := os.ReadFile(wantBackup)
	if err != nil {
		t.Fatalf("per-run backup missing: %v", err)
	}
	if !bytes.Equal(bakContent, operatorEdit) {
		t.Errorf("per-run backup has wrong content")
	}

	// 2. Managed file overwritten with rendered content (idempotency).
	now, _ := os.ReadFile(ModprobePath)
	if !bytes.Equal(now, managed) {
		t.Errorf("managed file not overwritten with rendered content")
	}

	// 3. Operator saw a warning naming the extra lines.
	out := w.String()
	if !strings.Contains(out, "unmanaged line") {
		t.Errorf("expected unmanaged-line warning, got:\n%s", out)
	}
	if !strings.Contains(out, "blacklist nfc") {
		t.Errorf("warning should name the operator-added line:\n%s", out)
	}
	if !strings.Contains(out, wantBackup) {
		t.Errorf("warning should point at the backup path:\n%s", out)
	}
}

func TestWriteModprobeFile_NoBackupWhenNoOperatorEdits(t *testing.T) {
	withTempModprobePath(t)

	// First write of the managed file.
	managed := []byte("# Managed by cfm kernsec — do not edit by hand.\nblacklist ksmbd\ninstall ksmbd /bin/false\n")
	if err := WriteModprobeFile(io.Discard, managed); err != nil {
		t.Fatal(err)
	}

	// Pin time so any spurious backup would be detectable.
	origNow := nowFunc
	nowFunc = func() time.Time {
		return time.Date(2026, 5, 10, 14, 5, 30, 0, time.UTC)
	}
	t.Cleanup(func() { nowFunc = origNow })

	// Re-render same content (idempotent apply). No per-run backup
	// should be created — there are no operator edits to preserve.
	var w bytes.Buffer
	if err := WriteModprobeFile(&w, managed); err != nil {
		t.Fatal(err)
	}

	wantBackup := ModprobePath + ".cfm-kernsec.bak.20260510T140530Z"
	if _, err := os.Stat(wantBackup); !os.IsNotExist(err) {
		t.Errorf("per-run backup created without operator edits: %v", err)
	}
	if w.String() != "" {
		t.Errorf("expected no warnings, got:\n%s", w.String())
	}
}

func TestWriteModprobeFile_AtomicWithBackup(t *testing.T) {
	withTempModprobePath(t)

	// First write — no .bak should be created (no prior file).
	first := []byte("# v1\nblacklist ksmbd\ninstall ksmbd /bin/false\n")
	if err := WriteModprobeFile(io.Discard, first); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(ModprobePath); string(got) != string(first) {
		t.Errorf("first write content mismatch")
	}
	if _, err := os.Stat(ModprobePath + BackupSuffix); !os.IsNotExist(err) {
		t.Errorf("backup created on first write — should not exist")
	}

	// Second write — same content as first (just whitespace difference)
	// → .bak should still be created (one-shot first-touch backup) but
	// no per-run timestamped backup since no operator edits.
	if err := WriteModprobeFile(io.Discard, first); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(ModprobePath + BackupSuffix)
	if err != nil {
		t.Fatalf("backup not created on second write: %v", err)
	}
	if string(bak) != string(first) {
		t.Errorf("backup has wrong content:\n  got:  %s\n  want: %s", bak, first)
	}

	// Third write — different content. .bak (one-shot) must NOT be
	// overwritten.
	third := []byte("# v3\n")
	if err := WriteModprobeFile(io.Discard, third); err != nil {
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
