package kernsec

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRunPreview_TierOverrideZeroResolvesAsTierZero(t *testing.T) {
	// Operator passes `--tier 0` (TierOverride=true, Tier=0) — every
	// rule must render as OFF (decision SkipByTier). Previously the
	// guard `if opts.Tier != 0` treated 0 as "no override" so the
	// operator couldn't preview "what would `disable` look like?".
	withTempConfPath(t)
	// Write a tier=2 conf so opts.Tier=0 is genuinely overriding.
	c := &Conf{Tier: Tier2, Overrides: map[string]RuleOverride{}}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	rc := RunPreview(&w, PreviewOptions{TierOverride: true, Tier: 0})
	if rc != 0 {
		t.Fatalf("expected rc=0 from preview, got %d. Output:\n%s", rc, w.String())
	}
	out := w.String()
	// Banner shows tier=0 (the override).
	if !strings.Contains(out, "Tier:     0") {
		t.Errorf("expected banner to show overridden tier=0, got:\n%s", out)
	}
	// And every rule renders as a SKIP-TIER decision.
	if !strings.Contains(out, "SKIP-TIER") {
		t.Errorf("expected SKIP-TIER decisions on every rule, got:\n%s", out)
	}
	// Critically: no Apply rows when the override is tier=0.
	if strings.Contains(out, " APPLY  ") {
		t.Errorf("tier=0 override should produce zero Apply rows, got:\n%s", out)
	}
}

func TestRunPreview_NoTierOverrideHonorsConf(t *testing.T) {
	// Without TierOverride, conf.Tier (set to Tier1 here) is honored.
	// Tier 1 rules should still resolve to Apply.
	withTempConfPath(t)
	c := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	rc := RunPreview(&w, PreviewOptions{}) // TierOverride=false, Tier=0
	if rc != 0 {
		t.Fatalf("rc=%d: %s", rc, w.String())
	}
	out := w.String()
	if !strings.Contains(out, "Tier:     1") {
		t.Errorf("expected banner to show conf tier=1 (no override), got:\n%s", out)
	}
	// At least some rule should resolve to APPLY at tier=1.
	if !strings.Contains(out, "APPLY") {
		t.Errorf("tier=1 should produce Apply rows, got:\n%s", out)
	}
}

func TestRunPreview_DryRunPlanDoesNotWriteAndShowsExactMutations(t *testing.T) {
	withTempConfPath(t)
	grubFile := t.TempDir() + "/grub"
	origDefaultGrub := PathDefaultGrub
	origPreviewFS := previewFSFactory
	origGrubSnap, origPVESnap := GRUBManagedBackupPath, ProxmoxManagedBackupPath
	PathDefaultGrub = grubFile
	GRUBManagedBackupPath = t.TempDir() + "/grub-managed.json"
	ProxmoxManagedBackupPath = t.TempDir() + "/pve-managed.json"
	defer func() {
		PathDefaultGrub = origDefaultGrub
		previewFSFactory = origPreviewFS
		GRUBManagedBackupPath = origGrubSnap
		ProxmoxManagedBackupPath = origPVESnap
	}()

	conf := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	if err := WriteConf(conf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SysctlPath, []byte("operator sysctl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ModprobePath, []byte("operator modprobe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	grubContent := "GRUB_CMDLINE_LINUX=\"root=/dev/sda1 ro init_on_alloc=0 console=ttyS0\"\n"
	if err := os.WriteFile(PathDefaultGrub, []byte(grubContent), 0o644); err != nil {
		t.Fatal(err)
	}

	fs := newFakeFS().withBin("update-grub").withFile(PathDefaultGrub, grubContent)
	previewFSFactory = func() FS { return fs }

	var w bytes.Buffer
	rc := RunPreview(&w, PreviewOptions{OnlyApply: true})
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d. Output:\n%s", rc, w.String())
	}
	out := w.String()
	for _, want := range []string{
		"[Apply dry-run plan]",
		"sysctl target:   " + SysctlPath,
		"modprobe target: " + ModprobePath,
		"boot target:     " + PathDefaultGrub,
		"current: root=/dev/sda1 ro init_on_alloc=0 console=ttyS0",
		"desired: root=/dev/sda1 ro console=ttyS0 slab_nomerge init_on_alloc=1 page_alloc.shuffle=1 randomize_kstack_offset=on initcall_blacklist=algif_aead_init kfence.sample_interval=100 tsx=off",
		SysctlPath + BackupSuffix,
		ModprobePath + BackupSuffix,
		PathDefaultGrub + BackupSuffix,
		GRUBManagedBackupPath,
		"update-grub",
		"sysctl: would write",
		"modprobe: would write",
		"boot args: would write",
		"# Managed by cfm kernsec — do not edit by hand.",
		"blacklist dccp",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("preview output missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"init_on_alloc=0 slab_nomerge", "operator sysctl.cfm-kernsec"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("preview output contained unexpected %q:\n%s", unwanted, out)
		}
	}

	assertFileContent(t, SysctlPath, "operator sysctl\n")
	assertFileContent(t, ModprobePath, "operator modprobe\n")
	assertFileContent(t, PathDefaultGrub, grubContent)
	for _, p := range []string{SysctlPath + BackupSuffix, ModprobePath + BackupSuffix, PathDefaultGrub + BackupSuffix, GRUBManagedBackupPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("preview must not create %s (stat err=%v)", p, err)
		}
	}
}

func TestRunPreview_ReadErrorReturnsNonZero(t *testing.T) {
	withTempConfPath(t)
	origPreviewFS := previewFSFactory
	origDefaultGrub := PathDefaultGrub
	PathDefaultGrub = t.TempDir() + "/grub"
	defer func() {
		previewFSFactory = origPreviewFS
		PathDefaultGrub = origDefaultGrub
	}()
	if err := WriteConf(&Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}); err != nil {
		t.Fatal(err)
	}
	previewFSFactory = func() FS {
		return newFakeFS().withFile(PathDefaultGrub, "")
	}
	// Delete the fake content after Exists succeeds by using a custom FS whose
	// ReadFile reports the bootloader read failure preview must surface.
	previewFSFactory = func() FS { return previewReadErrorFS{path: PathDefaultGrub} }

	var w bytes.Buffer
	rc := RunPreview(&w, PreviewOptions{})
	if rc == 0 {
		t.Fatalf("expected non-zero rc on read error. Output:\n%s", w.String())
	}
	if !strings.Contains(w.String(), "boot read error: read current cmdline: read current cmdline failed") {
		t.Fatalf("expected boot read error in output, got:\n%s", w.String())
	}
}

type previewReadErrorFS struct{ path string }

func (p previewReadErrorFS) ReadFile(path string) ([]byte, error) {
	if path == p.path {
		return nil, errors.New("read current cmdline failed")
	}
	return nil, errors.New("not found")
}
func (p previewReadErrorFS) Exists(path string) bool   { return path == p.path }
func (p previewReadErrorFS) IsDir(path string) bool    { return false }
func (p previewReadErrorFS) LookPath(name string) bool { return name == "update-grub" }
func (p previewReadErrorFS) RunCapture(name string, args ...string) (string, error) {
	return "", errors.New("unexpected command")
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s changed: got %q want %q", path, string(got), want)
	}
}
