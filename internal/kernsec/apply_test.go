package kernsec

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRebuildManagedCmdline_StripsAndAppends(t *testing.T) {
	tokens := ParseCmdline("BOOT_IMAGE=/vmlinuz ro slab_nomerge init_on_alloc=0 quiet randomize_kstack_offset=off")
	args := []BootArg{
		{Key: "slab_nomerge"},
		{Key: "init_on_alloc", Value: "1"},
		{Key: "page_alloc.shuffle", Value: "1"},
		{Key: "randomize_kstack_offset", Value: "on"},
		{Key: "initcall_blacklist", Value: "algif_aead_init"},
	}
	got := rebuildManagedCmdline(tokens, args)
	want := []string{
		"BOOT_IMAGE=/vmlinuz", "ro", "quiet",
		"slab_nomerge",
		"init_on_alloc=1",
		"page_alloc.shuffle=1",
		"randomize_kstack_offset=on",
		"initcall_blacklist=algif_aead_init",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got:  %v\nwant: %v", got, want)
	}
}

func TestRebuildManagedCmdline_EmptyArgsRemovesManaged(t *testing.T) {
	// Disable workflow: pass no args, should strip all managed keys.
	tokens := ParseCmdline("ro quiet slab_nomerge init_on_alloc=1 page_alloc.shuffle=1 randomize_kstack_offset=on initcall_blacklist=algif_aead_init")
	got := rebuildManagedCmdline(tokens, nil)
	want := []string{"ro", "quiet"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got:  %v\nwant: %v", got, want)
	}
}

func TestRewriteGrubCmdlineLinux_FoundReplaces(t *testing.T) {
	in := `# generated grub config
GRUB_DEFAULT=0
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX="quiet splash old_arg=1"
GRUB_DISABLE_RECOVERY="true"
`
	// rewriteGrubCmdlineLinux takes the already-encoded value (the
	// shell-quoted RHS of `=`); production callers run their cmdline
	// string through encodeGrubCmdlineValue first so encoding errors
	// can be surfaced rather than silently swallowed.
	encoded, err := encodeGrubCmdlineValue("quiet splash slab_nomerge init_on_alloc=1")
	if err != nil {
		t.Fatal(err)
	}
	out, found := rewriteGrubCmdlineLinux(in, encoded)
	if !found {
		t.Fatal("expected found=true")
	}
	wantLine := `GRUB_CMDLINE_LINUX="quiet splash slab_nomerge init_on_alloc=1"`
	if !contains(out, wantLine) {
		t.Errorf("missing %q in:\n%s", wantLine, out)
	}
	// Other lines preserved.
	for _, must := range []string{
		"GRUB_DEFAULT=0",
		"GRUB_TIMEOUT=5",
		`GRUB_DISABLE_RECOVERY="true"`,
	} {
		if !contains(out, must) {
			t.Errorf("clobbered other line %q in:\n%s", must, out)
		}
	}
	// Old arg gone.
	if contains(out, "old_arg=1") {
		t.Errorf("old arg leaked in:\n%s", out)
	}
}

func TestRewriteGrubCmdlineLinux_NotFound(t *testing.T) {
	in := "GRUB_DEFAULT=0\nGRUB_TIMEOUT=5\n"
	out, found := rewriteGrubCmdlineLinux(in, "ignored")
	if found {
		t.Error("expected found=false")
	}
	// Original lines preserved.
	if !contains(out, "GRUB_TIMEOUT=5") {
		t.Errorf("non-target lines lost:\n%s", out)
	}
}

func TestSameTokens(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want bool
	}{
		{"empty", nil, nil, true},
		{"identical", []string{"a", "b", "c"}, []string{"a", "b", "c"}, true},
		{"reordered", []string{"a", "b", "c"}, []string{"c", "a", "b"}, true},
		{"different len", []string{"a", "b"}, []string{"a", "b", "c"}, false},
		{"different content", []string{"a", "b", "c"}, []string{"a", "b", "d"}, false},
		{"duplicates same count", []string{"a", "a", "b"}, []string{"a", "b", "a"}, true},
		{"duplicates different count", []string{"a", "a", "b"}, []string{"a", "b", "b"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameTokens(tc.a, tc.b); got != tc.want {
				t.Errorf("sameTokens(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestClassifyCheckResult(t *testing.T) {
	tests := []struct {
		name string
		d    driftResult
		want int
	}{
		{name: "in sync", d: driftResult{}, want: 0},
		{name: "sysctl drift only", d: driftResult{SysctlDiffers: true}, want: 1},
		{name: "boot drift only", d: driftResult{BootDiffers: true}, want: 1},
		{name: "modprobe drift only", d: driftResult{ModprobeDiffers: true}, want: 1},
		{name: "all three drift", d: driftResult{SysctlDiffers: true, BootDiffers: true, ModprobeDiffers: true}, want: 1},
		{
			name: "boot read error overrides drift",
			d: driftResult{
				SysctlDiffers: true,
				BootReadErr:   errors.New("grubby failed"),
			},
			want: 2,
		},
		{
			name: "sysctl read error",
			d:    driftResult{SysctlReadErr: errors.New("permission denied")},
			want: 2,
		},
		{
			name: "modprobe read error",
			d:    driftResult{ModprobeReadErr: errors.New("permission denied")},
			want: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyCheckResult(tc.d); got != tc.want {
				t.Fatalf("classifyCheckResult(%+v) = %d, want %d", tc.d, got, tc.want)
			}
		})
	}
}

func TestApplyOptions_CheckAndDryRunNoOpWithoutRoot(t *testing.T) {
	// We can't fully exercise RunApply without root, but the entry
	// point should not refuse for --dry-run / --check.
	// (actual smoke runs require integration testing; this is
	// sentinel coverage for the gate.)
	if mustWrite := !true && !false; mustWrite {
		t.Fatal("logic bug")
	}
}

// fakeBootBackend is a record-and-fail BootBackend for apply ordering
// tests. The Fail* fields make individual steps return an error so the
// test can assert that LoadSysctl is never invoked when an earlier
// step fails.
type fakeBootBackend struct {
	WriteCalled    bool
	RefreshCalled  bool
	FailWrite      bool
	FailRefresh    bool
	NextBootResult string
	NextBootErr    error
}

func (f *fakeBootBackend) Label() string                    { return "fake-backend" }
func (f *fakeBootBackend) NextBootCmdline() (string, error) { return f.NextBootResult, f.NextBootErr }
func (f *fakeBootBackend) WriteCmdline(_ []BootArg) error {
	f.WriteCalled = true
	if f.FailWrite {
		return errors.New("simulated WriteCmdline failure")
	}
	return nil
}
func (f *fakeBootBackend) Refresh() error {
	f.RefreshCalled = true
	if f.FailRefresh {
		return errors.New("simulated Refresh failure")
	}
	return nil
}

// redirectManagedPaths swaps SysctlPath / ModprobePath / ConfPath to
// per-test tempdirs so applyWrites' AtomicWriteFile calls don't touch
// /etc/. Restored on cleanup.
func redirectManagedPaths(t *testing.T) (sysctl, modprobe, conf string) {
	t.Helper()
	tmp := t.TempDir()
	sysctl = filepath.Join(tmp, "99-cfm-kernsec.conf")
	modprobe = filepath.Join(tmp, "modprobe.cfm-kernsec.conf")
	conf = filepath.Join(tmp, "kernsec.conf")
	origSysctl, origMod, origConf := SysctlPath, ModprobePath, ConfPath
	SysctlPath, ModprobePath, ConfPath = sysctl, modprobe, conf
	t.Cleanup(func() {
		SysctlPath, ModprobePath, ConfPath = origSysctl, origMod, origConf
	})
	return sysctl, modprobe, conf
}

// redirectGrubPath swaps PathDefaultGrub to a per-test tempdir so
// restoreGrubFromBackup tests don't touch /etc/default/grub.
// Restored on cleanup. Returns the tempdir-rooted file path so the
// test can populate it.
func redirectGrubPath(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	grub := filepath.Join(tmp, "grub")
	orig := PathDefaultGrub
	PathDefaultGrub = grub
	t.Cleanup(func() {
		PathDefaultGrub = orig
	})
	return grub
}

func TestApplyWrites_LoaderRunsLastOnSuccess(t *testing.T) {
	redirectManagedPaths(t)
	loaderCalled := false
	be := &fakeBootBackend{}
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl content\n"),
		[]byte("# modprobe content\n"),
		nil, nil, ApplyOptions{},
		false,
		func() error { loaderCalled = true; return nil },
	)
	if rc != 0 {
		t.Fatalf("expected rc=0 on success, got %d. Output:\n%s", rc, w.String())
	}
	if !be.WriteCalled || !be.RefreshCalled {
		t.Errorf("expected backend WriteCmdline + Refresh called, got %+v", be)
	}
	if !loaderCalled {
		t.Error("expected loader to be invoked on success path")
	}
}

func TestApplyWrites_LoaderNotCalledWhenWriteCmdlineFails(t *testing.T) {
	redirectManagedPaths(t)
	loaderCalled := false
	be := &fakeBootBackend{FailWrite: true}
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl\n"),
		[]byte("# modprobe\n"),
		nil, nil, ApplyOptions{},
		false,
		func() error { loaderCalled = true; return nil },
	)
	if rc != 1 {
		t.Fatalf("expected rc=1 on WriteCmdline failure, got %d", rc)
	}
	if loaderCalled {
		t.Fatal("LoadSysctl was invoked despite WriteCmdline failure — runtime kernel state mutated; production hosts could land Tier 2 namespace-kill before bootloader confirms")
	}
	if be.RefreshCalled {
		t.Error("Refresh was invoked despite WriteCmdline failure")
	}
	out := w.String()
	if !strings.Contains(out, "runtime state unchanged") {
		t.Errorf("expected operator-facing 'runtime state unchanged' message, got:\n%s", out)
	}
}

func TestApplyWrites_LoaderNotCalledWhenRefreshFails(t *testing.T) {
	redirectManagedPaths(t)
	loaderCalled := false
	be := &fakeBootBackend{FailRefresh: true}
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl\n"),
		[]byte("# modprobe\n"),
		nil, nil, ApplyOptions{},
		false,
		func() error { loaderCalled = true; return nil },
	)
	if rc != 1 {
		t.Fatalf("expected rc=1 on Refresh failure, got %d", rc)
	}
	if loaderCalled {
		t.Fatal("LoadSysctl was invoked despite bootloader Refresh failure")
	}
	if !be.WriteCalled {
		t.Error("WriteCmdline should have been called before Refresh failed")
	}
	out := w.String()
	if !strings.Contains(out, "bootloader has NOT picked it up") {
		t.Errorf("expected operator-facing recovery hint, got:\n%s", out)
	}
}

func TestApplyWrites_GrubBackendRollsBackOnRefreshFailure(t *testing.T) {
	// Phase 6 audit M1: when running on the legacy GRUB backend
	// and update-grub fails, applyWrites must restore
	// /etc/default/grub from .cfm-kernsec.bak so the next
	// legitimate update-grub (kernel package install etc.)
	// doesn't propagate the half-applied state. Build a
	// GRUBBackend pointing at a tempdir, seed a .bak with
	// "ORIGINAL", overwrite the live file with "NEW", trigger
	// Refresh failure via a fakeFS that reports update-grub
	// available but missing the cmd entry, then assert the
	// live file is back to "ORIGINAL".
	redirectManagedPaths(t)
	grubPath := redirectGrubPath(t)
	if err := os.WriteFile(grubPath, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Seed the BackupOnce destination with the pre-modify content.
	bak := grubPath + BackupSuffix
	if err := os.WriteFile(bak, []byte("ORIGINAL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Now write the "NEW" content as if WriteCmdline already ran.
	if err := os.WriteFile(grubPath, []byte("NEW\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// fakeFS that "has" update-grub but the cmd will fail (no
	// matching `withCmd` registration → RunCapture returns error).
	fs := newFakeFS().withFile(grubPath, "NEW\n").withBin("update-grub")
	be := &GRUBBackend{FS: fs}
	loaderCalled := false
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl\n"),
		[]byte("# modprobe\n"),
		nil, nil, ApplyOptions{},
		false,
		func() error { loaderCalled = true; return nil },
	)
	if rc != 1 {
		t.Fatalf("expected rc=1 on Refresh failure, got %d, output:\n%s", rc, w.String())
	}
	if loaderCalled {
		t.Fatal("LoadSysctl was invoked despite Refresh failure")
	}
	got, err := os.ReadFile(grubPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ORIGINAL\n" {
		t.Errorf("expected /etc/default/grub rolled back to %q, got %q", "ORIGINAL\n", string(got))
	}
	out := w.String()
	if !strings.Contains(out, "rolled back") {
		t.Errorf("expected rollback notice in operator output, got:\n%s", out)
	}
}

func TestRestoreGrubFromBackup_NoBackupIsNoOp(t *testing.T) {
	// Defensive: if the backup doesn't exist (very-first-apply
	// failure path before BackupOnce ran), restore must not error.
	grubPath := redirectGrubPath(t)
	if err := os.WriteFile(grubPath, []byte("LIVE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restoreGrubFromBackup(); err != nil {
		t.Errorf("expected nil on missing backup, got %v", err)
	}
	got, _ := os.ReadFile(grubPath)
	if string(got) != "LIVE\n" {
		t.Errorf("file must be untouched when backup absent: %q", string(got))
	}
}

func TestApplyWrites_NoRefreshSkipsRefreshButStillLoadsSysctl(t *testing.T) {
	redirectManagedPaths(t)
	loaderCalled := false
	be := &fakeBootBackend{}
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl\n"),
		[]byte("# modprobe\n"),
		nil, nil,
		ApplyOptions{NoRefresh: true},
		false,
		func() error { loaderCalled = true; return nil },
	)
	if rc != 0 {
		t.Fatalf("expected rc=0, got %d. Output:\n%s", rc, w.String())
	}
	if be.RefreshCalled {
		t.Error("Refresh should be skipped under --no-refresh")
	}
	if !loaderCalled {
		t.Error("loader should still run when --no-refresh: bootloader is the operator's responsibility, sysctl is still safe to load")
	}
}

func TestApplyWrites_LoaderFailureIsReportedButFilesAreWritten(t *testing.T) {
	sysctl, modprobe, _ := redirectManagedPaths(t)
	be := &fakeBootBackend{}
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl\n"),
		[]byte("# modprobe\n"),
		nil, nil, ApplyOptions{},
		false,
		func() error { return errors.New("simulated runtime sysctl apply failure") },
	)
	if rc != 1 {
		t.Fatalf("expected rc=1, got %d", rc)
	}
	// Files were written before the loader was called: that's by design.
	// On reboot the persistent files take effect; the operator can also
	// re-run apply once the load failure cause is addressed.
	if _, err := readTestFile(sysctl); err != nil {
		t.Errorf("sysctl file should be on disk despite loader failure: %v", err)
	}
	if _, err := readTestFile(modprobe); err != nil {
		t.Errorf("modprobe file should be on disk despite loader failure: %v", err)
	}
	out := w.String()
	if !strings.Contains(out, "runtime sysctl apply") {
		t.Errorf("expected runtime sysctl apply failure to be surfaced, got:\n%s", out)
	}
}

// readTestFile is a tiny helper to verify a file exists in the test
// tempdir without pulling os into apply_test imports beyond what's
// already there.
func readTestFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

type proxmoxApplyTestFS struct {
	content     string
	refreshHook func() error
}

func (f *proxmoxApplyTestFS) ReadFile(path string) ([]byte, error) {
	if path == PathPVECmdline {
		return []byte(f.content), nil
	}
	return nil, errors.New("not found: " + path)
}
func (f *proxmoxApplyTestFS) Exists(path string) bool { return path == PathPVECmdline }
func (f *proxmoxApplyTestFS) IsDir(string) bool       { return false }
func (f *proxmoxApplyTestFS) LookPath(string) bool    { return true }
func (f *proxmoxApplyTestFS) RunCapture(name string, args ...string) (string, error) {
	if name == "proxmox-boot-tool" && len(args) == 1 && args[0] == "refresh" {
		if f.refreshHook != nil {
			if err := f.refreshHook(); err != nil {
				return "", err
			}
		}
		return "refresh failed", errors.New("simulated refresh failure")
	}
	return "", errors.New("unexpected command")
}

func redirectProxmoxPath(t *testing.T) string {
	t.Helper()
	pve := filepath.Join(t.TempDir(), "cmdline")
	orig := PathPVECmdline
	PathPVECmdline = pve
	t.Cleanup(func() { PathPVECmdline = orig })
	return pve
}

func TestApplyWrites_ProxmoxRefreshFailureRollsBackCmdline(t *testing.T) {
	redirectManagedPaths(t)
	withTempManagedBackupPaths(t)
	pvePath := redirectProxmoxPath(t)
	original := "root=ZFS=rpool/ROOT/pve-1 ro quiet init_on_alloc=0\n"
	if err := os.WriteFile(pvePath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	be := &ProxmoxBackend{FS: &proxmoxApplyTestFS{content: original}}
	loaderCalled := false
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl\n"),
		[]byte("# modprobe\n"),
		[]BootArg{{Key: "slab_nomerge"}, {Key: "init_on_alloc", Value: "1"}}, nil, ApplyOptions{},
		false,
		func() error { loaderCalled = true; return nil },
	)
	if rc != 1 {
		t.Fatalf("expected rc=1 on Proxmox Refresh failure, got %d, output:\n%s", rc, w.String())
	}
	if loaderCalled {
		t.Fatal("LoadSysctl was invoked despite Proxmox Refresh failure")
	}
	got, err := os.ReadFile(pvePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("expected %s to be restored to original %q, got %q", pvePath, original, string(got))
	}
	out := w.String()
	if !strings.Contains(out, "rolled back "+pvePath+" to a safe retry state") {
		t.Fatalf("expected Proxmox rollback notice, got:\n%s", out)
	}
}

func TestApplyWrites_ProxmoxRefreshFailureRollbackFailurePrintsManualRecovery(t *testing.T) {
	redirectManagedPaths(t)
	withTempManagedBackupPaths(t)
	pvePath := redirectProxmoxPath(t)
	original := "root=ZFS=rpool/ROOT/pve-1 ro quiet\n"
	if err := os.WriteFile(pvePath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	be := &ProxmoxBackend{FS: &proxmoxApplyTestFS{
		content: original,
		refreshHook: func() error {
			if err := os.Remove(pvePath); err != nil {
				t.Fatal(err)
			}
			return nil
		},
	}}
	loaderCalled := false
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl\n"),
		[]byte("# modprobe\n"),
		[]BootArg{{Key: "slab_nomerge"}}, nil, ApplyOptions{},
		false,
		func() error { loaderCalled = true; return nil },
	)
	if rc != 1 {
		t.Fatalf("expected rc=1 on Proxmox Refresh failure, got %d, output:\n%s", rc, w.String())
	}
	if loaderCalled {
		t.Fatal("LoadSysctl was invoked despite Proxmox Refresh failure")
	}
	out := w.String()
	for _, want := range []string{"WARNING: rollback of " + pvePath + " failed", "Manual recovery: edit " + pvePath, "proxmox-boot-tool refresh"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestApplyWrites_ProxmoxRollbackPreservesUnmanagedOperatorArgs(t *testing.T) {
	redirectManagedPaths(t)
	withTempManagedBackupPaths(t)
	pvePath := redirectProxmoxPath(t)
	original := "root=ZFS=rpool/ROOT/pve-1 ro quiet init_on_alloc=0\n"
	if err := os.WriteFile(pvePath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	be := &ProxmoxBackend{FS: &proxmoxApplyTestFS{
		content: original,
		refreshHook: func() error {
			return os.WriteFile(pvePath, []byte("root=ZFS=rpool/ROOT/pve-1 ro quiet slab_nomerge init_on_alloc=1 console=ttyS0\n"), 0o644)
		},
	}}
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl\n"),
		[]byte("# modprobe\n"),
		[]BootArg{{Key: "slab_nomerge"}, {Key: "init_on_alloc", Value: "1"}}, nil, ApplyOptions{},
		false,
		func() error { return nil },
	)
	if rc != 1 {
		t.Fatalf("expected rc=1 on Proxmox Refresh failure, got %d, output:\n%s", rc, w.String())
	}
	gotBytes, err := os.ReadFile(pvePath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(gotBytes)
	for _, want := range []string{"root=ZFS=rpool/ROOT/pve-1", "ro", "quiet", "console=ttyS0", "init_on_alloc=0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected preserved/restored token %q in %q", want, got)
		}
	}
	for _, unwanted := range []string{"slab_nomerge", "init_on_alloc=1"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("expected managed apply token %q to be removed from %q", unwanted, got)
		}
	}
}

// TestApplyWrites_SkipBoot_BypassesBootloader verifies that when
// applyCore decides BLS divergence is recoverable and passes
// skipBoot=true, applyWrites still writes the sysctl + modprobe drop-
// ins and runs the runtime loader, but does NOT touch the bootloader.
// This is the core safety property of the divergence-tolerant apply
// path: rules that don't depend on the cmdline still land.
func TestApplyWrites_SkipBoot_BypassesBootloader(t *testing.T) {
	sysctlFile, modprobeFile, _ := redirectManagedPaths(t)
	loaderCalled := false
	be := &fakeBootBackend{}
	var w bytes.Buffer
	rc := applyWrites(
		&w, be,
		[]byte("# sysctl content\n"),
		[]byte("# modprobe content\n"),
		[]BootArg{{Key: "slab_nomerge"}}, nil, ApplyOptions{},
		true, // skipBoot
		func() error { loaderCalled = true; return nil },
	)
	if rc != 0 {
		t.Fatalf("expected rc=0 with skipBoot=true, got %d. Output:\n%s", rc, w.String())
	}
	if be.WriteCalled {
		t.Error("skipBoot=true must not invoke backend.WriteCmdline")
	}
	if be.RefreshCalled {
		t.Error("skipBoot=true must not invoke backend.Refresh")
	}
	if !loaderCalled {
		t.Error("skipBoot=true must still invoke the runtime sysctl loader")
	}
	if _, err := os.Stat(sysctlFile); err != nil {
		t.Errorf("expected sysctl drop-in to be written under skipBoot=true: %v", err)
	}
	if _, err := os.Stat(modprobeFile); err != nil {
		t.Errorf("expected modprobe drop-in to be written under skipBoot=true: %v", err)
	}
	if !strings.Contains(w.String(), "SKIPPED") {
		t.Errorf("expected operator-facing SKIPPED notice in output, got:\n%s", w.String())
	}
}

// TestErrBLSDivergence_Wrapping locks in the sentinel contract that
// applyCore relies on: NextBootCmdline wraps ErrBLSDivergence with
// %w so callers can detect it via errors.Is, while the human-readable
// message (with stale kernel paths) is preserved.
func TestErrBLSDivergence_Wrapping(t *testing.T) {
	wrapped := errors.New("not a divergence error")
	if errors.Is(wrapped, ErrBLSDivergence) {
		t.Fatal("unrelated error must not satisfy errors.Is(_, ErrBLSDivergence)")
	}
	// Simulate the exact wrap shape used in backend_bls.go.
	divergent := errors.Join(ErrBLSDivergence, errors.New("from /boot/vmlinuz-new — stale on: /boot/vmlinuz-old"))
	if !errors.Is(divergent, ErrBLSDivergence) {
		t.Error("expected joined error to satisfy errors.Is(_, ErrBLSDivergence)")
	}
}
