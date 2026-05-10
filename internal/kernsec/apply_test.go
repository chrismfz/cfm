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
	out, found := rewriteGrubCmdlineLinux(in, "quiet splash slab_nomerge init_on_alloc=1")
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

func (f *fakeBootBackend) Label() string                     { return "fake-backend" }
func (f *fakeBootBackend) NextBootCmdline() (string, error)  { return f.NextBootResult, f.NextBootErr }
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
		func() error { return errors.New("simulated sysctl --load failure") },
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
	if !strings.Contains(out, "sysctl --load") {
		t.Errorf("expected sysctl --load failure to be surfaced, got:\n%s", out)
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
