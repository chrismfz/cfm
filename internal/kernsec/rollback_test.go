package kernsec

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const blsInfoAllMultipleUnmanaged = `index=0
kernel="/boot/vmlinuz-6.8.0"
args="ro crashkernel=auto transparent_hugepage=madvise slab_nomerge init_on_alloc=1"

index=1
kernel="/boot/vmlinuz-6.7.0"
args="ro crashkernel=2G-:512M transparent_hugepage=never slab_nomerge page_alloc.shuffle=1"

index=2
kernel="/boot/vmlinuz-0-rescue-abc123"
args="ro crashkernel=auto slab_nomerge"
`

func withTempBLSBackupPath(t *testing.T) string {
	t.Helper()
	orig := BLSBackupPath
	BLSBackupPath = t.TempDir() + "/bls-bak"
	t.Cleanup(func() { BLSBackupPath = orig })
	return BLSBackupPath
}

func TestRollbackBLS_StripsManagedOnlyAcrossDivergentUnmanagedArgs(t *testing.T) {
	withTempBLSBackupPath(t)

	expectedStrip := "grubby --update-kernel=/boot/vmlinuz-6.8.0,/boot/vmlinuz-6.7.0 --remove-args=" +
		strings.Join(ManagedBootArgKeys, " ")
	fs := newFakeFS().
		withCmd("grubby --info=ALL", blsInfoAllMultipleUnmanaged).
		withCmd(expectedStrip, "")

	var out bytes.Buffer
	if rc := rollbackBLS(&out, false, fs); rc != 0 {
		t.Fatalf("rollbackBLS rc=%d, output:\n%s", rc, out.String())
	}
	if len(fs.cmdLog) != 2 {
		t.Fatalf("expected info + strip calls only, got %d: %v", len(fs.cmdLog), fs.cmdLog)
	}
	stripCall := fs.cmdLog[1]
	if strings.Contains(stripCall, "--args=") {
		t.Fatalf("rollback must not append saved/default cmdline args in strip-only mode: %q", stripCall)
	}
	if strings.Contains(stripCall, "rescue") {
		t.Fatalf("rollback must not target rescue kernels: %q", stripCall)
	}
	if !strings.Contains(stripCall, "--remove-args="+strings.Join(ManagedBootArgKeys, " ")) {
		t.Fatalf("rollback must remove only kernsec-managed keys with grubby: %q", stripCall)
	}
}

func TestRollbackBLS_RestoresOnlyPerKernelManagedSnapshotTokens(t *testing.T) {
	bak := withTempBLSBackupPath(t)
	snap := blsRollbackSnapshot{
		Version: blsRollbackSnapshotVersion,
		Kernels: map[string][]string{
			"/boot/vmlinuz-6.8.0": {"init_on_alloc=0"},
			"/boot/vmlinuz-6.7.0": {"slab_nomerge", "page_alloc.shuffle=0"},
		},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bak, data, 0o644); err != nil {
		t.Fatal(err)
	}

	expectedStrip := "grubby --update-kernel=/boot/vmlinuz-6.8.0,/boot/vmlinuz-6.7.0 --remove-args=" +
		strings.Join(ManagedBootArgKeys, " ")
	expectedRestoreA := "grubby --update-kernel=/boot/vmlinuz-6.8.0 --args=init_on_alloc=0"
	expectedRestoreB := "grubby --update-kernel=/boot/vmlinuz-6.7.0 --args=slab_nomerge page_alloc.shuffle=0"
	fs := newFakeFS().
		withCmd("grubby --info=ALL", blsInfoAllMultipleUnmanaged).
		withCmd(expectedStrip, "").
		withCmd(expectedRestoreA, "").
		withCmd(expectedRestoreB, "")

	var out bytes.Buffer
	if rc := rollbackBLS(&out, false, fs); rc != 0 {
		t.Fatalf("rollbackBLS rc=%d, output:\n%s", rc, out.String())
	}
	if len(fs.cmdLog) != 4 {
		t.Fatalf("expected info + strip + per-kernel restores, got %d: %v", len(fs.cmdLog), fs.cmdLog)
	}
	for _, call := range fs.cmdLog[2:] {
		if strings.Contains(call, "crashkernel") || strings.Contains(call, "transparent_hugepage") || strings.Contains(call, " ro") {
			t.Fatalf("restore call must contain only per-kernel managed snapshot tokens, got: %q", call)
		}
	}
}

func TestRollbackBLS_IgnoresLegacyFullCmdlineSnapshot(t *testing.T) {
	bak := withTempBLSBackupPath(t)
	if err := os.WriteFile(bak, []byte("ro crashkernel=auto transparent_hugepage=madvise slab_nomerge init_on_alloc=0"), 0o644); err != nil {
		t.Fatal(err)
	}

	expectedStrip := "grubby --update-kernel=/boot/vmlinuz-6.8.0,/boot/vmlinuz-6.7.0 --remove-args=" +
		strings.Join(ManagedBootArgKeys, " ")
	fs := newFakeFS().
		withCmd("grubby --info=ALL", blsInfoAllMultipleUnmanaged).
		withCmd(expectedStrip, "")

	var out bytes.Buffer
	if rc := rollbackBLS(&out, false, fs); rc != 0 {
		t.Fatalf("rollbackBLS rc=%d, output:\n%s", rc, out.String())
	}
	if len(fs.cmdLog) != 2 {
		t.Fatalf("legacy full-cmdline snapshot must be ignored, got calls: %v", fs.cmdLog)
	}
	if strings.Contains(strings.Join(fs.cmdLog, "\n"), "--args=") {
		t.Fatalf("legacy full-cmdline snapshot must not be replayed: %v", fs.cmdLog)
	}
	if !strings.Contains(out.String(), "Ignoring BLS snapshot") {
		t.Fatalf("expected operator-facing ignored-snapshot warning, got:\n%s", out.String())
	}
}

func TestWriteBLSSnapshotSavesOnlyPerKernelManagedTokens(t *testing.T) {
	bak := withTempBLSBackupPath(t)
	fs := newFakeFS().withCmd("grubby --info=ALL", blsInfoAllMultipleUnmanaged)
	b := &BLSBackend{FS: fs}
	if err := b.writeBLSSnapshot(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bak)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "crashkernel") || strings.Contains(string(data), "transparent_hugepage") || strings.Contains(string(data), "\"ro\"") {
		t.Fatalf("BLS snapshot must not save unmanaged/default cmdline tokens:\n%s", string(data))
	}
	var snap blsRollbackSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(snap.Kernels["/boot/vmlinuz-6.8.0"], " "); got != "slab_nomerge init_on_alloc=1" {
		t.Fatalf("unexpected managed snapshot for first kernel: %q", got)
	}
	if got := strings.Join(snap.Kernels["/boot/vmlinuz-6.7.0"], " "); got != "slab_nomerge page_alloc.shuffle=1" {
		t.Fatalf("unexpected managed snapshot for second kernel: %q", got)
	}
}

func TestGRUBRefreshCommand_UpdateGrubHasNoArgs(t *testing.T) {
	fs := newFakeFS().withBin("update-grub")
	b := &GRUBBackend{FS: fs}

	name, args, err := b.refreshCommand()
	if err != nil {
		t.Fatal(err)
	}
	if name != "update-grub" {
		t.Fatalf("refresh command = %q, want update-grub", name)
	}
	if len(args) != 0 {
		t.Fatalf("update-grub must be called with no arguments, got: %v", args)
	}
}

func TestRollbackGRUB_Grub2MkconfigUsesDetectedOutputPath(t *testing.T) {
	grub := redirectGrubPath(t)
	if err := os.WriteFile(grub+BackupSuffix, []byte("GRUB_CMDLINE_LINUX=\"ro\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fs := newFakeFS().
		withBin("grub2-mkconfig").
		withDir("/boot/grub2").
		withCmd("grub2-mkconfig -o /boot/grub2/grub.cfg", "")

	var out bytes.Buffer
	if rc := rollbackGRUB(&out, false, fs); rc != 0 {
		t.Fatalf("rollbackGRUB rc=%d, output:\n%s", rc, out.String())
	}
	if len(fs.cmdLog) != 1 {
		t.Fatalf("expected one grub refresh command, got %d: %v", len(fs.cmdLog), fs.cmdLog)
	}
	if got, want := fs.cmdLog[0], "grub2-mkconfig -o /boot/grub2/grub.cfg"; got != want {
		t.Fatalf("rollbackGRUB refresh command = %q, want %q", got, want)
	}
	data, err := os.ReadFile(grub)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "GRUB_CMDLINE_LINUX=\"ro\"\n" {
		t.Fatalf("restored grub content = %q", string(data))
	}
}
