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
	withTempManagedBackupPaths(t)
	legacy := "GRUB_CMDLINE_LINUX=\"ro\"\n"
	current := "GRUB_CMDLINE_LINUX=\"ro slab_nomerge\"\n"
	if err := os.WriteFile(grub, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grub+BackupSuffix, []byte(legacy), 0o644); err != nil {
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
	if string(data) != legacy {
		t.Fatalf("restored grub content = %q", string(data))
	}
}

func withTempManagedBackupPaths(t *testing.T) (string, string) {
	t.Helper()
	origGrub, origPVE := GRUBManagedBackupPath, ProxmoxManagedBackupPath
	dir := t.TempDir()
	GRUBManagedBackupPath = dir + "/grub-managed.json"
	ProxmoxManagedBackupPath = dir + "/pve-managed.json"
	t.Cleanup(func() {
		GRUBManagedBackupPath = origGrub
		ProxmoxManagedBackupPath = origPVE
	})
	return GRUBManagedBackupPath, ProxmoxManagedBackupPath
}

func writeManagedSnapshotForTest(t *testing.T, path string, args []string) {
	t.Helper()
	data, err := json.Marshal(managedBootArgSnapshot{Version: managedBootArgSnapshotVersion, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackGRUB_ManagedSnapshotPreservesOperatorArgs(t *testing.T) {
	grub := redirectGrubPath(t)
	grubSnap, _ := withTempManagedBackupPaths(t)
	writeManagedSnapshotForTest(t, grubSnap, []string{"init_on_alloc=0"})
	current := "GRUB_CMDLINE_LINUX=\"ro slab_nomerge init_on_alloc=1 console=ttyS0 $tuned_params vendor.foo=bar\"\n" +
		"GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"\n"
	if err := os.WriteFile(grub, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}

	fs := newFakeFS().
		withBin("update-grub").
		withCmd("update-grub", "")

	var out bytes.Buffer
	if rc := rollbackGRUB(&out, false, fs); rc != 0 {
		t.Fatalf("rollbackGRUB rc=%d, output:\n%s", rc, out.String())
	}
	data, err := os.ReadFile(grub)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{"ro", "console=ttyS0", "$tuned_params", "vendor.foo=bar", "init_on_alloc=0", `GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("rollback did not preserve/restore %q in:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"slab_nomerge", "init_on_alloc=1"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("rollback kept stale managed token %q in:\n%s", unwanted, got)
		}
	}
}

func TestRollbackProxmox_ManagedSnapshotPreservesOperatorArgs(t *testing.T) {
	_, pveSnap := withTempManagedBackupPaths(t)
	origPVE := PathPVECmdline
	PathPVECmdline = t.TempDir() + "/cmdline"
	t.Cleanup(func() { PathPVECmdline = origPVE })
	writeManagedSnapshotForTest(t, pveSnap, []string{"page_alloc.shuffle=0"})
	current := "root=ZFS=rpool/ROOT/pve-1 ro slab_nomerge init_on_alloc=1 console=ttyS0 crashkernel=512M vendor.arg=1\n"
	if err := os.WriteFile(PathPVECmdline, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := newFakeFS().withCmd("proxmox-boot-tool refresh", "")

	var out bytes.Buffer
	if rc := rollbackProxmox(&out, false, fs); rc != 0 {
		t.Fatalf("rollbackProxmox rc=%d, output:\n%s", rc, out.String())
	}
	data, err := os.ReadFile(PathPVECmdline)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{"root=ZFS=rpool/ROOT/pve-1", "ro", "console=ttyS0", "crashkernel=512M", "vendor.arg=1", "page_alloc.shuffle=0"} {
		if !strings.Contains(got, want) {
			t.Fatalf("rollback did not preserve/restore %q in %q", want, got)
		}
	}
	for _, unwanted := range []string{"slab_nomerge", "init_on_alloc=1"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("rollback kept stale managed token %q in %q", unwanted, got)
		}
	}
}

func TestRollbackProxmox_LegacyBackupRefusesOperatorChanges(t *testing.T) {
	withTempManagedBackupPaths(t)
	origPVE := PathPVECmdline
	PathPVECmdline = t.TempDir() + "/cmdline"
	t.Cleanup(func() { PathPVECmdline = origPVE })
	legacy := "root=ZFS=rpool/ROOT/pve-1 ro\n"
	current := "root=ZFS=rpool/ROOT/pve-1 ro slab_nomerge console=ttyS0\n"
	if err := os.WriteFile(PathPVECmdline, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(PathPVECmdline+BackupSuffix, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := newFakeFS().withCmd("proxmox-boot-tool refresh", "")

	var out bytes.Buffer
	if rc := rollbackProxmox(&out, false, fs); rc == 0 {
		t.Fatalf("rollbackProxmox unexpectedly succeeded, output:\n%s", out.String())
	}
	data, err := os.ReadFile(PathPVECmdline)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != current {
		t.Fatalf("legacy refusal must leave current content unchanged, got %q", string(data))
	}
	if len(fs.cmdLog) != 0 {
		t.Fatalf("refused rollback must not refresh bootloader, got calls: %v", fs.cmdLog)
	}
	if !strings.Contains(out.String(), "refusing legacy byte-restore") || !strings.Contains(out.String(), "Manual recovery") {
		t.Fatalf("expected refusal and manual recovery instructions, got:\n%s", out.String())
	}
}

func TestRollbackGRUB_LegacyBackupRefusesOperatorChanges(t *testing.T) {
	grub := redirectGrubPath(t)
	withTempManagedBackupPaths(t)
	legacy := "GRUB_CMDLINE_LINUX=\"ro\"\n"
	current := "GRUB_CMDLINE_LINUX=\"ro slab_nomerge console=ttyS0\"\n"
	if err := os.WriteFile(grub, []byte(current), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grub+BackupSuffix, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := newFakeFS().withBin("update-grub").withCmd("update-grub", "")

	var out bytes.Buffer
	if rc := rollbackGRUB(&out, false, fs); rc == 0 {
		t.Fatalf("rollbackGRUB unexpectedly succeeded, output:\n%s", out.String())
	}
	data, err := os.ReadFile(grub)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != current {
		t.Fatalf("legacy refusal must leave current content unchanged, got %q", string(data))
	}
	if len(fs.cmdLog) != 0 {
		t.Fatalf("refused rollback must not refresh bootloader, got calls: %v", fs.cmdLog)
	}
	if !strings.Contains(out.String(), "refusing legacy byte-restore") || !strings.Contains(out.String(), "Manual recovery") {
		t.Fatalf("expected refusal and manual recovery instructions, got:\n%s", out.String())
	}
}
