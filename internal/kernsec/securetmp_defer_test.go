package kernsec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On a cPanel securetmp host (/usr/tmpDSK present), EnableMount must NOT add a
// `/tmp /var/tmp none bind` fstab line: securetmp owns /var/tmp, and a kernsec
// bind line generates a racing systemd var-tmp.mount that ends up orphaned as
// a dead inode once securetmp rebuilds /tmp on its loop device.
func TestEnableMount_VarTmp_DefersToCpanelSecuretmp(t *testing.T) {
	withFakeFstab(t, "UUID=abc / ext4 defaults 0 1\n")
	stub := &stubExec{}
	stub.install(t)

	// /var/tmp absent from /proc/mounts and no fstab line ⇒ MountNotSeparate.
	origRPM := readProcMounts
	readProcMounts = func() string { return "rootfs / rootfs rw 0 0\n" }
	t.Cleanup(func() { readProcMounts = origRPM })

	// Fake a cPanel securetmp host: /usr/tmpDSK present under the probe root.
	origRoot := hostProfileProbeRoot
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/tmpDSK"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostProfileProbeRoot = root
	t.Cleanup(func() { hostProfileProbeRoot = origRoot })

	rule := MountRule{
		ID:          "KSEC-FS-mount.tmp-002",
		MountPoint:  "/var/tmp",
		Recommended: "nodev,nosuid,noexec",
		CanEnable:   true,
	}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("EnableMount returned %v. Output:\n%s", err, w.String())
	}

	if got, _ := os.ReadFile(PathFstab); strings.Contains(string(got), "/var/tmp") {
		t.Errorf("securetmp host: no /var/tmp bind line should be added; fstab:\n%s", got)
	}
	if !strings.Contains(w.String(), "securetmp") {
		t.Errorf("expected a message about deferring to securetmp; got:\n%s", w.String())
	}
}

// Without cPanel securetmp (/usr/tmpDSK absent), the historical behaviour is
// preserved: EnableMount adds the `/tmp /var/tmp none bind` fstab line.
func TestEnableMount_VarTmp_AddsBindLineWithoutSecuretmp(t *testing.T) {
	withFakeFstab(t, "UUID=abc / ext4 defaults 0 1\n")
	stub := &stubExec{}
	stub.install(t)

	origRPM := readProcMounts
	readProcMounts = func() string { return "rootfs / rootfs rw 0 0\n" }
	t.Cleanup(func() { readProcMounts = origRPM })

	// Probe root with NO /usr/tmpDSK ⇒ not a securetmp host.
	origRoot := hostProfileProbeRoot
	hostProfileProbeRoot = t.TempDir()
	t.Cleanup(func() { hostProfileProbeRoot = origRoot })

	rule := MountRule{
		ID:          "KSEC-FS-mount.tmp-002",
		MountPoint:  "/var/tmp",
		Recommended: "nodev,nosuid,noexec",
		CanEnable:   true,
	}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("EnableMount returned %v. Output:\n%s", err, w.String())
	}

	got, _ := os.ReadFile(PathFstab)
	if !strings.Contains(string(got), "/var/tmp") || !strings.Contains(string(got), "bind") {
		t.Errorf("non-securetmp host: expected a `/tmp /var/tmp none bind` line; fstab:\n%s", got)
	}
}
