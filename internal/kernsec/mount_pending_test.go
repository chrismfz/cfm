package kernsec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeFstab returns a readFstab function bound to in-memory content.
func fakeFstab(content string) func() ([]fstabLine, error) {
	return func() ([]fstabLine, error) {
		return parseFstab(content), nil
	}
}

// fakeUnit returns a findUnit function that always returns the
// supplied options for the requested unit.
func fakeUnit(opts string) func(string) (string, string, bool) {
	return func(unit string) (string, string, bool) {
		return "/usr/lib/systemd/system/" + unit, opts, true
	}
}

// noUnit returns a findUnit function that always reports "no unit".
func noUnit() func(string) (string, string, bool) {
	return func(string) (string, string, bool) { return "", "", false }
}

func TestCheckMountDetail_PendingViaFstab(t *testing.T) {
	// /tmp live is missing noexec, but the fstab line already has
	// nodev,nosuid,noexec. State must be MountPending so the audit
	// surfaces PEND rather than DIFF.
	procMounts := `/dev/loop0 /tmp ext4 rw,nosuid,nodev 0 0
`
	fstab := `/dev/loop0 /tmp ext4 defaults,nodev,nosuid,noexec 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink,
		fakeFstab(fstab), noUnit())
	if d.State != MountPending {
		t.Fatalf("state = %d, want MountPending", d.State)
	}
	if d.PersistedSource != "fstab" {
		t.Errorf("PersistedSource = %q, want fstab", d.PersistedSource)
	}
	if d.NextBootOptions == "" {
		t.Errorf("NextBootOptions should be populated for PEND, got empty")
	}
}

func TestCheckMountDetail_PendingViaSystemdUnit(t *testing.T) {
	// Debian tmp.mount carries the recommended options; live is
	// still partial. Must surface MountPending.
	procMounts := `tmpfs /tmp tmpfs rw,nosuid,nodev,size=50%,inode64 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink,
		fakeFstab(""), fakeUnit("mode=1777,nodev,nosuid,noexec,size=50%,inode64"))
	if d.State != MountPending {
		t.Fatalf("state = %d, want MountPending", d.State)
	}
	if d.PersistedSource != "systemd-unit" {
		t.Errorf("PersistedSource = %q, want systemd-unit", d.PersistedSource)
	}
}

func TestCheckMountDetail_PartialWhenPersistedDoesNotCover(t *testing.T) {
	// Persistence layer ALSO missing some options → not PEND, just
	// PARTIAL — operator needs to either Enable or edit by hand.
	procMounts := `tmpfs /tmp tmpfs rw,nosuid,nodev 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink,
		fakeFstab(""), fakeUnit("mode=1777,nodev,nosuid,size=50%"))
	if d.State != MountPartialOptions {
		t.Fatalf("state = %d, want MountPartialOptions (persisted does not cover)", d.State)
	}
}

func TestCheckMountDetail_PendingViaFstabBindLine(t *testing.T) {
	// Post-Enable on /var/tmp when /var/tmp isn't separately mounted:
	// fstab now has `/tmp /var/tmp none bind 0 0`. /proc/mounts still
	// doesn't have /var/tmp (mount happens at reboot). The audit row
	// must show PEND with BindPrimaryPath=/tmp, NOT MountNotSeparate.
	procMounts := `tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
`
	fstab := `UUID=abc / ext4 defaults 0 1
/tmp /var/tmp none bind 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink,
		fakeFstab(fstab), noUnit())
	if d.State != MountPending {
		t.Fatalf("state = %d, want MountPending (fstab bind queued, reboot will mount)", d.State)
	}
	if d.BindPrimaryPath != "/tmp" {
		t.Errorf("BindPrimaryPath = %q, want /tmp", d.BindPrimaryPath)
	}
	if d.PersistedSource != "fstab" {
		t.Errorf("PersistedSource = %q, want fstab", d.PersistedSource)
	}
}

func TestCheckMountDetail_PendingViaFstabWhenNotMountedYet(t *testing.T) {
	// /var/tmp isn't in /proc/mounts AND fstab has a non-bind line
	// for it. Still PEND — the line will materialise the mount at
	// reboot. No BindPrimaryPath because it's not a bind.
	fstab := `UUID=abc / ext4 defaults 0 1
/dev/sda2 /var/tmp ext4 defaults,nodev,nosuid,noexec 0 2
`
	d := checkMountDetail(``,
		MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink,
		fakeFstab(fstab), noUnit())
	if d.State != MountPending {
		t.Fatalf("state = %d, want MountPending", d.State)
	}
	if d.BindPrimaryPath != "" {
		t.Errorf("BindPrimaryPath should be empty for non-bind PEND, got %q", d.BindPrimaryPath)
	}
}

func TestCheckMountDetail_NotSeparateWhenNoFstab(t *testing.T) {
	// Sanity: when /proc/mounts doesn't have it AND fstab has no
	// line, we still return MountNotSeparate so the secure-tmp tip
	// surfaces. (Don't regress to PEND on plain root-fs /var/tmp.)
	d := checkMountDetail(``,
		MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink,
		fakeFstab(""), noUnit())
	if d.State != MountNotSeparate {
		t.Fatalf("state = %d, want MountNotSeparate", d.State)
	}
}

func TestEnableMount_TmpSystemdDropin(t *testing.T) {
	// Debian-style: /tmp is mounted via systemd tmp.mount; no fstab
	// line exists. EnableMount must write a drop-in under our
	// redirected /etc/systemd/system, NOT edit fstab, and skip the
	// live remount.
	withFakeFstab(t, `UUID=abc / ext4 defaults 0 1
`)
	dir := t.TempDir()
	origEtc, origFinder := systemdSystemEtcDir, realSystemdUnitFinderWithDropins
	systemdSystemEtcDir = dir
	realSystemdUnitFinderWithDropins = fakeUnit("mode=1777,nodev,nosuid,size=50%,inode64")
	t.Cleanup(func() {
		systemdSystemEtcDir = origEtc
		realSystemdUnitFinderWithDropins = origFinder
	})

	// Also need /proc/mounts to show /tmp as separate so EnableMount
	// doesn't take the bind branch (only /var/tmp does that anyway).
	origProc := readProcMounts
	readProcMounts = func() string {
		return "tmpfs /tmp tmpfs rw,nosuid,nodev,size=50%,inode64 0 0\n"
	}
	t.Cleanup(func() { readProcMounts = origProc })

	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-001", MountPoint: "/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("EnableMount returned %v. Output:\n%s", err, w.String())
	}

	// Drop-in must exist at /etc/systemd/system/tmp.mount.d/10-cfm-hardening.conf.
	expectPath := filepath.Join(dir, "tmp.mount.d", "10-cfm-hardening.conf")
	body, err := os.ReadFile(expectPath)
	if err != nil {
		t.Fatalf("expected drop-in at %s: %v", expectPath, err)
	}
	if !strings.Contains(string(body), "Options=") || !strings.Contains(string(body), "noexec") {
		t.Errorf("drop-in body missing Options= / noexec; got:\n%s", body)
	}
	// Existing options (size=, mode=, inode64) must be preserved.
	for _, opt := range []string{"size=50%", "mode=1777", "inode64", "nodev", "nosuid"} {
		if !strings.Contains(string(body), opt) {
			t.Errorf("drop-in must preserve %q; got:\n%s", opt, body)
		}
	}
	// Daemon-reload must have run; live remount must NOT have run.
	if stub.daemonReloads != 1 {
		t.Errorf("expected 1 daemon-reload, got %d", stub.daemonReloads)
	}
	if len(stub.remounts) != 0 {
		t.Errorf("expected NO live remount for /tmp; got %v", stub.remounts)
	}
}

func TestEnableMount_TmpFstabEditPreservesOtherOptions(t *testing.T) {
	// EL-style: operator has /tmp in fstab with size=. Enable adds
	// noexec; size= must survive.
	withFakeFstab(t, `tmpfs /tmp tmpfs defaults,nodev,nosuid,size=4G 0 0
`)
	origFinder := realSystemdUnitFinderWithDropins
	realSystemdUnitFinderWithDropins = noUnit()
	t.Cleanup(func() { realSystemdUnitFinderWithDropins = origFinder })

	origProc := readProcMounts
	readProcMounts = func() string {
		return "tmpfs /tmp tmpfs rw,nosuid,nodev,size=4G 0 0\n"
	}
	t.Cleanup(func() { readProcMounts = origProc })

	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-001", MountPoint: "/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("EnableMount returned %v", err)
	}
	got, _ := os.ReadFile(PathFstab)
	for _, opt := range []string{"size=4G", "nodev", "nosuid", "noexec"} {
		if !strings.Contains(string(got), opt) {
			t.Errorf("expected %q in fstab; got:\n%s", opt, got)
		}
	}
	if len(stub.remounts) != 0 {
		t.Errorf("expected NO live remount for /tmp; got %v", stub.remounts)
	}
}

func TestEnableMount_TmpRefusedWhenNotSeparateAndNoUnit(t *testing.T) {
	// /tmp lives on / and there's no systemd tmp.mount unit. Must
	// refuse and point at secure-tmp; no fstab edit, no drop-in.
	fstabPath := withFakeFstab(t, `UUID=abc / ext4 defaults 0 1
`)
	origFinder := realSystemdUnitFinderWithDropins
	realSystemdUnitFinderWithDropins = noUnit()
	t.Cleanup(func() { realSystemdUnitFinderWithDropins = origFinder })

	origProc := readProcMounts
	readProcMounts = func() string { return "" } // no /tmp at all
	t.Cleanup(func() { readProcMounts = origProc })

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-001", MountPoint: "/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	err := EnableMount(rule, &w, EnableMountOptions{})
	if err == nil {
		t.Fatal("expected refusal when /tmp is on / and no unit owns it")
	}
	if !strings.Contains(err.Error(), "secure-tmp") {
		t.Errorf("error should mention secure-tmp recovery path; got %v", err)
	}
	got, _ := os.ReadFile(fstabPath)
	if strings.Contains(string(got), "/tmp") {
		t.Errorf("fstab must be untouched on refusal; got:\n%s", got)
	}
}

func TestEnableMount_TmpRefusedWhenUnitExistsButNotMounted(t *testing.T) {
	// /usr/lib/systemd/system/tmp.mount exists (every Debian) but
	// /tmp isn't actually mounted via it on this host — masked,
	// disabled, container overlayfs, whatever. Writing a drop-in
	// would be a dead override; EnableMount must refuse and point
	// at secure-tmp, not silently write a useless file.
	fstabPath := withFakeFstab(t, `UUID=abc / ext4 defaults 0 1
`)
	dir := t.TempDir()
	origEtc, origFinder := systemdSystemEtcDir, realSystemdUnitFinderWithDropins
	systemdSystemEtcDir = dir
	realSystemdUnitFinderWithDropins = fakeUnit("mode=1777,size=50%")
	t.Cleanup(func() {
		systemdSystemEtcDir = origEtc
		realSystemdUnitFinderWithDropins = origFinder
	})
	origProc := readProcMounts
	readProcMounts = func() string { return "" } // no /tmp in /proc/mounts
	t.Cleanup(func() { readProcMounts = origProc })

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-001", MountPoint: "/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	err := EnableMount(rule, &w, EnableMountOptions{})
	if err == nil {
		t.Fatal("expected refusal when tmp.mount exists but doesn't mount /tmp on this host")
	}
	if !strings.Contains(err.Error(), "secure-tmp") {
		t.Errorf("error should redirect to secure-tmp; got %v", err)
	}
	// No drop-in should have been written.
	deadPath := filepath.Join(dir, "tmp.mount.d", "10-cfm-hardening.conf")
	if _, err := os.Stat(deadPath); !os.IsNotExist(err) {
		t.Errorf("no drop-in should be written when refusing; stat err = %v", err)
	}
	// fstab untouched.
	got, _ := os.ReadFile(fstabPath)
	if strings.Contains(string(got), "/tmp ") {
		t.Errorf("fstab must be untouched on refusal; got:\n%s", got)
	}
}

func TestEnableMount_VarTmpBindWhenNotSeparate(t *testing.T) {
	// /var/tmp lives on /. Enable must add a bind fstab line so
	// /var/tmp inherits /tmp's hardening at reboot.
	fstabPath := withFakeFstab(t, `UUID=abc / ext4 defaults 0 1
`)
	origFinder := realSystemdUnitFinderWithDropins
	realSystemdUnitFinderWithDropins = noUnit()
	t.Cleanup(func() { realSystemdUnitFinderWithDropins = origFinder })

	origProc := readProcMounts
	readProcMounts = func() string {
		return "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n"
	}
	t.Cleanup(func() { readProcMounts = origProc })

	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-002", MountPoint: "/var/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("EnableMount returned %v. Output:\n%s", err, w.String())
	}
	got, _ := os.ReadFile(fstabPath)
	if !strings.Contains(string(got), "/var/tmp") {
		t.Errorf("fstab should contain a /var/tmp line; got:\n%s", got)
	}
	if !strings.Contains(string(got), "bind") {
		t.Errorf("fstab line should be a bind mount; got:\n%s", got)
	}
	if !strings.Contains(string(got), kernsecManagedFstabComment) {
		t.Errorf("bind line should carry managed-by-cfm marker; got:\n%s", got)
	}
	if len(stub.remounts) != 0 {
		t.Errorf("expected NO live mount for /var/tmp bind; got %v", stub.remounts)
	}
}

func TestDisableMount_RemovesSystemdDropin(t *testing.T) {
	// Pre-stage a drop-in under the redirected /etc/systemd/system
	// tree; DisableMount must remove it (and the empty .d/ dir).
	withFakeFstab(t, `UUID=abc / ext4 defaults 0 1
`)
	dir := t.TempDir()
	origEtc := systemdSystemEtcDir
	systemdSystemEtcDir = dir
	t.Cleanup(func() { systemdSystemEtcDir = origEtc })

	dropinDir := filepath.Join(dir, "tmp.mount.d")
	if err := os.MkdirAll(dropinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dropinFile := filepath.Join(dropinDir, "10-cfm-hardening.conf")
	// Marker on the first line is what tells Disable this is our
	// file (vs. an operator hand-edit at the same path).
	if err := os.WriteFile(dropinFile, []byte(systemdDropinMarker+" test fixture.\n[Mount]\nOptions=nodev,nosuid,noexec\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-001", MountPoint: "/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	if err := DisableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("DisableMount returned %v", err)
	}
	if _, err := os.Stat(dropinFile); !os.IsNotExist(err) {
		t.Errorf("drop-in should be removed; stat err = %v", err)
	}
	if _, err := os.Stat(dropinDir); !os.IsNotExist(err) {
		t.Errorf("empty .d/ dir should be removed; stat err = %v", err)
	}
	if len(stub.remounts) != 0 {
		t.Errorf("expected NO live remount for /tmp on Disable; got %v", stub.remounts)
	}
}

func TestEnableMount_RefusesToOverwriteOperatorOwnedDropin(t *testing.T) {
	// Operator already has /etc/systemd/system/tmp.mount.d/10-cfm-hardening.conf
	// — maybe they copy-pasted it from our README and tuned it by
	// hand. Same filename but no kernsec marker on the first line.
	// EnableMount must refuse rather than silently overwrite.
	withFakeFstab(t, `UUID=abc / ext4 defaults 0 1
`)
	dir := t.TempDir()
	origEtc, origFinder := systemdSystemEtcDir, realSystemdUnitFinderWithDropins
	systemdSystemEtcDir = dir
	realSystemdUnitFinderWithDropins = fakeUnit("mode=1777,nodev,nosuid,size=50%")
	t.Cleanup(func() {
		systemdSystemEtcDir = origEtc
		realSystemdUnitFinderWithDropins = origFinder
	})
	origProc := readProcMounts
	readProcMounts = func() string {
		return "tmpfs /tmp tmpfs rw,nosuid,nodev,size=50% 0 0\n"
	}
	t.Cleanup(func() { readProcMounts = origProc })

	// Pre-stage operator-owned drop-in at the path kernsec uses.
	operatorDir := filepath.Join(dir, "tmp.mount.d")
	if err := os.MkdirAll(operatorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	operatorFile := filepath.Join(operatorDir, "10-cfm-hardening.conf")
	operatorBody := "[Mount]\nOptions=mode=1777,nodev,nosuid,noexec,size=4G\nTimeoutSec=30\n"
	if err := os.WriteFile(operatorFile, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-001", MountPoint: "/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	err := EnableMount(rule, &w, EnableMountOptions{})
	if err == nil {
		t.Fatal("expected refusal when operator-owned drop-in is at our path")
	}
	if !strings.Contains(err.Error(), "operator-owned") {
		t.Errorf("error should call out the operator-owned condition; got %v", err)
	}
	got, _ := os.ReadFile(operatorFile)
	if string(got) != operatorBody {
		t.Errorf("operator file must be byte-identical after refusal; got:\n%s", got)
	}
}

func TestDisableMount_PreservesOperatorOwnedDropin(t *testing.T) {
	// Symmetric to the Enable test above: Disable must NOT remove
	// a drop-in at our path that lacks the kernsec marker.
	withFakeFstab(t, `UUID=abc / ext4 defaults 0 1
`)
	dir := t.TempDir()
	origEtc := systemdSystemEtcDir
	systemdSystemEtcDir = dir
	t.Cleanup(func() { systemdSystemEtcDir = origEtc })

	operatorDir := filepath.Join(dir, "tmp.mount.d")
	if err := os.MkdirAll(operatorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	operatorFile := filepath.Join(operatorDir, "10-cfm-hardening.conf")
	operatorBody := "[Mount]\nOptions=mode=1777,nodev,nosuid,noexec\n"
	if err := os.WriteFile(operatorFile, []byte(operatorBody), 0o644); err != nil {
		t.Fatal(err)
	}

	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-001", MountPoint: "/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	if err := DisableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("DisableMount returned %v", err)
	}
	got, err := os.ReadFile(operatorFile)
	if err != nil {
		t.Fatalf("operator drop-in must still exist after Disable; got %v", err)
	}
	if string(got) != operatorBody {
		t.Errorf("operator drop-in body changed; got:\n%s", got)
	}
}

func TestEnableMount_DropinConflictRefused(t *testing.T) {
	// Operator set Options= ... ,exec in tmp.mount. EnableMount must
	// refuse rather than silently override their intent.
	withFakeFstab(t, `UUID=abc / ext4 defaults 0 1
`)
	dir := t.TempDir()
	origEtc, origFinder := systemdSystemEtcDir, realSystemdUnitFinderWithDropins
	systemdSystemEtcDir = dir
	realSystemdUnitFinderWithDropins = fakeUnit("mode=1777,exec,size=50%")
	t.Cleanup(func() {
		systemdSystemEtcDir = origEtc
		realSystemdUnitFinderWithDropins = origFinder
	})

	origProc := readProcMounts
	readProcMounts = func() string {
		return "tmpfs /tmp tmpfs rw,exec,size=50% 0 0\n"
	}
	t.Cleanup(func() { readProcMounts = origProc })

	rule := MountRule{
		ID: "KSEC-FS-mount.tmp-001", MountPoint: "/tmp",
		Recommended: "nodev,nosuid,noexec", CanEnable: true,
	}
	var w bytes.Buffer
	err := EnableMount(rule, &w, EnableMountOptions{})
	if err == nil {
		t.Fatal("expected refusal on exec vs noexec conflict in systemd Options=")
	}
	if !strings.Contains(err.Error(), "contradicts") {
		t.Errorf("error should explain the contradiction; got %v", err)
	}
}
