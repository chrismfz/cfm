package kernsec

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withFakeFstab redirects PathFstab to a temp file containing the
// supplied content and registers a cleanup that restores the path.
// Returns the temp path so tests can re-read the post-apply state.
func withFakeFstab(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fstab")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := PathFstab
	PathFstab = path
	t.Cleanup(func() { PathFstab = orig })
	return path
}

// stubSystemctlAndMount captures invocations of the daemon-reload
// and remount hooks so tests can assert on them, and prevents the
// real systemctl / mount commands from running.
type stubExec struct {
	daemonReloads int
	remounts      []string // recorded "mountpoint:opts" strings
	reloadErr     error
	remountErr    error
}

func (s *stubExec) install(t *testing.T) {
	t.Helper()
	origReload := runSystemctlDaemonReload
	origRemount := runRemount
	runSystemctlDaemonReload = func() error {
		s.daemonReloads++
		return s.reloadErr
	}
	runRemount = func(mp, opts string) error {
		s.remounts = append(s.remounts, mp+":"+opts)
		return s.remountErr
	}
	t.Cleanup(func() {
		runSystemctlDaemonReload = origReload
		runRemount = origRemount
	})
}

func TestEnableMount_AppendsNewLine(t *testing.T) {
	withFakeFstab(t, `# distro-shipped fstab
UUID=abc / ext4 defaults 0 1
`)
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		ID:          "KSEC-FS-mount.tmp-003",
		MountPoint:  "/dev/shm",
		Recommended: "nodev,nosuid,noexec",
		CanEnable:   true,
	}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("EnableMount returned %v. Output:\n%s", err, w.String())
	}

	got, _ := os.ReadFile(PathFstab)
	if !strings.Contains(string(got), "/dev/shm") {
		t.Errorf("fstab should contain a /dev/shm line after enable; got:\n%s", got)
	}
	if !strings.Contains(string(got), "nodev,nosuid,noexec") {
		t.Errorf("appended line should carry the recommended options; got:\n%s", got)
	}
	if !strings.Contains(string(got), kernsecManagedFstabComment) {
		t.Errorf("appended line should carry the managed-by-cfm comment so disable can recognise it; got:\n%s", got)
	}
	if stub.daemonReloads != 1 {
		t.Errorf("expected systemctl daemon-reload once, got %d", stub.daemonReloads)
	}
	if len(stub.remounts) != 1 || stub.remounts[0] != "/dev/shm:nodev,nosuid,noexec" {
		t.Errorf("expected one remount of /dev/shm with the recommended opts; got %v", stub.remounts)
	}

	// Backup of pre-change fstab must exist.
	if _, err := os.Stat(PathFstab + BackupSuffix); err != nil {
		t.Errorf("expected backup at %s%s, got %v", PathFstab, BackupSuffix, err)
	}
}

func TestEnableMount_EditsExistingLine_PreservesOtherOptions(t *testing.T) {
	// Operator already had a /dev/shm fstab line with size= and
	// mode=. EnableMount must preserve those and only ADD the
	// missing nodev,nosuid,noexec.
	withFakeFstab(t, `tmpfs /dev/shm tmpfs defaults,size=8G,mode=1777 0 0
`)
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec", CanEnable: true}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("EnableMount returned %v", err)
	}

	got, _ := os.ReadFile(PathFstab)
	for _, opt := range []string{"defaults", "size=8G", "mode=1777", "nodev", "nosuid", "noexec"} {
		if !strings.Contains(string(got), opt) {
			t.Errorf("expected option %q in edited fstab; got:\n%s", opt, got)
		}
	}
}

func TestEnableMount_IdempotentOnAlreadyHardenedLine(t *testing.T) {
	withFakeFstab(t, `tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec,mode=1777 0 0
`)
	originalBytes, _ := os.ReadFile(PathFstab)
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec", CanEnable: true}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("EnableMount returned %v", err)
	}
	gotBytes, _ := os.ReadFile(PathFstab)
	if string(gotBytes) != string(originalBytes) {
		t.Errorf("expected fstab unchanged when already hardened; got change:\nbefore:\n%s\nafter:\n%s",
			originalBytes, gotBytes)
	}
	if !strings.Contains(w.String(), "already hardened") {
		t.Errorf("expected 'already hardened' log line; got:\n%s", w.String())
	}
	// daemon-reload still runs (cheap, harmless), but remount also
	// runs to ensure runtime matches. Both are acceptable on the
	// no-op path; they're documented as idempotent.
}

func TestEnableMount_RefusesConflictingOption(t *testing.T) {
	// Operator explicitly set `exec` — refuse to silently overwrite
	// their intent.
	withFakeFstab(t, `tmpfs /dev/shm tmpfs defaults,exec 0 0
`)
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec", CanEnable: true}
	var w bytes.Buffer
	err := EnableMount(rule, &w, EnableMountOptions{})
	if err == nil {
		t.Fatal("EnableMount should refuse when fstab line carries `exec`")
	}
	if !strings.Contains(err.Error(), "exec") {
		t.Errorf("error should name the conflict; got %v", err)
	}
	// No daemon-reload or remount should have happened on the
	// conflict path — we must NOT silently apply our recommendation.
	if stub.daemonReloads != 0 || len(stub.remounts) != 0 {
		t.Errorf("conflict path must not touch the running kernel; got reloads=%d remounts=%v",
			stub.daemonReloads, stub.remounts)
	}
}

func TestEnableMount_NoRemount_StillWritesFstab(t *testing.T) {
	withFakeFstab(t, ``)
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec", CanEnable: true}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{NoRemount: true}); err != nil {
		t.Fatalf("EnableMount returned %v", err)
	}
	got, _ := os.ReadFile(PathFstab)
	if !strings.Contains(string(got), "/dev/shm") {
		t.Errorf("expected fstab edit even with NoRemount; got:\n%s", got)
	}
	if len(stub.remounts) != 0 {
		t.Errorf("NoRemount must skip the live remount; got %v", stub.remounts)
	}
	if !strings.Contains(w.String(), "Apply manually") {
		t.Errorf("NoRemount should tell operator the manual remount command; got:\n%s", w.String())
	}
}

func TestEnableMount_RefusesIfCanEnableFalse(t *testing.T) {
	rule := MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec", CanEnable: false}
	var w bytes.Buffer
	if err := EnableMount(rule, &w, EnableMountOptions{}); err == nil {
		t.Fatal("EnableMount must refuse to operate on a CanEnable=false rule")
	}
}

func TestEnableMount_RemountFailurePropagates(t *testing.T) {
	withFakeFstab(t, ``)
	stub := &stubExec{remountErr: errors.New("device or resource busy")}
	stub.install(t)

	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec", CanEnable: true}
	var w bytes.Buffer
	err := EnableMount(rule, &w, EnableMountOptions{})
	if err == nil {
		t.Fatal("EnableMount should surface remount failures")
	}
	if !strings.Contains(err.Error(), "remount") {
		t.Errorf("error should name remount; got %v", err)
	}
	// fstab edit must still be persisted — the message tells the
	// operator the reboot path will pick it up.
	got, _ := os.ReadFile(PathFstab)
	if !strings.Contains(string(got), "/dev/shm") {
		t.Errorf("fstab edit must persist even if live remount fails; got:\n%s", got)
	}
}

func TestDisableMount_StripsOnlyKernsecAdditions_PreservesDistroDefaults(t *testing.T) {
	// /dev/shm on every modern distro mounts with nosuid,nodev
	// already on (systemd PID 1 mount-setup table). Kernsec only
	// adds `noexec` on top. Disable must therefore strip ONLY
	// noexec — leaving nodev,nosuid (and any operator-set options
	// like size=, mode=) untouched. Remounting with `dev,suid,exec`
	// would land the host *below* the distro baseline; that was a
	// real bug observed against findmnt /dev/shm on Alma, Debian,
	// and Ubuntu hosts.
	withFakeFstab(t, `tmpfs /dev/shm tmpfs defaults,size=8G,mode=1777,nodev,nosuid,noexec 0 0
`)
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		MountPoint:         "/dev/shm",
		Recommended:        "nodev,nosuid,noexec",
		DefaultLiveOptions: "nodev,nosuid",
		CanEnable:          true,
	}
	var w bytes.Buffer
	if err := DisableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("DisableMount returned %v", err)
	}
	got, _ := os.ReadFile(PathFstab)
	// Operator's own options + the distro-default kernsec-managed
	// options stay in fstab.
	for _, opt := range []string{"defaults", "size=8G", "mode=1777", "nodev", "nosuid"} {
		if !strings.Contains(string(got), opt) {
			t.Errorf("disable must preserve %q (operator or distro-default); got:\n%s", opt, got)
		}
	}
	// Only the kernsec-effective addition gets stripped.
	if strings.Contains(string(got), "noexec") {
		t.Errorf("disable must strip noexec from fstab; got:\n%s", got)
	}
	// Runtime revert must use ONLY the anti-option of the
	// kernsec-effective addition. `dev,suid,exec` would weaken the
	// host below the distro baseline and is the bug we are fixing.
	// Inspect just the opts portion (after the ":") so the "dev" in
	// "/dev/shm" doesn't false-positive the substring check.
	if len(stub.remounts) != 1 {
		t.Fatalf("expected exactly one remount; got %v", stub.remounts)
	}
	colon := strings.Index(stub.remounts[0], ":")
	if colon < 0 {
		t.Fatalf("malformed remount record: %q", stub.remounts[0])
	}
	gotOpts := stub.remounts[0][colon+1:]
	if gotOpts != "exec" {
		t.Errorf("remount opts must be exactly `exec` (the anti-option of noexec); got %q", gotOpts)
	}
}

func TestDisableMount_NoOpWhenRecommendationFullyCoveredByDefaults(t *testing.T) {
	// Defensive: if every Recommended option is in
	// DefaultLiveOptions (a hypothetical future rule where the
	// distro defaults are already perfect), disable should report
	// "nothing to do" and not run a daemon-reload or a remount.
	withFakeFstab(t, ``)
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		MountPoint:         "/some/path",
		Recommended:        "nodev,nosuid",
		DefaultLiveOptions: "nodev,nosuid",
		CanEnable:          true,
	}
	var w bytes.Buffer
	if err := DisableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("DisableMount returned %v", err)
	}
	if !strings.Contains(w.String(), "already a distro default") {
		t.Errorf("expected 'already a distro default' explanation; got:\n%s", w.String())
	}
	if stub.daemonReloads != 0 || len(stub.remounts) != 0 {
		t.Errorf("no kernel-affecting actions should run; got reloads=%d remounts=%v",
			stub.daemonReloads, stub.remounts)
	}
}

func TestKernsecEffectiveAdditions(t *testing.T) {
	tests := []struct {
		name string
		rule MountRule
		want []string
	}{
		{
			name: "dev/shm typical: noexec only",
			rule: MountRule{
				Recommended:        "nodev,nosuid,noexec",
				DefaultLiveOptions: "nodev,nosuid",
			},
			want: []string{"noexec"},
		},
		{
			name: "no defaults declared: all managed are additions",
			rule: MountRule{Recommended: "nodev,nosuid,noexec"},
			want: []string{"nodev", "nosuid", "noexec"},
		},
		{
			name: "defaults cover everything: empty additions",
			rule: MountRule{
				Recommended:        "nodev,nosuid",
				DefaultLiveOptions: "nodev,nosuid",
			},
			want: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := kernsecEffectiveAdditions(tc.rule)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("element %d: got %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestDisableMount_RemovesEntireKernsecOwnedLine(t *testing.T) {
	// kernsec appended its own line and tagged it with the marker
	// comment. Disable must remove the whole line so the host
	// returns to the pre-cfm state (systemd PID 1 defaults: nodev,
	// nosuid). The runtime revert still runs but it only undoes the
	// kernsec-effective addition (noexec) — NOT all three managed
	// options — so the host lands on the distro baseline, not below.
	managed := defaultFstabLineFor(MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec"})
	withFakeFstab(t, "UUID=abc / ext4 defaults 0 1\n"+managed+"\n")
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{
		MountPoint:         "/dev/shm",
		Recommended:        "nodev,nosuid,noexec",
		DefaultLiveOptions: "nodev,nosuid",
		CanEnable:          true,
	}
	var w bytes.Buffer
	if err := DisableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("DisableMount returned %v", err)
	}
	got, _ := os.ReadFile(PathFstab)
	if strings.Contains(string(got), "/dev/shm") {
		t.Errorf("kernsec-owned line should be removed entirely; got:\n%s", got)
	}
	if !strings.Contains(string(got), "UUID=abc") {
		t.Errorf("other operator lines must be preserved; got:\n%s", got)
	}
	// Runtime revert must run with `exec` only (not dev,suid,exec).
	if len(stub.remounts) != 1 || !strings.Contains(stub.remounts[0], ":exec") {
		t.Errorf("expected one remount with `exec`; got %v", stub.remounts)
	}
}

func TestDisableMount_NoChangeWhenLineAbsent(t *testing.T) {
	withFakeFstab(t, "UUID=abc / ext4 defaults 0 1\n")
	stub := &stubExec{}
	stub.install(t)

	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec", CanEnable: true}
	var w bytes.Buffer
	if err := DisableMount(rule, &w, EnableMountOptions{}); err != nil {
		t.Fatalf("DisableMount returned %v", err)
	}
	if !strings.Contains(w.String(), "already absent") {
		t.Errorf("expected 'already absent' log line; got:\n%s", w.String())
	}
}

func TestApplyEnableToFstabLines_AppendKeepsTrailingNewlineNeat(t *testing.T) {
	// Operator's fstab ends with a single trailing newline. After
	// append we should still have exactly one trailing blank line,
	// not zero and not three.
	in := []string{
		"UUID=abc / ext4 defaults 0 1",
		"",
	}
	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec"}
	out, action, err := applyEnableToFstabLines(in, rule, splitCSV(rule.Recommended))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != fstabActionAppended {
		t.Fatalf("expected appended action, got %v", action)
	}
	if out[len(out)-1] != "" {
		t.Errorf("expected trailing empty string; got %q", out[len(out)-1])
	}
	if strings.Count(strings.Join(out, "\n"), "\n\n") > 0 {
		t.Errorf("append should not produce double blank lines; got:\n%s", strings.Join(out, "\n"))
	}
}

func TestAntiOption(t *testing.T) {
	tests := map[string]string{
		"noexec": "exec",
		"nosuid": "suid",
		"nodev":  "dev",
		"rw":     "",
	}
	for in, want := range tests {
		if got := antiOption(in); got != want {
			t.Errorf("antiOption(%q) = %q, want %q", in, got, want)
		}
	}
}
