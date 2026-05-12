package kernsec

import (
	"errors"
	"strings"
	"testing"
)

// stubFstab returns a closure usable as the readFstab hook in
// buildMountTip. Empty lines slice means "fstab exists but has no
// relevant lines"; nil error means "read succeeded".
func stubFstab(content string) func() ([]fstabLine, error) {
	return func() ([]fstabLine, error) {
		return parseFstab(content), nil
	}
}

// stubFstabError makes the fstab read fail, exercising the
// "no fstab knowledge available" branch.
func stubFstabError() func() ([]fstabLine, error) {
	return func() ([]fstabLine, error) {
		return nil, errors.New("permission denied")
	}
}

// stubUnitFinder returns a closure usable as the findUnit hook. Only
// the unit name in `units` returns a hit; everything else returns
// "not found".
func stubUnitFinder(units map[string]struct{ Path, Options string }) func(string) (string, string, bool) {
	return func(name string) (string, string, bool) {
		if u, ok := units[name]; ok {
			return u.Path, u.Options, true
		}
		return "", "", false
	}
}

func TestBuildMountTip_OK_NoTip(t *testing.T) {
	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec"}
	tip := buildMountTip(rule,
		MountDetail{State: MountOK},
		stubFstab(""), stubUnitFinder(nil))
	if tip.Headline != "" || len(tip.Body) != 0 {
		t.Errorf("OK rows must not produce a tip; got %+v", tip)
	}
}

func TestBuildMountTip_PartialOptions_FstabPresent(t *testing.T) {
	rule := MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec"}
	d := MountDetail{
		State:          MountPartialOptions,
		CurrentOptions: "rw,nosuid,noexec,relatime,discard",
		Present:        []string{"nosuid", "noexec"},
		Missing:        []string{"nodev"},
		Source:         "/dev/loop0",
	}
	fstab := stubFstab("/dev/loop0 /tmp ext4 defaults,nosuid,noexec 0 0\n")
	tip := buildMountTip(rule, d, fstab, stubUnitFinder(nil))

	if !strings.Contains(tip.Headline, "fstab") {
		t.Errorf("headline should name fstab when an fstab line exists; got %q", tip.Headline)
	}
	body := strings.Join(tip.Body, "\n")
	if !strings.Contains(body, "/etc/fstab:1") {
		t.Errorf("body should quote the operator's actual fstab line+number; got:\n%s", body)
	}
	// The example "new options column" should add `nodev` to the
	// existing options without dropping the operator's other flags.
	if !strings.Contains(body, "defaults,nosuid,noexec,nodev") {
		t.Errorf("body should preserve existing fstab options and append the missing one; got:\n%s", body)
	}
	// The remount command names only the missing option, not the
	// full recommended set.
	if !strings.Contains(body, "mount -o remount,nodev /tmp") {
		t.Errorf("remount command should target only the missing option; got:\n%s", body)
	}
}

func TestBuildMountTip_PartialOptions_SystemdUnit(t *testing.T) {
	rule := MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec"}
	d := MountDetail{
		State:          MountPartialOptions,
		CurrentOptions: "rw,nosuid,noexec,relatime",
		Present:        []string{"nosuid", "noexec"},
		Missing:        []string{"nodev"},
	}
	units := map[string]struct{ Path, Options string }{
		"tmp.mount": {
			Path:    "/etc/systemd/system/tmp.mount",
			Options: "mode=1777,strictatime,nosuid,noexec",
		},
	}
	tip := buildMountTip(rule, d, stubFstab(""), stubUnitFinder(units))

	if !strings.Contains(tip.Headline, "tmp.mount") {
		t.Errorf("headline should name the unit; got %q", tip.Headline)
	}
	body := strings.Join(tip.Body, "\n")
	if !strings.Contains(body, "/etc/systemd/system/tmp.mount") {
		t.Errorf("body should quote the unit path; got:\n%s", body)
	}
	if !strings.Contains(body, "/etc/systemd/system/tmp.mount.d") {
		t.Errorf("body should recommend a drop-in override under tmp.mount.d; got:\n%s", body)
	}
	if !strings.Contains(body, "Options=mode=1777,strictatime,nosuid,noexec,nodev") {
		t.Errorf("body should show the merged Options= line; got:\n%s", body)
	}
	if !strings.Contains(body, "systemctl daemon-reload") {
		t.Errorf("body should include daemon-reload; got:\n%s", body)
	}
}

func TestBuildMountTip_PartialOptions_NoFstabNoUnit_DevShm(t *testing.T) {
	// The SDNS case: /dev/shm is partially hardened, /etc/fstab has
	// no line for it, no .mount unit either. The tip must explain
	// why nothing was found and recommend creating an fstab entry.
	rule := MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec"}
	d := MountDetail{
		State:          MountPartialOptions,
		CurrentOptions: "rw,nosuid,nodev,inode64",
		Present:        []string{"nodev", "nosuid"},
		Missing:        []string{"noexec"},
	}
	tip := buildMountTip(rule, d, stubFstab(""), stubUnitFinder(nil))

	if !strings.Contains(tip.Headline, "fstab") {
		t.Errorf("headline should steer operator at fstab; got %q", tip.Headline)
	}
	body := strings.Join(tip.Body, "\n")
	if !strings.Contains(body, "mounted by systemd PID 1") {
		t.Errorf("body should explain why grep -R /etc returns nothing; got:\n%s", body)
	}
	if !strings.Contains(body, "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0") {
		t.Errorf("body should suggest a concrete fstab line; got:\n%s", body)
	}
}

func TestBuildMountTip_NotSeparate_Tmp(t *testing.T) {
	rule := MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec"}
	d := MountDetail{State: MountNotSeparate}
	tip := buildMountTip(rule, d, stubFstab(""), stubUnitFinder(nil))

	body := strings.Join(tip.Body, "\n")
	if !strings.Contains(body, "Option A") || !strings.Contains(body, "Option B") {
		t.Errorf("the not-separate tip should offer tmpfs AND loop options; got:\n%s", body)
	}
	if !strings.Contains(body, "fallocate -l 4G /var/tmpDSK") {
		t.Errorf("loop option should include fallocate command; got:\n%s", body)
	}
	if !strings.Contains(body, "tmpfs /tmp tmpfs nodev,nosuid,noexec,size=4G,mode=1777 0 0") {
		t.Errorf("tmpfs option should include a concrete fstab line; got:\n%s", body)
	}
}

func TestBuildMountTip_NotSeparate_VarTmp(t *testing.T) {
	rule := MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"}
	d := MountDetail{State: MountNotSeparate}
	tip := buildMountTip(rule, d, stubFstab(""), stubUnitFinder(nil))

	body := strings.Join(tip.Body, "\n")
	if !strings.Contains(body, "/tmp /var/tmp none bind 0 0") {
		t.Errorf("/var/tmp tip should recommend a bind mount to /tmp; got:\n%s", body)
	}
}

func TestBuildMountTip_Symlink(t *testing.T) {
	rule := MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"}
	d := MountDetail{State: MountSymlink, SymlinkTarget: "/tmp"}
	tip := buildMountTip(rule, d, stubFstab(""), stubUnitFinder(nil))

	if !strings.Contains(tip.Headline, "/tmp") {
		t.Errorf("symlink tip headline should name the target; got %q", tip.Headline)
	}
	body := strings.Join(tip.Body, "\n")
	if !strings.Contains(body, "/tmp row") {
		t.Errorf("symlink tip should direct operator at the target row; got:\n%s", body)
	}
}

func TestBuildMountTip_BindOfAnother(t *testing.T) {
	rule := MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"}
	d := MountDetail{
		State:           MountBindOfAnother,
		BindPrimaryPath: "/tmp",
		Source:          "/dev/loop0",
		Missing:         []string{"nodev"},
	}
	tip := buildMountTip(rule, d, stubFstab(""), stubUnitFinder(nil))

	if !strings.Contains(tip.Headline, "/tmp") {
		t.Errorf("bind tip headline should name the primary; got %q", tip.Headline)
	}
	body := strings.Join(tip.Body, "\n")
	if !strings.Contains(body, "/dev/loop0") {
		t.Errorf("bind tip body should name the shared source; got:\n%s", body)
	}
	if !strings.Contains(body, "mount -o remount,nodev /var/tmp") {
		t.Errorf("bind tip should still expose a single-side remount escape hatch; got:\n%s", body)
	}
}

func TestParseFstab_SkipsCommentsAndBlanks(t *testing.T) {
	content := `# fstab
UUID=abc / ext4 defaults 0 1

tmpfs /tmp tmpfs nodev,nosuid 0 0
# comment after data
malformed three fields
`
	got := parseFstab(content)
	if len(got) != 2 {
		t.Fatalf("expected 2 lines, got %d: %+v", len(got), got)
	}
	if got[0].MountPoint != "/" || got[1].MountPoint != "/tmp" {
		t.Errorf("unexpected lines: %+v", got)
	}
	if got[1].LineNumber != 4 {
		t.Errorf("expected line number 4 for /tmp, got %d", got[1].LineNumber)
	}
}

func TestUnitNameForMountPath(t *testing.T) {
	tests := map[string]string{
		"/tmp":     "tmp.mount",
		"/var/tmp": "var-tmp.mount",
		"/dev/shm": "dev-shm.mount",
		"/":        "-.mount",
	}
	for path, want := range tests {
		if got := unitNameForMountPath(path); got != want {
			t.Errorf("unitNameForMountPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestParseUnitOptionsLine(t *testing.T) {
	unit := `[Unit]
Description=Test mount
Before=local-fs.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,nosuid,nodev
`
	if got := parseUnitOptionsLine(unit); got != "mode=1777,nosuid,nodev" {
		t.Errorf("got %q, want mode=1777,nosuid,nodev", got)
	}

	// Options= line in [Install] section should be ignored.
	unit2 := `[Install]
Options=should-be-ignored
`
	if got := parseUnitOptionsLine(unit2); got != "" {
		t.Errorf("Options outside [Mount] should be ignored; got %q", got)
	}
}

func TestAppendMissingToCSV_NoDuplicates(t *testing.T) {
	got := appendMissingToCSV("defaults,nosuid", []string{"nosuid", "nodev"})
	if got != "defaults,nosuid,nodev" {
		t.Errorf("got %q, want defaults,nosuid,nodev", got)
	}
}
