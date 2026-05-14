package kernsec

import (
	"errors"
	"io/fs"
	"os"
	"reflect"
	"testing"
	"time"
)

// stubFileInfo is a minimal os.FileInfo implementation that lets tests
// drive the symlink branch of checkMountDetail without touching the
// real filesystem.
type stubFileInfo struct {
	mode os.FileMode
}

func (s stubFileInfo) Name() string       { return "" }
func (s stubFileInfo) Size() int64        { return 0 }
func (s stubFileInfo) Mode() os.FileMode  { return s.mode }
func (s stubFileInfo) ModTime() time.Time { return time.Time{} }
func (s stubFileInfo) IsDir() bool        { return s.mode.IsDir() }
func (s stubFileInfo) Sys() any           { return nil }

// stubFS bundles lstat+readlink overrides for one test, keyed by
// audit path. Missing entries fall through to "not a symlink".
type stubFS struct {
	links map[string]string // path -> symlink target
}

func (s stubFS) lstat(p string) (os.FileInfo, error) {
	if _, ok := s.links[p]; ok {
		return stubFileInfo{mode: os.ModeSymlink}, nil
	}
	return stubFileInfo{mode: 0o755}, nil
}
func (s stubFS) readlink(p string) (string, error) {
	if target, ok := s.links[p]; ok {
		return target, nil
	}
	return "", &fs.PathError{Op: "readlink", Path: p, Err: errors.New("not a link")}
}

func TestHasAllMountOptions(t *testing.T) {
	tests := []struct {
		name        string
		current     string
		recommended string
		want        bool
	}{
		{name: "exact match", current: "nodev,nosuid,noexec", recommended: "nodev,nosuid,noexec", want: true},
		{name: "subset present", current: "rw,nosuid,nodev,seclabel,noexec,size=8G", recommended: "nodev,nosuid,noexec", want: true},
		{name: "ordering insensitive", current: "noexec,nosuid,nodev", recommended: "nodev,nosuid,noexec", want: true},
		{name: "missing one option", current: "rw,nodev,nosuid,seclabel", recommended: "nodev,nosuid,noexec", want: false},
		{name: "empty current", current: "", recommended: "nodev", want: false},
		{name: "empty recommended trivially passes", current: "rw", recommended: "", want: true},
		{name: "whitespace tolerated", current: " nodev , nosuid , noexec ", recommended: "nodev,nosuid,noexec", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasAllMountOptions(tc.current, tc.recommended); got != tc.want {
				t.Errorf("hasAllMountOptions(%q, %q) = %v, want %v",
					tc.current, tc.recommended, got, tc.want)
			}
		})
	}
}

func TestSplitMountOptions(t *testing.T) {
	tests := []struct {
		name        string
		current     string
		recommended string
		wantPresent []string
		wantMissing []string
	}{
		{
			name:        "two of three present",
			current:     "rw,nosuid,noexec,relatime,discard",
			recommended: "nodev,nosuid,noexec",
			wantPresent: []string{"nosuid", "noexec"},
			wantMissing: []string{"nodev"},
		},
		{
			name:        "all present",
			current:     "rw,nodev,nosuid,noexec",
			recommended: "nodev,nosuid,noexec",
			wantPresent: []string{"nodev", "nosuid", "noexec"},
			wantMissing: nil,
		},
		{
			name:        "none present",
			current:     "rw,relatime",
			recommended: "nodev,nosuid,noexec",
			wantPresent: nil,
			wantMissing: []string{"nodev", "nosuid", "noexec"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotP, gotM := splitMountOptions(tc.current, tc.recommended)
			if !reflect.DeepEqual(gotP, tc.wantPresent) {
				t.Errorf("present: got %v, want %v", gotP, tc.wantPresent)
			}
			if !reflect.DeepEqual(gotM, tc.wantMissing) {
				t.Errorf("missing: got %v, want %v", gotM, tc.wantMissing)
			}
		})
	}
}

func TestCheckMountFromProc(t *testing.T) {
	procMounts := `rootfs / rootfs rw 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,seclabel,size=8128124k,nr_inodes=409600,inode64 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,seclabel,inode64 0 0
`
	tests := []struct {
		name      string
		rule      MountRule
		wantState MountState
	}{
		{
			name: "/tmp partial (missing noexec)",
			rule: MountRule{
				MountPoint:  "/tmp",
				Recommended: "nodev,nosuid,noexec",
			},
			// Two of three recommended options present; one missing.
			wantState: MountPartialOptions,
		},
		{
			name: "/dev/shm has all options",
			rule: MountRule{
				MountPoint:  "/dev/shm",
				Recommended: "nodev,nosuid,noexec",
			},
			wantState: MountOK,
		},
		{
			name: "/var/tmp not a separate mount",
			rule: MountRule{
				MountPoint:  "/var/tmp",
				Recommended: "nodev,nosuid,noexec",
			},
			wantState: MountNotSeparate,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := checkMountFromProc(procMounts, tc.rule)
			if state != tc.wantState {
				t.Errorf("got state %d, want %d", state, tc.wantState)
			}
		})
	}
}

func TestCheckMountDetail_PartialNamesMissingOnly(t *testing.T) {
	// The orion case from the field: /dev/loop0 mounted at /tmp with
	// nosuid,noexec but no nodev. PARTIAL must report nodev as the
	// only missing option so the renderer's remount command names
	// just `nodev`, not the whole recommended set.
	procMounts := `/dev/loop0 /tmp ext4 rw,nosuid,noexec,relatime,discard 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink, nil, nil)
	if d.State != MountPartialOptions {
		t.Fatalf("state = %d, want MountPartialOptions", d.State)
	}
	if !reflect.DeepEqual(d.Present, []string{"nosuid", "noexec"}) {
		t.Errorf("present = %v, want [nosuid noexec]", d.Present)
	}
	if !reflect.DeepEqual(d.Missing, []string{"nodev"}) {
		t.Errorf("missing = %v, want [nodev]", d.Missing)
	}
}

func TestCheckMountDetail_FullyMissingHasEmptyPresent(t *testing.T) {
	procMounts := `/dev/sda1 /home ext4 rw,noatime 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/home", Recommended: "nodev,nosuid"},
		nil, stubFS{}.lstat, stubFS{}.readlink, nil, nil)
	if d.State != MountMissingOptions {
		t.Fatalf("state = %d, want MountMissingOptions", d.State)
	}
	if len(d.Present) != 0 {
		t.Errorf("present = %v, want empty", d.Present)
	}
}

func TestCheckMountDetail_Symlink(t *testing.T) {
	// /var/tmp → /tmp is the cPanel/CloudLinux pattern. The audit
	// must defer rather than re-audit and double-warn.
	procMounts := `/dev/loop0 /tmp ext4 rw,nosuid,noexec 0 0
`
	links := map[string]string{"/var/tmp": "/tmp"}
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{links: links}.lstat, stubFS{links: links}.readlink, nil, nil)
	if d.State != MountSymlink {
		t.Fatalf("state = %d, want MountSymlink", d.State)
	}
	if d.SymlinkTarget != "/tmp" {
		t.Errorf("symlink target = %q, want /tmp", d.SymlinkTarget)
	}
}

func TestCheckMountDetail_BindOfAnother(t *testing.T) {
	// The cPanel pattern: /usr/tmpDSK bind-mounted onto both /tmp and
	// /var/tmp. /tmp appears first in Tier1Mounts; /var/tmp's audit
	// row must defer to /tmp. This fixture is missing `nodev` on both
	// sides, so the bind sibling /var/tmp still surfaces as
	// MountBindOfAnother — remediation is "fix the primary row to
	// inherit", not "remount this side directly".
	procMounts := `/dev/loop0 /tmp ext4 rw,nosuid,noexec,relatime,discard 0 0
/dev/loop0 /var/tmp ext4 rw,nosuid,noexec,relatime,discard 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink, nil, nil)
	if d.State != MountBindOfAnother {
		t.Fatalf("state = %d, want MountBindOfAnother", d.State)
	}
	if d.BindPrimaryPath != "/tmp" {
		t.Errorf("bind primary = %q, want /tmp", d.BindPrimaryPath)
	}
}

func TestCheckMountDetail_BindOfAnotherFullyHardened(t *testing.T) {
	// The post-`cfm kernsec secure-tmp` shape from a real production
	// host: same source on /tmp and /var/tmp, both with the full
	// recommended option set live. The bind sibling /var/tmp must
	// render as MountOK (green) but keep BindPrimaryPath populated so
	// the renderer can add the "inherits hardening from /tmp" note.
	// Previously this row surfaced as a SKIP that operators had to
	// mentally resolve.
	procMounts := `/dev/loop0 /tmp ext4 rw,nosuid,nodev,noexec,relatime 0 0
/dev/loop0 /var/tmp ext4 rw,nosuid,nodev,noexec,relatime 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/var/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink, nil, nil)
	if d.State != MountOK {
		t.Fatalf("state = %d, want MountOK (fully-hardened bind sibling)", d.State)
	}
	if d.BindPrimaryPath != "/tmp" {
		t.Errorf("bind primary = %q, want /tmp (kept for the 'inherits' note)", d.BindPrimaryPath)
	}
	if len(d.Missing) != 0 {
		t.Errorf("Missing = %v, want []", d.Missing)
	}
}

func TestCheckMountDetail_BindPrimaryRowItselfStillOK(t *testing.T) {
	// The primary side of a bind pair (/tmp, first in Tier1Mounts)
	// must not pick up BindPrimaryPath — it IS the primary; nothing
	// "earlier" in the peer list shares its source. Sanity check the
	// peer-iteration short-circuit at p.MountPoint == rule.MountPoint.
	procMounts := `/dev/loop0 /tmp ext4 rw,nosuid,nodev,noexec,relatime 0 0
/dev/loop0 /var/tmp ext4 rw,nosuid,nodev,noexec,relatime 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/tmp", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink, nil, nil)
	if d.State != MountOK {
		t.Fatalf("state = %d, want MountOK", d.State)
	}
	if d.BindPrimaryPath != "" {
		t.Errorf("primary row should not carry BindPrimaryPath, got %q", d.BindPrimaryPath)
	}
}

func TestCheckMountDetail_GenericSourcesAreNotBinds(t *testing.T) {
	// Two tmpfs mounts (/tmp + /dev/shm) share the source string
	// "tmpfs" but are NOT bind mounts of each other. The audit must
	// not treat them as siblings.
	procMounts := `tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0
`
	d := checkMountDetail(procMounts,
		MountRule{MountPoint: "/dev/shm", Recommended: "nodev,nosuid,noexec"},
		Tier1Mounts, stubFS{}.lstat, stubFS{}.readlink, nil, nil)
	if d.State == MountBindOfAnother {
		t.Fatal("/dev/shm tmpfs must not be flagged as a bind of /tmp tmpfs (shared generic source)")
	}
	if d.State != MountOK {
		t.Errorf("state = %d, want MountOK", d.State)
	}
}

func TestMountRowState(t *testing.T) {
	tests := []struct {
		name string
		s    MountState
		want RuleState
	}{
		{name: "ok mount maps to OK", s: MountOK, want: StateOK},
		{name: "partial maps to DIFF", s: MountPartialOptions, want: StateDIFF},
		{name: "missing options maps to DIFF", s: MountMissingOptions, want: StateDIFF},
		{name: "not separate maps to SKIP", s: MountNotSeparate, want: StateSKIP},
		{name: "symlink maps to SKIP", s: MountSymlink, want: StateSKIP},
		{name: "bind sibling maps to SKIP", s: MountBindOfAnother, want: StateSKIP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mountRowState(tc.s); got != tc.want {
				t.Errorf("mountRowState(%d) = %s, want %s", tc.s, got, tc.want)
			}
		})
	}
}

func TestMountRowStateForDecision(t *testing.T) {
	tests := []struct {
		name string
		d    Decision
		s    MountState
		want RuleState
	}{
		{name: "tier0 -> OFF", d: SkipByTier, s: MountMissingOptions, want: StateOFF},
		{name: "per-rule skip -> OFF", d: SkipByConf, s: MountOK, want: StateOFF},
		{name: "host-profile skip -> SKIP", d: SkipByHostProfile, s: MountMissingOptions, want: StateSKIP},
		{name: "apply + ok -> OK", d: Apply, s: MountOK, want: StateOK},
		{name: "apply + partial -> DIFF", d: Apply, s: MountPartialOptions, want: StateDIFF},
		{name: "apply + missing -> DIFF", d: Apply, s: MountMissingOptions, want: StateDIFF},
		{name: "apply + not-separate -> SKIP", d: Apply, s: MountNotSeparate, want: StateSKIP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mountRowStateForDecision(tc.d, tc.s); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBuildAuditRows_IncludesMountRows(t *testing.T) {
	// Substitute a fixture /proc/mounts so the test is deterministic
	// across host filesystems.
	origReader := readProcMounts
	readProcMounts = func() string {
		return `tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,seclabel 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,seclabel 0 0
`
	}
	t.Cleanup(func() { readProcMounts = origReader })

	conf := &Conf{Tier: Tier1, Overrides: map[string]RuleOverride{}}
	rows := BuildAuditRows(conf, HostProfile{})

	mountRows := 0
	stateByMountPoint := map[string]RuleState{}
	for _, r := range rows {
		if r.Kind != KindMount {
			continue
		}
		mountRows++
		stateByMountPoint[r.MountPoint] = r.State
		if r.RecommendedOptions == "" {
			t.Errorf("mount row %s has empty RecommendedOptions", r.ID)
		}
	}
	if mountRows != len(Tier1Mounts) {
		t.Errorf("got %d mount rows, want %d", mountRows, len(Tier1Mounts))
	}
	// /tmp has full recommended set in the fixture → OK.
	if got := stateByMountPoint["/tmp"]; got != StateOK {
		t.Errorf("/tmp state = %s, want OK", got)
	}
	// /dev/shm has full set → OK.
	if got := stateByMountPoint["/dev/shm"]; got != StateOK {
		t.Errorf("/dev/shm state = %s, want OK", got)
	}
	// /var/tmp not in the fixture → SKIP (not a separate mount).
	if got := stateByMountPoint["/var/tmp"]; got != StateSKIP {
		t.Errorf("/var/tmp state = %s, want SKIP (not separate)", got)
	}
	// /home was deliberately removed from Tier1Mounts — make sure no
	// mount row references it any more.
	if _, ok := stateByMountPoint["/home"]; ok {
		t.Errorf("/home should no longer appear in Tier1Mounts audit rows")
	}
}
