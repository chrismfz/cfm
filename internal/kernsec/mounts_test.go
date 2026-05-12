package kernsec

import "testing"

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
			name: "/tmp missing noexec",
			rule: MountRule{
				MountPoint:  "/tmp",
				Recommended: "nodev,nosuid,noexec",
			},
			wantState: MountMissingOptions,
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

func TestMountRowState(t *testing.T) {
	tests := []struct {
		name string
		s    MountState
		want RuleState
	}{
		{name: "ok mount maps to OK", s: MountOK, want: StateOK},
		{name: "missing options maps to DIFF", s: MountMissingOptions, want: StateDIFF},
		{name: "not separate maps to SKIP", s: MountNotSeparate, want: StateSKIP},
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
		return `tmpfs /tmp tmpfs rw,nosuid,nodev,seclabel 0 0
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
	// /tmp lacks noexec → DIFF.
	if got := stateByMountPoint["/tmp"]; got != StateDIFF {
		t.Errorf("/tmp state = %s, want DIFF (missing noexec)", got)
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
