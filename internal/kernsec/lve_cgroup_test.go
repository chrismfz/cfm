package kernsec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLVECgroupStatus(t *testing.T) {
	tests := []struct {
		name    string
		profile HostProfile
		show    bool
		warn    bool
		wantSub string
	}{
		{
			name:    "non-cloudlinux host skips section",
			profile: HostProfile{},
			show:    false,
		},
		{
			name:    "LVE on unified cgroup v2 warns with the fix",
			profile: HostProfile{HasCloudLinuxLVE: true, CgroupV2Unified: true},
			show:    true,
			warn:    true,
			wantSub: "systemd.unified_cgroup_hierarchy=0",
		},
		{
			name:    "LVE on cgroup v1 is OK",
			profile: HostProfile{HasCloudLinuxLVE: true, CgroupV2Unified: false},
			show:    true,
			warn:    false,
			wantSub: "LVE-compatible",
		},
		{
			name:    "CageFS on v2 also warns",
			profile: HostProfile{HasCageFS: true, CgroupV2Unified: true},
			show:    true,
			warn:    true,
			wantSub: "resource limit reached",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lines, warn, show := lveCgroupStatus(tc.profile)
			if show != tc.show {
				t.Fatalf("show = %v, want %v", show, tc.show)
			}
			if !show {
				if len(lines) != 0 || warn {
					t.Fatalf("skipped section must return no lines and no warn; got lines=%v warn=%v", lines, warn)
				}
				return
			}
			if warn != tc.warn {
				t.Errorf("warn = %v, want %v", warn, tc.warn)
			}
			joined := strings.Join(lines, "\n")
			if tc.wantSub != "" && !strings.Contains(joined, tc.wantSub) {
				t.Errorf("lines missing %q:\n%s", tc.wantSub, joined)
			}
		})
	}
}

func TestDetectCgroupV2Unified(t *testing.T) {
	origRoot := hostProfileProbeRoot
	t.Cleanup(func() { hostProfileProbeRoot = origRoot })

	// Legacy v1 (and hybrid) keep /sys/fs/cgroup as a tmpfs with
	// per-controller subdirectories and NO cgroup.controllers at the root.
	v1Root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(v1Root, "sys/fs/cgroup/memory"), 0o755); err != nil {
		t.Fatal(err)
	}
	hostProfileProbeRoot = v1Root
	if detectCgroupV2Unified() {
		t.Error("legacy v1 layout must not be detected as unified cgroup v2")
	}

	// Pure unified v2 exposes cgroup.controllers at the root of the mount.
	v2Root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(v2Root, "sys/fs/cgroup"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(v2Root, "sys/fs/cgroup/cgroup.controllers"), []byte("cpuset cpu memory\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	hostProfileProbeRoot = v2Root
	if !detectCgroupV2Unified() {
		t.Error("unified v2 layout (root cgroup.controllers) must be detected")
	}
}
