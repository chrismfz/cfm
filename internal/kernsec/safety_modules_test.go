package kernsec

import (
	"strings"
	"testing"
)

func TestNoDangerousModulesInRegistry(t *testing.T) {
	// Compile-time-test invariant: every module rule kernsec ships
	// MUST NOT match a dangerous-driver pattern. This is the
	// belt-and-suspenders companion to the apply-time guard in
	// applyCore — a future PR adding e.g. `nvme_core` to Tier 1
	// would never make it past CI.
	if err := CheckSafeModuleRules(AllModules()); err != nil {
		t.Fatalf("dangerous module(s) in registry — would risk bricking next-boot:\n%v", err)
	}
}

func TestIsDangerousModule(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Storage — must reject
		{"nvme", true},
		{"nvme_core", true},
		{"nvme_tcp", true},
		{"ahci", true},
		{"sd_mod", true},
		{"libata", true},
		{"megaraid_sas", true},
		{"virtio_blk", true},
		{"xhci_pci", true},
		{"usb_storage", true},
		{"usb-storage", true},
		// Filesystems — must reject
		{"xfs", true},
		{"ext4", true},
		{"btrfs", true},
		{"vfat", true},
		{"overlay", true},
		// Network — must reject
		{"e1000e", true},
		{"igb", true},
		{"ixgbe", true},
		{"virtio_net", true},
		{"mlx5_core", true},
		// Console / video — must reject
		{"i915", true},
		{"amdgpu", true},
		{"nouveau", true},
		{"drm", true},
		{"vga", true},

		// Existing kernsec blacklist names — must accept
		{"ksmbd", false},
		{"vivid", false},
		{"binfmt_aout", false},
		{"dccp", false},
		{"sctp", false},
		{"bluetooth", false},
		{"firewire-core", false},
		{"thunderbolt", false},

		// Non-pattern-prefix collisions — must NOT false-positive
		{"random_seed", false},  // does not start with `raid`
		{"vm_stat", false},      // does not start with `vmxnet3`
		{"i2c_core", false},     // does not start with `i915`
		{"foo_xfs_thing", false}, // `xfs` only matches at prefix
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsDangerousModule(tc.name); got != tc.want {
				t.Errorf("IsDangerousModule(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestCheckSafeModuleRules_NamesEveryOffender(t *testing.T) {
	// Operator-friendly: error names every offending rule, not just
	// the first one. Hunting them one-at-a-time is awful.
	rules := []ModuleRule{
		{ID: "TEST-001", Name: "nvme"},
		{ID: "TEST-002", Name: "ksmbd"}, // safe
		{ID: "TEST-003", Name: "ext4"},
	}
	err := CheckSafeModuleRules(rules)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "nvme") {
		t.Errorf("error should name nvme: %v", msg)
	}
	if !strings.Contains(msg, "ext4") {
		t.Errorf("error should name ext4: %v", msg)
	}
	if strings.Contains(msg, "ksmbd") {
		t.Errorf("error should NOT name safe rule ksmbd: %v", msg)
	}
}

func TestCheckSafeModuleRules_EmptyAndAllSafe(t *testing.T) {
	if err := CheckSafeModuleRules(nil); err != nil {
		t.Errorf("nil rules should be safe, got %v", err)
	}
	safe := []ModuleRule{
		{ID: "T1", Name: "ksmbd"},
		{ID: "T2", Name: "dccp"},
		{ID: "T3", Name: "bluetooth"},
	}
	if err := CheckSafeModuleRules(safe); err != nil {
		t.Errorf("all-safe rules should pass, got %v", err)
	}
}
