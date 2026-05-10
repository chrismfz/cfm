package kernsec

import (
	"strings"
	"testing"
)

func TestTier1ModulesRemainNonDangerous(t *testing.T) {
	// Registry invariant: every Tier1Modules entry kernsec ships MUST NOT
	// match a dangerous-driver pattern. The delayed-brick scenario this
	// prevents is dracut host-only embedding /etc/modprobe.d/*.conf into a
	// future initramfs, so blacklisting the live rootfs / storage / network /
	// console driver can brick the NEXT reboot after a kernel update instead
	// of failing immediately during apply.
	for _, rule := range Tier1Modules {
		rule := rule
		t.Run(rule.ID+"/"+rule.Name, func(t *testing.T) {
			if IsDangerousModule(rule.Name) {
				t.Fatalf("Tier1 module %q (%s) matches dangerous pattern", rule.Name, rule.ID)
			}
		})
	}
}

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
		desc string
		name string
		want bool
	}{
		// Storage — must reject.
		{desc: "storage/nvme exact", name: "nvme", want: true},
		{desc: "storage/nvme core", name: "nvme_core", want: true},
		{desc: "storage/nvme tcp", name: "nvme_tcp", want: true},
		{desc: "storage/ahci", name: "ahci", want: true},
		{desc: "storage/ata piix", name: "ata_piix", want: true},
		{desc: "storage/sd_mod", name: "sd_mod", want: true},
		{desc: "storage/libata", name: "libata", want: true},
		{desc: "storage/megaraid sas", name: "megaraid_sas", want: true},
		{desc: "storage/qlogic fc", name: "qla2xxx", want: true},
		{desc: "storage/iscsi root", name: "iscsi_tcp", want: true},
		{desc: "storage/virtio block", name: "virtio_blk", want: true},
		{desc: "storage/hyper-v disk", name: "hv_storvsc", want: true},
		{desc: "storage/usb xhci", name: "xhci_pci", want: true},
		{desc: "storage/usb storage underscore", name: "usb_storage", want: true},
		{desc: "storage/usb storage hyphen", name: "usb-storage", want: true},
		{desc: "storage/usb attached scsi", name: "uas", want: true},

		// Root filesystems — must reject.
		{desc: "rootfs/xfs", name: "xfs", want: true},
		{desc: "rootfs/ext4", name: "ext4", want: true},
		{desc: "rootfs/btrfs", name: "btrfs", want: true},
		{desc: "rootfs/f2fs", name: "f2fs", want: true},
		{desc: "rootfs/zfs", name: "zfs", want: true},
		{desc: "rootfs/vfat", name: "vfat", want: true},
		{desc: "rootfs/overlay", name: "overlay", want: true},
		{desc: "rootfs/virtiofs", name: "virtiofs", want: true},
		{desc: "rootfs/nfs remote root", name: "nfs", want: true},
		{desc: "rootfs/cifs remote root", name: "cifs", want: true},
		{desc: "rootfs/9p remote root", name: "9pnet_virtio", want: true},

		// Networking — must reject.
		{desc: "network/e1000e", name: "e1000e", want: true},
		{desc: "network/igb", name: "igb", want: true},
		{desc: "network/ixgbe", name: "ixgbe", want: true},
		{desc: "network/aws ena", name: "ena", want: true},
		{desc: "network/hyper-v", name: "hv_netvsc", want: true},
		{desc: "network/xen", name: "xen_netfront", want: true},
		{desc: "network/virtio", name: "virtio_net", want: true},
		{desc: "network/mlx5", name: "mlx5_core", want: true},
		{desc: "network/broadcom", name: "bnxt_en", want: true},
		{desc: "network/qlogic", name: "qede", want: true},

		// Netfilter — must reject.
		{desc: "netfilter/conntrack", name: "nf_conntrack", want: true},
		{desc: "netfilter/nat", name: "nf_nat", want: true},
		{desc: "netfilter/tables", name: "nf_tables", want: true},
		{desc: "netfilter/nft chain", name: "nft_chain_nat", want: true},
		{desc: "netfilter/iptables", name: "ip_tables", want: true},
		{desc: "netfilter/iptable filter", name: "iptable_filter", want: true},
		{desc: "netfilter/ip6tables", name: "ip6_tables", want: true},
		{desc: "netfilter/x_tables", name: "x_tables", want: true},
		{desc: "netfilter/xt match", name: "xt_conntrack", want: true},
		{desc: "netfilter/bridge", name: "br_netfilter", want: true},
		{desc: "netfilter/ipset", name: "ip_set_hash_ip", want: true},

		// Console / video — must reject.
		{desc: "console/i915", name: "i915", want: true},
		{desc: "console/amdgpu", name: "amdgpu", want: true},
		{desc: "console/nouveau", name: "nouveau", want: true},
		{desc: "console/drm", name: "drm", want: true},
		{desc: "console/simpledrm", name: "simpledrm", want: true},
		{desc: "console/vga", name: "vga", want: true},
		{desc: "console/efi framebuffer", name: "efifb", want: true},
		{desc: "console/virtio serial", name: "virtio_console", want: true},
		{desc: "console/8250 serial", name: "8250_pci", want: true},

		// Virtualization substrate — must reject.
		{desc: "virtualization/virtio pci", name: "virtio_pci", want: true},
		{desc: "virtualization/virtio ring", name: "virtio_ring", want: true},
		{desc: "virtualization/hyper-v bus", name: "hv_vmbus", want: true},
		{desc: "virtualization/vmware pvscsi", name: "vmw_pvscsi", want: true},
		{desc: "virtualization/vmware gfx", name: "vmwgfx", want: true},
		{desc: "virtualization/xen bus", name: "xenbus", want: true},
		{desc: "virtualization/virtualbox guest", name: "vboxguest", want: true},

		// CloudLinux / hosting kernel extensions — must reject.
		{desc: "hosting/cloudlinux lve", name: "lve", want: true},
		{desc: "hosting/cloudlinux kmodlve", name: "kmodlve", want: true},
		{desc: "hosting/kernelcare", name: "kcare", want: true},
		{desc: "hosting/kpatch", name: "kpatch", want: true},
		{desc: "hosting/openvz", name: "vzdev", want: true},
		{desc: "hosting/ploop", name: "ploop", want: true},

		// Existing kernsec blacklist names — must accept.
		{desc: "safe/ksmbd", name: "ksmbd", want: false},
		{desc: "safe/vivid", name: "vivid", want: false},
		{desc: "safe/binfmt_aout", name: "binfmt_aout", want: false},
		{desc: "safe/dccp", name: "dccp", want: false},
		{desc: "safe/sctp", name: "sctp", want: false},
		{desc: "safe/cramfs", name: "cramfs", want: false},
		{desc: "safe/algif_hash", name: "algif_hash", want: false},
		{desc: "safe/bluetooth", name: "bluetooth", want: false},
		{desc: "safe/firewire-core", name: "firewire-core", want: false},
		{desc: "safe/firewire-sbp2", name: "firewire-sbp2", want: false},
		{desc: "safe/thunderbolt", name: "thunderbolt", want: false},
		{desc: "safe/nfc", name: "nfc", want: false},
		{desc: "safe/nfcsim", name: "nfcsim", want: false},

		// Non-pattern-prefix collisions — must NOT false-positive.
		{desc: "collision/random_seed not raid", name: "random_seed", want: false},
		{desc: "collision/vm_stat not vmxnet3", name: "vm_stat", want: false},
		{desc: "collision/i2c_core not i915", name: "i2c_core", want: false},
		{desc: "collision/foo_xfs_thing only contains xfs", name: "foo_xfs_thing", want: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			if got := IsDangerousModule(tc.name); got != tc.want {
				t.Errorf("IsDangerousModule(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestCheckSafeModuleRules(t *testing.T) {
	tests := []struct {
		name         string
		rules        []ModuleRule
		wantErr      bool
		wantContains []string
		wantNot      []string
	}{
		{
			name:    "empty rules are safe",
			rules:   nil,
			wantErr: false,
		},
		{
			name: "all safe rules pass",
			rules: []ModuleRule{
				{ID: "T1", Name: "ksmbd"},
				{ID: "T2", Name: "dccp"},
				{ID: "T3", Name: "bluetooth"},
			},
			wantErr: false,
		},
		{
			name: "names every offender",
			rules: []ModuleRule{
				{ID: "TEST-001", Name: "nvme"},
				{ID: "TEST-002", Name: "ksmbd"}, // safe
				{ID: "TEST-003", Name: "ext4"},
			},
			wantErr:      true,
			wantContains: []string{"nvme", "ext4"},
			wantNot:      []string{"ksmbd"},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSafeModuleRules(tc.rules)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if err == nil {
				return
			}
			msg := err.Error()
			for _, want := range tc.wantContains {
				if !strings.Contains(msg, want) {
					t.Errorf("error should name %s: %v", want, msg)
				}
			}
			for _, forbidden := range tc.wantNot {
				if strings.Contains(msg, forbidden) {
					t.Errorf("error should NOT name safe rule %s: %v", forbidden, msg)
				}
			}
		})
	}
}
