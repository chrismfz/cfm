package kernsec

// Tier1Modules is the safe-everywhere module-blacklist set: legacy
// network protocols, recently exploited modules with no use case on
// hosting / KVM / cPanel / EL / Debian boxes, dead filesystems, dead
// buses, and the broader algif_* userspace crypto API surface beyond
// what kspp.sh's initcall_blacklist already covers.
//
// Phase 2 carries the data (rule rows surface in `cfm kernsec preview`
// / TUI). The /etc/modprobe.d/cfm-kernsec.conf generator that actually
// disables them lives in Phase 3.
//
// IDs follow KSEC-MOD-<group>-<NNN>. Group tags match docs/kernsec.md.
// Per-host gating (e.g. skip ipsec group when `ip xfrm policy` is
// non-empty, skip wireless on hosts with wifi hardware) is the host
// profile probe's job — see profile_probe.go.
//
// NFS, cifs, and io_uring are intentionally excluded per operator use
// (NFS-over-VPN; io_uring with NVMe). Do not add them here.
var Tier1Modules = []ModuleRule{

	// --- modules.recent_cves: recently exploited, no hosting use -----

	{
		ID: "KSEC-MOD-recent_cves-001", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "ksmbd",
		Description: "In-kernel SMB server with multiple LPE CVEs 2023-2025.",
		Affects:     "None on hosting (NFS-over-VPN preferred over SMB).",
	},
	{
		ID: "KSEC-MOD-recent_cves-002", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "n_hdlc",
		Description: "TTY line discipline; the n_hdlc class of LPE exploits lives here.",
		Affects:     "None on servers.",
	},
	{
		ID: "KSEC-MOD-recent_cves-003", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "vivid",
		Description: "Virtual video driver, frequent CTF / CVE target.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-recent_cves-004", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "watch_queue",
		Description: "Vector for the Dirty Cred class.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-recent_cves-005", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "binfmt_aout",
		Description: "Dead a.out binfmt; occasional LPE vector.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-recent_cves-006", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "nfc",
		Description: "Near-field communication stack — never present on servers.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-recent_cves-007", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "nfcsim",
		Description: "NFC simulator; surface only useful to attackers.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-recent_cves-008", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "pn533",
		Description: "NFC reader driver; not used on servers.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-recent_cves-009", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "pn533_usb",
		Description: "USB transport for the NFC reader; same surface.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-recent_cves-010", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "kcm",
		Description: "Kernel Connection Multiplexor; CVE-2024-50264 UAF family. No hosting use.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-recent_cves-011", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "n_gsm",
		Description: "UMTS modem TTY line discipline; recent LPE chain. Same class as n_hdlc.",
		Affects:     "None on servers.",
	},
	{
		ID: "KSEC-MOD-recent_cves-012", Group: "modules.recent_cves", Tier: Tier1,
		Name:        "n_r3964",
		Description: "Siemens R3964 TTY line discipline — dead, CTF-popular surface.",
		Affects:     "None.",
	},

	// --- modules.net.legacy: dead network protocols ------------------

	{
		ID: "KSEC-MOD-net.legacy-001", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "dccp",
		Description: "Datagram Congestion Control — multiple LPE CVEs.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-003", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "tipc",
		Description: "Cluster IPC; has had LPEs.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-004", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "rds",
		Description: "Reliable Datagram Sockets; Oracle-internal.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-005", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "rxrpc",
		Description: "AFS RPC; never used on hosting.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-006", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "ax25",
		Description: "Ham-radio AX.25 — gone from any modern use case.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-007", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "netrom",
		Description: "Ham-radio NET/ROM.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-008", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "x25",
		Description: "X.25 protocol.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-009", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "rose",
		Description: "Ham-radio ROSE.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-010", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "decnet",
		Description: "DEC's DECnet protocol; long dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-011", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "econet",
		Description: "Acorn Econet; dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-012", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "ipx",
		Description: "Novell IPX; dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-013", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "appletalk",
		Description: "AppleTalk; dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-014", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "psnap",
		Description: "Subnetwork Access Protocol encapsulation.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-015", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "p8023",
		Description: "802.3 LLC encapsulation.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-016", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "p8022",
		Description: "802.2 LLC encapsulation.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-017", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "llc",
		Description: "Logical Link Control.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-018", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "llc2",
		Description: "LLC type 2.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-019", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "pptp",
		Description: "PPTP VPN protocol.",
		Affects:     "Breaks PPTP if anyone is still using it (don't).",
	},
	{
		ID: "KSEC-MOD-net.legacy-020", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "gtp",
		Description: "GPRS Tunneling Protocol.",
		Affects:     "None on hosting.",
	},
	{
		ID: "KSEC-MOD-net.legacy-021", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "can",
		Description: "Controller Area Network (automotive).",
		Affects:     "None on servers.",
	},
	{
		ID: "KSEC-MOD-net.legacy-022", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "atm",
		Description: "ATM stack; dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-023", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "irda",
		Description: "Infrared Data Association; gone from modern kernels.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-024", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "phonet",
		Description: "Nokia phone protocol; long dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-025", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "caif",
		Description: "ST-Ericsson modem comms (Communication CPU API Framework); dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-026", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "caif_socket",
		Description: "AF_CAIF socket family; dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-net.legacy-027", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "hsr",
		Description: "High-availability Seamless Redundancy; industrial fieldbus, not hosting.",
		Affects:     "None.",
	},

	// --- modules.net.virt: virt-only socket families ----------------
	//
	// Single-module group so host-profile gating can target it
	// precisely. vsock (virtio/VMware guest↔host socket protocol) is
	// a named killswitch candidate — useless on bare-metal hosting,
	// but the host-side transport (vhost_vsock) is a legitimate
	// hypervisor surface for guest comms. We skip the blacklist when
	// the host runs KVM (kvm_intel/kvm_amd loaded → IsKVMHost) so
	// hypervisors retain it; everywhere else it's blacklisted by
	// default.

	{
		ID: "KSEC-MOD-net.virt-001", Group: "modules.net.virt", Tier: Tier1,
		Name:        "vsock",
		Description: "Virtual socket protocol (virtio/VMware guest↔host). Named killswitch candidate; no use on bare-metal hosting.",
		Affects:     "Skipped automatically on KVM hosts (host-profile gated via IsKVMHost).",
	},

	// --- modules.net.iot: IEEE 802.15.4 / Zigbee-class wireless ------
	//
	// Low-power wireless PAN stack. Hosting boxes have no 802.15.4
	// radios; the module set exists only because distro kernels build
	// it. No host-profile gating — there is no detection probe for
	// 802.15.4 hardware and no realistic scenario where a hosting box
	// has one.

	{
		ID: "KSEC-MOD-net.iot-001", Group: "modules.net.iot", Tier: Tier1,
		Name:        "ieee802154",
		Description: "IEEE 802.15.4 protocol stack and AF_IEEE802154 socket family.",
		Affects:     "None on hosting.",
	},
	{
		ID: "KSEC-MOD-net.iot-002", Group: "modules.net.iot", Tier: Tier1,
		Name:        "mac802154",
		Description: "802.15.4 soft-MAC layer.",
		Affects:     "None on hosting.",
	},
	{
		ID: "KSEC-MOD-net.iot-003", Group: "modules.net.iot", Tier: Tier1,
		Name:        "6lowpan",
		Description: "IPv6 over Low-Power Wireless PANs.",
		Affects:     "None on hosting.",
	},

	// --- modules.fs.unused: filesystems no hosting box mounts --------

	{
		ID: "KSEC-MOD-fs.unused-001", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "cramfs",
		Description: "Embedded compressed ROM filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-002", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "freevxfs",
		Description: "Free Veritas filesystem reader.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-003", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "jffs2",
		Description: "Journaling Flash filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-004", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "hfs",
		Description: "macOS HFS filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-005", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "hfsplus",
		Description: "macOS HFS+ filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-006", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "udf",
		Description: "Universal Disk Format (optical media).",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-007", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "qnx4",
		Description: "QNX4 filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-008", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "qnx6",
		Description: "QNX6 filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-009", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "omfs",
		Description: "Optimized MPEG Filesystem (Rio Karma).",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-010", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "befs",
		Description: "BeOS filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-011", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "ufs",
		Description: "BSD UFS filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-012", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "affs",
		Description: "Amiga filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-013", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "sysv",
		Description: "AT&T System V filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-014", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "nilfs2",
		Description: "Continuous-snapshot filesystem; niche.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-015", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "gfs2",
		Description: "Cluster filesystem.",
		Affects:     "None on hosting.",
	},
	{
		ID: "KSEC-MOD-fs.unused-016", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "ocfs2",
		Description: "Oracle Cluster filesystem.",
		Affects:     "None on hosting.",
	},
	{
		ID: "KSEC-MOD-fs.unused-017", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "coda",
		Description: "Coda distributed filesystem.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-018", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "reiserfs",
		Description: "Officially deprecated filesystem; removed from upstream defaults.",
		Affects:     "None on modern hosting; legacy installs override with `state = skip`.",
	},

	// --- modules.fs.container: container-image filesystems ----------
	//
	// erofs (Enhanced Read-Only FS) is used by Android system images
	// and by some container layer formats. We default-blacklist it on
	// hosting boxes (no use case) but skip on hosts where containers
	// are running — runc/containerd/podman may pull layers that rely
	// on it.

	{
		ID: "KSEC-MOD-fs.container-001", Group: "modules.fs.container", Tier: Tier1,
		Name:        "erofs",
		Description: "Enhanced Read-Only FS; used by Android and some container image formats.",
		Affects:     "Skipped on hosts running containers (host-profile gated via HasContainers).",
	},

	// --- modules.bus.*: buses / devices not present on KVM/dedis ----
	//
	// Split into four sub-groups so host-profile gating can skip just
	// the relevant subset on hosts with the matching hardware:
	//
	//   modules.bus.bluetooth   skipped if HasBluetoothHardware
	//   modules.bus.thunderbolt skipped if HasThunderbolt
	//   modules.bus.firewire    no probe — dedicated FireWire cards
	//                           are rare; operator who has one
	//                           overrides with `state = skip` in conf
	//   modules.bus.misc        joydev / pcspkr / floppy — never
	//                           gate (no use case on servers)
	//
	// The previous single `modules.bus` group skipped or applied all
	// twelve modules together, so any hardware-aware gating was an
	// all-or-nothing trade-off (fix Bluetooth → skip floppy too).
	// IDs preserved across the rename so existing per-rule overrides
	// in operator-authored kernsec.conf files keep working.

	{
		ID: "KSEC-MOD-bus-001", Group: "modules.bus.bluetooth", Tier: Tier1,
		Name:        "bluetooth",
		Description: "Bluetooth core stack.",
		Affects:     "Skipped on hosts with Bluetooth hardware (host-profile gated).",
	},
	{
		ID: "KSEC-MOD-bus-002", Group: "modules.bus.bluetooth", Tier: Tier1,
		Name:        "btusb",
		Description: "USB Bluetooth dongle driver.",
		Affects:     "Skipped on hosts with Bluetooth hardware (host-profile gated).",
	},
	{
		ID: "KSEC-MOD-bus-003", Group: "modules.bus.bluetooth", Tier: Tier1,
		Name:        "bnep",
		Description: "Bluetooth network encapsulation.",
		Affects:     "Skipped on hosts with Bluetooth hardware (host-profile gated).",
	},
	{
		ID: "KSEC-MOD-bus-004", Group: "modules.bus.bluetooth", Tier: Tier1,
		Name:        "hci_uart",
		Description: "Bluetooth HCI over UART.",
		Affects:     "Skipped on hosts with Bluetooth hardware (host-profile gated).",
	},
	{
		ID: "KSEC-MOD-bus-005", Group: "modules.bus.firewire", Tier: Tier1,
		Name:        "firewire-core",
		Description: "FireWire stack — DMA attack surface.",
		Affects:     "None on servers; override per-rule if you actually use FireWire.",
	},
	{
		ID: "KSEC-MOD-bus-006", Group: "modules.bus.firewire", Tier: Tier1,
		Name:        "firewire-ohci",
		Description: "FireWire OHCI driver.",
		Affects:     "None on servers; override per-rule if you actually use FireWire.",
	},
	{
		ID: "KSEC-MOD-bus-007", Group: "modules.bus.firewire", Tier: Tier1,
		Name:        "firewire-net",
		Description: "FireWire networking.",
		Affects:     "None on servers; override per-rule if you actually use FireWire.",
	},
	{
		ID: "KSEC-MOD-bus-008", Group: "modules.bus.firewire", Tier: Tier1,
		Name:        "firewire-sbp2",
		Description: "FireWire storage transport.",
		Affects:     "None on servers; override per-rule if you actually use FireWire.",
	},
	{
		ID: "KSEC-MOD-bus-009", Group: "modules.bus.thunderbolt", Tier: Tier1,
		Name:        "thunderbolt",
		Description: "Thunderbolt stack — DMA attack surface.",
		Affects:     "Skipped on hosts with Thunderbolt hardware (host-profile gated).",
	},
	{
		ID: "KSEC-MOD-bus-010", Group: "modules.bus.misc", Tier: Tier1,
		Name:        "joydev",
		Description: "Joystick input — trivial surface, no use case.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-bus-011", Group: "modules.bus.misc", Tier: Tier1,
		Name:        "pcspkr",
		Description: "PC speaker driver.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-bus-012", Group: "modules.bus.misc", Tier: Tier1,
		Name:        "floppy",
		Description: "Floppy controller driver.",
		Affects:     "None.",
	},

	// --- modules.input.userspace: userspace virtual input devices ---
	//
	// uinput / uhid let a userspace process inject input events or
	// claim to be a HID device. Both have non-trivial historical
	// exploit surface and zero use case on a hosting / server box.

	{
		ID: "KSEC-MOD-input.userspace-001", Group: "modules.input.userspace", Tier: Tier1,
		Name:        "uinput",
		Description: "Userspace input device injection (synthetic keyboard/mouse events).",
		Affects:     "None on servers.",
	},
	{
		ID: "KSEC-MOD-input.userspace-002", Group: "modules.input.userspace", Tier: Tier1,
		Name:        "uhid",
		Description: "Userspace HID device — process claims to be a HID device.",
		Affects:     "None on servers.",
	},

	// --- modules.sidechannel ----------------------------------------

	{
		ID: "KSEC-MOD-sidechannel-001", Group: "modules.sidechannel", Tier: Tier1,
		Name:        "intel_rapl_common",
		Description: "Intel RAPL / Platypus power side-channel (CVE-2020-8694).",
		Affects:     "Loses RAPL power telemetry.",
	},
	{
		ID: "KSEC-MOD-sidechannel-002", Group: "modules.sidechannel", Tier: Tier1,
		Name:        "intel_rapl_msr",
		Description: "RAPL MSR interface; same family as CVE-2020-8694.",
		Affects:     "Loses RAPL power telemetry.",
	},

	// --- modules.crypto_userapi: extends kspp.sh's algif_aead block --

	{
		ID: "KSEC-MOD-crypto_userapi-001", Group: "modules.crypto_userapi", Tier: Tier1,
		Name:        "algif_hash",
		Description: "Userspace hash via AF_ALG.",
		Affects:     "Userspace tools using AF_ALG hash (rare).",
	},
	{
		ID: "KSEC-MOD-crypto_userapi-002", Group: "modules.crypto_userapi", Tier: Tier1,
		Name:        "algif_skcipher",
		Description: "Userspace symmetric cipher via AF_ALG.",
		Affects:     "Userspace tools using AF_ALG skcipher (rare).",
	},
	{
		ID: "KSEC-MOD-crypto_userapi-003", Group: "modules.crypto_userapi", Tier: Tier1,
		Name:        "algif_rng",
		Description: "Userspace RNG via AF_ALG.",
		Affects:     "Userspace tools using AF_ALG rng (rare).",
	},
	{
		ID: "KSEC-MOD-crypto_userapi-004", Group: "modules.crypto_userapi", Tier: Tier1,
		Name:        "algif_akcipher",
		Description: "Userspace asymmetric cipher via AF_ALG.",
		Affects:     "Userspace tools using AF_ALG akcipher (rare).",
	},
	{
		ID: "KSEC-MOD-crypto_userapi-005", Group: "modules.crypto_userapi", Tier: Tier1,
		Name:        "algif_aead",
		Description: "Userspace AEAD via AF_ALG; parity with the rest of the algif_* family. Module-level blacklist complements the boot-time initcall_blacklist=algif_aead_init.",
		Affects:     "Userspace tools using AF_ALG AEAD (rare).",
	},
}

// Tier2Modules is the server-aggressive module-blacklist set. These modules
// are useful for uncommon-but-real hosting-adjacent workloads, so they are
// opt-in and host-profile gated where kernsec can detect the risk.
var Tier2Modules = []ModuleRule{}
