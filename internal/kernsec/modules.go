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
		ID: "KSEC-MOD-recent_cves-001", Group: "modules.recent_cves.ksmbd", Tier: Tier1,
		Name:        "ksmbd",
		Description: "In-kernel SMB server with multiple LPE CVEs 2023-2025. Default-blacklist on hosting (NFS-over-VPN preferred over SMB), but a handful of operators run ksmbd deliberately as a kernel-fast Samba replacement.",
		Affects:     "Auto-skipped on hosts running ksmbd (host-profile gated via HasKSMBDServer: module loaded, /sys/class/ksmbd populated, or ksmbd-tools installed).",
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
		ID: "KSEC-MOD-net.legacy-003", Group: "modules.net.legacy.tipc", Tier: Tier1,
		Name:        "tipc",
		Description: "Transparent Inter-Process Communication; cluster IPC stack with a long LPE history. No use on web hosting; legitimate users are Pacemaker / Corosync HA clusters and Erlang/OTP distribution.",
		Affects:     "Auto-skipped on hosts with TIPC workload evidence (host-profile gated via HasTIPCWorkload).",
	},
	{
		ID: "KSEC-MOD-net.legacy-004", Group: "modules.net.legacy.rds", Tier: Tier1,
		Name:        "rds",
		Description: "Reliable Datagram Sockets; Oracle RAC interconnect transport. Has had LPEs and no use outside Oracle Database. Blacklisting `rds` also stops `rds_tcp` and `rds_rdma` from loading because both depend on `rds` for symbol resolution.",
		Affects:     "Auto-skipped on hosts with Oracle / RDS indicators (host-profile gated via HasRDSWorkload: oratab, lsnrctl, /u01/app/oracle, rds / rds_tcp / rds_rdma module loaded).",
	},
	{
		ID: "KSEC-MOD-net.legacy-005", Group: "modules.net.legacy.rxrpc", Tier: Tier1,
		Name:        "rxrpc",
		Description: "AFS RPC transport; entry point for CVE-2026-31635 (DirtyDecrypt / DirtyCBC) and the broader rxgk class. No use on standard hosting; legitimate users are AFS clients (kafs / openafs).",
		Affects:     "Auto-skipped on hosts with AFS evidence (host-profile gated via HasAFS: rxrpc / kafs / openafs loaded, /afs mounted, OpenAFS tooling).",
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
		ID: "KSEC-MOD-net.legacy-017", Group: "modules.net.legacy.llc", Tier: Tier1,
		Name:        "llc",
		Description: "Logical Link Control — only used by dead net protocols (IPX, AppleTalk, Token Ring) on the userland side, BUT the in-kernel `bridge` module hard-depends on llc (bridge → stp → llc).",
		Affects:     "Breaks every in-kernel bridge user: Docker (docker0, br-*), Podman, libvirt/KVM (virbr*), Proxmox (vmbr*), LXC/LXD, K8s CNIs, manual `brctl`/`ip link add type bridge`. Auto-skipped when a bridge interface, container runtime, KVM hypervisor, libvirt or Proxmox is detected. Force only on hosts that genuinely never bridge.",
	},
	{
		ID: "KSEC-MOD-net.legacy-018", Group: "modules.net.legacy.llc", Tier: Tier1,
		Name:        "llc2",
		Description: "LLC type 2 — same family as llc and pulled in alongside it by the bridge stack.",
		Affects:     "Same as llc (KSEC-MOD-net.legacy-017): paired blacklist breaks any in-kernel bridge user. Same auto-skip gate.",
	},
	{
		ID: "KSEC-MOD-net.legacy-019", Group: "modules.net.legacy.pptp", Tier: Tier1,
		Name:        "pptp",
		Description: "PPTP VPN protocol; obsolete, weak crypto, and a long LPE history. Still in use on Mikrotik fleets and some legacy site-to-site VPN deployments.",
		Affects:     "Auto-skipped on hosts with PPTP workload evidence (host-profile gated via HasPPTPWorkload: pptp module loaded, /etc/pptpd.conf, pptpd / accel-ppp installed).",
	},
	{
		ID: "KSEC-MOD-net.legacy-028", Group: "modules.net.legacy.l2tp", Tier: Tier1,
		Name:        "l2tp_core",
		Description: "L2TP VPN core; multiple LPE CVEs over the years and no hosting use case outside L2TP termination.",
		Affects:     "Auto-skipped on hosts with L2TP workload evidence (host-profile gated via HasL2TPWorkload: l2tp_* loaded, /proc/net/l2tp*, xl2tpd / kl2tpd / accel-ppp installed).",
	},
	{
		ID: "KSEC-MOD-net.legacy-029", Group: "modules.net.legacy.l2tp", Tier: Tier1,
		Name:        "l2tp_ip",
		Description: "L2TPv3 IP encapsulation (IPv4).",
		Affects:     "Same gate as l2tp_core (HasL2TPWorkload).",
	},
	{
		ID: "KSEC-MOD-net.legacy-030", Group: "modules.net.legacy.l2tp", Tier: Tier1,
		Name:        "l2tp_ip6",
		Description: "L2TPv3 IP encapsulation (IPv6).",
		Affects:     "Same gate as l2tp_core (HasL2TPWorkload).",
	},
	{
		ID: "KSEC-MOD-net.legacy-031", Group: "modules.net.legacy.l2tp", Tier: Tier1,
		Name:        "l2tp_eth",
		Description: "L2TP Ethernet pseudowires.",
		Affects:     "Same gate as l2tp_core (HasL2TPWorkload).",
	},
	{
		ID: "KSEC-MOD-net.legacy-032", Group: "modules.net.legacy.l2tp", Tier: Tier1,
		Name:        "l2tp_netlink",
		Description: "Netlink configuration interface for L2TP.",
		Affects:     "Same gate as l2tp_core (HasL2TPWorkload).",
	},
	{
		ID: "KSEC-MOD-net.legacy-033", Group: "modules.net.legacy.l2tp", Tier: Tier1,
		Name:        "l2tp_ppp",
		Description: "PPP over L2TP transport.",
		Affects:     "Same gate as l2tp_core (HasL2TPWorkload).",
	},
	{
		ID: "KSEC-MOD-net.legacy-034", Group: "modules.net.legacy.sctp", Tier: Tier1,
		Name:        "sctp",
		Description: "Stream Control Transmission Protocol — telecom signalling (SS7 / Diameter / M3UA), K8s Services with protocol: SCTP, and lksctp-tools-based monitoring only. Long LPE history (CVE-2018-5803, CVE-2019-8956, CVE-2021-23133, ...). WebRTC data channels run usrsctp in userspace and do NOT use this module.",
		Affects:     "Auto-skipped on hosts with any SCTP workload evidence (host-profile gated via HasSCTPWorkload): sctp module loaded, /proc/net/sctp present, sctp.service / sctp_darn / Nagios check_sctp / any *sctp*.service unit installed.",
	},
	{
		ID: "KSEC-MOD-net.legacy-035", Group: "modules.net.legacy.sctp", Tier: Tier1,
		Name:        "sctp_diag",
		Description: "Netlink socket diag for SCTP (ss -S). Loaded on-demand only when SCTP introspection is requested; same exposure family as sctp.",
		Affects:     "Auto-skipped on hosts with SCTP workload evidence (same gate as sctp).",
	},
	{
		ID: "KSEC-MOD-net.legacy-036", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "smc",
		Description: "IBM Shared Memory Communications over RDMA / IUCV — z/Linux mainframe socket family; recent LPE class (CVE-2024-46695 and siblings).",
		Affects:     "None on x86_64 hosting.",
	},
	{
		ID: "KSEC-MOD-net.legacy-037", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "smc_diag",
		Description: "Netlink socket diag for SMC; same exposure class as smc.",
		Affects:     "None on x86_64 hosting.",
	},
	{
		ID: "KSEC-MOD-net.legacy-038", Group: "modules.net.legacy", Tier: Tier1,
		Name:        "slip",
		Description: "Serial Line IP — dead dial-up era protocol, TTY line-discipline class (same family as n_hdlc / n_gsm already blacklisted).",
		Affects:     "None on servers; only matters if the host runs a serial-line IP link.",
	},
	{
		ID: "KSEC-MOD-net.legacy-039", Group: "modules.net.legacy.ppp", Tier: Tier1,
		Name:        "slhc",
		Description: "Van Jacobson header compression for SLIP / PPP — pulled in by slip and by PPP CCP (ppp_async, pptp, l2tp_ppp). No hosting use case outside legacy PPP links.",
		Affects:     "Auto-skipped on hosts terminating L2TP or PPTP (host-profile gated via HasL2TPWorkload or HasPPTPWorkload). Override per-rule on hosts running other PPP transports.",
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

	// --- modules.ipsec: kernel ESP transforms -----------------------
	//
	// esp4 / esp6 are the kernel-side ESP transforms used by IPsec.
	// They became a critical attack surface with CVE-2026-46300
	// ("Fragnesia") in the espintcp ULP and CVE-2026-XXXX-class
	// ("Dirty Frag") in the same XFRM/ESP path: an unprivileged local
	// user can splice file pages into a TCP socket, switch the socket
	// into ESP-in-TCP ULP mode, and have the kernel decrypt-in-place
	// into the page cache — a deterministic one-byte arbitrary write
	// per trigger into any readable file (the public PoC overwrites
	// /usr/bin/su).
	//
	// While patched kernels and KernelCare livepatches are still in
	// build/test, blacklisting these modules is the upstream-recommended
	// mitigation. Host-profile gating (HasIPsec via SkipReason on
	// `modules.ipsec`) auto-skips the rule when `/proc/net/xfrm_policy`
	// or `/proc/net/pfkey` is non-empty, so hosts that terminate or
	// transit IPsec / strongSwan / Libreswan tunnels are not affected.

	{
		ID: "KSEC-MOD-ipsec-001", Group: "modules.ipsec", Tier: Tier1,
		Name:        "esp4",
		Description: "IPv4 ESP transform; entry point for CVE-2026-46300 (Fragnesia) and the related Dirty Frag XFRM/ESP LPE class.",
		Affects:     "Skipped automatically on hosts with active IPsec policies (host-profile gated via HasIPsec).",
	},
	{
		ID: "KSEC-MOD-ipsec-002", Group: "modules.ipsec", Tier: Tier1,
		Name:        "esp6",
		Description: "IPv6 ESP transform; same XFRM/ESP exploit class as esp4 (Fragnesia, Dirty Frag).",
		Affects:     "Skipped automatically on hosts with active IPsec policies (host-profile gated via HasIPsec).",
	},
	{
		ID: "KSEC-MOD-ipsec-003", Group: "modules.ipsec", Tier: Tier1,
		Name:        "ah4",
		Description: "IPv4 IPsec Authentication Header transform — same XFRM transform layer as esp4, reachable by future ULP/transform-confusion bugs in that path. AH is almost never used in practice (ESP+AEAD replaced it).",
		Affects:     "Skipped automatically on hosts with active IPsec policies (host-profile gated via HasIPsec).",
	},
	{
		ID: "KSEC-MOD-ipsec-004", Group: "modules.ipsec", Tier: Tier1,
		Name:        "ah6",
		Description: "IPv6 IPsec Authentication Header transform; same XFRM family as ah4.",
		Affects:     "Skipped automatically on hosts with active IPsec policies (host-profile gated via HasIPsec).",
	},
	{
		ID: "KSEC-MOD-ipsec-005", Group: "modules.ipsec", Tier: Tier1,
		Name:        "ipcomp",
		Description: "IPv4 IPsec payload compression transform — XFRM data-path sibling of esp4/ah4.",
		Affects:     "Skipped automatically on hosts with active IPsec policies (host-profile gated via HasIPsec).",
	},
	{
		ID: "KSEC-MOD-ipsec-006", Group: "modules.ipsec", Tier: Tier1,
		Name:        "ipcomp6",
		Description: "IPv6 IPsec payload compression transform; same XFRM family as ipcomp.",
		Affects:     "Skipped automatically on hosts with active IPsec policies (host-profile gated via HasIPsec).",
	},
	{
		ID: "KSEC-MOD-ipsec-007", Group: "modules.ipsec", Tier: Tier1,
		Name:        "xfrm_interface",
		Description: "Routing-based XFRM virtual interface — net-new XFRM attack surface with no hosting use outside IPsec.",
		Affects:     "Skipped automatically on hosts with active IPsec policies (host-profile gated via HasIPsec).",
	},
	{
		ID: "KSEC-MOD-ipsec-008", Group: "modules.ipsec", Tier: Tier1,
		Name:        "af_key",
		Description: "PF_KEYv2 IPsec keying socket family — the SA/SP management channel libreswan/strongSwan/iked uses to talk to the kernel XFRM SADB. Same gate as esp4/6: not loaded means no PF_KEY attack surface.",
		Affects:     "Skipped automatically on hosts with active IPsec policies (host-profile gated via HasIPsec).",
	},

	// --- modules.net.virt: virt-only socket families ----------------
	//
	// Single-module group so host-profile gating can target it
	// precisely. vsock (virtio/VMware guest↔host socket protocol) is
	// a named killswitch candidate — useless on bare-metal hosting,
	// but the host-side transport (vhost_vsock) is a legitimate
	// hypervisor surface for guest comms. We skip the blacklist when
	// the host is actually a KVM hypervisor (kvm module loaded AND
	// vhost/libvirt/QEMU/Proxmox evidence → IsKVMHost; see
	// detectKVMHost) so hypervisors retain it. A bare-metal hosting box
	// where kvm_intel merely auto-loaded on VT-x is NOT skipped —
	// vsock stays blacklisted there.

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
	//
	// Single-group blacklist gated by HasMountedDeadFS: if any of the
	// filesystems shipped under this group appears in /proc/mounts or
	// /etc/fstab, the whole group is skipped and the kernsec audit
	// row reports which FS triggered it. Same defensive flavour as
	// the llc/llc2 bridge gate — one hit (e.g. a UDF mount for
	// archive recovery, or a legacy JFS partition nobody migrated)
	// preserves the entire group rather than silently breaking a
	// hand-rolled mount.

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
	{
		ID: "KSEC-MOD-fs.unused-019", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "adfs",
		Description: "Acorn Disc Filing System — dead, fuzzer-popular surface.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-020", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "hpfs",
		Description: "OS/2 High Performance File System — dead.",
		Affects:     "None.",
	},
	{
		ID: "KSEC-MOD-fs.unused-021", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "minix",
		Description: "Minix filesystem driver — same syzkaller-fuzz class as the other dead-FS entries in this group.",
		Affects:     "None on hosting.",
	},
	{
		ID: "KSEC-MOD-fs.unused-022", Group: "modules.fs.unused", Tier: Tier1,
		Name:        "bfs",
		Description: "UnixWare boot filesystem — dead.",
		Affects:     "None.",
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
		Affects:     "Skipped on hosts with FireWire hardware (host-profile gated via HasFirewireHardware).",
	},
	{
		ID: "KSEC-MOD-bus-006", Group: "modules.bus.firewire", Tier: Tier1,
		Name:        "firewire-ohci",
		Description: "FireWire OHCI driver.",
		Affects:     "Skipped on hosts with FireWire hardware (host-profile gated via HasFirewireHardware).",
	},
	{
		ID: "KSEC-MOD-bus-007", Group: "modules.bus.firewire", Tier: Tier1,
		Name:        "firewire-net",
		Description: "FireWire networking.",
		Affects:     "Skipped on hosts with FireWire hardware (host-profile gated via HasFirewireHardware).",
	},
	{
		ID: "KSEC-MOD-bus-008", Group: "modules.bus.firewire", Tier: Tier1,
		Name:        "firewire-sbp2",
		Description: "FireWire storage transport.",
		Affects:     "Skipped on hosts with FireWire hardware (host-profile gated via HasFirewireHardware).",
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

	// --- modules.mctp: in-band Management Component Transport Protocol -
	//
	// In-band MCTP (over PCIe VDM, SMBus/I2C, serial) is the OpenBMC /
	// NVMe-MI / firmware-update sideband. Classic Supermicro IPMI and
	// Dell iDRAC live on their own NIC and never touch this stack, so
	// the default on hosting boxes is blacklist. The host-profile
	// HasMCTPInBand probe auto-skips when /sys/bus/mctp or /sys/class/mctp
	// has registered endpoints, or when a netdev advertises ARPHRD_MCTP
	// — covering OpenBMC platforms like the Supermicro H13SRD-F
	// MicroCloud nodes.

	{
		ID: "KSEC-MOD-mctp-001", Group: "modules.mctp", Tier: Tier1,
		Name:        "mctp",
		Description: "Kernel MCTP core (AF_MCTP socket family). In-band only — out-of-band BMC NICs do not use it.",
		Affects:     "Skipped automatically on hosts with in-band MCTP endpoints (host-profile gated via HasMCTPInBand).",
	},
	{
		ID: "KSEC-MOD-mctp-002", Group: "modules.mctp", Tier: Tier1,
		Name:        "mctp-i2c",
		Description: "MCTP-over-I2C/SMBus transport — sideband path used by OpenBMC.",
		Affects:     "Skipped automatically on hosts with in-band MCTP endpoints (host-profile gated via HasMCTPInBand).",
	},
	{
		ID: "KSEC-MOD-mctp-003", Group: "modules.mctp", Tier: Tier1,
		Name:        "mctp-serial",
		Description: "MCTP-over-serial transport — debug/console sideband.",
		Affects:     "Skipped automatically on hosts with in-band MCTP endpoints (host-profile gated via HasMCTPInBand).",
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
