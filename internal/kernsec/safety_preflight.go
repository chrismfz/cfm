package kernsec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// preflightSummary is the operator-facing safety preview printed at
// the top of an interactive `cfm kernsec apply`. It lists every
// surface kernsec is about to mutate and explicitly calls out the
// boot-bricking risks the audit identified — operator gets one last
// chance to abort before any write happens.
//
// Layout (matches the existing [Sysctl] / [Boot args] / [Modules]
// sections kernsec already prints):
//
//	[!] About to mutate the following:
//	    - sysctl: /etc/sysctl.d/99-cfm-kernsec.conf  (N rules)
//	    - boot args: /etc/default/grub               (M args)
//	    - modules: /etc/modprobe.d/cfm-kernsec.conf  (K modules)
//	[!] Boot-impacting changes detected — read carefully:
//	    - bootloader configuration will be regenerated.
//	[!] Backup files (operator recovery path):
//	    - /etc/default/grub → /etc/default/grub.cfm-kernsec.bak
//
// Then prompts `Apply changes? [y/N]:`.
func preflightSummary(
	w io.Writer,
	label string,
	sysctls []SysctlRule,
	bootArgs []BootArg,
	modules []ModuleRule,
	profile HostProfile,
	mountsToEnable []MountRule,
) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "[!] About to %s:\n", strings.ToLower(label))
	fmt.Fprintf(w, "    - sysctl:    %-50s (%d rules)\n", SysctlPath, len(sysctls))
	fmt.Fprintf(w, "    - boot args: next-boot cmdline                              (%d args)\n", len(bootArgs))
	fmt.Fprintf(w, "    - modules:   %-50s (%d modules)\n", ModprobePath, len(modules))
	for _, m := range mountsToEnable {
		liveNote := "remount live"
		if !liveRemountSafe(m) {
			liveNote = "PEND until reboot"
		}
		fmt.Fprintf(w, "    - mounts:    %-50s (+ %s on %s; %s)\n",
			PathFstab, m.Recommended, m.MountPoint, liveNote)
	}

	risks := boot_impacting_risks(bootArgs, modules, profile)
	risks = append(risks, sysctl_impacting_risks(sysctls, profile)...)
	risks = append(risks, mount_impacting_risks(mountsToEnable)...)
	if len(risks) > 0 {
		fmt.Fprintln(w, "[!] Boot-impacting changes — read carefully:")
		for _, r := range risks {
			fmt.Fprintf(w, "    - %s\n", r)
		}
	}

	fmt.Fprintln(w, "[!] Backup files (operator recovery path):")
	fmt.Fprintf(w, "    - %s%s\n", PathDefaultGrub, BackupSuffix)
	fmt.Fprintf(w, "    - %s%s\n", SysctlPath, BackupSuffix)
	fmt.Fprintf(w, "    - %s%s\n", ModprobePath, BackupSuffix)
	if len(mountsToEnable) > 0 {
		fmt.Fprintf(w, "    - %s%s\n", PathFstab, BackupSuffix)
	}
	fmt.Fprintln(w, "    (timestamped per-run backups go alongside if a managed file already had operator edits)")

	fmt.Fprintln(w, "[!] Pass --yes to skip this prompt in unattended runs.")
	fmt.Fprintln(w)
}

// mount_impacting_risks names every CanEnable mount rule about to be
// applied so the operator sees exactly which mount points will be
// remounted live. /dev/shm noexec is the documented workload-
// breaker; surface the recovery command up-front so an operator who
// realises mid-prompt that they run headless Chromium has it in
// scrollback.
func mount_impacting_risks(mountsToEnable []MountRule) []string {
	var risks []string
	for _, m := range mountsToEnable {
		switch m.MountPoint {
		case "/dev/shm":
			risks = append(risks,
				"/dev/shm: live remount with nodev,nosuid,noexec. Pre-15 PostgreSQL JIT and headless Chromium can break — revert with `mount -o remount,exec /dev/shm` then `cfm kernsec disable` (disable only un-does noexec; the distro-default nodev,nosuid stay live).")
		case "/tmp":
			risks = append(risks,
				"/tmp: persistence-only (fstab line or systemd tmp.mount drop-in). Live remount deliberately skipped — services with PrivateTmp=yes (mysqld, named, php-fpm, nginx, exim) hold bind mounts in the current /tmp namespace. Row reports PEND until next reboot; noexec breaks some composer / pip / cPanel workflows, review first.")
		case "/var/tmp":
			risks = append(risks,
				"/var/tmp: persistence-only. If /var/tmp is not separately mounted today, kernsec adds a bind fstab line `/tmp /var/tmp none bind` so /var/tmp inherits /tmp's hardening at reboot. Existing /var/tmp content is SHADOWED (not deleted) by the bind — if you keep state under /var/tmp, run `cfm kernsec secure-tmp` instead.")
		default:
			risks = append(risks,
				fmt.Sprintf("%s: live remount with %s.", m.MountPoint, m.Recommended))
		}
	}
	return risks
}

func sysctl_impacting_risks(sysctls []SysctlRule, profile HostProfile) []string {
	var risks []string
	for _, s := range sysctls {
		switch s.Key {
		case "kernel.core_pattern":
			detail := "kernel.core_pattern=|/bin/false suppresses coredumps globally for every process; this can disable crash diagnostics until the sysctl is changed back and affected services are retried."
			if profile.HasHostingPanelWorkload || profile.HasBackupWorkload || profile.HasMonitoringWorkload {
				detail += " Host-profile diagnostics risk was detected; this rule should only be present if forced."
			}
			risks = append(risks, detail)
		}
	}
	return risks
}

// boot_impacting_risks returns one human-readable bullet per
// boot-impacting decision in the apply set. Empty slice when nothing
// risky is being applied (Tier 1 KSPP sysctls + safe module blacklists
// = no boot impact, for example).
func boot_impacting_risks(bootArgs []BootArg, modules []ModuleRule, profile HostProfile) []string {
	var risks []string
	for _, a := range bootArgs {
		switch a.Key {
		case "init_on_alloc", "init_on_free":
			// Performance impact rather than brick — call it out
			// briefly so operators on large RAM hosts see it.
			// init_on_free explicitly stacks on top of init_on_alloc;
			// surface the combined ceiling so operators opting in at
			// Tier 3 see what they're signing up for.
			if a.Key == "init_on_free" {
				risks = append(risks, a.Key+"="+a.Value+": ~1-3% additional memory-allocation perf cost on free paths, stacked on top of init_on_alloc=1 (~0-5%); combined ceiling ~3-8% in the worst case. Brick-safe.")
			} else {
				risks = append(risks, a.Key+"="+a.Value+": ~0-5% memory-allocation perf cost on alloc paths; brick-safe.")
			}
		}
	}
	for _, m := range modules {
		if IsDangerousModule(m.Name) {
			// Already deny-listed at apply time, but if we're past
			// the deny-list (operator added a new pattern that
			// passed the static test), surface it here too.
			risks = append(risks, "module blacklist contains "+m.Name+" — boot-critical driver pattern; will be REJECTED by apply-time guard.")
		}
	}
	if len(bootArgs) > 0 {
		// Always remind that the bootloader is being touched even
		// when no specifically-flagged arg landed.
		risks = append(risks, "bootloader configuration (/etc/default/grub or BLS / proxmox-boot-tool) will be regenerated; rescue / debug kernel entries are intentionally excluded on BLS.")
	}
	return risks
}

// confirmApply reads y/n from `in` (defaulting to os.Stdin when
// nil) and returns true if the operator typed `y` or `yes`
// (case-insensitive). Anything else, EOF, or a TTY-less stream
// (input == nil after default) is treated as decline so a piped
// `echo` accidentally typing yes doesn't bypass the gate. To
// run unattended, set ApplyOptions.AssumeYes = true.
func confirmApply(w io.Writer, in io.Reader) (bool, error) {
	if in == nil {
		in = os.Stdin
	}
	fmt.Fprint(w, "Apply these kernsec changes? This may include irreversible-until-reboot sysctls and global coredump suppression. [y/N]: ")
	r := bufio.NewReader(in)
	line, err := r.ReadString('\n')
	if err != nil {
		// EOF on a non-interactive input → treat as decline. If the
		// operator wants unattended apply they pass --yes; we don't
		// silently consume `echo "" | cfm kernsec apply` as a yes.
		if err == io.EOF {
			fmt.Fprintln(w)
			return false, nil
		}
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
