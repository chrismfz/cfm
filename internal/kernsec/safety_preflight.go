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
//	    - module.sig_enforce=1 will be added.
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
) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "[!] About to %s:\n", strings.ToLower(label))
	fmt.Fprintf(w, "    - sysctl:    %-50s (%d rules)\n", SysctlPath, len(sysctls))
	fmt.Fprintf(w, "    - boot args: next-boot cmdline                              (%d args)\n", len(bootArgs))
	fmt.Fprintf(w, "    - modules:   %-50s (%d modules)\n", ModprobePath, len(modules))

	risks := boot_impacting_risks(bootArgs, modules, profile)
	risks = append(risks, sysctl_impacting_risks(sysctls, profile)...)
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
	fmt.Fprintln(w, "    (timestamped per-run backups go alongside if a managed file already had operator edits)")

	fmt.Fprintln(w, "[!] Pass --yes to skip this prompt in unattended runs.")
	fmt.Fprintln(w)
}

func sysctl_impacting_risks(sysctls []SysctlRule, profile HostProfile) []string {
	var risks []string
	for _, s := range sysctls {
		switch s.Key {
		case "kernel.core_pattern":
			detail := "kernel.core_pattern=|/bin/false suppresses coredumps globally for every process; this can disable crash diagnostics until the sysctl is changed back and affected services are retried."
			if profile.HasHostingPanelWorkload || profile.HasBackupWorkload || profile.HasMonitoringWorkload || profile.HasKdump {
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
		case "module.sig_enforce":
			detail := "module.sig_enforce=1 will be added; every module must be signed by a trusted key. KernelCare / akmod / DKMS modules signed by their own key will fail."
			risks = append(risks, detail)
		case "init_on_alloc", "init_on_free":
			// Performance impact rather than brick — call it out
			// briefly so operators on large RAM hosts see it.
			risks = append(risks, a.Key+"="+a.Value+": ~1-3% memory-allocation perf cost; brick-safe.")
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
