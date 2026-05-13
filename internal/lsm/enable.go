//go:build linux

package lsm

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// EnableOptions controls RunEnable behaviour.
type EnableOptions struct {
	// AssumeYes skips the interactive confirmation prompt that is
	// otherwise shown when any policy in /etc/cfm/lsm.conf is set to
	// `mode = enforce`. Required for unattended runs (cron, ansible,
	// systemd-unit-driven activations).
	AssumeYes bool

	// In is the stream the prompt reads from. Defaults to os.Stdin
	// when nil. Tests inject a strings.Reader to drive the prompt.
	In io.Reader
}

// RunEnable is the operator-facing `cfm lsm enable` entry point.
// It runs preflight, attaches every non-disabled policy in
// /etc/cfm/lsm.conf, pins everything to DefaultPinDir, then exits.
//
// The pinned state survives the CLI process exiting and any
// subsequent daemon restart. To turn cfm-lsm off, run `cfm lsm
// disable`. Restarting the daemon does not detach.
//
// When any enabled policy has `mode = enforce`, RunEnable prompts
// for confirmation before proceeding — enforce mode returns -EPERM
// from bprm_check_security on a match, which fails the calling
// process's exec() and can break a legitimate workflow if the
// detection has a false-positive. Pass --yes (EnableOptions.AssumeYes)
// for unattended runs.
func RunEnable(w io.Writer, opts EnableOptions) int {
	fmt.Fprintln(w, "===== CFM lsm ENABLE =====")
	fmt.Fprintln(w)

	if !requireRootEnable(w, "enable") {
		return 1
	}

	pf := RunPreflight()
	if !pf.OK {
		fmt.Fprintln(w, "Preflight: FAIL")
		fmt.Fprintln(w, "Cannot enable cfm-lsm until every preflight check passes.")
		fmt.Fprintln(w, "Run `cfm lsm status` for the failing checks and remediation.")
		return 1
	}
	fmt.Fprintln(w, "Preflight: PASS")
	fmt.Fprintln(w)

	conf, _ := loadStatusConf()
	ConfigureKmsg(conf.Kmsg)

	availability := map[PolicyID]PolicyAvailability{}
	for _, pa := range pf.PolicyAvailability {
		availability[pa.PolicyID] = pa
	}

	var policies []PolicyID
	modes := map[PolicyID]Mode{}
	enforceList := []PolicyID{}
	for _, p := range AllPolicies() {
		m := conf.ModeFor(p.ID)
		if m == ModeDisabled {
			continue
		}
		if pa, ok := availability[p.ID]; ok && !pa.Available {
			fmt.Fprintf(w, "Note: %s is unavailable on this kernel; skipping this policy without disabling cfm-lsm.\n", p.ID)
			if pa.Reason != "" {
				fmt.Fprintf(w, "      %s\n", pa.Reason)
			}
			fmt.Fprintln(w)
			continue
		}
		// CFML-CRED-002 is monitor-only by design (returning -EPERM
		// from the cred-install path can deadlock systemd helpers
		// and pkexec mid-transition; see docs/cfm-lsm.md). Warn and
		// downgrade if an operator set enforce — better than silently
		// respecting it and then not blocking, which would mislead them.
		if (p.ID == PolicyCredEscal || p.ID == PolicyDirectCredInstall) && m == ModeEnforce {
			fmt.Fprintf(w, "Note: %s is monitor-only by design; downgrading lsm.conf's enforce setting.\n", p.ID)
			fmt.Fprintln(w, "      See docs/cfm-lsm.md → credential policies → monitor-only strategy.")
			fmt.Fprintln(w)
			m = ModeMonitor
		}
		policies = append(policies, p.ID)
		modes[p.ID] = m
		if m == ModeEnforce {
			enforceList = append(enforceList, p.ID)
		}
	}
	if len(policies) == 0 {
		fmt.Fprintf(w, "Nothing to enable: every policy in %s has mode=disabled.\n", ConfPath)
		fmt.Fprintln(w, "Set at least one policy to monitor or enforce, then re-run `cfm lsm enable`.")
		return 1
	}

	// Refuse to enable on top of an already-enabled state. The
	// operator should `cfm lsm disable` first if they want to change
	// the policy set. Quietly re-pinning would leak old links AND
	// (worse) silently swallow a mode change — the new mode would
	// not take effect until disable+enable.
	if st := InspectPinned(DefaultPinDir); st.Exists {
		fmt.Fprintf(w, "cfm-lsm is already enabled (pinned state at %s).\n", DefaultPinDir)
		fmt.Fprintln(w, "Run `cfm lsm status` to see the live attach state.")
		fmt.Fprintln(w, "To change the policy set or mode, run `cfm lsm disable` first, then re-enable.")
		return 1
	}

	// Enforce-mode confirmation. enforce returns -EPERM from
	// bprm_check_security on a match, which fails the calling
	// process's execve(). Operators need to actively opt in.
	if len(enforceList) > 0 && !opts.AssumeYes {
		if !confirmEnforce(w, opts.In, conf, enforceList) {
			fmt.Fprintln(w, "Aborted. No changes made.")
			return 1
		}
	}

	l, err := NewLoader(LoaderOptions{
		EventBufferSize:       16,
		Policies:              policies,
		Modes:                 modes,
		FS005WebOriginMonitor: conf.FS005WebOriginMonitor,
		PinDir:                DefaultPinDir,
	})
	if err != nil {
		fmt.Fprintln(w, "Enable FAILED.")
		fmt.Fprintf(w, "Loader error: %v\n", err)
		if errors.Is(err, ErrBPFLSMUnavailable) {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Preflight passed but the kernel still refused the BPF load.")
			fmt.Fprintln(w, "This usually means SELinux/AppArmor denied bpf() — check audit.log.")
		}
		return 1
	}
	defer l.Close() // releases userspace fds; pinned state persists.

	// Populate the FS-005 + CRED-002 maps from the live host so the
	// BPF programs have something to match against. Best-effort:
	// partial population is far better than failing the enable.
	if uids, inodes, setuid, perr := PopulateMaps(l, conf); perr != nil {
		fmt.Fprintf(w, "Warning: partial map population: %v\n", perr)
		fmt.Fprintf(w, "         watched_uids=%d watched_inodes=%d setuid_inodes=%d (populated before error)\n",
			uids, inodes, setuid)
	} else {
		fmt.Fprintf(w, "Maps populated: watched_uids=%d watched_inodes=%d setuid_inodes=%d\n",
			uids, inodes, setuid)
		fmt.Fprintln(w)
	}

	attach := l.Attach()
	fmt.Fprintln(w, "Attached and pinned:")
	for _, id := range attach.Attached {
		mode := conf.ModeFor(id)
		marker := ""
		if mode == ModeEnforce {
			marker = "  [ENFORCE — will return -EPERM on match]"
		}
		if p, ok := PolicyByID(id); ok {
			fmt.Fprintf(w, "  %s  %s  (mode=%s)%s\n", id, p.Title, mode, marker)
		} else {
			fmt.Fprintf(w, "  %s  (mode=%s)%s\n", id, mode, marker)
		}
	}
	if len(attach.Failed) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Some policies failed to attach (partial mode):")
		for id, e := range attach.Failed {
			fmt.Fprintf(w, "  %s: %v\n", id, e)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Pin location: %s\n", DefaultPinDir)
	fmt.Fprintln(w, "These attachments survive cfm daemon restarts and crashes.")
	fmt.Fprintln(w, "Run `cfm lsm disable` to detach.")
	fmt.Fprintln(w, "Run `cfm lsm status` to inspect live state.")

	// Emit a one-line ALIVE record to dmesg so the activation shows
	// up in /var/log/messages / journalctl alongside other kernel-
	// adjacent state changes. Mirrors LKRG's ALIVE convention.
	KmsgStatef("ALIVE", "enabled %s pinned=%s", policyModeSummary(conf, attach.Attached), DefaultPinDir)

	return 0
}

// confirmEnforce prints the enforce-mode warning and reads a y/N
// response. Returns true only on an explicit "y" or "yes" (case
// insensitive). Anything else — including EOF, empty input, or an
// unexpected error — is treated as "no" so an accidentally piped
// stdin cannot greenlight an enforce attach.
func confirmEnforce(w io.Writer, in io.Reader, conf *Conf, enforceList []PolicyID) bool {
	fmt.Fprintln(w, "WARNING: enabling cfm-lsm with ENFORCE mode active.")
	fmt.Fprintln(w)
	for _, id := range enforceList {
		title := string(id)
		if p, ok := PolicyByID(id); ok {
			title = p.Title
		}
		fmt.Fprintf(w, "  %s  %s\n", id, title)
		fmt.Fprintln(w, "    → on match the BPF program returns -EPERM, which fails the calling")
		fmt.Fprintln(w, "      process's execve(). A false-positive will crash a legitimate workload.")
	}
	for _, p := range AllPolicies() {
		m := conf.ModeFor(p.ID)
		if m == ModeMonitor {
			fmt.Fprintf(w, "  %s  (mode=monitor — events only, no block)\n", p.ID)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Recovery if a legitimate workflow breaks: run `cfm lsm disable` (one CLI command).")
	fmt.Fprintln(w, "Pass --yes to skip this prompt in unattended scripts.")
	fmt.Fprintln(w)
	fmt.Fprint(w, "Continue? [y/N]: ")

	if in == nil {
		in = os.Stdin
	}
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(w, "(read error: %v) — treating as N\n", err)
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}

// policyModeSummary builds a compact "CFML-EXEC-001=monitor CFML-EXEC-003=monitor"
// string suitable for one-line dmesg / log emission.
func policyModeSummary(conf *Conf, attached []PolicyID) string {
	parts := make([]string, 0, len(attached))
	for _, id := range attached {
		parts = append(parts, fmt.Sprintf("%s=%s", id, conf.ModeFor(id)))
	}
	if len(parts) == 0 {
		return "(none attached)"
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += " " + p
	}
	return out
}

// RunDisable is the operator-facing `cfm lsm disable` entry point.
// It removes every pinned cfm-lsm entry under DefaultPinDir, which
// causes the kernel to detach the BPF programs and release the map.
func RunDisable(w io.Writer) int {
	fmt.Fprintln(w, "===== CFM lsm DISABLE =====")
	fmt.Fprintln(w)

	if !requireRootEnable(w, "disable") {
		return 1
	}

	st := InspectPinned(DefaultPinDir)
	if !st.Exists {
		fmt.Fprintf(w, "cfm-lsm is not currently enabled (no pinned state at %s).\n", DefaultPinDir)
		fmt.Fprintln(w, "Nothing to do.")
		return 0
	}

	// Report what is about to be removed so the operator sees the
	// detach surface clearly.
	if st.MapPresent {
		fmt.Fprintf(w, "Removing pinned ringbuf map at %s/maps/%s\n", DefaultPinDir, pinFileMap)
	}
	for _, id := range st.Links {
		fmt.Fprintf(w, "Removing pinned link  for %s\n", id)
	}

	if err := UnpinAll(DefaultPinDir); err != nil {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Disable FAILED: %v\n", err)
		fmt.Fprintln(w, "Partial-disable is possible — inspect", DefaultPinDir, "by hand.")
		return 1
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "cfm-lsm disabled. All BPF programs detached.")
	// Load conf so the kmsg config (state-transitions toggle) is
	// applied before the STATE emission. Disable predates a started
	// daemon process; the writer may not have been configured yet.
	if conf, _ := loadStatusConf(); conf != nil {
		ConfigureKmsg(conf.Kmsg)
	}
	KmsgStatef("STATE", "disabled, all programs detached")
	return 0
}

// requireRootEnable mirrors probe's requireRoot but with a distinct
// name so the linker does not flag the helper as duplicate on
// hypothetical non-linux stub files. CFM is linux-only in practice;
// this just keeps the helper local to the enable/disable file.
func requireRootEnable(w io.Writer, verb string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	fmt.Fprintf(w, "lsm %s: must run as root (BPF LSM load + pin require CAP_BPF / CAP_SYS_ADMIN)\n", verb)
	return false
}
