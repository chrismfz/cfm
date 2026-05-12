package lsm

import (
	"fmt"
	"io"
)

// RunPreview prints what `cfm lsm` would do at daemon startup, given
// the current /etc/cfm/lsm.conf and the current kernel. It is the
// read-only "dry run" — no attaches, no writes.
//
// Useful before flipping `enabled = true` in lsm.conf: the operator
// can see ahead of time whether preflight will pass and which
// policies will activate.
func RunPreview(w io.Writer) int {
	conf, confErr := loadStatusConf()
	pf := RunPreflight()

	fmt.Fprintln(w, "===== CFM lsm PREVIEW =====")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Config source: %s\n", conf.Source)
	if confErr != nil {
		fmt.Fprintf(w, "Config error:  %v\n", confErr)
	}
	fmt.Fprintf(w, "enabled =      %t\n", conf.Enabled)
	fmt.Fprintln(w)

	if !pf.OK {
		fmt.Fprintln(w, "Preflight: FAIL — no policies would attach on this host.")
		fmt.Fprintln(w, "Run `cfm lsm status` for the failing checks and remediation.")
		fmt.Fprintln(w)
	} else {
		fmt.Fprintln(w, "Preflight: PASS")
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "On daemon start, with the current config + kernel:")
	fmt.Fprintln(w)
	for _, p := range AllPolicies() {
		mode := conf.ModeFor(p.ID)
		fmt.Fprintf(w, "  %s  %s\n", p.ID, p.Title)
		fmt.Fprintf(w, "    hook:    %s\n", p.Hook)
		fmt.Fprintf(w, "    mode:    %s\n", mode)
		fmt.Fprintf(w, "    action:  %s\n", describePreviewAction(pf, conf, mode, p.ID))
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Note: preview is a read-only prediction. It does not touch the kernel.")
	fmt.Fprintln(w, "      Run `cfm lsm probe` to actually load the BPF programs briefly and")
	fmt.Fprintln(w, "      confirm the kernel accepts them on this host.")
	return 0
}

func describePreviewAction(pf Preflight, conf *Conf, mode Mode, id PolicyID) string {
	if !conf.Enabled {
		return "skip — cfm-lsm globally disabled in lsm.conf (set `enabled = true` to activate)"
	}
	if !pf.OK {
		return "skip — preflight failed; see `cfm lsm status`"
	}
	if reason, unavailable := unavailablePolicyReason(pf, id); unavailable {
		return "skip — policy unavailable on this kernel: " + reason
	}
	switch mode {
	case ModeDisabled:
		return "skip — policy mode is `disabled` in lsm.conf"
	case ModeMonitor:
		return "would attach in monitor mode (log events, do not block)"
	case ModeEnforce:
		return "would attach in enforce mode (block matching behaviour)"
	}
	return "skip"
}
