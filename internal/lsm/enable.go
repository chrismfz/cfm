//go:build linux

package lsm

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// RunEnable is the operator-facing `cfm lsm enable` entry point.
// It runs preflight, attaches every non-disabled policy in
// /etc/cfm/lsm.conf, pins everything to DefaultPinDir, then exits.
//
// The pinned state survives the CLI process exiting and any
// subsequent daemon restart. To turn cfm-lsm off, run `cfm lsm
// disable`. Restarting the daemon does not detach.
func RunEnable(w io.Writer) int {
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
	var policies []PolicyID
	for _, p := range AllPolicies() {
		if conf.ModeFor(p.ID) != ModeDisabled {
			policies = append(policies, p.ID)
		}
	}
	if len(policies) == 0 {
		fmt.Fprintf(w, "Nothing to enable: every policy in %s has mode=disabled.\n", ConfPath)
		fmt.Fprintln(w, "Set at least one policy to monitor or enforce, then re-run `cfm lsm enable`.")
		return 1
	}

	// Refuse to enable on top of an already-enabled state. The
	// operator should `cfm lsm disable` first if they want to change
	// the policy set. Quietly re-pinning would leak old links.
	if st := InspectPinned(DefaultPinDir); st.Exists {
		fmt.Fprintf(w, "cfm-lsm is already enabled (pinned state at %s).\n", DefaultPinDir)
		fmt.Fprintln(w, "Run `cfm lsm status` to see the live attach state.")
		fmt.Fprintln(w, "To change the policy set, run `cfm lsm disable` first, then re-enable.")
		return 1
	}

	l, err := NewLoader(LoaderOptions{
		EventBufferSize: 16,
		Policies:        policies,
		PinDir:          DefaultPinDir,
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

	attach := l.Attach()
	fmt.Fprintln(w, "Attached and pinned:")
	for _, id := range attach.Attached {
		if p, ok := PolicyByID(id); ok {
			fmt.Fprintf(w, "  %s  %s\n", id, p.Title)
		} else {
			fmt.Fprintf(w, "  %s\n", id)
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

	return 0
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
