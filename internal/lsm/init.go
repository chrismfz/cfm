package lsm

import (
	"fmt"
	"io"
	"os"
)

// RunInit is the "bring this host up" convenience for cfm-lsm:
// preflight → enable → status. Does NOT write a default lsm.conf —
// the shipped template at configs/lsm.conf (installed to
// /etc/cfm/lsm.conf by the rpm/deb package) is the authoritative
// starting point. If /etc/cfm/lsm.conf is missing, init refuses
// with a pointer at the shipped template; an operator running from
// a source checkout should `cp configs/lsm.conf /etc/cfm/lsm.conf`
// (or install the package) before retrying.
//
// Rationale: the old RunInit wrote a generated default that didn't
// match the shipped template's per-policy modes — operators
// bootstrapping with `cfm lsm init` got a different baseline
// (every policy at ModeDisabled, the policy.DefaultMode) than
// operators who installed the package (every policy at monitor,
// per the hand-curated template). Removing the generated path
// resolves the divergence and makes init a one-shot bring-up.
func RunInit(w io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(w, "lsm init: must run as root")
		return 1
	}

	// Bail early with a useful hint when the operator hasn't installed
	// a conf yet. ConfPath is the canonical /etc/cfm/lsm.conf location.
	if _, err := os.Stat(ConfPath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(w, "lsm init: %s not found.\n", ConfPath)
			fmt.Fprintln(w, "  Install the shipped template before running `cfm lsm init`:")
			fmt.Fprintln(w, "    cp configs/lsm.conf /etc/cfm/lsm.conf")
			fmt.Fprintln(w, "  (Or install the cfm rpm/deb package, which drops it in place.)")
			return 1
		}
		fmt.Fprintln(w, "lsm init: stat", ConfPath+":", err)
		return 1
	}

	// Step 1: preflight + status. RunStatus already prints the full
	// kernel-preflight table and the per-policy view. If preflight
	// FAILs, RunEnable would refuse to attach — surface that here
	// before attempting.
	fmt.Fprintln(w, "===== cfm lsm init: preflight =====")
	fmt.Fprintln(w)
	res := RunStatus(w, StatusOptions{})
	if !res.PreflightOK {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Preflight FAIL — see the table above for the specific check that failed.")
		fmt.Fprintln(w, "Resolve the failing check before retrying `cfm lsm init`.")
		return 1
	}
	if res.ConfError != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Conf parse error:", res.ConfError)
		return 1
	}

	// Step 2: enable. AssumeYes=true because init is the no-prompt
	// bring-up path; an operator running it knows they want to
	// activate. Per-policy enforce decisions stay in lsm.conf.
	//
	// Idempotency: detect already-pinned state up front. RunEnable
	// returns rc=1 with "cfm-lsm is already enabled" when InspectPinned
	// sees existing pins, which would otherwise make `cfm lsm init`
	// non-idempotent — re-running for convergence (Ansible, systemd
	// ConditionPathExists wrappers, manual operator iteration) would
	// see failures. The convergent contract here is "ensure cfm-lsm
	// is up"; if it's already up, just refresh the operator's view
	// of state and exit 0.
	if InspectPinned(DefaultPinDir).Exists {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "===== cfm lsm init: already enabled =====")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "cfm-lsm is already enabled (pinned state at %s).\n", DefaultPinDir)
		fmt.Fprintln(w, "Showing current status without re-attaching.")
		fmt.Fprintln(w)
		RunStatus(w, StatusOptions{})
		return 0
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "===== cfm lsm init: enable =====")
	fmt.Fprintln(w)
	if rc := RunEnable(w, EnableOptions{AssumeYes: true, Build: CLIBuild}); rc != 0 {
		return rc
	}

	// Step 3: final status snapshot so the operator sees attached/
	// pinned state without a second command.
	fmt.Fprintln(w)
	fmt.Fprintln(w, "===== cfm lsm init: post-enable status =====")
	fmt.Fprintln(w)
	RunStatus(w, StatusOptions{})
	return 0
}
