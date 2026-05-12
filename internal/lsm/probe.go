//go:build linux

package lsm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ProbeResult is the structured outcome of one `cfm lsm probe` run.
type ProbeResult struct {
	// PreflightOK mirrors RunPreflight().OK at probe time. When
	// false the probe did not attempt to load anything.
	PreflightOK bool

	// AttachAttempted is true once the loader actually tried to
	// attach. False when preflight failed or lsm.conf disabled
	// every policy.
	AttachAttempted bool

	// Attached lists policy IDs whose BPF program is now attached
	// (was attached during the probe — the loader detached again
	// immediately).
	Attached []PolicyID

	// Failed maps a policy whose attach failed to the reason.
	Failed map[PolicyID]error

	// LoadError, when non-nil, indicates the loader could not bring
	// up *any* policy (NewLoader returned error). Mutually
	// exclusive with Attached being non-empty.
	LoadError error

	// SpontaneousEvents is the count of events the probe received
	// during its short observation window. A non-zero value on a
	// real host means actual memfd execs or reverse shells happened
	// while the probe was attached — useful to spot already-active
	// compromise.
	SpontaneousEvents int

	// FirstEvent, if SpontaneousEvents > 0, is the first event
	// captured. Useful so the CLI can show "memfd exec from pid X
	// (comm=Y)" rather than just "1 event".
	FirstEvent *Event
}

// RunProbe attempts to actually load + attach the cfm-lsm BPF
// programs, observe events for a short window, then cleanly detach.
// Intended to be invoked from `cfm lsm probe` so an operator can
// verify the host's BPF LSM support without committing to a daemon
// restart.
//
// The probe respects /etc/cfm/lsm.conf: policies with mode=disabled
// are skipped. If lsm.conf has enabled=false, the probe still runs
// (an operator running `cfm lsm probe` explicitly wants to test
// attach capability regardless of the daemon-level enable flag).
func RunProbe(w io.Writer) int {
	res := RunProbeOnce(50 * time.Millisecond)
	emitProbeText(w, res)
	if res.PreflightOK && res.LoadError == nil && len(res.Failed) == 0 {
		return 0
	}
	return 1
}

// RunProbeOnce is the package-level entry point for tests and for
// callers that want the structured result without the text output.
// The observe duration controls how long the probe drains the ring
// buffer before closing. 50ms is the default for the CLI.
func RunProbeOnce(observe time.Duration) ProbeResult {
	res := ProbeResult{Failed: map[PolicyID]error{}}

	pf := RunPreflight()
	res.PreflightOK = pf.OK
	if !pf.OK {
		return res
	}

	conf, _ := loadStatusConf()

	availability := map[PolicyID]PolicyAvailability{}
	for _, pa := range pf.PolicyAvailability {
		availability[pa.PolicyID] = pa
	}

	// Build the policy subset from lsm.conf: any policy with a
	// non-disabled mode is included unless optional preflight marked it
	// unavailable. If every policy is disabled/unavailable, the probe
	// skips the attach step.
	var policies []PolicyID
	for _, p := range AllPolicies() {
		if conf.ModeFor(p.ID) == ModeDisabled {
			continue
		}
		if pa, ok := availability[p.ID]; ok && !pa.Available {
			res.Failed[p.ID] = errors.New(pa.Reason)
			continue
		}
		policies = append(policies, p.ID)
	}
	if len(policies) == 0 {
		return res
	}

	res.AttachAttempted = true
	l, err := NewLoader(LoaderOptions{
		EventBufferSize: 16,
		Policies:        policies,
	})
	if err != nil {
		res.LoadError = err
		return res
	}
	defer l.Close()

	attach := l.Attach()
	res.Attached = append(res.Attached, attach.Attached...)
	for id, e := range attach.Failed {
		res.Failed[id] = e
	}

	// Observe briefly. Any event captured during this window is
	// real activity on the host, not synthetic — note it in the
	// result. The drain goroutine handles the ringbuf read; we just
	// pull a single event with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), observe)
	defer cancel()
	l.Start(ctx)

	select {
	case ev, ok := <-l.Events():
		if ok {
			res.SpontaneousEvents = 1
			evCopy := ev
			res.FirstEvent = &evCopy
		}
	case <-ctx.Done():
	}

	return res
}

func emitProbeText(w io.Writer, r ProbeResult) {
	fmt.Fprintln(w, "===== CFM lsm PROBE =====")
	fmt.Fprintln(w)

	if !r.PreflightOK {
		fmt.Fprintln(w, "Result: SKIPPED")
		fmt.Fprintln(w, "Preflight failed; cannot attempt BPF load.")
		fmt.Fprintln(w, "Run `cfm lsm status` for the failing checks and remediation.")
		return
	}
	if !r.AttachAttempted {
		fmt.Fprintln(w, "Result: SKIPPED")
		fmt.Fprintln(w, "Every policy in /etc/cfm/lsm.conf has mode=disabled.")
		fmt.Fprintln(w, "Set at least one policy to monitor or enforce to probe attach.")
		return
	}
	if r.LoadError != nil {
		fmt.Fprintln(w, "Result: FAIL")
		fmt.Fprintf(w, "Loader error: %v\n", r.LoadError)
		if errors.Is(r.LoadError, ErrBPFLSMUnavailable) {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Preflight passed but the kernel still refused the BPF load.")
			fmt.Fprintln(w, "This usually means SELinux/AppArmor denied bpf() — check audit.log.")
		}
		return
	}

	switch {
	case len(r.Attached) > 0 && len(r.Failed) == 0:
		fmt.Fprintln(w, "Result: PASS — all enabled policies attached cleanly")
	case len(r.Attached) > 0 && len(r.Failed) > 0:
		fmt.Fprintln(w, "Result: PARTIAL — some policies attached, others failed")
	case len(r.Attached) == 0 && len(r.Failed) > 0:
		fmt.Fprintln(w, "Result: FAIL — no policies attached")
	}
	fmt.Fprintln(w)

	if len(r.Attached) > 0 {
		fmt.Fprintln(w, "[Attached]")
		for _, id := range r.Attached {
			if p, ok := PolicyByID(id); ok {
				fmt.Fprintf(w, "  %s  %s\n", id, p.Title)
			} else {
				fmt.Fprintf(w, "  %s\n", id)
			}
		}
		fmt.Fprintln(w)
	}
	if len(r.Failed) > 0 {
		fmt.Fprintln(w, "[Failed]")
		for id, e := range r.Failed {
			fmt.Fprintf(w, "  %s: %v\n", id, e)
		}
		fmt.Fprintln(w)
	}

	switch r.SpontaneousEvents {
	case 0:
		fmt.Fprintln(w, "No events observed during the probe window (expected on an idle host).")
	default:
		fmt.Fprintf(w, "Spontaneous events observed: %d\n", r.SpontaneousEvents)
		if r.FirstEvent != nil {
			fmt.Fprintf(w, "  first event: policy=%s pid=%d comm=%q filename=%q\n",
				r.FirstEvent.PolicyID, r.FirstEvent.PID, r.FirstEvent.Comm, r.FirstEvent.Filename)
			fmt.Fprintln(w, "  ^ a process on this host hit one of the detection rules during the probe.")
			fmt.Fprintln(w, "    On a quiet host this is noteworthy; investigate the pid/comm above.")
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Note: this probe attached the BPF programs briefly, then detached.")
	fmt.Fprintln(w, "      The daemon does not yet attach them at startup — that wiring is the")
	fmt.Fprintln(w, "      next slice. For now, `cfm lsm probe` is the way to verify attach.")
}

// requireRoot bails out of any subcommand that needs CAP_BPF /
// CAP_SYS_ADMIN. Kept in the same file as the only caller so its
// purpose is obvious.
func requireRoot(w io.Writer, verb string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	fmt.Fprintf(w, "lsm %s: must run as root (BPF LSM load requires CAP_BPF / CAP_SYS_ADMIN)\n", verb)
	return false
}
