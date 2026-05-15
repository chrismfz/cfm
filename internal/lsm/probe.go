//go:build linux

package lsm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
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

	// Failed maps a policy whose attach failed to the reason. These are
	// actual load/attach failures, not optional per-policy availability
	// skips reported by preflight.
	Failed map[PolicyID]error

	// Unavailable maps an optional policy that preflight proved cannot
	// attach on this kernel to its reason. This does not fail the
	// component-wide probe as long as at least one requested policy can
	// still be attempted.
	Unavailable map[PolicyID]string

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

	// DriftPicks records which BPF program variant was selected for
	// each drifting LSM hook (see internal/lsm/btfprobe.go). Populated
	// for any probe that successfully constructed a Loader; nil when
	// the load failed before the BTF probe ran. Surfaced by
	// `cfm lsm probe --verbose`.
	DriftPicks map[string]string
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
//
// When verbose is true the printed report includes the BTF-probed LSM
// hook variant picks (which `cfm_fs005_setattr_*` variant the loader
// chose for this kernel, etc.) — useful for fleets that span EL9 +
// EL10 + Debian + Ubuntu where the picks should diverge by host.
func RunProbe(w io.Writer, verbose bool) int {
	res := RunProbeOnce(50 * time.Millisecond)
	emitProbeText(w, res, verbose)
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
	res := ProbeResult{
		Failed:      map[PolicyID]error{},
		Unavailable: map[PolicyID]string{},
	}

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
			res.Unavailable[p.ID] = pa.Reason
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

	res.DriftPicks = l.DriftPicks()
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

func emitProbeText(w io.Writer, r ProbeResult, verbose bool) {
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
		if len(r.Unavailable) > 0 {
			fmt.Fprintln(w, "Every enabled policy is unavailable on this kernel.")
			fmt.Fprintln(w, "Unavailable optional policies do not fail component-wide preflight.")
			fmt.Fprintln(w)
			emitProbeUnavailable(w, r.Unavailable)
			return
		}
		fmt.Fprintln(w, "Every policy in /etc/cfm/lsm.conf has mode=disabled.")
		fmt.Fprintln(w, "Set at least one policy to monitor or enforce to probe attach.")
		return
	}
	if r.LoadError != nil {
		fmt.Fprintln(w, "Result: FAIL")
		fmt.Fprintf(w, "Loader error: %v\n", r.LoadError)
		if errors.Is(r.LoadError, ErrBPFLSMUnavailable) {
			fmt.Fprintln(w)
			emitLoadFailureHint(w, r.LoadError)
		}
		return
	}

	switch {
	case len(r.Attached) > 0 && len(r.Failed) == 0 && len(r.Unavailable) == 0:
		fmt.Fprintln(w, "Result: PASS — all enabled policies attached cleanly")
	case len(r.Attached) > 0 && len(r.Failed) == 0 && len(r.Unavailable) > 0:
		fmt.Fprintln(w, "Result: PASS — enabled policies attached; optional policies unavailable")
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
	if len(r.Unavailable) > 0 {
		emitProbeUnavailable(w, r.Unavailable)
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

	if verbose {
		emitProbeDriftPicks(w, r.DriftPicks)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Note: this probe attached the BPF programs briefly, then detached.")
	fmt.Fprintln(w, "      The daemon does not yet attach them at startup — that wiring is the")
	fmt.Fprintln(w, "      next slice. For now, `cfm lsm probe` is the way to verify attach.")
}

// emitProbeDriftPicks lists which BPF program variant was selected for
// each LSM hook whose signature drifts across the kernels we support.
// Quiet when picks is empty (kernel has no drifting hooks in scope —
// e.g. a future kernel where the hook stops drifting, or AdoptPinned
// mode where this loader didn't run the BTF probe).
func emitProbeDriftPicks(w io.Writer, picks map[string]string) {
	if len(picks) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[BTF probe — LSM hook variant picks]")
	keys := make([]string, 0, len(picks))
	for k := range picks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, hook := range keys {
		fmt.Fprintf(w, "  %s → %s\n", hook, picks[hook])
	}
	fmt.Fprintln(w, "  (one per hook whose kernel signature varies across distros — see internal/lsm/btfprobe.go)")
}

func emitProbeUnavailable(w io.Writer, unavailable map[PolicyID]string) {
	fmt.Fprintln(w, "[Unavailable]")
	for id, reason := range unavailable {
		if reason == "" {
			reason = "optional policy prerequisite unavailable on this kernel"
		}
		fmt.Fprintf(w, "  %s: %s\n", id, reason)
	}
	fmt.Fprintln(w)
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
