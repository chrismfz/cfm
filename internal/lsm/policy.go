package lsm

// PolicyID is the stable identifier for one cfm-lsm policy.
//
// IDs use the CFML-<DOMAIN>-<NNN> shape from docs/cfm-lsm.md.
// They are stable across releases — operators reference them in
// /etc/cfm/lsm.conf, in alerts, and in audit logs, so renaming a
// policy ID is a breaking change.
type PolicyID string

const (
	// PolicyMemfdExec — CFML-EXEC-001: refuse execve when the
	// backing file has no on-disk path (memfd / anonymous shmem).
	PolicyMemfdExec PolicyID = "CFML-EXEC-001"

	// PolicyReverseShell — CFML-EXEC-003: detect a process about
	// to exec with fds 0/1/2 dup'd onto a remote-connected socket.
	PolicyReverseShell PolicyID = "CFML-EXEC-003"
)

// Mode is the per-policy enforcement mode.
type Mode int

const (
	// ModeDisabled means the policy is not loaded.
	ModeDisabled Mode = iota
	// ModeMonitor means the policy is attached and emits events,
	// but does not block. This is the default for any policy that
	// has not yet completed its 30-day monitor window.
	ModeMonitor
	// ModeEnforce means the policy is attached and blocks matching
	// behaviour. Only safe after monitor-mode telemetry confirms a
	// near-zero false-positive rate.
	ModeEnforce
)

// String renders the mode as it appears in lsm.conf.
func (m Mode) String() string {
	switch m {
	case ModeMonitor:
		return "monitor"
	case ModeEnforce:
		return "enforce"
	}
	return "disabled"
}

// Policy is the static metadata for one CFM-LSM policy.
//
// Runtime state (whether the BPF program is actually attached,
// recent event counts, last failure reason) is intentionally
// separate — see RuntimeStatus when the BPF backend lands.
type Policy struct {
	ID          PolicyID
	Title       string
	Hook        string // LSM hook this policy attaches to
	DefaultMode Mode   // mode used when lsm.conf is silent on this ID
	Description string
}

// AllPolicies returns the MVP policy catalogue in display order.
// New policies require a separate design proposal; this list is
// the authoritative scope of cfm-lsm.
func AllPolicies() []Policy {
	return []Policy{
		{
			ID:          PolicyMemfdExec,
			Title:       "Block exec from memfd",
			Hook:        "bprm_check_security",
			DefaultMode: ModeDisabled,
			Description: "Refuse execve when the backing file is anonymous shmem (memfd_create).",
		},
		{
			ID:          PolicyReverseShell,
			Title:       "Reverse shell pattern",
			Hook:        "bprm_check_security",
			DefaultMode: ModeDisabled,
			Description: "Detect exec where stdin/stdout/stderr are dup'd to a remote-connected socket.",
		},
	}
}

// PolicyByID returns the Policy with the given ID, or (zero, false)
// if the ID is unknown.
func PolicyByID(id PolicyID) (Policy, bool) {
	for _, p := range AllPolicies() {
		if p.ID == id {
			return p, true
		}
	}
	return Policy{}, false
}
