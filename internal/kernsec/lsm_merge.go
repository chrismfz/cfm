package kernsec

import (
	"fmt"
	"os"
	"strings"
)

// LSMBPFRuleID is the rule identifier operators use in
// /etc/cfm/kernsec.conf overrides:
//
//	[rule "KSEC-LSM-bpf-001"]
//	state = force
//
// Default state is "default" (not forced); the rule is **Tier 2,
// not forced by default**. Operators opt in explicitly because
// changing the LSM list requires a reboot to take effect AND
// affects security-critical kernel state.
const LSMBPFRuleID = "KSEC-LSM-bpf-001"

// LSMBPFRuleDescription is what operators see in audit / preview
// output (when the catalog row integration lands in a follow-up).
const LSMBPFRuleDescription = "Add `bpf` to the kernel lsm= command line so the BPF LSM is active at boot. " +
	"Required for cfm-lsm to load BPF LSM programs on most distros."

// LSMSecurityListPath is the runtime-visible LSM list. Var so tests
// can redirect to a fixture.
var LSMSecurityListPath = "/sys/kernel/security/lsm"

// IsLSMBPFForced reports whether KSEC-LSM-bpf-001 is in the operator's
// kernsec.conf overrides as OverrideForce. The rule does not auto-
// apply at Tier 2 (it requires a reboot to take effect — too
// invasive for the implicit-apply pattern). Operators opt in.
func IsLSMBPFForced(c *Conf) bool {
	if c == nil {
		return false
	}
	return c.Overrides[LSMBPFRuleID] == OverrideForce
}

// MergeLSMBPF appends `bpf` to the existing `lsm=` token in tokens,
// preserving every other LSM the operator has on the cmdline. The
// merge is idempotent: if `bpf` is already in the list, tokens are
// returned unchanged.
//
// Two cases:
//
//   - tokens contains an `lsm=` entry — split on commas, ensure
//     `bpf` is in the list, write back.
//   - tokens contains NO `lsm=` entry — this is the harder case.
//     We do NOT synthesise an `lsm=` from /sys/kernel/security/lsm
//     because the live list reflects the running kernel, which may
//     differ from the boot kernel (KernelCare live-patch swaps,
//     pending package upgrade, etc.). Operators who want kernsec
//     to manage `lsm=` from scratch must run `apply` after at
//     least one boot with the desired list manually configured.
//     Today, we leave tokens untouched in this case and let
//     `cfm lsm status` instruct the operator.
//
// Returns the (possibly modified) token slice. Pure function: never
// touches disk, never logs, suitable for unit tests.
func MergeLSMBPF(tokens []string) []string {
	for i, t := range tokens {
		key, val, ok := splitLSMArg(t)
		if !ok || key != "lsm" {
			continue
		}
		if val == "" {
			// `lsm=` with no value — bizarre but harmless. We
			// write `lsm=bpf` as the merged result.
			tokens[i] = "lsm=bpf"
			return tokens
		}
		parts := strings.Split(val, ",")
		for _, p := range parts {
			if strings.TrimSpace(p) == "bpf" {
				return tokens // already there
			}
		}
		// Append `bpf` preserving the operator's order.
		tokens[i] = "lsm=" + val + ",bpf"
		return tokens
	}
	// No `lsm=` token. Conservative: do not synthesise one. The
	// operator must add `lsm=...` manually first; the next apply
	// will then add `bpf` to it.
	return tokens
}

// UnmergeLSMBPF removes `bpf` from the `lsm=` token if present.
// Idempotent; safe to call when `bpf` was never there.
//
// Used by kernsec's disable path. Symmetric counterpart to
// MergeLSMBPF — kernsec's disable should leave the cmdline in the
// state the operator had before forcing the LSM rule.
func UnmergeLSMBPF(tokens []string) []string {
	for i, t := range tokens {
		key, val, ok := splitLSMArg(t)
		if !ok || key != "lsm" {
			continue
		}
		parts := strings.Split(val, ",")
		out := parts[:0]
		removed := false
		for _, p := range parts {
			if strings.TrimSpace(p) == "bpf" {
				removed = true
				continue
			}
			out = append(out, p)
		}
		if !removed {
			return tokens
		}
		if len(out) == 0 {
			// We removed the last entry — drop the `lsm=` token
			// entirely. The operator wasn't using it for anything
			// else.
			return append(tokens[:i], tokens[i+1:]...)
		}
		tokens[i] = "lsm=" + strings.Join(out, ",")
		return tokens
	}
	return tokens
}

// splitLSMArg splits a single cmdline token into (key, value, ok).
// Bare keys like `slab_nomerge` return ("slab_nomerge", "", true).
// "key=value" tokens return ("key", "value", true).
// Anything else returns ("", "", false).
func splitLSMArg(token string) (string, string, bool) {
	if token == "" {
		return "", "", false
	}
	if eq := strings.IndexByte(token, '='); eq > 0 {
		return token[:eq], token[eq+1:], true
	}
	return token, "", true
}

// LiveLSMHasBPF reports whether the running kernel's LSM list
// (/sys/kernel/security/lsm) contains `bpf`. Used by status to
// answer "did the operator's lsm= edit take effect on the running
// kernel?" — independent of what's in the cmdline file.
func LiveLSMHasBPF() bool {
	b, err := os.ReadFile(LSMSecurityListPath)
	if err != nil {
		return false
	}
	for _, p := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if strings.TrimSpace(p) == "bpf" {
			return true
		}
	}
	return false
}

// LSMBPFAuditState classifies the current rule state for status
// output. Returned by LSMBPFStatus.
type LSMBPFAuditState int

const (
	// LSMBPFNotForced — operator did not opt in to the rule in
	// kernsec.conf. Audit ignores it.
	LSMBPFNotForced LSMBPFAuditState = iota
	// LSMBPFForcedNotApplied — operator forced the rule but `bpf`
	// is not in the live LSM list. Apply has either not run or has
	// not been followed by a reboot.
	LSMBPFForcedNotApplied
	// LSMBPFForcedAndLive — operator forced the rule and `bpf` is
	// in the live LSM list. Working as intended.
	LSMBPFForcedAndLive
)

// String renders the audit state as a short token suitable for
// status output.
func (s LSMBPFAuditState) String() string {
	switch s {
	case LSMBPFForcedAndLive:
		return "FORCED+LIVE"
	case LSMBPFForcedNotApplied:
		return "FORCED, NOT LIVE (reboot required)"
	}
	return "not forced"
}

// LSMBPFStatus returns the human-readable audit state for use in
// `cfm kernsec status`. Self-contained — does not depend on the
// existing audit-row machinery.
func LSMBPFStatus(c *Conf) (LSMBPFAuditState, string) {
	if !IsLSMBPFForced(c) {
		return LSMBPFNotForced, fmt.Sprintf(
			"%s not forced (set [rule %q] state = force in /etc/cfm/kernsec.conf to enable)",
			LSMBPFRuleID, LSMBPFRuleID)
	}
	if LiveLSMHasBPF() {
		return LSMBPFForcedAndLive, fmt.Sprintf(
			"%s active — `bpf` is in /sys/kernel/security/lsm", LSMBPFRuleID)
	}
	return LSMBPFForcedNotApplied, fmt.Sprintf(
		"%s forced but `bpf` not in live LSM list — `cfm kernsec apply` then reboot to take effect",
		LSMBPFRuleID)
}
