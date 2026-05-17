package lsm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// filter.go — userspace post-emission allowlist for cfm-lsm events.
//
// The BPF programs deliberately err on the side of "report and let
// userspace decide": adding map lookups or comm comparisons to every
// hook costs verifier complexity, takes effect only after `make bpf`
// regeneration, and can't see across containerised exe-file identities
// (the same daemon under a Docker overlayfs has a different inode every
// time the image is repulled).
//
// This filter lives entirely in the daemon. It consults a per-policy
// allowlist of known-legitimate triggers and silently drops matching
// events before they reach notify/log/kmsg. The allowlist is loaded
// from compiled-in defaults plus operator-configurable lsm.conf
// entries; the matcher is intentionally simple (basename equality for
// exe identities, exact match for comm names) to keep the suppression
// surface auditable.
//
// Two match dimensions:
//
//   - ExeBasenames: matches Event.Filename when it is either an
//     absolute path (CFML-EXEC-003 / CFML-EXEC-005 emit the bprm
//     filename) or a bare d_name (CFML-CRED-002 emits the exe
//     dentry's d_name). filepath.Base normalises both forms before
//     comparing against the allowlist.
//
//   - Comms: matches Event.Comm exactly. Comm strings come from
//     bpf_get_current_comm and are TASK_COMM_LEN (16) bytes — long
//     binary names get truncated to 15 chars, so the allowlist must
//     hold the truncated forms (e.g. "containerd-shim" not
//     "containerd-shim-runc-v2").
//
// The filter never observes pid/uid; that's deliberate. The default
// list covers daemons whose detector match is structural to the way
// the daemon implements privilege separation or inetd-style worker
// dispatch, not specific to one host's account layout.

// EventFilter encodes which events to silently drop. Construction is
// cheap; the daemon installs one global instance via SetEventFilter
// after parsing lsm.conf and consults it from emitNotify.
type EventFilter struct {
	rules map[PolicyID]policyAllow
}

type policyAllow struct {
	exeBasenames   map[string]struct{}
	comms          map[string]struct{}
	pathPrefixes []string // matched against /proc/<pid>/cmdline args
}

// defaultEventFilter is the package-internal singleton consulted by
// emitNotify. Atomic so ApplyConfig can swap a fresh filter in without
// racing against the drain goroutine.
var defaultEventFilter atomic.Pointer[EventFilter]

// SetEventFilter installs f as the global filter consulted by
// emitNotify. Safe to call from any goroutine; the swap is atomic.
// Pass nil to clear the filter (no suppression).
func SetEventFilter(f *EventFilter) {
	defaultEventFilter.Store(f)
}

// shouldSuppressEvent reports whether the globally-installed filter
// would drop ev. Returns false when no filter is installed.
func shouldSuppressEvent(ev Event) bool {
	f := defaultEventFilter.Load()
	if f == nil {
		return false
	}
	return f.Match(ev)
}

// Match reports whether ev is on f's allowlist for its policy. The
// match is conservative: only events whose policy has an explicit
// rule set are even consulted; everything else falls through to
// "report normally."
func (f *EventFilter) Match(ev Event) bool {
	if f == nil {
		return false
	}
	rule, ok := f.rules[ev.PolicyID]
	if !ok {
		return false
	}
	if len(rule.exeBasenames) > 0 && ev.Filename != "" {
		base := filepath.Base(ev.Filename)
		if _, hit := rule.exeBasenames[base]; hit {
			return true
		}
	}
	if len(rule.comms) > 0 && ev.Comm != "" {
		if _, hit := rule.comms[ev.Comm]; hit {
			return true
		}
	}
	// Script-prefix match is last because it does I/O (one /proc read).
	// Only consulted when comm + exe haven't already decided, and only
	// when the policy actually has any prefixes configured — keeps the
	// fast path zero-syscall.
	if len(rule.pathPrefixes) > 0 && ev.PID != 0 {
		if cmdlineHasPathPrefix(ev.PID, rule.pathPrefixes) {
			return true
		}
	}
	return false
}

// cmdlineHasPathPrefix reads /proc/<pid>/cmdline and reports whether
// any argument has one of the given path prefixes. Best-effort: a
// missing /proc entry (race with process exit) or a read error returns
// false — the event flows normally rather than being silently dropped.
//
// The prefix match is on full argument strings, not just basename. So
// `/usr/share/lve-stats/` matches an arg `/usr/share/lve-stats/lvestats-server.py`
// but not an arg `/tmp/lve-stats-fake.py`. Operators configure prefixes
// via `allow_path` in lsm.conf.
func cmdlineHasPathPrefix(pid uint32, prefixes []string) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	// /proc cmdline is NUL-separated arg strings with a trailing NUL.
	for _, arg := range strings.Split(string(b), "\x00") {
		if arg == "" {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(arg, p) {
				return true
			}
		}
	}
	return false
}

// BuildEventFilter constructs an EventFilter from compiled-in defaults
// merged with operator-supplied conf overrides. Conf may be nil, in
// which case only defaults apply.
//
// allow_exe entries are normalised to filepath.Base before storage so
// the matcher can compare against either bare d_name or absolute path
// emissions uniformly. allow_comm entries are stored as-is; the BPF
// side truncates to TASK_COMM_LEN, so operators copy the comm exactly
// as it appears in dmesg.
func BuildEventFilter(c *Conf) *EventFilter {
	f := &EventFilter{rules: map[PolicyID]policyAllow{}}
	if c != nil {
		// Drive the merge through AllowExeFor / AllowCommFor so the
		// global [allow] section is honoured without the filter caring
		// about storage layout. Iterate the policy catalogue rather
		// than ranging the per-policy map so policies that consume the
		// allowlist but have no per-policy entry still pick up the
		// global fanout.
		for _, p := range AllPolicies() {
			if allowExePolicy(p.ID) {
				for _, path := range c.AllowExeFor(p.ID) {
					f.addExeBasenames(p.ID, []string{filepath.Base(path)})
				}
			}
			if allowCommPolicy(p.ID) {
				if comms := c.AllowCommFor(p.ID); len(comms) > 0 {
					f.addComms(p.ID, comms)
				}
			}
			if allowPathPolicy(p.ID) {
				if prefixes := c.AllowPathFor(p.ID); len(prefixes) > 0 {
					f.addPathPrefixes(p.ID, prefixes)
				}
			}
		}
	}
	return f
}

func (f *EventFilter) addExeBasenames(id PolicyID, names []string) {
	if len(names) == 0 {
		return
	}
	r := f.rules[id]
	if r.exeBasenames == nil {
		r.exeBasenames = map[string]struct{}{}
	}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		r.exeBasenames[n] = struct{}{}
	}
	f.rules[id] = r
}

func (f *EventFilter) addComms(id PolicyID, names []string) {
	if len(names) == 0 {
		return
	}
	r := f.rules[id]
	if r.comms == nil {
		r.comms = map[string]struct{}{}
	}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		r.comms[n] = struct{}{}
	}
	f.rules[id] = r
}

func (f *EventFilter) addPathPrefixes(id PolicyID, prefixes []string) {
	if len(prefixes) == 0 {
		return
	}
	r := f.rules[id]
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		r.pathPrefixes = append(r.pathPrefixes, p)
	}
	f.rules[id] = r
}

// All baseline allowlist entries now live in the conf layer
// (DefaultGlobalAllowExe / DefaultGlobalAllowComm in conf.go). Having
// a single source of truth means an operator who edits /etc/cfm/lsm.conf
// is editing the actual effective allowlist — no compiled-in defaults
// silently re-add entries the operator deliberately removed. A daemon
// running against a config that pre-dates `[allow]` will see no
// suppression and the operator can refresh by diffing the shipped
// configs/lsm.conf template into their /etc/cfm/lsm.conf and running
// `cfm lsm restart`.
