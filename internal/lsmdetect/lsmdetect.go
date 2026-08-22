// Package lsmdetect reads and aggregates the cfm-lsm DETECT lines CFM writes to
// its dedicated lsm log (/var/log/cfm/cfm.lsm.log, legacy /var/log/cfm/lsm.log;
// see internal/logging.LogfLSM + internal/lsm/eventsink.go). It backs the
// read-only `lsm_detections` MCP tool: a bounded on-demand tail + pure
// aggregation that answers "which policy keeps firing, on which binaries, and
// how much is repeat noise?" so an operator can separate a real compromise from
// a chatty false positive (the sssd/cagefsctl/panel-perl class of CRED-002
// noise) and tune /etc/cfm/lsm.conf allow_exe/allow_comm accordingly.
//
// Same cost discipline as the other on-demand log readers: nothing retained;
// the caller tails only the last N lines under a timeout (via internal/cfmlog,
// which owns the path candidates). Parsing is pure and unit-tested.
//
// Log-line anatomy (one line each, emitted by emitDetect / emitDetectSummary):
//
//	2026-08-22 20:39:17 [lsm] Privilege escalation without setuid path: pid=2456528 (sssd) policy=CFML-CRED-002 path=sssd user=root(0) exe=/usr/sbin/sssd sha256=… parent_exe=/usr/lib/systemd/systemd
//	2026-08-22 20:39:17 [lsm] CFML-CRED-002 suppressed=12 in_last=60s (cfm.log+notify)
//
// Lifecycle notes share the "[lsm] " prefix but match neither shape and are
// ignored.
//
// Trust model of the parse: everything after "policy=" mixes emitter-owned tags
// with attacker-influenceable values (paths, cwd, cmdline — a pre-root process
// can also spoof its comm). stripCtl guarantees one line per event (control
// bytes became '?'), so the parse can never be made to merge/split LINES, but a
// crafted value can still try to forge a later field or a second "policy="
// token inside the tail. Two cheap hardenings: the policy ID is taken from the
// rightmost ") policy=" anchor whose value looks like a CFML ID (the emitter
// writes exactly one real one; later values rarely carry that shape), and the
// tail tokenizer honours strconv.Quote quoting so an " exe=…" hidden inside a
// quoted cmdline cannot overwrite the exe field. Residual spoofing of free-form
// VALUES remains possible — this is a best-effort triage view; the log line
// itself and the notify JSONL audit stay the authoritative record.
package lsmdetect

import (
	"sort"
	"strconv"
	"strings"
)

const lsmMarker = "[lsm] "

// Entry is one parsed lsm-log line.
type Entry struct {
	When       string `json:"when,omitempty"`  // raw "2006-01-02 15:04:05" prefix
	Kind       string `json:"kind"`            // "detect" | "suppressed"
	Title      string `json:"title,omitempty"` // human policy title (detect only)
	Policy     string `json:"policy"`          // e.g. CFML-CRED-002
	PID        uint32 `json:"pid,omitempty"`
	Comm       string `json:"comm,omitempty"`    // kernel comm, ≤15 chars, may contain spaces
	Path       string `json:"path,omitempty"`    // event target filename (policy-dependent)
	Op         string `json:"op,omitempty"`      // FS op tag when present
	User       string `json:"user,omitempty"`    // resolved name from the /proc snapshot
	Exe        string `json:"exe,omitempty"`     // real exe path from the /proc snapshot
	Deleted    bool   `json:"deleted,omitempty"` // exe was unlinked (" (deleted)")
	SHA256     string `json:"sha256,omitempty"`  // full exe hash (enrichment on)
	ParentExe  string `json:"parent_exe,omitempty"`
	Gone       bool   `json:"gone,omitempty"`       // caller had already exited (" proc=gone")
	Suppressed int    `json:"suppressed,omitempty"` // Kind=="suppressed": dropped-event count
}

// knownKeys are the key=value tags the emitter can produce after policy=
// (eventDetailTail + eventCallerTags + procSnapshot.logSuffix). A token whose
// pre-'=' part is NOT one of these continues the previous value — that is how
// spaces inside exe/cwd/path survive the split.
var knownKeys = map[string]bool{
	"path": true, "op": true, "target_pid": true, "target_uid": true,
	"user": true, "uid": true, "exe": true, "sha256": true, "cwd": true,
	"cmdline": true, "ppid": true, "parent_exe": true, "loginuid": true,
	"origin": true,
}

// Parse extracts an Entry from one lsm.log line. ok=false for anything that is
// neither a DETECT nor a suppression-summary line (lifecycle notes, garbage).
func Parse(line string) (Entry, bool) {
	i := strings.Index(line, lsmMarker)
	if i < 0 {
		return Entry{}, false
	}
	e := Entry{When: strings.TrimSpace(line[:i])}
	rest := line[i+len(lsmMarker):]

	if pol, n, ok := parseSuppressed(rest); ok {
		e.Kind = "suppressed"
		e.Policy = pol
		e.Suppressed = n
		return e, true
	}
	return parseDetect(e, rest)
}

// parseSuppressed recognises "CFML-CRED-002 suppressed=12 in_last=60s …".
func parseSuppressed(rest string) (string, int, bool) {
	fields := strings.Fields(rest)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "CFML-") {
		return "", 0, false
	}
	for _, f := range fields[1:] {
		if v, ok := strings.CutPrefix(f, "suppressed="); ok && isDigits(v) {
			n, _ := strconv.Atoi(v)
			return fields[0], n, true
		}
	}
	return "", 0, false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// parseDetect recognises "<title>: pid=N (<comm>) policy=<ID> <kv tail>".
func parseDetect(e Entry, rest string) (Entry, bool) {
	polStart := findPolicyAnchor(rest)
	if polStart < 0 {
		return Entry{}, false
	}
	head := rest[:polStart]
	tail := rest[polStart:]

	pv := tail
	if sp := strings.IndexByte(tail, ' '); sp >= 0 {
		pv, tail = tail[:sp], tail[sp+1:]
	} else {
		tail = ""
	}
	if !strings.HasPrefix(pv, "CFML-") {
		return Entry{}, false
	}
	e.Kind = "detect"
	e.Policy = pv

	// head = "<title>: pid=N (<comm>)" — split at the FIRST ": pid=": policy
	// titles are emitter-fixed and never contain it, while a spoofed comm can
	// carry a fake ": pid=" later in the line, so first-match is the real one.
	if j := strings.Index(head, ": pid="); j >= 0 {
		h := head[j+len(": pid="):]
		e.Title = strings.TrimSpace(head[:j])
		digits := h
		if sp := strings.IndexByte(h, ' '); sp >= 0 {
			digits = h[:sp]
		}
		e.PID = uint32(atoiPos(digits))
		if lp := strings.IndexByte(h, '('); lp >= 0 {
			// The closing paren is the LAST one in head: a spoofed comm may
			// nest parens, and head always ends with ") policy=".
			end := len(h)
			if rp := strings.LastIndexByte(h, ')'); rp >= 0 {
				end = rp
			}
			e.Comm = h[lp+1 : end]
		}
	}

	parseTail(&e, tail)
	return e, true
}

// findPolicyAnchor returns the index where the real policy-ID VALUE starts.
// Preference order: the rightmost ") policy=" whose value token starts with
// "CFML-", then the rightmost bare " policy=", then -1.
func findPolicyAnchor(rest string) int {
	const anchored = ") policy="
	best := -1
	for i := strings.LastIndex(rest, anchored); i >= 0; i = strings.LastIndex(rest[:i], anchored) {
		if strings.HasPrefix(tokenAfter(rest, i+len(anchored)), "CFML-") {
			return i + len(anchored)
		}
		best = i + len(" policy=")
	}
	if best >= 0 {
		return best
	}
	// Last resort: any bare " policy=" (the emitter always writes the comm
	// parenthetical today, so this is only future-proofing).
	const plain = " policy="
	if j := strings.LastIndex(rest, plain); j >= 0 {
		return j + len(plain)
	}
	return -1
}

// tokenAfter returns the space-delimited token starting at index i of s.
func tokenAfter(s string, i int) string {
	if i >= len(s) {
		return ""
	}
	if sp := strings.IndexByte(s[i:], ' '); sp >= 0 {
		return s[i : i+sp]
	}
	return s[i:]
}

// parseTail walks the key=value tail. Tokens are quote-aware (cmdline is
// strconv.Quote'd and may contain spaces and "key=" text), and a token that
// does not open a known key continues the previous value — so paths/comms
// containing spaces reconstruct intact.
func parseTail(e *Entry, tail string) {
	curKey, curVal := "", ""
	flush := func() {
		switch curKey {
		case "path":
			e.Path = curVal
		case "op":
			e.Op = curVal
		case "user":
			e.User = userName(curVal)
		case "exe":
			e.Exe, e.Deleted = splitDeleted(curVal)
		case "sha256":
			e.SHA256 = curVal
		case "parent_exe":
			e.ParentExe = curVal
		}
	}
	for _, tok := range splitTailTokens(tail) {
		if tok == "proc=gone" { // bare enrichment tag, not a kv pair
			e.Gone = true
			continue
		}
		k, v, ok := strings.Cut(tok, "=")
		if ok && knownKeys[k] {
			flush()
			curKey, curVal = k, v
			continue
		}
		switch {
		case curKey == "":
			// stray prose before any key — ignore
		case curKey == "exe" && tok == "(deleted)":
			curVal += " (deleted)"
		default:
			curVal += " " + tok
		}
	}
	flush()
}

// splitTailTokens splits on spaces but never splits inside a double-quoted
// region (strconv.Quote output: interior quotes appear as \"). Unquoted values
// containing spaces arrive as several tokens and are re-glued by parseTail.
func splitTailTokens(s string) []string {
	out := []string{}
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start := i
		inQ := false
		for i < len(s) {
			c := s[i]
			if inQ && c == '\\' && i+1 < len(s) {
				i += 2
				continue
			}
			if c == '"' {
				inQ = !inQ
			}
			if c == ' ' && !inQ {
				break
			}
			i++
		}
		if i > start {
			out = append(out, s[start:i])
		}
	}
	return out
}

// userName strips the "(uid)" suffix logSuffix appends: "root(0)" → "root".
func userName(v string) string {
	if lp := strings.IndexByte(v, '('); lp > 0 {
		return v[:lp]
	}
	return v
}

// splitDeleted separates the " (deleted)" marker the emitter appends to an
// unlinked exe path.
func splitDeleted(v string) (string, bool) {
	const mark = " (deleted)"
	if strings.HasSuffix(v, mark) {
		return strings.TrimSuffix(v, mark), true
	}
	return v, false
}

func atoiPos(s string) int {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if err != nil {
		return 0
	}
	return int(n)
}

// ── Aggregation ───────────────────────────────────────────────────────────────

// kv is a {key,count} pair for top-N breakdowns.
type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Offender is one repeated (policy, comm, exe) triplet — the unit an operator
// allow-lists: "sssd under CRED-002 fired 240× in the window".
type Offender struct {
	Policy        string `json:"policy"`
	Comm          string `json:"comm,omitempty"`
	Exe           string `json:"exe,omitempty"`
	User          string `json:"user,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
	Count         int    `json:"count"`
	LastSeen      string `json:"last_seen,omitempty"`
	DeletedEvents int    `json:"deleted_events,omitempty"`
}

// PolicyBlock rolls up one policy ID.
type PolicyBlock struct {
	Policy     string `json:"policy"`
	Count      int    `json:"count"`
	Suppressed int    `json:"suppressed"` // dropped by the per-minute cap inside the window
	LastSeen   string `json:"last_seen,omitempty"`
	TopComm    []kv   `json:"top_comm"`
	TopExe     []kv   `json:"top_exe"`
	TopUser    []kv   `json:"top_user"`
}

// Summary is the aggregate the endpoint returns.
type Summary struct {
	TotalEvents     int           `json:"total_events"`
	TotalSuppressed int           `json:"suppressed_total"`
	UniquePolicies  int           `json:"unique_policies"`
	Policies        []PolicyBlock `json:"policies"`
	TopOffenders    []Offender    `json:"top_offenders"`
}

const (
	topPerPolicy = 10
	topOffendMax = 25
	shaShortLen  = 16 // abbreviated hash in the offender rows; full hash stays in the log line
)

// Summarize aggregates parsed lines: per-policy counts (+ suppression-summary
// roll-up), and the top repeat offenders by (policy, comm, exe) — ranked by
// count, newest last-seen first as tiebreak. Deterministic output (stable sort
// order) so consecutive calls over the same window diff cleanly.
func Summarize(lines []string) Summary {
	var s Summary
	s.Policies = make([]PolicyBlock, 0)
	type agg struct {
		block    PolicyBlock
		comms    map[string]int
		exes     map[string]int
		users    map[string]int
		lastSeen string
	}
	byPolicy := map[string]*agg{}
	offenders := map[string]*Offender{}

	for _, ln := range lines {
		e, ok := Parse(ln)
		if !ok {
			continue
		}
		a := byPolicy[e.Policy]
		if a == nil {
			a = &agg{
				block: PolicyBlock{Policy: e.Policy},
				comms: map[string]int{}, exes: map[string]int{}, users: map[string]int{},
			}
			byPolicy[e.Policy] = a
		}
		switch e.Kind {
		case "suppressed":
			a.block.Suppressed += e.Suppressed
			s.TotalSuppressed += e.Suppressed
			continue
		case "detect":
			a.block.Count++
			s.TotalEvents++
			if e.Comm != "" {
				a.comms[e.Comm]++
			}
			if e.Exe != "" {
				a.exes[e.Exe]++
			} else if e.Path != "" {
				// enrichment off / proc gone: the event target filename is
				// often the binary basename for CRED-002 — still worth a row.
				a.exes[e.Path]++
			}
			if u := e.User; u != "" {
				a.users[u]++
			} else {
				a.users["(unknown)"]++
			}
			if e.When > a.lastSeen {
				a.lastSeen = e.When
			}
		}

		key := e.Policy + "\x00" + e.Comm + "\x00" + exeOrPath(e)
		o := offenders[key]
		if o == nil {
			o = &Offender{Policy: e.Policy, Comm: e.Comm, Exe: e.Exe}
			offenders[key] = o
		}
		o.Count++
		if e.User != "" {
			o.User = e.User
		}
		if e.SHA256 != "" && len(o.SHA256) == 0 {
			o.SHA256 = shortSHA(e.SHA256)
		}
		if e.When > o.LastSeen {
			o.LastSeen = e.When
		}
		if e.Deleted {
			o.DeletedEvents++
		}
	}

	s.UniquePolicies = len(byPolicy)
	for _, a := range byPolicy {
		a.block.TopComm = topKV(a.comms, topPerPolicy)
		a.block.TopExe = topKV(a.exes, topPerPolicy)
		a.block.TopUser = topKV(a.users, topPerPolicy)
		a.block.LastSeen = a.lastSeen
		s.Policies = append(s.Policies, a.block)
	}
	sort.Slice(s.Policies, func(i, j int) bool {
		if s.Policies[i].Count != s.Policies[j].Count {
			return s.Policies[i].Count > s.Policies[j].Count
		}
		return s.Policies[i].Policy < s.Policies[j].Policy
	})

	s.TopOffenders = make([]Offender, 0, len(offenders))
	for _, o := range offenders {
		s.TopOffenders = append(s.TopOffenders, *o)
	}
	sort.Slice(s.TopOffenders, func(i, j int) bool {
		if s.TopOffenders[i].Count != s.TopOffenders[j].Count {
			return s.TopOffenders[i].Count > s.TopOffenders[j].Count
		}
		if s.TopOffenders[i].LastSeen != s.TopOffenders[j].LastSeen {
			return s.TopOffenders[i].LastSeen > s.TopOffenders[j].LastSeen
		}
		return offenderLess(s.TopOffenders[i], s.TopOffenders[j])
	})
	if len(s.TopOffenders) > topOffendMax {
		s.TopOffenders = s.TopOffenders[:topOffendMax]
	}
	return s
}

func exeOrPath(e Entry) string {
	if e.Exe != "" {
		return e.Exe
	}
	return e.Path
}

func shortSHA(s string) string {
	if len(s) > shaShortLen {
		return s[:shaShortLen]
	}
	return s
}

func topKV(m map[string]int, limit int) []kv {
	out := make([]kv, 0, len(m))
	for k, c := range m {
		out = append(out, kv{Key: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func offenderLess(a, b Offender) bool {
	return a.Policy+"\x00"+a.Comm+"\x00"+a.Exe < b.Policy+"\x00"+b.Comm+"\x00"+b.Exe
}
