//go:build linux

package lsm

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"cfm/internal/logging"
	"cfm/internal/syslookup"
)

// procsnap.go — best-effort forensic snapshot of the task behind a
// cfm-lsm event, read from /proc at drain time.
//
// The BPF ring-buffer event carries only pid/tgid/uid/gid/comm/filename
// (see events.go). That is enough to know THAT something happened but
// not WHO / WHAT / WHERE: the real binary path (comm is spoofable via
// prctl(PR_SET_NAME) or argv[0]), the working directory, the launching
// parent, the login origin. This file fills that gap by reading the
// caller's /proc entries as soon as the daemon drains the event — far
// faster than any human could, but still a best-effort race against
// process exit.
//
// Parent context (ppid / parent exe / parent comm) is resolved from the
// caller's own /proc/<pid>/status, so it is available only while the
// caller is STILL ALIVE at drain time (the common case — the drain runs
// within milliseconds). A caller that has already fully exited yields
// `proc=gone` with no parent: the BPF event carries no ppid, so there is
// no seed to walk up from. Carrying ppid in the event (a future BPF wire
// change) is what would let us resolve the launcher for an already-exited
// caller.
//
// Everything here is defence-oriented forensics, not a security
// boundary. An attacker who controls the process can spoof comm and
// argv, but cannot fake the exe symlink's inode target or the SHA-256
// of the bytes actually mapped as the program — which is exactly why
// exe + sha256 are the high-value fields for "what IS this". The
// SHA-256 also feeds straight into a VirusTotal / YARA lookup.
//
// SECURITY: every field read here (exe, cwd, comm, parent exe, roster
// peer paths) is attacker-controlled — a user picks their binary's path,
// working directory, and comm. Linux paths may contain any byte except
// NUL and '/', including newlines. Callers MUST run the composed log /
// email strings through stripCtl (lifecycle.go) before emitting so a
// crafted path cannot forge log lines or break the email body.

// procRoot is the procfs mount. Declared as a var so tests can point it
// at a synthetic tree without needing a live /proc.
var procRoot = "/proc"

const (
	// maxCmdlineBytes bounds the /proc/<pid>/cmdline read so one hostile
	// argv can never dominate a log line or an email body.
	maxCmdlineBytes = 512
	// maxExeHashBytes bounds the exe read for both hashing and capture.
	// This work runs synchronously on the single ringbuf-drain goroutine,
	// so the cap doubles as a bound on how long the drain can block on a
	// slow/large read before the kernel ring buffer risks overflow; real
	// dropper binaries are far smaller than this.
	maxExeHashBytes = 32 << 20 // 32 MiB
	// snapCacheTTL keeps a snapshot reusable across the burst of events a
	// single caller emits (an OBS-004 sweep fires dozens per second), so
	// the exe is hashed once, not per event. The cache key also carries
	// the process start time, so a recycled pid is never served a stale
	// snapshot regardless of TTL.
	snapCacheTTL = 10 * time.Second
	// snapCacheMaxEntry bounds each cache; exceeding it drops the whole
	// map (cheap, and the working set is tiny — a handful of live
	// callers at a time).
	snapCacheMaxEntry = 512
	// loginUIDUnset is (uint32)-1, the kernel's "no audit login uid"
	// sentinel in /proc/<pid>/loginuid.
	loginUIDUnset = 0xffffffff
)

// procSnapshot is the forensic context recovered for one event's
// caller. The zero value (Alive=false, empty strings, LoginUID=-1) is
// the safe "process already gone / unreadable" result — every consumer
// treats empty fields as "unknown" rather than erroring.
type procSnapshot struct {
	Alive      bool
	PID        uint32
	StartTime  uint64 // /proc/<pid>/stat field 22; disambiguates a recycled pid
	UID        uint32
	User       string
	Exe        string
	ExeDeleted bool
	SHA256     string
	Cmdline    string
	Cwd        string
	PPid       uint32
	ParentComm string
	ParentExe  string
	LoginUID   int64 // -1 when unset / unreadable
}

// snapshotProc reads a best-effort forensic snapshot of pid from
// procRoot. Never errors: a process that raced to exit yields
// Alive=false with whatever could still be resolved (the uid→user
// mapping does not need /proc). hash controls whether the exe SHA-256
// is computed.
//
// ppidHint is the parent tgid carried by the BPF event (captured
// in-kernel at event time). It is preferred over /proc/<pid>/status
// because it is authoritative at the instant the event fired and is
// available even after the caller has exited — which is what lets the
// parent (the persistent launcher) still be resolved for a short-lived
// dropper whose own /proc entry is already gone. 0 means "no hint".
func snapshotProc(pid, uid, ppidHint uint32, hash bool) procSnapshot {
	s := procSnapshot{PID: pid, UID: uid, User: lookupUser(uid), LoginUID: -1, PPid: ppidHint}

	base := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10))
	s.StartTime = readStartTime(filepath.Join(base, "stat"))
	if _, err := os.Stat(base); err != nil {
		// Caller already exited — the race was lost for its own fields, but
		// the event-provided ppid still lets us resolve the launcher. This
		// is best-effort: the event carries the ppid NUMBER, not the
		// parent's identity, so if the parent ALSO exited and its pid was
		// recycled by drain time, /proc/<ppid> is an unrelated process and
		// ParentExe/Comm mislabel the launcher. Narrow (both the caller and
		// its parent must exit within the ~ms drain window and the ppid be
		// reused), and the caller is already flagged proc=gone; usually the
		// parent is the long-lived launcher and resolves correctly.
		s.resolveParent()
		return s
	}
	s.Alive = true

	if exe, del := procReadlink(filepath.Join(base, "exe")); exe != "" {
		s.Exe, s.ExeDeleted = exe, del
	}
	if cwd, _ := procReadlink(filepath.Join(base, "cwd")); cwd != "" {
		s.Cwd = cwd
	}
	s.Cmdline = readCmdline(filepath.Join(base, "cmdline"))
	// Alive caller: the live status ppid is the ONLY self-consistent parent
	// — it matches the exe/cwd/cmdline just read from the same /proc entry.
	// Set it unconditionally (overriding the event hint): if the pid was
	// recycled between the event firing and this read, os.Stat succeeds for
	// the NEW occupant, and the event's ppidHint belongs to the OLD one, so
	// pairing hint-parent with live-child would misattribute the launcher.
	// If status can't be read we leave PPid 0 (parent unknown) rather than
	// fall back to that possibly-wrong hint. The event ppid is used only for
	// the gone-caller branch above, where it is the sole available source.
	s.PPid = readPPid(filepath.Join(base, "status"))
	s.LoginUID = readLoginUID(filepath.Join(base, "loginuid"))
	if hash {
		s.SHA256 = hashExe(filepath.Join(base, "exe"))
	}
	s.resolveParent()
	return s
}

// resolveParent fills ParentExe / ParentComm from /proc/<PPid> when a
// ppid is known. The parent (cron entry, shell script, malware
// controller) is the persistent launcher and usually the more actionable
// "where do I look" pointer than the short-lived caller.
func (s *procSnapshot) resolveParent() {
	if s.PPid == 0 {
		return
	}
	pbase := filepath.Join(procRoot, strconv.FormatUint(uint64(s.PPid), 10))
	if pexe, _ := procReadlink(filepath.Join(pbase, "exe")); pexe != "" {
		s.ParentExe = pexe
	}
	s.ParentComm = strings.TrimSpace(readProcFile(filepath.Join(pbase, "comm"), 64))
}

// snapshot cache — one entry per live caller pid, reused for the
// duration of that caller's event burst. The emit path is single-
// goroutine (Lifecycle.run), but ConfigureEventSink and future callers
// could touch this concurrently, so it is mutex-guarded.
type cachedSnap struct {
	snap procSnapshot
	at   time.Time
}

var (
	snapCacheMu sync.Mutex
	snapCache   = map[uint32]cachedSnap{}
)

// cachedSnapshotProc returns a snapshot for pid, reusing a recent one
// only when the pid's uid AND start time still match — so a recycled pid
// (a new process reusing pid P under the same uid within the TTL, common
// under fork churn) is never served the prior process's exe/sha/cmdline.
// The current start time is a single small read; on a hit it saves the
// expensive exe hash + readlinks. now is injected so tests stay
// deterministic.
func cachedSnapshotProc(pid, uid, ppidHint uint32, hash bool, now time.Time) procSnapshot {
	st := readStartTime(filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "stat"))

	snapCacheMu.Lock()
	if c, ok := snapCache[pid]; ok && c.snap.UID == uid && c.snap.StartTime == st && st != 0 && now.Sub(c.at) < snapCacheTTL {
		snapCacheMu.Unlock()
		return c.snap
	}
	snapCacheMu.Unlock()

	snap := snapshotProc(pid, uid, ppidHint, hash)

	snapCacheMu.Lock()
	if len(snapCache) >= snapCacheMaxEntry {
		snapCache = map[uint32]cachedSnap{}
	}
	snapCache[pid] = cachedSnap{snap: snap, at: now}
	snapCacheMu.Unlock()
	return snap
}

// logSuffix renders the full enrichment for a cfm.log line: verbose,
// unabbreviated, one caller. Empty fields are omitted so a raced /
// half-readable process still produces a clean line.
func (s procSnapshot) logSuffix() string {
	var b strings.Builder
	if s.User != "" {
		fmt.Fprintf(&b, " user=%s(%d)", s.User, s.UID)
	} else {
		fmt.Fprintf(&b, " uid=%d", s.UID)
	}
	if s.Exe != "" {
		b.WriteString(" exe=" + s.Exe)
		if s.ExeDeleted {
			b.WriteString(" (deleted)")
		}
	}
	if s.SHA256 != "" {
		b.WriteString(" sha256=" + s.SHA256)
	}
	if s.Cwd != "" {
		b.WriteString(" cwd=" + s.Cwd)
	}
	if s.Cmdline != "" {
		b.WriteString(" cmdline=" + strconv.Quote(s.Cmdline))
	}
	if s.PPid != 0 {
		fmt.Fprintf(&b, " ppid=%d", s.PPid)
		if s.ParentComm != "" {
			fmt.Fprintf(&b, "(%s)", s.ParentComm)
		}
	}
	if s.ParentExe != "" {
		b.WriteString(" parent_exe=" + s.ParentExe)
	}
	if s.LoginUID >= 0 {
		fmt.Fprintf(&b, " loginuid=%d", s.LoginUID)
	}
	if !s.Alive {
		b.WriteString(" proc=gone")
	}
	return b.String()
}

// identitySuffix renders the caller-stable subset used to build the
// notify (email) reason. It deliberately excludes per-event and
// per-invocation volatile fields (pid, cwd, cmdline) so that every
// event in a single caller's burst produces a byte-identical reason —
// which lets the notify deduper collapse a whole /proc sweep into one
// email instead of one-per-target. The SHA-256 is abbreviated to keep
// the subject line readable; the full hash is in logSuffix + Extra.
func (s procSnapshot) identitySuffix() string {
	var b strings.Builder
	if s.User != "" {
		b.WriteString(" user=" + s.User)
	}
	if s.Exe != "" {
		b.WriteString(" exe=" + s.Exe)
		if s.ExeDeleted {
			b.WriteString(" (deleted)")
		}
	}
	if s.SHA256 != "" {
		b.WriteString(" sha256=" + shortHash(s.SHA256))
	}
	if s.ParentExe != "" {
		b.WriteString(" parent_exe=" + s.ParentExe)
	}
	if !s.Alive {
		b.WriteString(" proc=gone")
	}
	return b.String()
}

// addExtra copies the structured fields into a notify Extra map for
// downstream consumers (JSONL audit, future email templates).
func (s procSnapshot) addExtra(m map[string]string) {
	if m == nil {
		return
	}
	if s.User != "" {
		m["user"] = s.User
	}
	if s.Exe != "" {
		m["exe"] = s.Exe
	}
	if s.ExeDeleted {
		m["exe_deleted"] = "1"
	}
	if s.SHA256 != "" {
		m["exe_sha256"] = s.SHA256
	}
	if s.Cwd != "" {
		m["cwd"] = s.Cwd
	}
	if s.Cmdline != "" {
		m["cmdline"] = s.Cmdline
	}
	if s.PPid != 0 {
		m["ppid"] = strconv.FormatUint(uint64(s.PPid), 10)
	}
	if s.ParentComm != "" {
		m["parent_comm"] = s.ParentComm
	}
	if s.ParentExe != "" {
		m["parent_exe"] = s.ParentExe
	}
	if s.LoginUID >= 0 {
		m["loginuid"] = strconv.FormatInt(s.LoginUID, 10)
	}
	if !s.Alive {
		m["proc"] = "gone"
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// All the readers below take a path built as
// filepath.Join(procRoot, <numeric-pid>, <fixed-basename>), a structurally
// constrained /proc path — the gosec G304 (file-inclusion-via-variable)
// annotations mirror the same-reasoning ones in internal/outbound/forensics.go.

// procReadlink resolves a /proc magic symlink, splitting off the
// kernel's " (deleted)" suffix that marks an unlinked target — the
// classic dropper fingerprint (stage a binary, unlink it, keep
// running). Returns ("", false) on any error.
func procReadlink(path string) (target string, deleted bool) {
	dst, err := os.Readlink(path)
	if err != nil {
		return "", false
	}
	if t := strings.TrimSuffix(dst, " (deleted)"); t != dst {
		return t, true
	}
	return dst, false
}

// readCmdline reads /proc/<pid>/cmdline (NUL-separated argv) and joins
// it into a single space-separated string, bounded to maxCmdlineBytes.
func readCmdline(path string) string {
	// #nosec G304 -- path is procRoot/<pid>/cmdline, structurally constrained.
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(b) > maxCmdlineBytes {
		b = b[:maxCmdlineBytes]
	}
	fields := strings.FieldsFunc(string(b), func(r rune) bool { return r == 0 })
	return strings.Join(fields, " ")
}

// readProcFile reads up to max bytes from a small /proc file (comm,
// etc.) without pulling in a full ReadFile for a one-line value.
func readProcFile(path string, max int) string {
	// #nosec G304 -- path is procRoot/<pid>/<fixed basename>, structurally constrained.
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

// readPPid extracts the PPid field from /proc/<pid>/status. Returns 0
// when the file is unreadable or the field is absent.
func readPPid(statusPath string) uint32 {
	// #nosec G304 -- statusPath is procRoot/<pid>/status, structurally constrained.
	f, err := os.Open(statusPath)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32); err == nil {
				return uint32(n)
			}
			return 0
		}
	}
	return 0
}

// readStartTime returns field 22 (starttime, in clock ticks since boot)
// of /proc/<pid>/stat — the stable per-process identity that survives a
// pid recycle. Field 2 (comm) may contain spaces and parentheses, so the
// remaining space-separated fields are parsed after the FINAL ')'.
// Returns 0 on any error.
func readStartTime(statPath string) uint64 {
	// #nosec G304 -- statPath is procRoot/<pid>/stat, structurally constrained.
	b, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 > len(s) {
		return 0
	}
	// After ')' the fields start at field 3 (state); starttime is field 22,
	// i.e. index 22-3 = 19 in the post-')' slice.
	fields := strings.Fields(s[i+1:])
	if len(fields) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[19], 10, 64)
	return v
}

// readLoginUID reads /proc/<pid>/loginuid, the audit subsystem's record
// of which login session owns the task (which sshd session / cron run
// started the chain). Returns -1 when unset (the (uint32)-1 sentinel)
// or unreadable.
func readLoginUID(path string) int64 {
	// #nosec G304 -- path is procRoot/<pid>/loginuid, structurally constrained.
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n == loginUIDUnset {
		return -1
	}
	return n
}

// hashExe computes the SHA-256 of the bytes behind /proc/<pid>/exe.
// Opening the magic symlink yields the real program image even when the
// on-disk path was unlinked (the inode stays pinned while the process
// lives), so this identifies a deleted dropper too. Bounded by
// maxExeHashBytes; returns "" on any error or oversize image.
func hashExe(path string) string {
	// #nosec G304 -- path is procRoot/<pid>/exe, structurally constrained.
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > maxExeHashBytes {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxExeHashBytes)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// userMap resolves uid→name CGO-free from /etc/passwd with a periodic
// reload — the shared internal/syslookup resolver (also used by
// internal/outbound), rather than os/user.LookupId (which can pull in
// cgo/NSS and never refreshes). Lazily created on first use so package
// init does no file I/O.
var (
	userMapOnce sync.Once
	userMap     *syslookup.Map
)

// lookupUser resolves a uid to its username, best-effort: returns "" when
// the uid is not in /etc/passwd.
func lookupUser(uid uint32) string {
	userMapOnce.Do(func() { userMap = syslookup.New() })
	return userMap.User(uid)
}

// ------------------------------------------------------------------ //
// uid swarm roster — every process sharing the caller's real uid.     //
// ------------------------------------------------------------------ //

const (
	// rosterPeerLimit bounds how many peer processes are listed (and how
	// many exe readlinks the scan does). The distinct-exe/suspicious
	// aggregates still count the full match set; only the per-process
	// list is capped.
	rosterPeerLimit = 64
	// maxDistinctExeList bounds the distinct-exe and suspicious-exe
	// aggregate slices so a host with a genuinely varied per-uid process
	// mix can't produce an unbounded summary.
	maxDistinctExeList = 16
)

// peerProc is one process in the uid roster.
type peerProc struct {
	PID     uint32
	Comm    string
	Exe     string
	Deleted bool
}

// uidRoster is the set of processes sharing one real uid, captured at
// event time. Total may exceed len(Peers) when the scan hit the cap.
type uidRoster struct {
	UID         uint32
	Total       int
	Peers       []peerProc
	DistinctExe []string
	Suspicious  []string // distinct exe paths that are deleted or on an ephemeral fs
}

// ephemeralExeRoots is the set of filesystems a legitimate long-running
// daemon does not execute from — the same ephemeral / tmpfs trees the
// EXEC-006 BPF policy treats as suspicious (docs/cfm-lsm.md). It is
// deliberately NOT extended with /home or bare /run: on shared hosting
// every legitimate per-user binary lives under /home, and /run holds
// systemd per-user runtime dirs, so treating those as suspicious would
// over-capture benign binaries — the exact hazard conf.go's allow_path
// SECURITY TRADE-OFF note warns about. A dropper that hides in a homedir
// is still caught: droppers almost always unlink themselves, and the
// `(deleted)` flag triggers capture independent of path.
var ephemeralExeRoots = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}

// suspiciousExePath reports whether an exe path lives on an ephemeral
// filesystem a normal daemon does not exec from.
func suspiciousExePath(p string) bool {
	for _, pre := range ephemeralExeRoots {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// procUID returns the owning real uid of a /proc/<pid> directory (the
// task's real uid), via one stat — cheaper than reading status.
func procUID(dir string) (uint32, bool) {
	fi, err := os.Stat(dir)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// snapshotUIDRoster scans procRoot for every task whose real uid is uid
// and returns a bounded roster. Best-effort: unreadable entries are
// skipped. limit caps the per-process list.
func snapshotUIDRoster(uid uint32, limit int) uidRoster {
	r := uidRoster{UID: uid}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return r
	}
	exeSeen := map[string]bool{}
	suspSeen := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		base := filepath.Join(procRoot, e.Name())
		puid, ok := procUID(base)
		if !ok || puid != uid {
			continue
		}
		r.Total++
		exe, del := procReadlink(filepath.Join(base, "exe"))
		if exe != "" && !exeSeen[exe] {
			exeSeen[exe] = true
			if len(r.DistinctExe) < maxDistinctExeList {
				r.DistinctExe = append(r.DistinctExe, exe)
			}
			if (del || suspiciousExePath(exe)) && !suspSeen[exe] {
				suspSeen[exe] = true
				if len(r.Suspicious) < maxDistinctExeList {
					r.Suspicious = append(r.Suspicious, exe)
				}
			}
		}
		if len(r.Peers) < limit {
			comm := strings.TrimSpace(readProcFile(filepath.Join(base, "comm"), 64))
			r.Peers = append(r.Peers, peerProc{PID: uint32(pid), Comm: comm, Exe: exe, Deleted: del})
		}
	}
	sort.Slice(r.Peers, func(i, j int) bool { return r.Peers[i].PID < r.Peers[j].PID })
	return r
}

// roster cache — keyed by uid (not pid) so an entire swarm's event
// burst, which spans many pids under one uid, triggers a single /proc
// scan per snapCacheTTL rather than one per caller pid.
type cachedRoster struct {
	roster uidRoster
	at     time.Time
}

var (
	rosterCacheMu sync.Mutex
	rosterCache   = map[uint32]cachedRoster{}
)

func cachedUIDRoster(uid uint32, now time.Time) uidRoster {
	rosterCacheMu.Lock()
	if c, ok := rosterCache[uid]; ok && now.Sub(c.at) < snapCacheTTL {
		rosterCacheMu.Unlock()
		return c.roster
	}
	rosterCacheMu.Unlock()

	r := snapshotUIDRoster(uid, rosterPeerLimit)

	rosterCacheMu.Lock()
	if len(rosterCache) >= snapCacheMaxEntry {
		rosterCache = map[uint32]cachedRoster{}
	}
	rosterCache[uid] = cachedRoster{roster: r, at: now}
	rosterCacheMu.Unlock()
	return r
}

func (r uidRoster) summary() string {
	if r.Total == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, " swarm=%dprocs distinct_exe=%d", r.Total, len(r.DistinctExe))
	if len(r.Suspicious) > 0 {
		b.WriteString(" suspicious_exe=" + strings.Join(r.Suspicious, ","))
	}
	return b.String()
}

// samples renders the roster as email body lines (one per peer). The
// header states the true total even when the per-process list was
// capped.
func (r uidRoster) samples() []string {
	if r.Total == 0 {
		return nil
	}
	header := fmt.Sprintf("uid=%d swarm: %d process(es) sharing this uid", r.UID, r.Total)
	if len(r.Peers) < r.Total {
		header += fmt.Sprintf(" (listing first %d)", len(r.Peers))
	}
	out := make([]string, 0, len(r.Peers)+1)
	out = append(out, header)
	for _, p := range r.Peers {
		line := fmt.Sprintf("  peer pid=%d comm=%s", p.PID, p.Comm)
		if p.Exe != "" {
			line += " exe=" + p.Exe
			if p.Deleted {
				line += " (deleted)"
			}
		}
		out = append(out, line)
	}
	return out
}

func (r uidRoster) addExtra(m map[string]string) {
	if m == nil || r.Total == 0 {
		return
	}
	m["swarm_count"] = strconv.Itoa(r.Total)
	if len(r.DistinctExe) > 0 {
		m["swarm_distinct_exe"] = strings.Join(r.DistinctExe, ",")
	}
	if len(r.Suspicious) > 0 {
		m["swarm_suspicious_exe"] = strings.Join(r.Suspicious, ",")
	}
}

// ------------------------------------------------------------------ //
// binary capture — preserve the offending image before it is unlinked. //
// ------------------------------------------------------------------ //

const (
	// captureMaxPerEvent bounds how many distinct suspicious binaries a
	// single event preserves (caller + roster peers combined).
	captureMaxPerEvent = 8
	// captureMaxFiles caps the number of files the capture dir may hold;
	// once reached, capture no-ops rather than filling the disk. Old
	// captures are left for the operator to triage/clear.
	captureMaxFiles = 512
)

// capturedFile records one preserved binary.
type capturedFile struct {
	Exe    string // the /proc-resolved exe path it came from
	Path   string // where it was saved (<dir>/<sha>.bin)
	SHA256 string
}

// captureExe copies /proc/<pid>/exe into dir as <sha256>.bin. Reading
// the magic symlink yields the real image even when the on-disk path was
// unlinked, so a self-deleting dropper is still preserved while its
// process lives. Deduplicated by content hash: a binary already captured
// is not rewritten. Files are root-only (0600) and never executed.
func captureExe(pid uint32, dir string, maxBytes int64) (capturedFile, error) {
	src := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "exe")
	// #nosec G304 -- src is procRoot/<pid>/exe, structurally constrained.
	f, err := os.Open(src)
	if err != nil {
		return capturedFile{}, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > maxBytes {
		return capturedFile{}, fmt.Errorf("exe exceeds capture size cap")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return capturedFile{}, err
	}
	tmp, err := os.CreateTemp(dir, ".capture-*")
	if err != nil {
		return capturedFile{}, err
	}
	tmpName := tmp.Name()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(f, maxBytes)); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return capturedFile{}, err
	}
	tmp.Close()
	sha := hex.EncodeToString(h.Sum(nil))
	dst := filepath.Join(dir, sha+".bin")
	if _, err := os.Stat(dst); err == nil {
		os.Remove(tmpName) // already captured this content
		return capturedFile{Path: dst, SHA256: sha}, nil
	}
	_ = os.Chmod(tmpName, 0o600)
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return capturedFile{}, err
	}
	return capturedFile{Path: dst, SHA256: sha}, nil
}

func dirFileCount(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	return len(entries)
}

// capture dedup cache — keyed by EXE PATH, not uid. A caller's event
// burst re-reads/re-hashes each distinct path at most once per
// snapCacheTTL, but a DISTINCT new dropper path under the same uid is
// still captured (a per-uid cache would return the first dropper's files
// and silently skip a second, different dropper run in the same window).
// On a clean host captureThreat finds no suspicious exe and returns nil
// cheaply, so this only earns its keep on a compromised host.
type cachedPathCapture struct {
	file capturedFile
	ok   bool // a capture succeeded for this path
	at   time.Time
}

var (
	capturePathMu    sync.Mutex
	capturePathCache = map[string]cachedPathCapture{}
	captureFullOnce  sync.Once
)

// captureThreat preserves the suspicious binaries behind snap's caller
// and its roster peers. "Suspicious" = exe unlinked, or on an ephemeral
// fs (see suspiciousExePath) — system and homedir binaries are never
// copied. Path-keyed dedup avoids re-hashing within a burst; content is
// additionally deduplicated on disk by captureExe. Bounded per event and
// by a directory file cap (surfaced once when hit). now is injected so
// tests stay deterministic.
func captureThreat(dir string, snap procSnapshot, roster uidRoster, now time.Time) []capturedFile {
	if dir == "" {
		return nil
	}
	type cand struct {
		pid uint32
		exe string
	}
	var cands []cand
	seen := map[string]bool{}
	add := func(pid uint32, exe string, deleted bool) {
		if exe == "" || seen[exe] {
			return
		}
		if !deleted && !suspiciousExePath(exe) {
			return
		}
		seen[exe] = true
		cands = append(cands, cand{pid, exe})
	}
	add(snap.PID, snap.Exe, snap.ExeDeleted)
	for _, p := range roster.Peers {
		add(p.PID, p.Exe, p.Deleted)
	}
	if len(cands) == 0 {
		return nil
	}

	var out []capturedFile
	for _, c := range cands {
		if len(out) >= captureMaxPerEvent {
			break
		}
		capturePathMu.Lock()
		if pc, ok := capturePathCache[c.exe]; ok && now.Sub(pc.at) < snapCacheTTL {
			capturePathMu.Unlock()
			if pc.ok {
				out = append(out, pc.file)
			}
			continue
		}
		capturePathMu.Unlock()

		if dirFileCount(dir) >= captureMaxFiles {
			// Surface once — a silent stop hides lost evidence exactly when
			// it matters. Don't cache the miss so a cleared dir resumes.
			captureFullOnce.Do(func() {
				logging.LogfLSM("[lsm] capture dir %s at cap (%d files); pausing binary capture — clear old <sha>.bin files to resume", dir, captureMaxFiles)
				KmsgStatef("ISSUE", "lsm capture dir at cap (%d files); binary capture paused", captureMaxFiles)
			})
			continue
		}

		cf, err := captureExe(c.pid, dir, maxExeHashBytes)
		if err == nil {
			cf.Exe = c.exe
		}
		capturePathMu.Lock()
		if len(capturePathCache) >= snapCacheMaxEntry {
			capturePathCache = map[string]cachedPathCapture{}
		}
		capturePathCache[c.exe] = cachedPathCapture{file: cf, ok: err == nil, at: now}
		capturePathMu.Unlock()
		if err != nil {
			continue
		}
		out = append(out, cf)
	}
	return out
}

// ------------------------------------------------------------------ //
// enrichment bundle — everything the drain path gathers for one event. //
// ------------------------------------------------------------------ //

// eventEnrichment aggregates the /proc-derived context for one event.
// on is false when enrichment is disabled, in which case every render
// method is a no-op.
type eventEnrichment struct {
	on       bool
	snap     procSnapshot
	roster   uidRoster
	captured []capturedFile
}

// gatherEnrichment performs all the /proc I/O for one event under cfg.
// Ordered snapshot → roster → capture so capture can reuse the roster's
// suspicious-peer discovery. ppidHint is the event's BPF-provided parent
// tgid, used to resolve the launcher even for an exited caller.
// Everything is best-effort and bounded.
func gatherEnrichment(pid, uid, ppidHint uint32, cfg enrichConf, now time.Time) eventEnrichment {
	if !cfg.Enrich {
		return eventEnrichment{}
	}
	e := eventEnrichment{on: true}
	e.snap = cachedSnapshotProc(pid, uid, ppidHint, cfg.Hash, now)
	if cfg.Peers && uid != 0 {
		e.roster = cachedUIDRoster(uid, now)
	}
	if cfg.Capture {
		e.captured = captureThreat(cfg.CaptureDir, e.snap, e.roster, now)
	}
	return e
}

func (e eventEnrichment) capturedSummary() string {
	if len(e.captured) == 0 {
		return ""
	}
	paths := make([]string, 0, len(e.captured))
	for _, c := range e.captured {
		paths = append(paths, c.Path)
	}
	return " captured=" + strings.Join(paths, ",")
}

// logSuffix is the full one-line enrichment for cfm.log.
func (e eventEnrichment) logSuffix() string {
	if !e.on {
		return ""
	}
	return e.snap.logSuffix() + e.roster.summary() + e.capturedSummary()
}

// identitySuffix is the caller-stable subset for the notify (email)
// reason — snapshot identity only, so the deduper collapses a burst.
func (e eventEnrichment) identitySuffix() string {
	if !e.on {
		return ""
	}
	return e.snap.identitySuffix()
}

// samples returns the multi-line detail for the email body: the uid
// swarm roster followed by any preserved-binary references.
func (e eventEnrichment) samples() []string {
	if !e.on {
		return nil
	}
	out := e.roster.samples()
	for _, c := range e.captured {
		out = append(out, fmt.Sprintf("captured binary: %s (sha256=%s exe=%s)", c.Path, c.SHA256, c.Exe))
	}
	return out
}

func (e eventEnrichment) addExtra(m map[string]string) {
	if !e.on || m == nil {
		return
	}
	e.snap.addExtra(m)
	e.roster.addExtra(m)
	if len(e.captured) > 0 {
		paths := make([]string, 0, len(e.captured))
		for _, c := range e.captured {
			paths = append(paths, c.Path)
		}
		m["captured"] = strings.Join(paths, ",")
	}
}
