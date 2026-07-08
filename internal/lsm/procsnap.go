//go:build linux

package lsm

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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
// process exit. When the caller has already gone (ENOENT) the snapshot
// marks itself not-alive; the caller's PARENT is usually still around
// (a cron/launcher outlives the short-lived tool it spawned), so a
// missed caller still frequently yields ParentExe / ParentComm.
//
// Everything here is defence-oriented forensics, not a security
// boundary. An attacker who controls the process can spoof comm and
// argv, but cannot fake the exe symlink's inode target or the SHA-256
// of the bytes actually mapped as the program — which is exactly why
// exe + sha256 are the high-value fields for "what IS this". The
// SHA-256 also feeds straight into a VirusTotal / YARA lookup.

// procRoot is the procfs mount. Declared as a var so tests can point it
// at a synthetic tree without needing a live /proc.
var procRoot = "/proc"

const (
	// maxCmdlineBytes bounds the /proc/<pid>/cmdline read so one hostile
	// argv can never dominate a log line or an email body.
	maxCmdlineBytes = 512
	// maxExeHashBytes skips hashing pathologically large exe blobs; real
	// dropper binaries are far smaller.
	maxExeHashBytes = 64 << 20 // 64 MiB
	// snapCacheTTL keeps a snapshot reusable across the burst of events a
	// single caller pid emits (an OBS-004 sweep fires dozens per second
	// from one pid), so the exe is hashed once, not per event. Short
	// enough that a later burst from a reused pid re-snapshots.
	snapCacheTTL = 10 * time.Second
	// snapCacheMaxEntry bounds the cache; exceeding it drops the whole
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
func snapshotProc(pid, uid uint32, hash bool) procSnapshot {
	s := procSnapshot{PID: pid, UID: uid, User: lookupUser(uid), LoginUID: -1}

	base := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10))
	if _, err := os.Stat(base); err != nil {
		// Caller already exited — the race was lost. Leave Alive=false.
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
	s.PPid = readPPid(filepath.Join(base, "status"))
	s.LoginUID = readLoginUID(filepath.Join(base, "loginuid"))
	if hash {
		s.SHA256 = hashExe(filepath.Join(base, "exe"))
	}

	// The parent is the persistent launcher (cron entry, shell script,
	// malware controller) that usually outlives the short-lived caller —
	// often the more actionable "where do I look" pointer.
	if s.PPid != 0 {
		pbase := filepath.Join(procRoot, strconv.FormatUint(uint64(s.PPid), 10))
		if pexe, _ := procReadlink(filepath.Join(pbase, "exe")); pexe != "" {
			s.ParentExe = pexe
		}
		s.ParentComm = strings.TrimSpace(readProcFile(filepath.Join(pbase, "comm"), 64))
	}
	return s
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
// when the same (pid, uid) was snapshotted within snapCacheTTL. now is
// injected so tests stay deterministic.
func cachedSnapshotProc(pid, uid uint32, hash bool, now time.Time) procSnapshot {
	snapCacheMu.Lock()
	if c, ok := snapCache[pid]; ok && c.snap.UID == uid && now.Sub(c.at) < snapCacheTTL {
		snapCacheMu.Unlock()
		return c.snap
	}
	snapCacheMu.Unlock()

	snap := snapshotProc(pid, uid, hash)

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

// readLoginUID reads /proc/<pid>/loginuid, the audit subsystem's record
// of which login session owns the task (which sshd session / cron run
// started the chain). Returns -1 when unset (the (uint32)-1 sentinel)
// or unreadable.
func readLoginUID(path string) int64 {
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

// lookupUser resolves a uid to its username, cached because a busy host
// re-resolves the same handful of web/panel uids on every event. Best-
// effort: returns "" when the uid is not in the password database.
var (
	userCacheMu sync.Mutex
	userCache   = map[uint32]string{}
)

func lookupUser(uid uint32) string {
	userCacheMu.Lock()
	if n, ok := userCache[uid]; ok {
		userCacheMu.Unlock()
		return n
	}
	userCacheMu.Unlock()

	name := ""
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = u.Username
	}
	userCacheMu.Lock()
	if len(userCache) < 4096 {
		userCache[uid] = name
	}
	userCacheMu.Unlock()
	return name
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
	Suspicious  []string // distinct exe paths that are deleted or in ephemeral/home trees
}

// suspiciousExePath reports whether an exe path lives somewhere a
// legitimate long-running daemon normally would not — the ephemeral /
// user-writable trees a dropped payload runs from.
func suspiciousExePath(p string) bool {
	for _, pre := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/home/"} {
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

// capture cache — keyed by uid like the roster, so a swarm's event
// burst re-hashes the offending binaries once per snapCacheTTL rather
// than on every one of the thousands of events a sweep emits. On a clean
// host captureThreat finds no suspicious exe and returns nil cheaply
// (no hashing at all), so the cache only earns its keep on a compromised
// host — which is exactly where the burst is.
type cachedCapture struct {
	files []capturedFile
	at    time.Time
}

var (
	captureCacheMu sync.Mutex
	captureCache   = map[uint32]cachedCapture{}
)

func cachedCaptureThreat(uid uint32, dir string, snap procSnapshot, roster uidRoster, now time.Time) []capturedFile {
	captureCacheMu.Lock()
	if c, ok := captureCache[uid]; ok && now.Sub(c.at) < snapCacheTTL {
		captureCacheMu.Unlock()
		return c.files
	}
	captureCacheMu.Unlock()

	files := captureThreat(dir, snap, roster)

	captureCacheMu.Lock()
	if len(captureCache) >= snapCacheMaxEntry {
		captureCache = map[uint32]cachedCapture{}
	}
	captureCache[uid] = cachedCapture{files: files, at: now}
	captureCacheMu.Unlock()
	return files
}

// captureThreat preserves the suspicious binaries behind snap's caller
// and its roster peers. "Suspicious" = exe unlinked, or under an
// ephemeral/home tree — system binaries are never copied. Deduplicated
// by exe path (then by content in captureExe) and bounded per event.
func captureThreat(dir string, snap procSnapshot, roster uidRoster) []capturedFile {
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
	if dirFileCount(dir) >= captureMaxFiles {
		return nil
	}
	var out []capturedFile
	for _, c := range cands {
		if len(out) >= captureMaxPerEvent {
			break
		}
		cf, err := captureExe(c.pid, dir, maxExeHashBytes)
		if err != nil {
			continue
		}
		cf.Exe = c.exe
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
// suspicious-peer discovery. Everything is best-effort and bounded.
func gatherEnrichment(pid, uid uint32, cfg enrichConf, now time.Time) eventEnrichment {
	if !cfg.Enrich {
		return eventEnrichment{}
	}
	e := eventEnrichment{on: true}
	e.snap = cachedSnapshotProc(pid, uid, cfg.Hash, now)
	if cfg.Peers && uid != 0 {
		e.roster = cachedUIDRoster(uid, now)
	}
	if cfg.Capture {
		e.captured = cachedCaptureThreat(uid, cfg.CaptureDir, e.snap, e.roster, now)
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
