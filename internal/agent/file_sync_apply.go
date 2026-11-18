package agent

// file_sync_apply.go — applying the config files cfm-web distributes
// (Admin → Configs → targets, pulled by syncConfigs): write each file, then run
// the target's post_update_command so the service that reads it picks it up.
//
// Before this, post_update_command was never read: a SpamAssassin rule file
// reached the node within a minute, but spamd kept the old rules until its next
// restart (the nightly cPanel update, if any).
//
// cfm-web is a remote party the node must not hand root to, so:
//   - the command is one of postUpdateActions, run as a fixed argv with no
//     shell. cfm-web holds every node's token; running whatever command it
//     names would make a compromise of it root on the whole fleet (the same
//     reason the write path is prefix-allowlisted).
//   - that alone is not enough under /etc/mail/spamassassin/: spamd runs as
//     root and loads Perl from a plugin file path, a `.pre` file or a file it
//     `include`s, so a file written there is code once spamd restarts. Only
//     `.cf` files are accepted there, with plugins by module name only and
//     includes only inside that dir (saContentRefusal).
//     The other allowed dirs (/etc/cfm, the OpenResty conf and Lua dirs) are
//     not sandboxed by this file: what lands there is trusted as it always was.
//
// A change under spamassassinDir is also linted before and after the write. A
// problem the new files introduced (one the lint before the write did not
// report) rolls them back and skips the restart; when several SpamAssassin
// files changed at once, each is then retried alone so only the one at fault
// is parked (left alone until cfm-web sends a different version); the files
// are narrowed down by halving, not one lint per file. Problems that were
// already there (a dcc_* line with the DCC plugin off) do not block, and a
// lint that cannot run backs off instead of retrying every tick.
//
// After a spamd action the agent checks spamd is active again (runAction). If
// it is not and this sync wrote SpamAssassin files, those are rolled back and
// parked and spamd is restarted on the old ones; an action that still fails
// is retried on later syncs (runActions, retryPendingActions).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"cfm/internal/logging"
)

// postAction is what an allowlisted post_update_command runs. Commands with
// the same id are the same action (run once per sync).
type postAction struct {
	id   string
	argv []string
}

const (
	actionRestartSpamd = "restart-spamd"
	actionReloadSpamd  = "reload-spamd"
)

// postUpdateActions maps the post_update_command strings cfm-web may send to
// what the agent runs. Anything else is refused and logged. Every action is a
// systemctl job, cPanel's /scripts/restartsrv_spamd included: systemd carries
// the restart through even if the cfm daemon is stopped (and its cgroup
// killed) mid-command, where a script killed between its stop and start would
// leave spamd down.
var postUpdateActions = map[string]postAction{
	"systemctl restart spamd":   {actionRestartSpamd, []string{"systemctl", "restart", "spamd"}},
	"/scripts/restartsrv_spamd": {actionRestartSpamd, []string{"systemctl", "restart", "spamd"}},
	"systemctl reload spamd":    {actionReloadSpamd, []string{"systemctl", "reload", "spamd"}},
}

// actionSupersedes: an action that makes another redundant in the same sync.
var actionSupersedes = map[string]string{actionRestartSpamd: actionReloadSpamd}

// syncAllowedPrefixes are the only directories a distributed file may land in.
var syncAllowedPrefixes = []string{
	"/etc/cfm/",
	"/usr/local/openresty/nginx/conf/",
	"/usr/local/openresty/nginx/lua/",
	"/etc/mail/spamassassin/",
}

// Seams for tests: the SpamAssassin config dir whose files get linted, the
// spamassassin binaries tried for the lint, and the command runner.
var (
	spamassassinDir  = "/etc/mail/spamassassin/"
	spamassassinBins = []string{
		"/usr/local/cpanel/3rdparty/bin/spamassassin", // cPanel
		"/usr/bin/spamassassin",
		"/usr/local/bin/spamassassin",
	}
	runSyncCommand = func(ctx context.Context, argv []string) ([]byte, error) {
		return exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	}
)

const (
	postUpdateTimeout = 2 * time.Minute
	saLintTimeout     = 3 * time.Minute
)

// fileSyncState is what the sync remembers between ticks. Only the config-sync
// goroutine touches it (one at a time, startConfigSync).
type fileSyncState struct {
	// parked: target path → the hash that failed the SpamAssassin lint or the
	// content check. That version is neither downloaded nor applied again; a
	// new hash is.
	parked map[string]string
	// lintRetryAt / lintBackoff: after a lint that did not complete (timed
	// out on a loaded box), SpamAssassin changes wait until lintRetryAt
	// instead of starting another multi-minute lint on every tick.
	lintRetryAt time.Time
	lintBackoff time.Duration
	// pendingActions: post-update actions (id → argv) that failed and are
	// retried at the start of a later sync, at most every actionRetryEvery
	// (a node with no spamd at all must not restart-fail every 20 s).
	pendingActions map[string][]string
	actionRetryAt  time.Time
}

const actionRetryEvery = 5 * time.Minute

const (
	lintBackoffMin = time.Minute
	lintBackoffMax = time.Hour
)

// now is the clock, a seam for the backoff tests.
var now = time.Now

// lintFailed schedules the next lint attempt, doubling the wait each time.
func (st *fileSyncState) lintFailed() {
	if st.lintBackoff < lintBackoffMin {
		st.lintBackoff = lintBackoffMin
	} else if st.lintBackoff *= 2; st.lintBackoff > lintBackoffMax {
		st.lintBackoff = lintBackoffMax
	}
	st.lintRetryAt = now().Add(st.lintBackoff)
}

func (st *fileSyncState) lintOK() { st.lintRetryAt, st.lintBackoff = time.Time{}, 0 }

// lintWaiting reports whether SpamAssassin changes are waiting out a backoff.
func (st *fileSyncState) lintWaiting() bool {
	return !st.lintRetryAt.IsZero() && now().Before(st.lintRetryAt)
}

// isParked reports whether path's version hash is parked.
func (st *fileSyncState) isParked(path, hash string) bool {
	h, ok := st.parked[filepath.Clean(path)]
	return ok && strings.EqualFold(h, hash)
}

// applyResult reports one applyUpdates run, for logging and tests.
type applyResult struct {
	Written    []string // paths written and kept
	RolledBack []string // paths written, then restored after a failed lint
	Deferred   []string // SpamAssassin paths not written because no lint could run
	Ran        []string // post-update action ids run
	Failed     []string // post-update action ids that did not succeed (retried later)
	Refused    []string // post-update commands not in the allowlist
}

// pendingWrite is one update on its way to disk, with what it replaces.
type pendingWrite struct {
	u       ConfigUpdate
	path    string
	prev    []byte
	existed bool
	mode    fs.FileMode
}

// applyUpdates writes the updates that differ from disk, lints SpamAssassin
// changes, and runs each distinct allowlisted post-update action once.
func (st *fileSyncState) applyUpdates(ctx context.Context, updates []ConfigUpdate, allowed []string) applyResult {
	var res applyResult
	if st.parked == nil {
		st.parked = map[string]string{}
	}

	var other, sa []pendingWrite
	for _, u := range updates {
		if local := sha1File(u.TargetPath); strings.EqualFold(local, u.Hash) {
			continue
		}
		path := filepath.Clean(u.TargetPath)
		if !pathUnder(path, allowed) {
			logging.LogfAPI("[files] REJECTED write to disallowed path: %s", u.TargetPath)
			continue
		}
		if st.isParked(path, u.Hash) {
			continue // this version failed lint already; wait for a new one
		}
		if isSpamassassinFile(path) {
			if why := saContentRefusal(path, u.Content); why != "" {
				logging.LogfAPI("[files] REJECTED %s: %s", path, why)
				st.parked[path] = u.Hash // logged once, not downloaded again
				continue
			}
		}
		w := pendingWrite{u: u, path: path, mode: 0600}
		prev, err := os.ReadFile(path)
		switch {
		case err == nil:
			w.prev, w.existed = prev, true
			if fi, err := os.Stat(path); err == nil {
				w.mode = fi.Mode().Perm()
			}
		case errors.Is(err, fs.ErrNotExist):
		default:
			// Not "absent": a rollback could not restore it, so don't touch it.
			logging.LogfAPI("[files] cannot read current %s, not updating it: %v", path, err)
			continue
		}
		if isSpamassassinFile(path) {
			sa = append(sa, w)
		} else {
			other = append(other, w)
		}
	}

	var kept []pendingWrite
	for _, w := range other {
		if writePending(w) {
			kept = append(kept, w)
		}
	}
	if len(sa) > 0 {
		kept = append(kept, st.applySpamassassin(ctx, sa, &res)...)
	}

	actions := map[string][]string{}
	for _, w := range kept {
		res.Written = append(res.Written, w.path)
		delete(st.parked, w.path)
		cmd := strings.TrimSpace(w.u.PostUpdateCommand)
		if cmd == "" {
			continue
		}
		a, ok := postUpdateActions[cmd]
		if !ok {
			logging.LogfAPI("[files] REFUSED post_update_command %q for %s: not an allowed action", cmd, w.path)
			res.Refused = append(res.Refused, cmd)
			continue
		}
		if _, dup := actions[a.id]; !dup {
			actions[a.id] = a.argv
		}
	}
	for id, redundant := range actionSupersedes {
		if _, ok := actions[id]; ok {
			delete(actions, redundant)
		}
	}
	var keptSA []pendingWrite
	for _, w := range kept {
		if isSpamassassinFile(w.path) {
			keptSA = append(keptSA, w)
		}
	}
	st.runActions(actions, keptSA, &res)
	return res
}

// runActions runs each action and checks the service came back. A spamd action
// that leaves spamd down, while this sync wrote SpamAssassin files, rolls those
// files back (and parks them: lint passed but spamd would not start with
// them) and restarts spamd again. An action that still fails is kept in
// pendingActions and retried on the next syncs, since the files on disk now
// match cfm-web and no later update would trigger it again.
func (st *fileSyncState) runActions(actions map[string][]string, sa []pendingWrite, res *applyResult) {
	ids := make([]string, 0, len(actions))
	for id := range actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		res.Ran = append(res.Ran, id)
		if runAction(id, actions[id]) {
			delete(st.pendingActions, id)
			continue
		}
		if isSpamdAction(id) && len(sa) > 0 {
			paths := make([]string, 0, len(sa))
			for _, w := range sa {
				paths = append(paths, w.path)
			}
			logging.LogfAPI("[files] spamd is not running after %s; rolling back %s and restarting it", id, strings.Join(paths, ", "))
			rollback(sa, res)
			for _, w := range sa {
				st.parked[w.path] = w.u.Hash
				res.Written = without(res.Written, w.path)
			}
			sa = nil
			restart := postUpdateActions["systemctl restart spamd"]
			if runAction(restart.id, restart.argv) {
				delete(st.pendingActions, id)
				continue
			}
			// What is pending now is the restart, whatever action failed.
			// (Two statements: in `id, actions[id] = ...` the index would be
			// the old id, leaving the restart id with no argv.)
			actions[restart.id] = restart.argv
			id = restart.id
		}
		if st.pendingActions == nil {
			st.pendingActions = map[string][]string{}
		}
		st.pendingActions[id] = actions[id]
		st.actionRetryAt = now().Add(actionRetryEvery)
		res.Failed = append(res.Failed, id)
		logging.LogfAPI("[files] post-update %s did not succeed; retrying on the next sync", id)
	}
}

// retryPendingActions reruns the actions that failed on an earlier sync.
func (st *fileSyncState) retryPendingActions() {
	if len(st.pendingActions) == 0 || now().Before(st.actionRetryAt) {
		return
	}
	pending := st.pendingActions
	st.pendingActions = nil
	var res applyResult
	st.runActions(pending, nil, &res)
}

// runAction runs one post-update action with its own timeout (not the sync
// context: Stop must not cancel a restart half-way) and, for spamd, waits for
// the service to be active again. It reports whether both succeeded.
func runAction(id string, argv []string) bool {
	if len(argv) == 0 {
		logging.LogfAPI("[files] post-update %s has no command; dropping it", id)
		return true
	}
	cctx, cancel := context.WithTimeout(context.Background(), postUpdateTimeout)
	out, err := runSyncCommand(cctx, argv)
	cancel()
	if err != nil {
		logging.LogfAPI("[files] post-update %s (%s) failed: %v: %s", id, strings.Join(argv, " "), err, clipOutput(out))
		return false
	}
	if isSpamdAction(id) && !waitActive("spamd") {
		logging.LogfAPI("[files] post-update %s ran but spamd is not active", id)
		return false
	}
	logging.LogfAPI("[files] post-update %s done", id)
	return true
}

func without(list []string, v string) []string {
	out := list[:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func isSpamdAction(id string) bool { return id == actionRestartSpamd || id == actionReloadSpamd }

// activePolls / activePollDelay bound the wait for a unit still "activating"
// after its restart returned. Vars for tests.
var (
	activePolls     = 15
	activePollDelay = 2 * time.Second
)

// waitActive reports whether systemd has unit active, waiting out a short
// "activating" phase.
func waitActive(unit string) bool {
	for i := 0; i < activePolls; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, _ := runSyncCommand(ctx, []string{"systemctl", "is-active", unit})
		cancel()
		switch strings.TrimSpace(string(out)) {
		case "active", "reloading":
			return true
		case "activating", "deactivating":
			time.Sleep(activePollDelay)
		default:
			return false
		}
	}
	return false
}

// applySpamassassin writes the SpamAssassin files behind a lint gate and
// returns the ones kept.
func (st *fileSyncState) applySpamassassin(ctx context.Context, sa []pendingWrite, res *applyResult) []pendingWrite {
	bin := findSpamassassin()
	if bin == "" {
		logging.LogfAPI("[files] spamassassin binary not found; applying %s changes without a lint", spamassassinDir)
		var kept []pendingWrite
		for _, w := range sa {
			if writePending(w) {
				kept = append(kept, w)
			}
		}
		return kept
	}
	if st.lintWaiting() {
		for _, w := range sa {
			res.Deferred = append(res.Deferred, w.path)
		}
		return nil
	}
	baseline, err := saLintProblems(ctx, bin)
	if err != nil {
		// Without a baseline nothing can be attributed; try again later.
		st.lintFailed()
		logging.LogfAPI("[files] spamassassin lint did not run (%v); deferring %d file(s) until %s",
			err, len(sa), st.lintRetryAt.Format(time.RFC3339))
		for _, w := range sa {
			res.Deferred = append(res.Deferred, w.path)
		}
		return nil
	}
	st.lintOK()

	var written []pendingWrite
	for _, w := range sa {
		if writePending(w) {
			written = append(written, w)
		}
	}
	return st.bisect(ctx, bin, baseline, written, res)
}

// bisect keeps the files in ws that lint clean on top of what is already
// kept: all of them when the set is clean, else each half in turn, down to
// the single files at fault, which are parked. A sync of n files with one bad
// costs about 2·log2(n) lints instead of one per file. ws are already on disk.
func (st *fileSyncState) bisect(ctx context.Context, bin string, baseline map[string]int, ws []pendingWrite, res *applyResult) []pendingWrite {
	if len(ws) == 0 {
		return nil
	}
	introduced, err := saIntroduced(ctx, bin, baseline)
	switch {
	case err != nil:
		st.lintFailed()
		logging.LogfAPI("[files] spamassassin lint after the update did not run (%v); rolling back, retrying after %s",
			err, st.lintRetryAt.Format(time.RFC3339))
		rollback(ws, res)
		return nil
	case len(introduced) == 0:
		return ws
	case len(ws) == 1:
		st.park(ws, introduced, res)
		return nil
	}
	logging.LogfAPI("[files] spamassassin lint: %d file(s) changed together introduced %d problem(s); narrowing down",
		len(ws), len(introduced))
	rollback(ws, res)
	res.RolledBack = res.RolledBack[:len(res.RolledBack)-len(ws)]
	half := len(ws) / 2
	var kept []pendingWrite
	for _, part := range [][]pendingWrite{ws[:half], ws[half:]} {
		if st.lintWaiting() {
			// A lint in an earlier part did not run: the box is too loaded to
			// judge the rest now. Leave it unwritten for after the backoff.
			for _, w := range part {
				res.Deferred = append(res.Deferred, w.path)
			}
			continue
		}
		var onDisk []pendingWrite
		for _, w := range part {
			if writePending(w) {
				onDisk = append(onDisk, w)
			}
		}
		kept = append(kept, st.bisect(ctx, bin, baseline, onDisk, res)...)
	}
	return kept
}

// park rolls back ws, which introduced the lint problems in intro, and
// remembers their versions so they are not tried again.
func (st *fileSyncState) park(ws []pendingWrite, intro []string, res *applyResult) {
	paths := make([]string, 0, len(ws))
	for _, w := range ws {
		paths = append(paths, w.path)
	}
	logging.LogfAPI("[files] spamassassin lint: %s introduced %d problem(s), rolled back, not restarting: %s",
		strings.Join(paths, ", "), len(intro), strings.Join(intro, " | "))
	rollback(ws, res)
	for _, w := range ws {
		st.parked[w.path] = w.u.Hash
	}
}

func writePending(w pendingWrite) bool {
	if err := os.MkdirAll(filepath.Dir(w.path), 0750); err != nil {
		logging.LogfAPI("[files] mkdir %s: %v", filepath.Dir(w.path), err)
		return false
	}
	if err := atomicWrite(w.path, []byte(w.u.Content), 0600); err != nil {
		logging.LogfAPI("[files] write %s: %v", w.path, err)
		return false
	}
	logging.LogfAPI("[files] updated %s", w.path)
	return true
}

// rollback puts each file back as it was: its old content and mode, or gone
// when it did not exist.
func rollback(ws []pendingWrite, res *applyResult) {
	for _, w := range ws {
		var err error
		if w.existed {
			if err = atomicWrite(w.path, w.prev, w.mode); err == nil {
				err = os.Chmod(w.path, w.mode) // atomicWrite's mode is masked by the umask
			}
		} else {
			err = os.Remove(w.path)
		}
		if err != nil {
			logging.LogfAPI("[files] rollback %s: %v", w.path, err)
		}
		res.RolledBack = append(res.RolledBack, w.path)
	}
}

func pathUnder(p string, prefixes []string) bool {
	for _, pfx := range prefixes {
		if strings.HasPrefix(p, pfx) {
			return true
		}
	}
	return false
}

func isSpamassassinFile(p string) bool { return strings.HasPrefix(p, spamassassinDir) }

// perlPackageName is what a `loadplugin Module` name must look like.
var perlPackageName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z0-9_]+)*$`)

// saPluginLine and saIncludeLine match the SpamAssassin directives that can
// pull code or other files into spamd.
var (
	saPluginLine  = regexp.MustCompile(`(?mi)^[ \t]*(loadplugin|tryplugin)[ \t]+(\S+)(?:[ \t]+(\S+))?`)
	saIncludeLine = regexp.MustCompile(`(?mi)^[ \t]*include[ \t]+(\S+)`)
)

// saContentRefusal says why a file may not be written to the SpamAssassin
// dir, or "" when it may. Only rule files (.cf). A `loadplugin Module` line
// is fine: it loads a module already installed in Perl's @INC, none of which
// the sync can write (myip.cf loads SPF, DKIM, DCC, HashBL that way). A
// plugin with a file path (`loadplugin Name /path/x.pm`) is Perl from
// wherever the sender chose, run by spamd as root, so it is refused; so is an
// `include` of a file outside the SpamAssassin dir, which could be one the
// sync wrote unchecked under /etc/cfm/.
func saContentRefusal(path, content string) string {
	if filepath.Ext(path) != ".cf" {
		return "only .cf rule files may be distributed to " + spamassassinDir + " (a .pre or .pm file loads Perl into spamd)"
	}
	for _, m := range saPluginLine.FindAllStringSubmatch(content, -1) {
		if m[3] != "" && !strings.HasPrefix(m[3], "#") { // a trailing "# comment" is not a path
			return fmt.Sprintf("%s %s loads Perl from the file %s into spamd, which runs as root", m[1], m[2], m[3])
		}
		if !perlPackageName.MatchString(m[2]) {
			// Not a package name: what SpamAssassin's loader does with it
			// depends on its version; don't find out.
			return fmt.Sprintf("%s %q is not a Perl package name", m[1], m[2])
		}
	}
	for _, m := range saIncludeLine.FindAllStringSubmatch(content, -1) {
		target := m[1]
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(spamassassinDir)+"/") {
			return fmt.Sprintf("includes %s, outside %s", m[1], spamassassinDir)
		}
	}
	return ""
}

func findSpamassassin() string {
	for _, b := range spamassassinBins {
		if fi, err := os.Stat(b); err == nil && !fi.IsDir() && fi.Mode()&0111 != 0 {
			return b
		}
	}
	return ""
}

// saLintPrefix is the "Nov 18 18:06:05.000 [270837] " stamp SpamAssassin puts
// on each lint line; it differs between runs, so it is cut before comparing.
var saLintPrefix = regexp.MustCompile(`^[A-Z][a-z]{2} +\d+ [\d:.]+ \[\d+\] `)

// saLintVolatile are the parts of a lint line that move without the problem
// changing: Perl's "(eval 180)" counter and the "<DATA> line 717" position of
// a plugin load warning (they shift when any rule file grows), and the
// "(line 33)" of a warning in a file whose earlier lines changed. Kept, they
// would make a pre-existing warning (rigel's dcc_home in myip.cf, titan's
// missing Hashcash plugin) read as new.
var saLintVolatile = regexp.MustCompile(`\(eval \d+\)|<[A-Z]+> line \d+|\(line \d+\)`)

// saLintProblems runs `spamassassin --lint` and returns its problem lines with
// the per-run stamp and the volatile counters removed. The closing "lint: N
// issues detected" summary is dropped: its count changes with every problem.
// An error means the lint did not complete (timed out, could not start); a
// non-zero exit for reported problems is not an error.
func saLintProblems(ctx context.Context, bin string) (map[string]int, error) {
	cctx, cancel := context.WithTimeout(ctx, saLintTimeout)
	defer cancel()
	out, err := runSyncCommand(cctx, []string{bin, "--lint"})
	if cctx.Err() != nil {
		return nil, fmt.Errorf("lint: %w", cctx.Err())
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return nil, err
	}
	problems := map[string]int{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		l := strings.TrimSpace(saLintPrefix.ReplaceAllString(string(line), ""))
		l = saLintVolatile.ReplaceAllString(l, "…")
		if l == "" || strings.Contains(l, "issues detected, please rerun") {
			continue
		}
		problems[l]++ // counted: the same warning on a second line is a new problem
	}
	return problems, nil
}

// saIntroduced lints again and returns the problems reported more often than
// in baseline, sorted.
func saIntroduced(ctx context.Context, bin string, baseline map[string]int) ([]string, error) {
	after, err := saLintProblems(ctx, bin)
	if err != nil {
		return nil, err
	}
	var introduced []string
	for p, n := range after {
		if n > baseline[p] {
			introduced = append(introduced, p)
		}
	}
	sort.Strings(introduced)
	return introduced, nil
}

func clipOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}
