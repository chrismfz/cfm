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
//     root and loads Perl named by `loadplugin`/`tryplugin` lines and `.pre`
//     files, so a file written there is code once spamd restarts. Only `.cf`
//     files without those directives are accepted there (saContentRefusal).
//     The other allowed dirs (/etc/cfm, the OpenResty conf and Lua dirs) are
//     not sandboxed by this file: what lands there is trusted as it always was.
//
// A change under spamassassinDir is also linted before and after the write. A
// problem the new files introduced (one the lint before the write did not
// report) rolls them back and skips the restart; when several SpamAssassin
// files changed at once, each is then retried alone so only the one at fault
// is parked (left alone until cfm-web sends a different version). Problems
// that were already there (a dcc_* line with the DCC plugin off) do not block.

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
// what the agent runs. Anything else is refused and logged.
var postUpdateActions = map[string]postAction{
	"systemctl restart spamd":   {actionRestartSpamd, []string{"systemctl", "restart", "spamd"}},
	"/scripts/restartsrv_spamd": {actionRestartSpamd, []string{"/scripts/restartsrv_spamd"}},
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
	// parked: target path → the hash whose SpamAssassin lint failed. That
	// version is neither downloaded nor applied again; a new hash is.
	parked map[string]string
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
	ids := make([]string, 0, len(actions))
	for id := range actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		cctx, cancel := context.WithTimeout(ctx, postUpdateTimeout)
		out, err := runSyncCommand(cctx, actions[id])
		cancel()
		if err != nil {
			logging.LogfAPI("[files] post-update %s (%s) failed: %v: %s", id, strings.Join(actions[id], " "), err, clipOutput(out))
		} else {
			logging.LogfAPI("[files] post-update %s done", id)
		}
		res.Ran = append(res.Ran, id)
	}
	return res
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
	baseline, err := saLintProblems(ctx, bin)
	if err != nil {
		// Without a baseline nothing can be attributed; try again next sync.
		logging.LogfAPI("[files] spamassassin lint did not run (%v); deferring %d file(s) to the next sync", err, len(sa))
		for _, w := range sa {
			res.Deferred = append(res.Deferred, w.path)
		}
		return nil
	}

	var written []pendingWrite
	for _, w := range sa {
		if writePending(w) {
			written = append(written, w)
		}
	}
	if len(written) == 0 {
		return nil
	}
	introduced, err := saIntroduced(ctx, bin, baseline)
	switch {
	case err != nil:
		logging.LogfAPI("[files] spamassassin lint after the update did not run (%v); rolling back, retrying next sync", err)
		rollback(written, res)
		return nil
	case len(introduced) == 0:
		return written
	case len(written) == 1:
		st.park(written, introduced, res)
		return nil
	}

	// Several files changed and something broke: find which, one at a time.
	logging.LogfAPI("[files] spamassassin lint: %d file(s) changed together introduced %d problem(s); retrying each alone",
		len(written), len(introduced))
	rollback(written, res)
	res.RolledBack = res.RolledBack[:len(res.RolledBack)-len(written)]
	var kept []pendingWrite
	for _, w := range written {
		if !writePending(w) {
			continue
		}
		one := []pendingWrite{w}
		intro, err := saIntroduced(ctx, bin, baseline)
		switch {
		case err != nil:
			logging.LogfAPI("[files] spamassassin lint did not run (%v); rolling back %s, retrying next sync", err, w.path)
			rollback(one, res)
		case len(intro) > 0:
			st.park(one, intro, res)
		default:
			kept = append(kept, w)
		}
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

// saCodeDirective matches the SpamAssassin lines that load Perl code.
var saCodeDirective = regexp.MustCompile(`(?mi)^[ \t]*(loadplugin|tryplugin)\b`)

// saContentRefusal says why a file may not be written to the SpamAssassin
// dir, or "" when it may: only rule files (.cf), and none that load code.
func saContentRefusal(path, content string) string {
	if filepath.Ext(path) != ".cf" {
		return "only .cf rule files may be distributed to " + spamassassinDir + " (a .pre or .pm file loads Perl into spamd)"
	}
	if m := saCodeDirective.FindString(content); m != "" {
		return fmt.Sprintf("contains a %q directive (loads Perl into spamd, which runs as root)", strings.TrimSpace(m))
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
func saLintProblems(ctx context.Context, bin string) (map[string]bool, error) {
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
	problems := map[string]bool{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		l := strings.TrimSpace(saLintPrefix.ReplaceAllString(string(line), ""))
		l = saLintVolatile.ReplaceAllString(l, "…")
		if l == "" || strings.Contains(l, "issues detected, please rerun") {
			continue
		}
		problems[l] = true
	}
	return problems, nil
}

// saIntroduced lints again and returns the problems not in baseline, sorted.
func saIntroduced(ctx context.Context, bin string, baseline map[string]bool) ([]string, error) {
	after, err := saLintProblems(ctx, bin)
	if err != nil {
		return nil, err
	}
	var introduced []string
	for p := range after {
		if !baseline[p] {
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
