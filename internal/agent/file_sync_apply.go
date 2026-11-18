package agent

// file_sync_apply.go — applying the config files cfm-web distributes
// (Admin → Configs → targets, pulled by syncConfigs): write each file, then run
// the target's post_update_command so the service that reads it picks it up.
//
// Before this, post_update_command was never read: a SpamAssassin rule file
// reached the node within a minute, but spamd kept the old rules until its next
// restart (the nightly cPanel update, if any).
//
// Two guards, both because cfm-web is a remote party the node must not trust
// with root:
//   - the command is one of postUpdateActions, run as a fixed argv with no
//     shell. cfm-web holds every node's token; running whatever command it
//     names would turn a compromise of it into root on the whole fleet (the
//     same reason the write path is prefix-allowlisted).
//   - a change under spamassassinDir is linted first. A lint problem the new
//     files introduced (one the lint run before the write did not report)
//     rolls the files back, skips the restart, and parks that file version
//     until cfm-web sends a different one, instead of restarting spamd onto a
//     broken rule set or re-downloading and re-linting it every tick.
//     Problems that were already there (a dcc_* line with the DCC plugin
//     off) do not block.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"cfm/internal/logging"
)

// postUpdateActions maps the post_update_command strings cfm-web may send to
// the argv the agent runs. Anything else is refused and logged.
var postUpdateActions = map[string][]string{
	"systemctl restart spamd":   {"systemctl", "restart", "spamd"},
	"systemctl reload spamd":    {"systemctl", "reload", "spamd"},
	"/scripts/restartsrv_spamd": {"/scripts/restartsrv_spamd"},
}

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

// fileSyncState is what the sync remembers between ticks.
type fileSyncState struct {
	// parked: target path → the hash whose SpamAssassin lint failed. That
	// version is not applied again; a new hash from cfm-web is.
	parked map[string]string
}

// applyResult reports one applyUpdates run, for logging and tests.
type applyResult struct {
	Written    []string // paths written and kept
	RolledBack []string // paths written, then restored after a failed lint
	Ran        []string // post-update commands run (allowlist keys)
	Refused    []string // post-update commands not in the allowlist
}

// applyUpdates writes the updates that differ from disk, lints SpamAssassin
// changes, and runs each distinct allowlisted post-update command once.
func (st *fileSyncState) applyUpdates(ctx context.Context, updates []ConfigUpdate, allowed []string) applyResult {
	var res applyResult
	if st.parked == nil {
		st.parked = map[string]string{}
	}

	type written struct {
		u       ConfigUpdate
		path    string
		prev    []byte
		existed bool
	}
	var todo []ConfigUpdate
	for _, u := range updates {
		if local := sha1File(u.TargetPath); strings.EqualFold(local, u.Hash) {
			continue
		}
		cleanPath := filepath.Clean(u.TargetPath)
		if !pathUnder(cleanPath, allowed) {
			logging.LogfAPI("[files] REJECTED write to disallowed path: %s", u.TargetPath)
			continue
		}
		if h, ok := st.parked[cleanPath]; ok && strings.EqualFold(h, u.Hash) {
			continue // this version failed lint already; wait for a new one
		}
		u.TargetPath = cleanPath
		todo = append(todo, u)
	}
	if len(todo) == 0 {
		return res
	}

	saChanged := false
	for _, u := range todo {
		if isSpamassassinFile(u.TargetPath) {
			saChanged = true
		}
	}
	var saBin string
	var baseline map[string]bool
	if saChanged {
		saBin = findSpamassassin()
		if saBin == "" {
			logging.LogfAPI("[files] spamassassin binary not found; applying %s changes without a lint", spamassassinDir)
		} else {
			baseline = saLintProblems(ctx, saBin)
		}
	}

	var done []written
	for _, u := range todo {
		prev, err := os.ReadFile(u.TargetPath)
		existed := err == nil
		if err := os.MkdirAll(filepath.Dir(u.TargetPath), 0750); err != nil {
			logging.LogfAPI("[files] mkdir %s: %v", filepath.Dir(u.TargetPath), err)
			continue
		}
		if err := atomicWrite(u.TargetPath, []byte(u.Content), 0600); err != nil {
			logging.LogfAPI("[files] write %s: %v", u.TargetPath, err)
			continue
		}
		logging.LogfAPI("[files] updated %s", u.TargetPath)
		done = append(done, written{u: u, path: u.TargetPath, prev: prev, existed: existed})
	}

	if saBin != "" && len(done) > 0 {
		after := saLintProblems(ctx, saBin)
		var introduced []string
		for p := range after {
			if !baseline[p] {
				introduced = append(introduced, p)
			}
		}
		if len(introduced) > 0 {
			sort.Strings(introduced)
			logging.LogfAPI("[files] spamassassin lint: the update introduced %d problem(s), rolling back and not restarting: %s",
				len(introduced), strings.Join(introduced, " | "))
			kept := done[:0]
			for _, w := range done {
				if !isSpamassassinFile(w.path) {
					kept = append(kept, w)
					continue
				}
				if w.existed {
					if err := atomicWrite(w.path, w.prev, 0600); err != nil {
						logging.LogfAPI("[files] rollback %s: %v", w.path, err)
					}
				} else if err := os.Remove(w.path); err != nil {
					logging.LogfAPI("[files] rollback (remove) %s: %v", w.path, err)
				}
				st.parked[w.path] = w.u.Hash
				res.RolledBack = append(res.RolledBack, w.path)
			}
			done = kept
		} else if len(after) > 0 {
			logging.LogfAPI("[files] spamassassin lint reports %d problem(s) that were there before this update; applying anyway", len(after))
		}
	}

	seen := map[string]bool{}
	for _, w := range done {
		res.Written = append(res.Written, w.path)
		delete(st.parked, w.path)
		cmd := strings.TrimSpace(w.u.PostUpdateCommand)
		if cmd == "" || seen[cmd] {
			continue
		}
		seen[cmd] = true
		argv, ok := postUpdateActions[cmd]
		if !ok {
			logging.LogfAPI("[files] REFUSED post_update_command %q for %s: not an allowed action", cmd, w.path)
			res.Refused = append(res.Refused, cmd)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, postUpdateTimeout)
		out, err := runSyncCommand(cctx, argv)
		cancel()
		if err != nil {
			logging.LogfAPI("[files] post_update_command %q failed: %v: %s", cmd, err, clipOutput(out))
		} else {
			logging.LogfAPI("[files] post_update_command %q done", cmd)
		}
		res.Ran = append(res.Ran, cmd)
	}
	return res
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

// saLintVolatile are the parts of a lint line that move when any rule file
// changes size, not just the broken one: Perl's "(eval 180)" counter and the
// "<DATA> line 717" position of a plugin load warning. Kept, they would make a
// pre-existing warning (titan's missing Hashcash plugin) read as new.
var saLintVolatile = regexp.MustCompile(`\(eval \d+\)|<[A-Z]+> line \d+`)

// saLintProblems runs `spamassassin --lint` and returns its problem lines with
// the per-run stamp removed. The closing "lint: N issues detected" summary is
// dropped: its count changes with every problem and would read as new.
func saLintProblems(ctx context.Context, bin string) map[string]bool {
	cctx, cancel := context.WithTimeout(ctx, saLintTimeout)
	defer cancel()
	out, _ := runSyncCommand(cctx, []string{bin, "--lint"})
	problems := map[string]bool{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		l := strings.TrimSpace(saLintPrefix.ReplaceAllString(string(line), ""))
		l = saLintVolatile.ReplaceAllString(l, "…")
		if l == "" || strings.Contains(l, "issues detected, please rerun") {
			continue
		}
		problems[l] = true
	}
	return problems
}

func clipOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}
