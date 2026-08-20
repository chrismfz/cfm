package kernsec

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// legacySysctlConf is the pre-drop-in single sysctl file that
// `sysctl --system` still applies. A conflicting reconcile-eligible
// key here overrides kernsec's drop-in exactly like a later-sorting
// drop-in would, so the foreign reconcile scans it too. var, not
// const, so tests can point it at a tempdir (or "" to skip it).
var legacySysctlConf = "/etc/sysctl.conf"

// foreignReconcileKeys is the set of kernsec-managed sysctl keys that
// `apply` actively RECONCILES in *foreign* sysctl files — any sysctl
// config file other than kernsec's own SysctlPath.
//
// kernsec normally relies on its `99-cfm-kernsec.conf` drop-in winning
// the `sysctl --system` ordering race. But that race is lexical by
// basename: a foreign drop-in that sorts AFTER `99-cfm-kernsec.conf`
// (e.g. the legacy `99-kspp.conf` the old scripts/kspp.sh shipped,
// which sets `fs.protected_regular=2`) is applied LAST and silently
// reverts kernsec's value on the next reboot / `sysctl --system`.
// kernsec's live `sysctl -w` fixes the running kernel this minute, but
// the stale foreign line re-breaks things after a reboot — a latent
// trap that `apply --check` (which only compares kernsec's own file +
// cmdline) never sees.
//
// For keys where that silent revert re-introduces a KNOWN breakage,
// kernsec neutralises the foreign line (comments it out, backing the
// file up first) so the key falls through to kernsec's drop-in value
// and the setting settles everywhere.
//
// Today the only member is fs.protected_regular: kernsec deliberately
// ships =1 (not the KSPP =2) because =2 covers group-writable sticky
// dirs and breaks cPanel's DNS Zone Editor, and a leftover foreign =2
// re-breaks it after a reboot. The authoritative value + accept set
// come from the resolved rule (single source of truth — profile.go),
// so this stays a bare key→reason set; the reason string is
// operator-facing only.
//
// This is a deliberately narrow allowlist, NOT "kernsec overwrites any
// operator sysctl". Adding a key here asserts kernsec fully owns it and
// a divergent foreign copy is always drift to be defused — only true
// for keys kernsec pins to a specific value for compatibility reasons.
var foreignReconcileKeys = map[string]string{
	"fs.protected_regular": "value 2 breaks cPanel's DNS Zone Editor; kernsec pins =1",
}

// foreignConflict is one active line in a foreign sysctl file that sets
// a reconcile-eligible key to a value kernsec does not accept.
type foreignConflict struct {
	File   string // path of the foreign file (as scanned)
	Line   int    // 1-based line number of the offending assignment
	Key    string // the reconcile-eligible key
	Found  string // the divergent value on disk
	Want   string // kernsec's authoritative value for the key
	Reason string // operator-facing why-it-matters
}

// detectForeignSysctlConflicts scans every sysctl config file other
// than kernsec's own SysctlPath for an ACTIVE assignment of a
// reconcile-eligible key whose value diverges from what kernsec is
// applying. Read-only: used by the apply preview (report + `--check`
// drift accounting) and by the mutate path, which neutralises whatever
// this returns.
//
// Only keys kernsec is actually applying AND the running kernel exposes
// are considered — that guarantees kernsec's own drop-in carries an
// ACTIVE line for the key to fall through to once the foreign line is
// commented out, so the reconcile can never leave the key unset.
func detectForeignSysctlConflicts(applied []SysctlRule) []foreignConflict {
	type target struct {
		want   string
		accept []string
	}
	targets := map[string]target{}
	for _, r := range applied {
		if _, ok := foreignReconcileKeys[r.Key]; !ok {
			continue
		}
		if !sysctlExists(r.Key) {
			continue
		}
		targets[r.Key] = target{want: r.Value, accept: r.AcceptValues}
	}
	if len(targets) == 0 {
		return nil
	}

	var out []foreignConflict
	for _, path := range foreignSysctlFiles() {
		content, err := os.ReadFile(path)
		if err != nil {
			// Absent / unreadable foreign file — nothing to reconcile
			// here. Not fatal: the scan is best-effort.
			continue
		}
		for i, raw := range strings.Split(string(content), "\n") {
			key, val, ok := parseSysctlAssignment(raw)
			if !ok {
				continue
			}
			t, eligible := targets[key]
			if !eligible {
				continue
			}
			if isAcceptable(val, t.want, t.accept) {
				continue
			}
			out = append(out, foreignConflict{
				File:   path,
				Line:   i + 1,
				Key:    key,
				Found:  val,
				Want:   t.want,
				Reason: foreignReconcileKeys[key],
			})
		}
	}
	return out
}

// foreignSysctlFiles returns the canonical path of every sysctl config
// file kernsec scans for foreign conflicts: all `*.conf` in the drop-in
// directory (filepath.Dir(SysctlPath) — `/etc/sysctl.d` in production, a
// tempdir under test) EXCEPT kernsec's own SysctlPath, plus the legacy
// single-file /etc/sysctl.conf. Deriving the directory from SysctlPath
// (rather than hardcoding /etc/sysctl.d) keeps the scan hermetic: tests
// that redirect SysctlPath to a tempdir automatically scan only that
// tempdir.
//
// Every candidate is canonicalised through filepath.EvalSymlinks so
// that a symlinked drop-in and its target dedup to one entry and edits
// land on the REAL file: Debian/Ubuntu ship
// `/etc/sysctl.d/99-sysctl.conf -> ../sysctl.conf`, so the glob match
// and legacySysctlConf are the same underlying file — without resolving
// symlinks kernsec would scan it twice AND the atomic rewrite would
// replace the distro symlink with a regular file. Returning the
// resolved target keeps the symlink intact.
//
// The result is deterministic. Non-.conf files and kernsec's own
// backups (`*.cfm-kernsec.bak*`) are excluded by the `*.conf` glob.
// Only /etc is scanned — vendor-owned dirs (/usr/lib/sysctl.d,
// /run/sysctl.d) are deliberately neither detected nor auto-edited (a
// conflict kernsec won't fix must not be reported as never-converging
// drift; an operator override there is the operator's to resolve).
func foreignSysctlFiles() []string {
	dir := filepath.Dir(SysctlPath)

	seen := map[string]bool{canonPath(SysctlPath): true} // never our own file
	var files []string
	add := func(p string) {
		c := canonPath(p)
		if seen[c] {
			return
		}
		seen[c] = true
		files = append(files, c)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	sort.Strings(matches)
	for _, m := range matches {
		add(m)
	}
	if legacySysctlConf != "" {
		add(legacySysctlConf)
	}
	return files
}

// canonPath resolves p through symlinks (and to an absolute path) so
// two names for the same file compare equal. Falls back to an absolute
// path if the file does not exist / the symlink is broken (EvalSymlinks
// requires the target to exist), and to p unchanged if even that fails.
func canonPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return absOrSame(p)
}

// absOrSame returns filepath.Abs(p) or p unchanged if Abs fails.
func absOrSame(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// parseSysctlAssignment parses one line of a sysctl config file into
// (key, value). Mirrors systemd-sysctl / procps parsing: blank lines
// and lines beginning with '#' or ';' are comments; an optional leading
// '-' on the key (the "ignore write errors" marker) is stripped; the
// key/value split is on the first '='. ok is false for any
// non-assignment line.
//
// The key is normalised to dotted form: sysctl.conf(5) accepts '/' and
// '.' as interchangeable separators (e.g. `fs/protected_regular` ==
// `fs.protected_regular`), so a foreign drop-in written with slashes
// must still match the dotted allowlist. Normalising `/`→`.` is exact
// for the reconcile keys (none carry a dotted component that would need
// slash disambiguation); a non-allowlisted key that normalises
// ambiguously simply fails to match any target and is ignored.
func parseSysctlAssignment(raw string) (key, val string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s[0] == '#' || s[0] == ';' {
		return "", "", false
	}
	eq := strings.IndexByte(s, '=')
	if eq < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s[:eq]), "-"))
	key = strings.ReplaceAll(key, "/", ".")
	val = strings.TrimSpace(s[eq+1:])
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

// uniqueForeignFiles returns the distinct file paths named by the
// conflicts, in first-seen order — one entry per file kernsec will
// rewrite (a file may carry several conflicting lines).
func uniqueForeignFiles(conflicts []foreignConflict) []string {
	seen := map[string]bool{}
	var files []string
	for _, c := range conflicts {
		if !seen[c.File] {
			seen[c.File] = true
			files = append(files, c.File)
		}
	}
	return files
}

// foreignKeysFor returns a compact "key=found[, key=found …]" summary of
// the conflicts in one file, for the operator-facing preview/summary.
func foreignKeysFor(conflicts []foreignConflict, file string) string {
	var parts []string
	for _, c := range conflicts {
		if c.File == file {
			parts = append(parts, c.Key+"="+c.Found)
		}
	}
	return strings.Join(parts, ", ")
}

// reportForeignConflicts prints the pending foreign-conflict lines in
// the [Sysctl] section of the apply preview (shown for apply / dry-run
// / check). The mutate path prints its own past-tense "neutralised"
// lines separately in neutraliseForeignSysctls.
func reportForeignConflicts(w io.Writer, conflicts []foreignConflict) {
	if len(conflicts) == 0 {
		return
	}
	fmt.Fprintf(w, "  foreign: %d conflicting drop-in line(s) — apply neutralises these so the value persists across reboot:\n",
		len(conflicts))
	for _, c := range conflicts {
		fmt.Fprintf(w, "             %s:%d  %s=%s (kernsec pins %s=%s — %s)\n",
			c.File, c.Line, c.Key, c.Found, c.Key, c.Want, c.Reason)
	}
}

// neutraliseForeignSysctls rewrites each foreign file carrying a
// conflict, commenting out the offending assignment(s) with a marker so
// the key falls through to kernsec's own drop-in value on the next
// `sysctl --system` / reboot. The original file is backed up once
// (`<path>.cfm-kernsec.bak`) before its first rewrite; the file's
// existing permissions are preserved.
//
// Best-effort and continue-on-error: a failure on one foreign file is
// reported to w but never aborts apply. Even if a rewrite fails, the
// live `sysctl -w` in the loader still sets the correct value this run;
// only the persist-across-reboot guarantee for that one file is missed,
// and the operator sees exactly which file to fix by hand.
func neutraliseForeignSysctls(w io.Writer, conflicts []foreignConflict) {
	byFile := map[string][]foreignConflict{}
	var order []string
	for _, c := range conflicts {
		if _, ok := byFile[c.File]; !ok {
			order = append(order, c.File)
		}
		byFile[c.File] = append(byFile[c.File], c)
	}

	for _, path := range order {
		cs := byFile[path]
		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(w, "[Sysctl] foreign reconcile: cannot read %s: %v — skipped\n", path, err)
			continue
		}

		lineHit := make(map[int]foreignConflict, len(cs))
		for _, c := range cs {
			lineHit[c.Line] = c
		}

		in := strings.Split(string(content), "\n")
		out := make([]string, 0, len(in)+len(cs))
		var done []foreignConflict // conflicts actually commented out
		for i, ln := range in {
			if c, hit := lineHit[i+1]; hit {
				// Re-parse to guard against a race / stale line number:
				// only comment out a line that STILL parses to the exact
				// conflict we detected. Also makes the pass idempotent —
				// an already-commented line no longer parses as an
				// assignment, so a second apply is a no-op.
				if k, v, ok := parseSysctlAssignment(ln); ok && k == c.Key && v == c.Found {
					out = append(out,
						fmt.Sprintf("# %s=%s neutralised by cfm kernsec: %s. kernsec pins %s=%s in %s.",
							c.Key, c.Found, c.Reason, c.Key, c.Want, filepath.Base(SysctlPath)),
						"# "+strings.TrimRight(ln, "\r"),
					)
					done = append(done, c)
					continue
				}
			}
			out = append(out, ln)
		}
		if len(done) == 0 {
			// Nothing actually matched on re-parse (already neutralised
			// or changed under us) — leave the file untouched, and take
			// no backup (nothing was modified).
			continue
		}
		// One-shot backup, taken only now that we know we are editing —
		// never leave a stray .bak for a file we didn't touch, and never
		// rewrite without a recovery copy on disk.
		if err := BackupOnce(path, path+BackupSuffix); err != nil {
			fmt.Fprintf(w, "[Sysctl] foreign reconcile: cannot back up %s: %v — skipped (not editing without a backup)\n", path, err)
			continue
		}
		if err := AtomicWriteFile(path, []byte(strings.Join(out, "\n")), foreignFileMode(path)); err != nil {
			fmt.Fprintf(w, "[Sysctl] foreign reconcile: cannot rewrite %s: %v — left as-is\n", path, err)
			continue
		}
		for _, c := range done {
			fmt.Fprintf(w, "[Sysctl] foreign reconcile: %s:%d %s=%s neutralised (kernsec pins %s=%s; %s). Backup: %s\n",
				c.File, c.Line, c.Key, c.Found, c.Key, c.Want, c.Reason, path+BackupSuffix)
		}
	}
}

// foreignFileMode returns the existing permission bits of path so a
// rewrite preserves them, falling back to 0644 (the sysctl.d default)
// if the file cannot be stat'd.
func foreignFileMode(path string) os.FileMode {
	if st, err := os.Stat(path); err == nil {
		return st.Mode().Perm()
	}
	return 0o644
}
