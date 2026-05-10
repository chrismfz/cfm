package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BackupSuffix is appended to managed files when kernsec takes its
// one-shot backup before first modifying them. Mirrors kspp.sh's
// `.kspp.bak` convention; renamed for ownership clarity.
const BackupSuffix = ".cfm-kernsec.bak"

// AtomicWriteFile writes content to path via a same-directory tmp
// file + fsync + rename. Creates the parent directory with perm 0755
// if absent. The dest gets the requested perm.
func AtomicWriteFile(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".cfm-tmp-")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := f.Name()
	defer func() {
		// Best-effort cleanup of stray tmp on any error path.
		if _, err := os.Stat(tmpPath); err == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(content); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync %s: %w", tmpPath, err)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// nowFunc returns the current time. var, not const, so tests can
// substitute deterministic timestamps for backup filenames.
var nowFunc = time.Now

// BackupTimestampedSuffix returns the per-run backup suffix for `path`.
// Used by WriteSysctlFile / WriteModprobeFile when operator edits to
// the managed file are detected — those edits would otherwise be lost
// on overwrite. Suffix is unambiguous and sortable:
//
//	<path>.cfm-kernsec.bak.20260510T140530Z
//
// One per apply run. The single-shot BackupSuffix (no timestamp) is
// preserved for first-touch backups of unmanaged files like
// /etc/default/grub; the timestamped form is for "operator changed
// our managed file between apply runs and we don't want to clobber
// their changes silently".
func BackupTimestampedSuffix() string {
	return BackupSuffix + "." + nowFunc().UTC().Format("20060102T150405Z")
}

// CopyFileTo copies src to dst, atomically (tmp + rename). Used when
// preserving operator edits via a per-run backup. Unlike BackupOnce
// it overwrites dst if it exists — caller picks a unique destination.
func CopyFileTo(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	content, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	return AtomicWriteFile(dst, content, st.Mode().Perm())
}

// auditExtraLines reads `path`, compares against `desired` content, and
// returns lines present on disk but not in the desired set (after
// normalising whitespace and ignoring blank/comment lines).
//
// Returns:
//
//	(nil, nil)      file absent OR file matches desired modulo
//	                comments / whitespace.
//	(extras, nil)   operator-added or stale lines were found.
//	(nil, err)      file present but unreadable; caller can still
//	                proceed but should surface the error.
func auditExtraLines(path string, desired []byte) ([]string, error) {
	existing, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	want := canonicalLineSet(desired)
	var extras []string
	for _, line := range strings.Split(string(existing), "\n") {
		canon := canonicalLine(line)
		if canon == "" {
			continue
		}
		if _, ok := want[canon]; !ok {
			extras = append(extras, strings.TrimRight(line, "\r"))
		}
	}
	return extras, nil
}

// canonicalLineSet returns the set of canonical (whitespace-normalised,
// comment-stripped) lines in b. Used by auditExtraLines to compare
// existing vs desired without false positives from formatting.
func canonicalLineSet(b []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(string(b), "\n") {
		if c := canonicalLine(line); c != "" {
			out[c] = struct{}{}
		}
	}
	return out
}

// canonicalLine collapses a kernsec-managed-file line to its
// comparable form: trimmed, comments dropped, whitespace runs
// collapsed, and " = " / " =" / "= " normalised to "=" so
// `kernel.kptr_restrict = 2` and `kernel.kptr_restrict=2` compare
// equal. Returns "" for blank / comment-only input.
func canonicalLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	s = strings.ReplaceAll(s, " = ", "=")
	s = strings.ReplaceAll(s, " =", "=")
	s = strings.ReplaceAll(s, "= ", "=")
	return strings.Join(strings.Fields(s), " ")
}

// preserveAndWarnOnExtras runs auditExtraLines and, if any extras are
// present, writes them out as a backup at <path>.cfm-kernsec.bak.<TS>
// and emits a warning section to w. Returns the backup path that
// was written (or "" if no extras were detected).
//
// Used by WriteSysctlFile / WriteModprobeFile to satisfy the
// "operator edited the managed file; warn loudly + back up + proceed"
// contract — keeping `apply` idempotent (still overwrites with the
// rendered content) but giving the operator a recovery path.
func preserveAndWarnOnExtras(w io.Writer, path string, desired []byte, label string) (backupPath string, err error) {
	extras, auditErr := auditExtraLines(path, desired)
	if auditErr != nil {
		fmt.Fprintf(w, "[!] %s: cannot audit existing file at %s: %v — proceeding\n", label, path, auditErr)
		return "", nil
	}
	if len(extras) == 0 {
		return "", nil
	}
	backupPath = path + BackupTimestampedSuffix()
	if cpErr := CopyFileTo(path, backupPath); cpErr != nil {
		fmt.Fprintf(w, "[!] %s: detected %d unmanaged line(s) in %s but could not back up to %s: %v\n",
			label, len(extras), path, backupPath, cpErr)
		fmt.Fprintln(w, "    refusing to overwrite without a backup")
		return "", cpErr
	}
	fmt.Fprintf(w, "[!] %s: %d unmanaged line(s) in %s — overwriting; backed up to %s\n",
		label, len(extras), path, backupPath)
	for _, line := range extras {
		fmt.Fprintf(w, "    > %s\n", line)
	}
	return backupPath, nil
}

// BackupOnce copies src to dst exactly once. If dst already exists it
// is left untouched (this is the one-shot guarantee). If src does not
// exist the call is a no-op. Used to preserve the original
// /etc/default/grub or /etc/kernel/cmdline before kernsec first
// edits them.
func BackupOnce(src, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil // backup already exists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", dst, err)
	}
	in, err := os.Open(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // nothing to back up
		}
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, st.Mode())
	if err != nil {
		// Race with a concurrent backup — accept the existing one.
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	return out.Sync()
}
