package kernsec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
