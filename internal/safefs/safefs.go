// Package safefs is how root touches a path in a directory the edge's user
// (the cfm group the OpenResty/Angie workers run as) can write — the
// scanner's pending dir, the sslcollector dir: never through a symlink
// planted at the name, never blocking on a FIFO, never writing through a
// name that already exists. One copy of these rules for every caller.
package safefs

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// SecureDir makes path a directory with mode and, when gid >= 0, owner
// root:gid — set on the opened directory, never by name, and refusing a
// symlink at path (O_NOFOLLOW): a name the edge's user replaced with a
// symlink had root chmod/chown its target (/etc, say).
func SecureDir(path string, mode os.FileMode, gid int) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: not a plain directory (left alone): %w", path, err)
	}
	defer f.Close()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if gid >= 0 {
		return f.Chown(0, gid)
	}
	return nil
}

// ChownRegularFile gives path (when it exists, and is a regular file with
// one link, not a symlink) to root:gid, on the opened file. A missing path
// is not an error.
func ChownRegularFile(path string, gid int) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: not a plain file (left alone): %w", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file (left alone)", path)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Nlink != 1 {
		return fmt.Errorf("%s: %d hard links (left alone)", path, sys.Nlink)
	}
	return f.Chown(0, gid)
}

// OpenRegular opens path for reading without following a symlink at path,
// without blocking on a FIFO, and only when it is a regular file.
func OpenRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	return f, nil
}

// CopyToNew copies the regular file src into a new file in dir, mode 0600,
// and returns its path. The name is prefix + a random part (os.CreateTemp:
// O_EXCL, so a name that exists — a planted symlink — is never written
// through). Only the last component is protected: dir itself must not be
// replaceable by the edge's user (its parent not writable by it).
func CopyToNew(src, dir, prefix string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("no destination dir")
	}
	in, err := OpenRegular(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	// CreateTemp puts the random part at the last "*"; none may come from
	// the (client-influenced) prefix.
	out, err := os.CreateTemp(dir, strings.ReplaceAll(prefix, "*", "_")+"*")
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(out.Name())
		return "", err
	}
	return out.Name(), nil
}
