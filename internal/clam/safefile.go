package clam

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// The scanner dirs (pending, infected) are root:cfm 0770: the edge's user
// can create, rename and replace names in them. Root reads and writes there
// through these two helpers only — a path is never followed through a
// symlink, never blocks on a FIFO, and a file is never written by a name
// that already exists.

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
// O_EXCL, so an existing name — a planted symlink — is never written
// through). os.WriteFile to a fixed name followed a symlink planted there:
// root wrote the upload's bytes wherever it pointed (/etc/cron.d/…).
func CopyToNew(src, dir, prefix string) (string, error) {
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
