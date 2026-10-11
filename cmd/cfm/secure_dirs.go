package main

import (
	"fmt"
	"os"
	"syscall"
)

// secureDir makes path a directory with mode and, when gid > 0, group gid —
// without following a symlink at path. For a dir whose parent the edge's
// user (cfm group) can write: scanner/pending and scanner/infected sit in
// scanner (root:cfm 0770), and a name planted there as a symlink had root
// chmod 0770 and chown root:cfm its target (/etc, say) at every daemon
// start. The mode and group are set on the opened directory, not by name.
// (A dir in a root-only parent may be an operator's symlink to a bigger
// disk, and is followed as before.)
func secureDir(path string, mode os.FileMode, gid int) error {
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
	if gid > 0 {
		return f.Chown(0, gid)
	}
	return nil
}

// chownRegularFile gives path (when it exists, and is a regular file with
// one link, not a symlink) to root:gid, on the opened file. dump.json sits
// in the cfm-group writable sslcollector dir: chowned by name, a symlink
// there handed its target (/etc/shadow is 0640 on Debian) to the cfm group
// at startup; a hard link would too where fs.protected_hardlinks is off.
// O_NONBLOCK: a FIFO planted at path must not hang the daemon's start.
func chownRegularFile(path string, gid int) error {
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
