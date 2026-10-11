package main

import (
	"fmt"
	"os"
	"syscall"
)

// secureDir makes path a directory with mode and, when gid > 0, group gid —
// without following a symlink at path. The mode and group are set on the
// opened directory, not by name: several of these dirs sit in a parent the
// edge's user (cfm group) can write (scanner/pending in scanner, the Site
// Cache zones), and a name planted there as a symlink had root chmod 0770
// and chown root:cfm its target (/etc, say) at every daemon start.
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

// chownRegularFile gives path (when it exists, and is a regular file, not a
// symlink) to root:gid, on the opened file. dump.json sits in the cfm-group
// writable sslcollector dir: chowned by name, a symlink there handed its
// target (/etc/shadow is 0640 on Debian) to the cfm group at startup.
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
	return f.Chown(0, gid)
}
