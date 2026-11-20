//go:build unix

package edgecli

import (
	"os"
	"syscall"
)

// fileOwner is the uid/gid of a stat'ed file, so a rewrite keeps them.
func fileOwner(st os.FileInfo) (int, int, bool) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(s.Uid), int(s.Gid), true
}
