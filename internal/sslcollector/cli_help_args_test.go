package sslcollector

import (
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// `cfm ssl` answers -h, --help and help with its usage and never reaches the
// daemon's socket (`ssl refresh help` asked the daemon for a refresh) or
// scans: RunCLI returns before either.
func TestCLIHelpWordsReachNothing(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "ssl.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix socket: %v", err)
	}
	defer ln.Close()
	var conns atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			c.Close()
		}
	}()
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()
	for _, h := range []string{"-h", "--help", "help"} {
		RunCLI([]string{h}, sock, "")
		for _, sub := range []string{"stats", "scan", "dump", "refresh"} {
			RunCLI([]string{sub, h}, sock, "")
			RunCLI([]string{sub, "--json", h}, sock, "")
		}
	}
	if n := conns.Load(); n != 0 {
		t.Errorf("%d socket connection(s) on help words", n)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("files written: %v", ents)
	}
}
