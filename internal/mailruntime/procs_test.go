package mailruntime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsPidDir(t *testing.T) {
	tests := map[string]bool{
		"1":    true,
		"123":  true,
		"0":    true,
		"self": false,
		"net":  false,
		"sys":  false,
		"12a":  false,
		"":     false,
	}
	for name, want := range tests {
		if got := isPidDir(name); got != want {
			t.Errorf("isPidDir(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestReadCommsInAndCount(t *testing.T) {
	root := t.TempDir()
	// pid dirs with a comm each; note the space in "spamd child" and the
	// trailing newline the kernel writes.
	mk := func(pid, comm string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("100", "spamd\n")
	mk("101", "spamd child\n")
	mk("102", "spamd child\n")
	mk("103", "exim\n")
	mk("104", "spamd child\n")
	// A non-pid /proc entry that also has a comm-like file must be ignored.
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "self", "comm"), []byte("spamd child\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	comms := readCommsIn(root)
	if n := countComms(comms, DefaultSpamdChildComm); n != 3 {
		t.Fatalf("spamd child = %d, want 3 (the 'self' entry must be skipped)", n)
	}
	if n := countComms(comms, "spamd"); n != 1 {
		t.Errorf("master spamd = %d, want 1", n)
	}
	if n := countComms(comms, "exim"); n != 1 {
		t.Errorf("exim = %d, want 1", n)
	}
}

func TestReadCommsInMissingRoot(t *testing.T) {
	if got := readCommsIn(filepath.Join(t.TempDir(), "does-not-exist")); got != nil {
		t.Errorf("missing proc root should return nil, got %v", got)
	}
}
