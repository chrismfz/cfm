//go:build linux

package lsm

import (
	"os"
	"strings"
	"testing"
	"unsafe"
)

func TestInodeMapsUseCompoundKeys(t *testing.T) {
	if got, want := unsafe.Sizeof(inodeKey{}), uintptr(16); got != want {
		t.Fatalf("unsafe.Sizeof(inodeKey{}) = %d, want %d", got, want)
	}

	src, err := os.ReadFile("bpf/cfmlsm.bpf.c")
	if err != nil {
		t.Fatalf("read BPF source: %v", err)
	}
	out := string(src)

	for _, name := range []string{"cfm_watched_inodes", "cfm_setuid_inodes"} {
		idx := strings.Index(out, "} "+name+" SEC(\".maps\");")
		if idx < 0 {
			t.Fatalf("BPF source missing map %q", name)
		}
		start := strings.LastIndex(out[:idx], "struct {")
		if start < 0 {
			t.Fatalf("BPF source missing struct literal for map %q", name)
		}
		block := out[start:idx]
		if !strings.Contains(block, "__type(key, struct cfm_inode_key);") {
			t.Errorf("%s key type should be struct cfm_inode_key; block:\n%s", name, block)
		}
	}
}

func TestStatInodeKeyIncludesDeviceAndInode(t *testing.T) {
	path := t.TempDir() + "/watched"
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	key, ok := statInodeKey(path)
	if !ok {
		t.Fatalf("statInodeKey(%q) returned !ok", path)
	}
	if key.Dev == 0 {
		t.Fatal("statInodeKey returned zero Dev")
	}
	if key.Ino == 0 {
		t.Fatal("statInodeKey returned zero Ino")
	}
}
