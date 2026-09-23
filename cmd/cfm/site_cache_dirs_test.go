package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The daemon runs under UMask=0077. A missing /var/cache/nginx used to be
// created 0700 as a side effect of os.MkdirAll on a zone dir, which the edge
// workers (user cfm) cannot traverse. Not parallel: the umask is process-wide.
func TestEnsureSiteCacheDirs_MissingParentIsTraversableUnderUmask077(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	root := filepath.Join(t.TempDir(), "nginx")
	ensureSiteCacheDirs(root, os.Getgid())

	fi, err := os.Stat(root)
	if err != nil {
		t.Fatalf("parent not created: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Fatalf("parent mode = %#o, want 0755 (workers must traverse it)", got)
	}
	for _, name := range siteCacheDirNames {
		fi, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("%s not created: %v", name, err)
		}
		if got := fi.Mode().Perm(); got != 0o770 {
			t.Fatalf("%s mode = %#o, want 0770", name, got)
		}
	}
}

func TestEnsureSiteCacheDirs_ExistingParentOnlyGainsTraverse(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want os.FileMode
	}{
		{"root-only 0700 gains a+x", 0o700, 0o711},
		{"0750 gains o+x", 0o750, 0o751},
		{"already 0755 is untouched", 0o755, 0o755},
		{"setgid is kept", os.ModeSetgid | 0o750, os.ModeSetgid | 0o751},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "nginx")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, tc.mode); err != nil {
				t.Fatal(err)
			}
			ensureSiteCacheDirs(root, os.Getgid())
			fi, err := os.Stat(root)
			if err != nil {
				t.Fatal(err)
			}
			got := fi.Mode() & (os.ModePerm | os.ModeSetgid | os.ModeSetuid | os.ModeSticky)
			if got != tc.want {
				t.Fatalf("parent mode = %v, want %v", got, tc.want)
			}
		})
	}
}
