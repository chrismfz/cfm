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

// A missing ANCESTOR of the parent must come out traversable too: os.MkdirAll
// would create it 0700 under the daemon's umask.
func TestEnsureSiteCacheDirs_MissingAncestorsAreTraversableUnderUmask077(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)

	base := t.TempDir()
	root := filepath.Join(base, "var", "cache", "nginx")
	ensureSiteCacheDirs(root, os.Getgid())

	for _, d := range []string{filepath.Join(base, "var"), filepath.Join(base, "var", "cache"), root} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatalf("%s not created: %v", d, err)
		}
		if got := fi.Mode().Perm(); got != 0o755 {
			t.Fatalf("%s mode = %#o, want 0755", d, got)
		}
	}
	if fi, err := os.Stat(filepath.Join(root, "cfm_static")); err != nil || fi.Mode().Perm() != 0o770 {
		t.Fatalf("cfm_static = %v, %v; want 0770", fi, err)
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
