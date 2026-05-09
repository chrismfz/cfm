package kernsec

import (
	"errors"
	"testing"
)

// fakeFS is an in-memory FS for testing backend detection without real
// bootloaders. Only Phase 1 read-only methods are exercised.
type fakeFS struct {
	files map[string][]byte
	dirs  map[string]bool
	bins  map[string]bool
	cmds  map[string]string // "name arg1 arg2" -> output
}

func newFakeFS() *fakeFS {
	return &fakeFS{
		files: map[string][]byte{},
		dirs:  map[string]bool{},
		bins:  map[string]bool{},
		cmds:  map[string]string{},
	}
}

func (f *fakeFS) ReadFile(p string) ([]byte, error) {
	if b, ok := f.files[p]; ok {
		return b, nil
	}
	return nil, errors.New("not found: " + p)
}
func (f *fakeFS) Exists(p string) bool {
	if _, ok := f.files[p]; ok {
		return true
	}
	return f.dirs[p]
}
func (f *fakeFS) IsDir(p string) bool   { return f.dirs[p] }
func (f *fakeFS) LookPath(n string) bool { return f.bins[n] }
func (f *fakeFS) RunCapture(name string, args ...string) (string, error) {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if out, ok := f.cmds[key]; ok {
		return out, nil
	}
	return "", errors.New("no fake for: " + key)
}

// withFile is a small builder helper.
func (f *fakeFS) withFile(path, content string) *fakeFS {
	f.files[path] = []byte(content)
	return f
}
func (f *fakeFS) withDir(path string) *fakeFS  { f.dirs[path] = true; return f }
func (f *fakeFS) withBin(name string) *fakeFS  { f.bins[name] = true; return f }
func (f *fakeFS) withCmd(key, out string) *fakeFS {
	f.cmds[key] = out
	return f
}

func TestDetectBackend_Proxmox(t *testing.T) {
	t.Run("via proc cmdline initrd", func(t *testing.T) {
		fs := newFakeFS().
			withBin("proxmox-boot-tool").
			withFile("/etc/kernel/cmdline", "ro quiet").
			withFile("/proc/cmdline", `BOOT_IMAGE=/vmlinuz initrd=\EFI\proxmox\initrd ro`)
		be := DetectBackend(fs)
		if _, ok := be.(*ProxmoxBackend); !ok {
			t.Fatalf("got %T, want *ProxmoxBackend", be)
		}
	})

	t.Run("via proxmox-boot-tool status", func(t *testing.T) {
		fs := newFakeFS().
			withBin("proxmox-boot-tool").
			withFile("/etc/kernel/cmdline", "ro quiet").
			withFile("/proc/cmdline", "ro quiet").
			withCmd("proxmox-boot-tool status", "System currently booted with uefi\nESP /dev/sda2 is configured\n")
		be := DetectBackend(fs)
		if _, ok := be.(*ProxmoxBackend); !ok {
			t.Fatalf("got %T, want *ProxmoxBackend", be)
		}
	})

	t.Run("missing pve cmdline file means not proxmox", func(t *testing.T) {
		fs := newFakeFS().withBin("proxmox-boot-tool")
		be := DetectBackend(fs)
		if _, ok := be.(*ProxmoxBackend); ok {
			t.Fatalf("got Proxmox, expected fallback")
		}
	})
}

func TestDetectBackend_BLS(t *testing.T) {
	t.Run("via blscfg in grub.cfg", func(t *testing.T) {
		fs := newFakeFS().
			withDir("/boot/loader/entries").
			withBin("grubby").
			withFile("/boot/grub2/grub.cfg", "set default=0\nblscfg\n")
		be := DetectBackend(fs)
		if _, ok := be.(*BLSBackend); !ok {
			t.Fatalf("got %T, want *BLSBackend", be)
		}
	})

	t.Run("via GRUB_ENABLE_BLSCFG=true", func(t *testing.T) {
		fs := newFakeFS().
			withDir("/boot/loader/entries").
			withBin("grubby").
			withFile("/etc/default/grub", `GRUB_ENABLE_BLSCFG="true"`+"\n")
		be := DetectBackend(fs)
		if _, ok := be.(*BLSBackend); !ok {
			t.Fatalf("got %T, want *BLSBackend", be)
		}
	})

	t.Run("explicit GRUB_ENABLE_BLSCFG=false rejects", func(t *testing.T) {
		fs := newFakeFS().
			withDir("/boot/loader/entries").
			withBin("grubby").
			withFile("/etc/default/grub", `GRUB_ENABLE_BLSCFG="false"`+"\n").
			withFile("/boot/grub2/grub.cfg", "blscfg\n")
		be := DetectBackend(fs)
		if _, ok := be.(*BLSBackend); ok {
			t.Fatalf("got BLS, expected fallback (BLSCFG=false)")
		}
	})

	t.Run("missing grubby falls back", func(t *testing.T) {
		fs := newFakeFS().
			withDir("/boot/loader/entries").
			withFile("/boot/grub2/grub.cfg", "blscfg\n")
		be := DetectBackend(fs)
		if _, ok := be.(*BLSBackend); ok {
			t.Fatalf("got BLS without grubby")
		}
	})
}

func TestDetectBackend_GRUBFallback(t *testing.T) {
	fs := newFakeFS().withFile("/etc/default/grub", `GRUB_CMDLINE_LINUX="ro quiet"`)
	be := DetectBackend(fs)
	if _, ok := be.(*GRUBBackend); !ok {
		t.Fatalf("got %T, want *GRUBBackend", be)
	}
}

func TestProxmoxBackend_NextBootCmdline(t *testing.T) {
	fs := newFakeFS().withFile("/etc/kernel/cmdline", "  root=ZFS=rpool/ROOT/pve-1 ro slab_nomerge  \n")
	p := &ProxmoxBackend{FS: fs}
	got, err := p.NextBootCmdline()
	if err != nil {
		t.Fatal(err)
	}
	if got != "root=ZFS=rpool/ROOT/pve-1 ro slab_nomerge" {
		t.Fatalf("got %q", got)
	}
}

func TestBLSBackend_NextBootCmdline(t *testing.T) {
	out := `index=0
kernel="/boot/vmlinuz-6.1.0"
initrd="/boot/initramfs-6.1.0.img"
args="ro crashkernel=auto slab_nomerge init_on_alloc=1"
title="Rocky Linux"
`
	fs := newFakeFS().withCmd("grubby --info=DEFAULT", out)
	b := &BLSBackend{FS: fs}
	got, err := b.NextBootCmdline()
	if err != nil {
		t.Fatal(err)
	}
	if got != "ro crashkernel=auto slab_nomerge init_on_alloc=1" {
		t.Fatalf("got %q", got)
	}
}

func TestGRUBBackend_NextBootCmdline(t *testing.T) {
	fs := newFakeFS().withFile("/etc/default/grub", `# comment
GRUB_DEFAULT=0
GRUB_CMDLINE_LINUX="quiet splash slab_nomerge init_on_alloc=1"
GRUB_TIMEOUT=5
`)
	g := &GRUBBackend{FS: fs}
	got, err := g.NextBootCmdline()
	if err != nil {
		t.Fatal(err)
	}
	if got != "quiet splash slab_nomerge init_on_alloc=1" {
		t.Fatalf("got %q", got)
	}
}

func TestGrubVarMatches(t *testing.T) {
	content := `GRUB_TIMEOUT=5
GRUB_ENABLE_BLSCFG="true"
GRUB_DEFAULT=0
`
	if !grubVarMatches(content, "GRUB_ENABLE_BLSCFG", "true") {
		t.Error("expected match for true")
	}
	if grubVarMatches(content, "GRUB_ENABLE_BLSCFG", "false") {
		t.Error("unexpected match for false")
	}
	if !grubVarMatches("GRUB_ENABLE_BLSCFG=true\n", "GRUB_ENABLE_BLSCFG", "true") {
		t.Error("expected match for unquoted true")
	}
}
