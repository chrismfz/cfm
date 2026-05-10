package kernsec

import (
	"errors"
	"strings"
	"testing"
)

// fakeFS is an in-memory FS for testing backend detection without real
// bootloaders. Phase 5 follow-up adds cmdLog so write-path tests can
// assert what argv was actually invoked.
type fakeFS struct {
	files  map[string][]byte
	dirs   map[string]bool
	bins   map[string]bool
	cmds   map[string]string // "name arg1 arg2" -> output
	cmdLog []string          // append-only record of every RunCapture key
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
	f.cmdLog = append(f.cmdLog, key)
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

func TestBLSBackend_NextBootCmdline_SingleKernel(t *testing.T) {
	out := `index=0
kernel="/boot/vmlinuz-6.1.0"
initrd="/boot/initramfs-6.1.0.img"
args="ro crashkernel=auto slab_nomerge init_on_alloc=1"
title="Rocky Linux"
`
	fs := newFakeFS().withCmd("grubby --info=ALL", out)
	b := &BLSBackend{FS: fs}
	got, err := b.NextBootCmdline()
	if err != nil {
		t.Fatal(err)
	}
	if got != "ro crashkernel=auto slab_nomerge init_on_alloc=1" {
		t.Fatalf("got %q", got)
	}
}

func TestBLSBackend_NextBootCmdline_AllKernelsAgree(t *testing.T) {
	out := `index=0
kernel="/boot/vmlinuz-6.1.0"
args="ro slab_nomerge init_on_alloc=1"
title="Rocky 9"

index=1
kernel="/boot/vmlinuz-5.14.0"
args="ro slab_nomerge init_on_alloc=1"
title="Rocky 9 (older)"
`
	fs := newFakeFS().withCmd("grubby --info=ALL", out)
	b := &BLSBackend{FS: fs}
	got, err := b.NextBootCmdline()
	if err != nil {
		t.Fatalf("expected no error when all kernels agree, got %v", err)
	}
	if got != "ro slab_nomerge init_on_alloc=1" {
		t.Fatalf("got %q", got)
	}
}

func TestBLSBackend_NextBootCmdline_DivergedKernel(t *testing.T) {
	// Older kernel is missing init_on_alloc=1 — drift the apply check
	// must surface so the operator doesn't reboot into a stale entry.
	out := `index=0
kernel="/boot/vmlinuz-6.1.0"
args="ro slab_nomerge init_on_alloc=1"
title="Rocky 9"

index=1
kernel="/boot/vmlinuz-5.14.0"
args="ro slab_nomerge"
title="Rocky 9 (older)"

index=2
kernel="/boot/vmlinuz-rescue"
args="ro slab_nomerge init_on_alloc=1"
title="Rescue"
`
	fs := newFakeFS().withCmd("grubby --info=ALL", out)
	b := &BLSBackend{FS: fs}
	got, err := b.NextBootCmdline()
	if err == nil {
		t.Fatal("expected divergence error, got nil")
	}
	if !strings.Contains(err.Error(), "/boot/vmlinuz-5.14.0") {
		t.Errorf("error message should name the divergent kernel: %v", err)
	}
	if strings.Contains(err.Error(), "/boot/vmlinuz-rescue") {
		t.Errorf("rescue kernel matches first entry; should not be flagged: %v", err)
	}
	if got != "ro slab_nomerge init_on_alloc=1" {
		t.Errorf("returned args should be from index=0: got %q", got)
	}
}

func TestBLSBackend_NextBootCmdline_UnmanagedOnlyDivergenceIsNotDrift(t *testing.T) {
	// Two kernels with the SAME managed args but different unmanaged
	// tokens (crashkernel=, transparent_hugepage=, distro-specific). The
	// previous implementation flagged this as drift — wrong, because
	// WriteCmdline preserves each kernel's unmanaged tokens. The fix
	// projects to managed args before comparison, so this case must
	// pass without error.
	out := `index=0
kernel="/boot/vmlinuz-6.1.0"
args="ro slab_nomerge init_on_alloc=1 crashkernel=auto transparent_hugepage=madvise"

index=1
kernel="/boot/vmlinuz-5.14.0"
args="ro slab_nomerge init_on_alloc=1 crashkernel=2G-:512M transparent_hugepage=never"
`
	fs := newFakeFS().withCmd("grubby --info=ALL", out)
	b := &BLSBackend{FS: fs}
	if _, err := b.NextBootCmdline(); err != nil {
		t.Fatalf("unmanaged-only divergence should not be drift, got %v", err)
	}
}

func TestBLSBackend_NextBootCmdline_DivergenceOnManagedKeyStillFlagged(t *testing.T) {
	// Stale kernel is missing init_on_alloc=1 (a managed key) — must be
	// flagged even though crashkernel= legitimately differs.
	out := `index=0
kernel="/boot/vmlinuz-6.1.0"
args="ro slab_nomerge init_on_alloc=1 crashkernel=auto"

index=1
kernel="/boot/vmlinuz-5.14.0"
args="ro slab_nomerge crashkernel=2G-:512M"
`
	fs := newFakeFS().withCmd("grubby --info=ALL", out)
	b := &BLSBackend{FS: fs}
	_, err := b.NextBootCmdline()
	if err == nil {
		t.Fatal("expected divergence error on managed-key drift, got nil")
	}
	if !strings.Contains(err.Error(), "/boot/vmlinuz-5.14.0") {
		t.Errorf("error message should name the divergent kernel: %v", err)
	}
	if !strings.Contains(err.Error(), "managed args") {
		t.Errorf("error message should clarify it's managed-args divergence: %v", err)
	}
}

func TestBLSBackend_NextBootCmdline_TokenOrderInsensitive(t *testing.T) {
	// Reordered args on different kernels must not be flagged as drift —
	// the kernel cmdline is order-insensitive.
	out := `index=0
kernel="/boot/vmlinuz-6.1.0"
args="ro slab_nomerge init_on_alloc=1"

index=1
kernel="/boot/vmlinuz-5.14.0"
args="init_on_alloc=1 ro slab_nomerge"
`
	fs := newFakeFS().withCmd("grubby --info=ALL", out)
	b := &BLSBackend{FS: fs}
	if _, err := b.NextBootCmdline(); err != nil {
		t.Fatalf("reordered tokens should not be drift, got %v", err)
	}
}

func TestBLSBackend_NextBootCmdline_NoKernels(t *testing.T) {
	fs := newFakeFS().withCmd("grubby --info=ALL", "")
	b := &BLSBackend{FS: fs}
	got, err := b.NextBootCmdline()
	if err != nil {
		t.Fatalf("expected nil error on empty grubby output, got %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestBLSBackend_WriteCmdline_SingleGrubbyCall(t *testing.T) {
	fs := newFakeFS().withCmd(
		"grubby --update-kernel=ALL --remove-args="+strings.Join(ManagedBootArgKeys, " ")+
			" --args=slab_nomerge init_on_alloc=1",
		"",
	)
	b := &BLSBackend{FS: fs}
	if err := b.WriteCmdline([]BootArg{
		{Key: "slab_nomerge"},
		{Key: "init_on_alloc", Value: "1"},
	}); err != nil {
		t.Fatal(err)
	}
	if len(fs.cmdLog) != 1 {
		t.Fatalf("expected exactly 1 grubby invocation, got %d: %v", len(fs.cmdLog), fs.cmdLog)
	}
	got := fs.cmdLog[0]
	if !strings.Contains(got, "--remove-args=") {
		t.Errorf("expected --remove-args in single call, got: %q", got)
	}
	if !strings.Contains(got, "--args=") {
		t.Errorf("expected --args in single call, got: %q", got)
	}
}

func TestBLSBackend_WriteCmdline_EmptyArgsNoAddFlag(t *testing.T) {
	// Disable workflow: no managed args to add. Must still issue the
	// remove call (in a single grubby invocation), but must not pass
	// an empty --args= flag (grubby treats --args="" as a no-op anyway,
	// but the omission keeps the command line cleaner).
	fs := newFakeFS().withCmd(
		"grubby --update-kernel=ALL --remove-args="+strings.Join(ManagedBootArgKeys, " "),
		"",
	)
	b := &BLSBackend{FS: fs}
	if err := b.WriteCmdline(nil); err != nil {
		t.Fatal(err)
	}
	if len(fs.cmdLog) != 1 {
		t.Fatalf("expected 1 grubby call, got %d: %v", len(fs.cmdLog), fs.cmdLog)
	}
	if strings.Contains(fs.cmdLog[0], "--args=") {
		t.Errorf("expected no --args= flag for empty arg set, got: %q", fs.cmdLog[0])
	}
}

func TestParseGrubbyAll(t *testing.T) {
	tests := []struct {
		name      string
		out       string
		wantCount int
		wantArgs  []string
	}{
		{
			name:      "empty",
			out:       "",
			wantCount: 0,
		},
		{
			name: "single kernel",
			out: `index=0
kernel="/boot/vmlinuz"
args="ro slab_nomerge"
`,
			wantCount: 1,
			wantArgs:  []string{"ro slab_nomerge"},
		},
		{
			name: "two kernels blank-line separated",
			out: `index=0
kernel="/boot/vmlinuz-A"
args="ro a"

index=1
kernel="/boot/vmlinuz-B"
args="ro b"
`,
			wantCount: 2,
			wantArgs:  []string{"ro a", "ro b"},
		},
		{
			name: "two kernels no blank separator",
			out: `index=0
kernel="/boot/vmlinuz-A"
args="ro a"
index=1
kernel="/boot/vmlinuz-B"
args="ro b"
`,
			wantCount: 2,
			wantArgs:  []string{"ro a", "ro b"},
		},
		{
			name: "missing args key tolerated",
			out: `index=0
kernel="/boot/vmlinuz"
title="weird"
`,
			wantCount: 1,
			wantArgs:  []string{""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseGrubbyAll(tc.out)
			if len(got) != tc.wantCount {
				t.Fatalf("parseGrubbyAll() returned %d entries, want %d (got: %+v)",
					len(got), tc.wantCount, got)
			}
			for i, want := range tc.wantArgs {
				if got[i].Args != want {
					t.Errorf("entry[%d].Args = %q, want %q", i, got[i].Args, want)
				}
			}
		})
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

func TestDecodeGrubCmdlineValue(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "double-quoted simple", in: `"ro slab_nomerge"`, want: "ro slab_nomerge"},
		{name: "single-quoted simple", in: `'ro slab_nomerge'`, want: "ro slab_nomerge"},
		{name: "unquoted simple", in: `ro`, want: "ro"},
		{name: "double-quoted with escaped quotes",
			in: `"ro module.parameter=\"x y\" quiet"`, want: `ro module.parameter="x y" quiet`},
		{name: "double-quoted with escaped backslash",
			in: `"ro path=\\foo"`, want: `ro path=\foo`},
		{name: "rejects shell variable expansion",
			in: `"ro $extra quiet"`, wantErr: true},
		{name: "rejects backtick command substitution",
			in: "\"ro `cmd` quiet\"", wantErr: true},
		{name: "rejects $() command substitution",
			in: `"ro $(cmd) quiet"`, wantErr: true},
		{name: "rejects single quote inside double-quoted",
			in: `"ro 'foo' quiet"`, wantErr: true},
		{name: "rejects unsupported backslash escape",
			in: `"ro \n quiet"`, wantErr: true},
		{name: "rejects trailing backslash",
			in: `"ro slab_nomerge\"`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeGrubCmdlineValue(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("decodeGrubCmdlineValue(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("decodeGrubCmdlineValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEncodeGrubCmdlineValue(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "simple", in: "ro slab_nomerge", want: `"ro slab_nomerge"`},
		{name: "embedded double quote",
			in: `ro module.parameter="x y" quiet`,
			want: `"ro module.parameter=\"x y\" quiet"`},
		{name: "embedded backslash",
			in: `ro path=\foo`, want: `"ro path=\\foo"`},
		{name: "rejects $",
			in: "ro $extra quiet", wantErr: true},
		{name: "rejects backtick",
			in: "ro `cmd`", wantErr: true},
		{name: "rejects single quote",
			in: "ro 'foo'", wantErr: true},
		{name: "rejects $(",
			in: "ro $(cmd)", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeGrubCmdlineValue(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("encodeGrubCmdlineValue(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("encodeGrubCmdlineValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGrubCmdline_RoundTripPreservesEmbeddedQuotes(t *testing.T) {
	// Operator's existing /etc/default/grub has a kernel arg with a
	// quoted value: `module.parameter="x y"`. Round-tripping through
	// decode → encode must preserve the literal `"x y"` portion.
	// Previously the rewriter emitted GRUB_CMDLINE_LINUX="...="x y"..."
	// which is broken shell.
	original := `ro module.parameter="x y" quiet`
	encoded, err := encodeGrubCmdlineValue(original)
	if err != nil {
		t.Fatal(err)
	}
	// The encoded form is the RHS of GRUB_CMDLINE_LINUX=. Decode it
	// back; we must get the original string.
	decoded, err := decodeGrubCmdlineValue(encoded)
	if err != nil {
		t.Fatalf("encoded form did not decode: %v\nencoded: %s", err, encoded)
	}
	if decoded != original {
		t.Errorf("round-trip mismatch:\n  before: %q\n  after:  %q", original, decoded)
	}
}

func TestGRUBBackend_NextBootCmdline_RejectsShellExpansion(t *testing.T) {
	// Operator wrote `GRUB_CMDLINE_LINUX="ro $extra quiet"` for shell
	// expansion. kernsec cannot reason about $extra at parse time.
	// Refuse with a clear error rather than silently mangling.
	fs := newFakeFS().withFile("/etc/default/grub", `GRUB_CMDLINE_LINUX="ro $extra quiet"`+"\n")
	g := &GRUBBackend{FS: fs}
	_, err := g.NextBootCmdline()
	if err == nil {
		t.Fatal("expected error on shell-expansion cmdline, got nil")
	}
	if !strings.Contains(err.Error(), "shell metacharacter") {
		t.Errorf("error should mention the offending metacharacter: %v", err)
	}
}

func TestGRUBBackend_NextBootCmdline_HandlesEscapedQuotes(t *testing.T) {
	// `module.parameter=\"x y\"` is the shell-encoded form of
	// `module.parameter="x y"`. NextBootCmdline must decode the
	// escapes so the kernel cmdline string we work with matches what
	// the kernel will actually see at boot.
	fs := newFakeFS().withFile("/etc/default/grub",
		`GRUB_CMDLINE_LINUX="ro module.parameter=\"x y\" quiet"`+"\n")
	g := &GRUBBackend{FS: fs}
	got, err := g.NextBootCmdline()
	if err != nil {
		t.Fatal(err)
	}
	want := `ro module.parameter="x y" quiet`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
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
