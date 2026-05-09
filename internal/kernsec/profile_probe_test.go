package kernsec

import (
	"os"
	"path/filepath"
	"testing"
)

// makeFakeProc builds a minimal fake /proc tree with a /<pid>/comm
// file per entry in commByPID. Returns the procDir path.
func makeFakeProc(t *testing.T, commByPID map[string]string) string {
	t.Helper()
	procDir := t.TempDir()
	for pid, comm := range commByPID {
		dir := filepath.Join(procDir, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Throw a non-numeric directory in for good measure — the probe
	// must skip it without erroring.
	if err := os.MkdirAll(filepath.Join(procDir, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	return procDir
}

func TestContainerProbe_DaemonProcess(t *testing.T) {
	tests := []struct {
		name string
		comm string
		want bool
	}{
		{"dockerd present", "dockerd", true},
		{"crio present", "crio", true},
		{"containerd present", "containerd", true},
		{"conmon present", "conmon", true},
		{"lxd present", "lxd", true},
		{"podman present", "podman", true},
		{"kubelet present", "kubelet", true},
		{"systemd-nspawn present", "systemd-nspawn", true},
		{"kata-runtime present", "kata-runtime", true},
		{"runsc present", "runsc", true},
		{"runc present", "runc", true},
		{"unrelated binary not detected", "nginx", false},
		{"prefix collision not detected", "runcheck", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			procDir := makeFakeProc(t, map[string]string{
				"1":    "systemd",
				"4242": tc.comm,
			})
			p := containerProbe{procDir: procDir, nspawnDir: t.TempDir()}
			if got := p.detect(); got != tc.want {
				t.Fatalf("detect() = %v, want %v (comm=%q)", got, tc.want, tc.comm)
			}
		})
	}
}

func TestContainerProbe_ContainerdShimPrefix(t *testing.T) {
	procDir := makeFakeProc(t, map[string]string{
		"1":   "systemd",
		"123": "containerd-shim-runc-v2",
	})
	p := containerProbe{procDir: procDir, nspawnDir: t.TempDir()}
	if !p.detect() {
		t.Fatal("expected containerd-shim-runc-v2 to be detected")
	}
}

func TestContainerProbe_DaemonSocket(t *testing.T) {
	tmp := t.TempDir()
	// Empty /proc — no container processes.
	procDir := makeFakeProc(t, map[string]string{"1": "systemd"})
	sock := filepath.Join(tmp, "docker.sock")
	if err := os.WriteFile(sock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p := containerProbe{
		procDir:   procDir,
		sockets:   []string{sock},
		nspawnDir: t.TempDir(),
	}
	if !p.detect() {
		t.Fatal("expected daemon socket to trigger detection")
	}
}

func TestContainerProbe_NspawnMachine(t *testing.T) {
	procDir := makeFakeProc(t, map[string]string{"1": "systemd"})
	nspawnDir := t.TempDir()
	// One registered machine entry.
	if err := os.WriteFile(filepath.Join(nspawnDir, "alpine.nspawn"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	p := containerProbe{procDir: procDir, nspawnDir: nspawnDir}
	if !p.detect() {
		t.Fatal("expected /run/systemd/nspawn entry to trigger detection")
	}
}

func TestContainerProbe_EmptyHost(t *testing.T) {
	procDir := makeFakeProc(t, map[string]string{
		"1":   "systemd",
		"100": "sshd",
		"200": "nginx",
	})
	// Sockets list points at a clean tempdir; nspawnDir is empty.
	tmp := t.TempDir()
	p := containerProbe{
		procDir:   procDir,
		sockets:   []string{filepath.Join(tmp, "missing.sock")},
		nspawnDir: t.TempDir(),
	}
	if p.detect() {
		t.Fatal("expected empty host to report no containers")
	}
}

func TestContainerProbe_MissingProcDir(t *testing.T) {
	// Pointing procDir at a path that doesn't exist must not panic and
	// must not return true on its own.
	tmp := t.TempDir()
	p := containerProbe{
		procDir:   filepath.Join(tmp, "no-such-proc"),
		sockets:   []string{filepath.Join(tmp, "missing.sock")},
		nspawnDir: filepath.Join(tmp, "no-nspawn"),
	}
	if p.detect() {
		t.Fatal("missing /proc should not assert containers")
	}
}

func TestDefaultContainerProbe_ShapeOnly(t *testing.T) {
	// Sanity: the default probe points at real host paths. Run it on
	// the test host — result is whatever it is, but it must not panic
	// and the procDir must be /proc.
	p := defaultContainerProbe()
	if p.procDir != "/proc" {
		t.Errorf("default procDir = %q, want /proc", p.procDir)
	}
	if len(p.sockets) == 0 {
		t.Error("default sockets list should not be empty")
	}
	if p.nspawnDir == "" {
		t.Error("default nspawnDir should not be empty")
	}
	_ = p.detect()
}
