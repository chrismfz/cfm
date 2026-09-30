package hostsecrets

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	seedBegin = "# >>> cfm-token-seed"
	seedEnd   = "# <<< cfm-token-seed"
)

// seedBlock extracts the token-seed block from a packaging file.
func seedBlock(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	s := string(b)
	i, j := strings.Index(s, seedBegin), strings.Index(s, seedEnd)
	if i < 0 || j < i || strings.Count(s, seedBegin) != 1 {
		t.Fatalf("%s: want exactly one %q ... %q block", path, seedBegin, seedEnd)
	}
	return s[i : j+len(seedEnd)]
}

// The Debian preinst and the RPM pre scriptlet carry the same block: the
// daemon can only take a token over while the old detectors.conf is in place,
// and both package managers can replace that file before the new daemon
// starts. Two copies are unavoidable (a pre scriptlet runs before any packaged
// file exists), so they are pinned identical here.
func TestPackageSeedBlockIsIdenticalInBothPackages(t *testing.T) {
	root := filepath.Join("..", "..", "packaging")
	deb := seedBlock(t, filepath.Join(root, "debian", "DEBIAN", "preinst"))
	rpm := seedBlock(t, filepath.Join(root, "rpm", "SPECS", "cfm.spec"))
	if deb != rpm {
		t.Fatal("the cfm-token-seed block differs between packaging/debian/DEBIAN/preinst and the rpm spec; keep them identical")
	}
	// rpm expands macros on every spec line, code and comments alike
	// (CLAUDE.md §5): the block must not contain a single '%'.
	if strings.Contains(rpm, "%") {
		t.Fatal("the cfm-token-seed block contains '%'; rpm would expand it as a macro")
	}
	if fi, err := os.Stat(filepath.Join(root, "debian", "DEBIAN", "preinst")); err != nil || fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("packaging/debian/DEBIAN/preinst must be executable (mode %v, err %v)", fi.Mode().Perm(), err)
	}
}

// runSeed runs the block with shell against conf, snapshotting into dir.
func runSeed(t *testing.T, shell, conf, dir string) {
	t.Helper()
	block := seedBlock(t, filepath.Join("..", "..", "packaging", "debian", "DEBIAN", "preinst"))
	cmd := exec.Command(shell, "-e", "-c", block)
	cmd.Env = append(os.Environ(), "CFM_SEED_CONF="+conf, "CFM_SEED_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: seed block failed: %v\n%s", shell, err, out)
	}
}

func seedShells() []string {
	shells := []string{"sh"}
	if _, err := exec.LookPath("dash"); err == nil {
		shells = append(shells, "dash")
	}
	return shells
}

func TestPackageSeedBlockSnapshotsDetectorsConf(t *testing.T) {
	const conf = "[webdetector]\nCHALLENGE_TOKEN = 0123456789abcdef0123456789abcdef0123456789abcdef\n"
	for _, shell := range seedShells() {
		t.Run(shell, func(t *testing.T) {
			tmp := t.TempDir()
			// /var/lib/cfm absent: the block must create it 0755 (the edge
			// workers reach /var/lib/cfm/lua through it), only the store 0700.
			parent := filepath.Join(tmp, "lib", "cfm")
			dir := filepath.Join(parent, "secrets")
			cf := filepath.Join(tmp, "detectors.conf")
			if err := os.WriteFile(cf, []byte(conf), 0o644); err != nil {
				t.Fatal(err)
			}
			runSeed(t, shell, cf, dir)

			old := Dir
			Dir = dir
			defer func() { Dir = old }()
			b, err := os.ReadFile(PreUpgradePath())
			if err != nil || string(b) != conf {
				t.Fatalf("snapshot = %q (err %v), want the conffile verbatim", b, err)
			}
			for path, want := range map[string]os.FileMode{parent: 0o755, dir: 0o700, PreUpgradePath(): 0o600} {
				if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
					t.Errorf("%s mode = %v (err %v), want %v", path, fi.Mode().Perm(), err, want)
				}
			}
			if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) > 0 {
				t.Errorf("temp file left behind: %v", left)
			}

			// A second run (an upgrade the daemon never started after) keeps
			// the older snapshot: it holds what the node ran before.
			if err := os.WriteFile(cf, []byte("[webdetector]\nCHALLENGE_TOKEN = placeholder\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			runSeed(t, shell, cf, dir)
			if b, _ := os.ReadFile(PreUpgradePath()); string(b) != conf {
				t.Fatalf("an existing snapshot was overwritten: %q", b)
			}
		})
	}
}

// A missing detectors.conf (fresh install) is a no-op, not an error.
func TestPackageSeedBlockFreshInstallIsANoop(t *testing.T) {
	tmp := t.TempDir()
	runSeed(t, "sh", filepath.Join(tmp, "absent.conf"), filepath.Join(tmp, "secrets"))
	if _, err := os.Stat(filepath.Join(tmp, "secrets")); !os.IsNotExist(err) {
		t.Fatalf("store dir created on a fresh install (err %v)", err)
	}
}

// The Debian preinst stops a running OLD daemon (a binary without the token
// store) on upgrade, and only then: an old daemon regenerates the stock
// placeholder in detectors.conf if dpkg installs the packaged file.
func TestDebianPreinstStopsOnlyAnOldDaemon(t *testing.T) {
	preinst, err := filepath.Abs(filepath.Join("..", "..", "packaging", "debian", "DEBIAN", "preinst"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, arg, bin string
		active, stop   bool
	}{
		{"old daemon, upgrade", "upgrade", "cfm daemon\x00/etc/cfm/detectors.conf\x00", true, true},
		{"new daemon, upgrade", "upgrade", "cfm daemon\x00/var/lib/cfm/secrets\x00", true, false},
		{"old daemon not running", "upgrade", "cfm daemon", false, false},
		{"fresh install", "install", "cfm daemon", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			bin := filepath.Join(tmp, "cfm")
			if err := os.WriteFile(bin, []byte(tc.bin), 0o755); err != nil {
				t.Fatal(err)
			}
			// A systemctl stub that records its calls.
			calls := filepath.Join(tmp, "calls")
			active := "exit 3"
			if tc.active {
				active = "exit 0"
			}
			stub := "#!/bin/sh\necho \"$*\" >> " + calls + "\ncase \"$1\" in is-active) " + active + " ;; esac\nexit 0\n"
			if err := os.MkdirAll(filepath.Join(tmp, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tmp, "bin", "systemctl"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", preinst, tc.arg, "2026.09.01-1")
			cmd.Env = append(os.Environ(),
				"PATH="+filepath.Join(tmp, "bin")+":"+os.Getenv("PATH"),
				"CFM_PREINST_BIN="+bin,
				"CFM_SEED_CONF="+filepath.Join(tmp, "absent.conf"),
				"CFM_SEED_DIR="+filepath.Join(tmp, "secrets"))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("preinst failed: %v\n%s", err, out)
			}
			got, _ := os.ReadFile(calls)
			if stopped := strings.Contains(string(got), "stop cfm.service"); stopped != tc.stop {
				t.Fatalf("stopped = %v, want %v (systemctl calls: %q)", stopped, tc.stop, got)
			}
		})
	}
}
