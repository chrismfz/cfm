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
// daemon can only migrate a token while the old detectors.conf is in place,
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

// runSeed runs the block with sh against conf, seeding dir. It returns the
// stored values (key → content) afterwards.
func runSeed(t *testing.T, shell, conf, dir string) map[string]string {
	t.Helper()
	block := seedBlock(t, filepath.Join("..", "..", "packaging", "debian", "DEBIAN", "preinst"))
	cmd := exec.Command(shell, "-e", "-c", block)
	cmd.Env = append(os.Environ(), "CFM_SEED_CONF="+conf, "CFM_SEED_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: seed block failed: %v\n%s", shell, err, out)
	}
	got := map[string]string{}
	for _, key := range []string{ChallengeToken, BridgeToken} {
		p := filepath.Join(dir, strings.ToLower(key))
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		got[key] = string(b)
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %s mode = %v, want 0600", shell, p, fi.Mode().Perm())
		}
		if leftovers, _ := filepath.Glob(p + ".seed"); len(leftovers) > 0 {
			t.Errorf("%s: temp file left behind: %v", shell, leftovers)
		}
	}
	if di, err := os.Stat(dir); err == nil && di.Mode().Perm() != 0o700 {
		t.Errorf("%s: store dir mode = %v, want 0700", shell, di.Mode().Perm())
	}
	return got
}

func TestPackageSeedBlockSeedsTheStore(t *testing.T) {
	const (
		tokA = "0123456789abcdef0123456789abcdef0123456789abcdef"
		tokB = "fedcba9876543210fedcba9876543210fedcba9876543210"
	)
	cases := []struct {
		name string
		conf string
		pre  map[string]string // store files present before the run
		want map[string]string // store contents after (Read, trimmed)
	}{
		{
			name: "strong tokens in [webdetector] are copied",
			conf: "[global]\nENRICH = 1\n[webdetector]\nENABLED = 1\nCHALLENGE_TOKEN = " + tokA + "\nOPENRESTY_TOKEN = " + tokB + "\n[health]\nENABLED = 1\n",
			want: map[string]string{ChallengeToken: tokA, BridgeToken: tokB},
		},
		{
			name: "inline comment, quotes, CRLF and lower-case key",
			conf: "[webdetector]\r\n  challenge_token = \"" + tokA + "\" ; note\r\n",
			want: map[string]string{ChallengeToken: tokA},
		},
		{
			name: "placeholder and short values are not seeded",
			conf: "[webdetector]\nCHALLENGE_TOKEN = placeholder\nOPENRESTY_TOKEN = tooshort\n",
			want: map[string]string{},
		},
		{
			// The speedhost layout: the token sits in another section, which
			// the daemon never reads either.
			name: "a token outside [webdetector] is not seeded",
			conf: "[webdetector]\nENABLED = 1\n[challenge_cookie_discard]\nENABLED = 1\nCHALLENGE_TOKEN = " + tokA + "\n",
			want: map[string]string{},
		},
		{
			name: "a commented-out line is not seeded",
			conf: "[webdetector]\n; CHALLENGE_TOKEN = " + tokA + "\n",
			want: map[string]string{},
		},
		{
			name: "an existing store file is never overwritten",
			conf: "[webdetector]\nCHALLENGE_TOKEN = " + tokA + "\n",
			pre:  map[string]string{ChallengeToken: tokB},
			want: map[string]string{ChallengeToken: tokB},
		},
		{
			name: "the last assignment wins, as in the daemon's parser",
			conf: "[webdetector]\nCHALLENGE_TOKEN = " + tokB + "\n[webdetector]\nCHALLENGE_TOKEN = " + tokA + "\n",
			want: map[string]string{ChallengeToken: tokA},
		},
	}
	shells := []string{"sh"}
	if _, err := exec.LookPath("dash"); err == nil {
		shells = append(shells, "dash")
	}
	for _, shell := range shells {
		for _, tc := range cases {
			t.Run(shell+"/"+tc.name, func(t *testing.T) {
				tmp := t.TempDir()
				conf := filepath.Join(tmp, "detectors.conf")
				dir := filepath.Join(tmp, "secrets")
				if err := os.WriteFile(conf, []byte(tc.conf), 0o600); err != nil {
					t.Fatal(err)
				}
				for k, v := range tc.pre {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, strings.ToLower(k)), []byte(v+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				got := runSeed(t, shell, conf, dir)
				if len(got) != len(tc.want) {
					t.Fatalf("store = %v, want %v", got, tc.want)
				}
				for k, v := range tc.want {
					if strings.TrimSpace(got[k]) != v {
						t.Errorf("%s = %q, want %q", k, got[k], v)
					}
				}
				// What the seed wrote is what the daemon then reads.
				old := Dir
				Dir = dir
				defer func() { Dir = old }()
				for k, v := range tc.want {
					if r, ok := Read(k); !ok || r != v {
						t.Errorf("Read(%s) = (%q, %v), want %q", k, r, ok, v)
					}
				}
			})
		}
	}

	// A missing detectors.conf (fresh install) is a no-op, not an error.
	t.Run("fresh install", func(t *testing.T) {
		tmp := t.TempDir()
		got := runSeed(t, "sh", filepath.Join(tmp, "absent.conf"), filepath.Join(tmp, "secrets"))
		if len(got) != 0 {
			t.Fatalf("store = %v, want nothing on a fresh install", got)
		}
		if _, err := os.Stat(filepath.Join(tmp, "secrets")); !os.IsNotExist(err) {
			t.Fatalf("store dir created on a fresh install (err %v)", err)
		}
	})
}
