package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
)

// The bundle's pprof-cpu-top / pprof-heap-top were missing from every bundle:
// the profile went to `go tool pprof -top -cum -` on stdin, and pprof reads
// `-` as a file name ("stat -: no such file or directory"). A fake `go` on
// PATH stands in for pprof (a cold build of the real one takes 25-40 s): it
// fails unless its last argument is a file holding the profile, and records
// the path so the test can check the temp file is gone afterwards.
func TestRunPProfTopPassesTheProfileAsAFile(t *testing.T) {
	bin := t.TempDir()
	seen := filepath.Join(t.TempDir(), "seen")
	script := `#!/bin/sh
[ "$1 $2" = "tool pprof" ] || { echo "unexpected: $*" >&2; exit 3; }
for last; do :; done
[ -f "$last" ] || { echo "$last: stat $last: no such file or directory" >&2; exit 2; }
printf '%s' "$last" > "$SEEN"
printf '      flat  flat%%   sum%%        cum   cum%%\n'
cat "$last"
`
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SEEN", seen)

	work := t.TempDir()
	top, err := runPProfTop([]byte("PROFILE-BYTES"), work)
	if err != nil {
		t.Fatalf("runPProfTop: %v", err)
	}
	if !strings.Contains(string(top), "flat") || !strings.Contains(string(top), "PROFILE-BYTES") {
		t.Fatalf("pprof did not get the profile:\n%s", top)
	}
	p, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(string(p)) != work {
		t.Errorf("temp profile %s, want it in the work dir %s", p, work)
	}
	if _, err := os.Stat(string(p)); !os.IsNotExist(err) {
		t.Errorf("temp profile %s left behind", p)
	}
}

// The real pprof, opt-in: CI's restored build cache rarely holds a pprof
// build, and building it cold under `go test -race ./...` passes the 30 s
// timeout. CFM_PPROF_INTEGRATION=1 go test ./internal/cli -run RealPProf
func TestRunPProfTopRealPProf(t *testing.T) {
	if os.Getenv("CFM_PPROF_INTEGRATION") != "1" {
		t.Skip("set CFM_PPROF_INTEGRATION=1 (builds and runs go tool pprof)")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	var prof bytes.Buffer
	if err := pprof.Lookup("heap").WriteTo(&prof, 0); err != nil {
		t.Fatal(err)
	}
	top, err := runPProfTop(prof.Bytes(), "")
	if err != nil {
		t.Fatalf("runPProfTop: %v", err)
	}
	if !strings.Contains(string(top), "flat") || !strings.Contains(string(top), "cum") {
		t.Fatalf("no top table:\n%s", top)
	}
}

func pprofEnvMap(workDir string) map[string]string {
	got := map[string]string{}
	for _, kv := range pprofEnv(workDir) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			got[k] = v // later entries win, as in exec
		}
	}
	return got
}

// The go build cache lives next to the bundles, shared, not inside each one
// (it was ~160 MB per bundle) — but only under a root nobody else can write:
// it holds a binary root runs.
func TestPProfEnvSharesTheBuildCacheOnlyUnderAPrivateRoot(t *testing.T) {
	if env := pprofEnv(""); env != nil {
		t.Errorf("no workDir: env %v, want the inherited one (nil)", env)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "20261010T155826Z")
	got := pprofEnvMap(bundle)
	if got["TMPDIR"] != bundle || got["GOTMPDIR"] != bundle {
		t.Errorf("TMPDIR %q GOTMPDIR %q, want the bundle dir", got["TMPDIR"], got["GOTMPDIR"])
	}
	if want := filepath.Join(root, ".gocache"); got["GOCACHE"] != want {
		t.Errorf("private root: GOCACHE %q, want %q (shared, outside the bundle)", got["GOCACHE"], want)
	}

	// A root others can write (`--output /tmp`): the bundle's own cache.
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(bundle, ".gocache"); pprofEnvMap(bundle)["GOCACHE"] != want {
		t.Errorf("world-writable root: GOCACHE %q, want %q", pprofEnvMap(bundle)["GOCACHE"], want)
	}

	// A private root whose .gocache is not a private dir (a symlink planted
	// before the root was locked down).
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, ".gocache")); err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(bundle, ".gocache"); pprofEnvMap(bundle)["GOCACHE"] != want {
		t.Errorf("symlinked shared cache: GOCACHE %q, want %q", pprofEnvMap(bundle)["GOCACHE"], want)
	}
}
