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
// `-` as a file name ("stat -: no such file or directory").
func TestRunPProfTopRendersAProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs go tool pprof")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	var prof bytes.Buffer
	if err := pprof.Lookup("heap").WriteTo(&prof, 0); err != nil {
		t.Fatal(err)
	}
	// The inherited GOCACHE (no workDir): a warm one holds the pprof build.
	// TMPDIR is where the temp profile goes, and it must not stay there.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	top, err := runPProfTop(prof.Bytes(), "")
	if err != nil {
		t.Fatalf("runPProfTop: %v", err)
	}
	if !strings.Contains(string(top), "flat") || !strings.Contains(string(top), "cum") {
		t.Fatalf("no top table:\n%s", top)
	}
	left, _ := os.ReadDir(tmp)
	for _, e := range left {
		if strings.HasPrefix(e.Name(), ".pprof-") {
			t.Errorf("temp profile left behind: %s", e.Name())
		}
	}
}

// The go build cache lives next to the bundles, shared, not inside each one
// (it was ~160 MB per bundle).
func TestPProfEnvSharesTheBuildCacheAcrossBundles(t *testing.T) {
	if env := pprofEnv(""); env != nil {
		t.Errorf("no workDir: env %v, want the inherited one (nil)", env)
	}
	root := t.TempDir()
	bundle := filepath.Join(root, "20261010T155826Z")
	got := map[string]string{}
	for _, kv := range pprofEnv(bundle) {
		if k, v, ok := strings.Cut(kv, "="); ok {
			got[k] = v // later entries win, as in exec
		}
	}
	if got["TMPDIR"] != bundle || got["GOTMPDIR"] != bundle {
		t.Errorf("TMPDIR %q GOTMPDIR %q, want the bundle dir", got["TMPDIR"], got["GOTMPDIR"])
	}
	if want := filepath.Join(root, ".gocache"); got["GOCACHE"] != want {
		t.Errorf("GOCACHE %q, want %q (shared, outside the bundle)", got["GOCACHE"], want)
	}
}
