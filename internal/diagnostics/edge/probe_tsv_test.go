package edge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProbeTSVLog(t *testing.T) {
	dir := t.TempDir()
	logf := filepath.Join(dir, "access_cfm_tsv.log")
	if err := os.WriteFile(logf, []byte("line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Quoted + inline-comment value, as it appears in detectors.conf.
	got := ProbeTSVLog(`"` + logf + `"  ; the tsv access log`)
	if !got.Configured || !got.Exists || !got.IsFile {
		t.Fatalf("expected configured/exists/file, got %+v", got)
	}
	if got.Path != logf {
		t.Errorf("Path = %q, want cleaned %q", got.Path, logf)
	}
	if got.ModAgeSec < 0 {
		t.Errorf("ModAgeSec = %d, want >= 0", got.ModAgeSec)
	}

	// Unset LOG_PATH → not configured, no false alarm.
	if p := ProbeTSVLog("  "); p.Configured || p.Exists {
		t.Errorf("empty LOG_PATH should be unconfigured, got %+v", p)
	}

	// Configured but missing file.
	if p := ProbeTSVLog(filepath.Join(dir, "nope.log")); !p.Configured || p.Exists {
		t.Errorf("missing file should be configured+!exists, got %+v", p)
	}
}

func TestCleanConfValue(t *testing.T) {
	cases := map[string]string{
		`"/var/log/apache2/access_cfm_tsv.log"`: "/var/log/apache2/access_cfm_tsv.log",
		`/var/log/x.log  ; inline note`:         "/var/log/x.log",
		`  '/tmp/y.log'  `:                      "/tmp/y.log",
		``:                                      "",
	}
	for in, want := range cases {
		if got := cleanConfValue(in); got != want {
			t.Errorf("cleanConfValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// A file over the size cap must be skipped even when it would otherwise match.
