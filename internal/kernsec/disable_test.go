package kernsec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTempConfPath redirects ConfPath + SysctlPath to per-test
// temporary files for the duration of the test. Restores the
// originals on cleanup.
func withTempConfPath(t *testing.T) (confDir, sysctlDir string) {
	t.Helper()
	confDir = t.TempDir()
	sysctlDir = t.TempDir()
	modprobeDir := t.TempDir()
	origConf := ConfPath
	origSysctl := SysctlPath
	origModprobe := ModprobePath
	ConfPath = filepath.Join(confDir, "kernsec.conf")
	SysctlPath = filepath.Join(sysctlDir, "99-cfm-kernsec.conf")
	ModprobePath = filepath.Join(modprobeDir, "cfm-kernsec.conf")
	t.Cleanup(func() {
		ConfPath = origConf
		SysctlPath = origSysctl
		ModprobePath = origModprobe
	})
	return confDir, sysctlDir
}

func TestWriteConf_RoundTrip(t *testing.T) {
	withTempConfPath(t)
	c := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-MOD-net.legacy-001": OverrideSkip,
		},
	}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConf(false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tier != Tier1 {
		t.Errorf("tier = %d, want 1", got.Tier)
	}
	if got.Overrides["KSEC-MOD-net.legacy-001"] != OverrideSkip {
		t.Errorf("override lost in round-trip: %+v", got.Overrides)
	}
}

func TestWriteConf_NilRefused(t *testing.T) {
	withTempConfPath(t)
	if err := WriteConf(nil); err == nil {
		t.Error("expected error for nil conf")
	}
}

func TestWriteConf_TierZeroPersistsAcrossLoad(t *testing.T) {
	withTempConfPath(t)
	c := &Conf{
		Tier:      0,
		Overrides: map[string]RuleOverride{},
	}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConf(false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tier != 0 {
		t.Errorf("tier 0 not persisted: got %d", got.Tier)
	}
}

func TestPurgeManagedFiles_RemovesAllManaged(t *testing.T) {
	confDir, sysctlDir := withTempConfPath(t)

	// Pre-create all three managed files.
	if err := os.WriteFile(ConfPath, []byte("tier = 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SysctlPath, []byte("# managed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ModprobePath, []byte("# managed\nblacklist ksmbd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// And backup files alongside the sysctl + modprobe — must NOT be
	// removed by purge.
	sysctlBak := SysctlPath + BackupSuffix
	modprobeBak := ModprobePath + BackupSuffix
	for _, b := range []string{sysctlBak, modprobeBak} {
		if err := os.WriteFile(b, []byte("# old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := purgeManagedFiles(devnullWriter{}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{ConfPath, SysctlPath, ModprobePath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists after purge: %v", p, err)
		}
	}
	for _, b := range []string{sysctlBak, modprobeBak} {
		if _, err := os.Stat(b); err != nil {
			t.Errorf("backup %s removed by purge (should be left in place): %v", b, err)
		}
	}
	// Make sure conf temp dir is clean (no .bak there).
	if entries, _ := os.ReadDir(confDir); len(entries) != 0 {
		t.Errorf("confDir has stray entries after purge: %v", entries)
	}
	_ = sysctlDir
}

func TestPurgeManagedFiles_IdempotentOnMissing(t *testing.T) {
	withTempConfPath(t)
	// Don't create either file.
	if err := purgeManagedFiles(devnullWriter{}); err != nil {
		t.Errorf("purge on missing files: %v", err)
	}
}

func TestLoadConfForDisable_NoConfReturnsTier0(t *testing.T) {
	withTempConfPath(t)
	// No conf on disk.
	c, err := loadConfForDisable()
	if err != nil {
		t.Fatalf("absent conf should not be an error: %v", err)
	}
	if c.Tier != 0 {
		t.Errorf("got tier %d, want 0", c.Tier)
	}
	if !strings.Contains(c.Source, "no conf") {
		t.Errorf("source should signal absence: %q", c.Source)
	}
}

func TestLoadConfForDisable_PreservesOverrides(t *testing.T) {
	withTempConfPath(t)
	c := &Conf{
		Tier: Tier1,
		Overrides: map[string]RuleOverride{
			"KSEC-MOD-net.legacy-001": OverrideSkip,
			"KSEC-BOOT-kspp-005":      OverrideForce,
		},
	}
	if err := WriteConf(c); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfForDisable()
	if err != nil {
		t.Fatalf("loadConfForDisable on valid conf: %v", err)
	}
	if got.Overrides["KSEC-MOD-net.legacy-001"] != OverrideSkip {
		t.Error("skip override lost")
	}
	if got.Overrides["KSEC-BOOT-kspp-005"] != OverrideForce {
		t.Error("force override lost")
	}
	// Tier hasn't been overridden yet — the caller does that.
	if got.Tier != Tier1 {
		t.Errorf("tier mutated by loadConfForDisable: got %d", got.Tier)
	}
}

func TestLoadConfForDisable_ParseErrorSurfacesError(t *testing.T) {
	withTempConfPath(t)
	// Garbage that ParseConf will reject (unknown top-level key).
	if err := os.WriteFile(ConfPath, []byte("totally not a conf file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfForDisable()
	if err == nil {
		t.Fatal("expected error on malformed conf, got nil")
	}
	if c != nil {
		t.Errorf("expected nil conf on parse error, got: %+v", c)
	}
}

func TestRunDisable_RefusesOverwriteOnParseErrorWithoutForce(t *testing.T) {
	withTempConfPath(t)
	original := []byte("garbage = sentinel\n")
	if err := os.WriteFile(ConfPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	rc := RunDisable(&w, DisableOptions{DryRun: true})
	if rc != 1 {
		t.Fatalf("expected rc=1 (refuse), got %d. Output:\n%s", rc, w.String())
	}
	if !strings.Contains(w.String(), "--force") {
		t.Errorf("expected operator-facing --force hint, got:\n%s", w.String())
	}
	// Original file untouched.
	got, err := os.ReadFile(ConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("malformed conf was overwritten without --force:\n  before: %q\n  after:  %q",
			original, got)
	}
}

func TestRunDisable_ForceProceedsThroughParseError(t *testing.T) {
	withTempConfPath(t)
	if err := os.WriteFile(ConfPath, []byte("garbage = sentinel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	rc := RunDisable(&w, DisableOptions{DryRun: true, Force: true})
	if rc != 0 {
		t.Fatalf("--force --dry-run should succeed, got %d. Output:\n%s", rc, w.String())
	}
	if !strings.Contains(w.String(), "proceeding with --force") {
		t.Errorf("expected confirmation of forced overwrite, got:\n%s", w.String())
	}
}

func TestRunDisable_PurgeProceedsThroughParseError(t *testing.T) {
	withTempConfPath(t)
	if err := os.WriteFile(ConfPath, []byte("garbage = sentinel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	rc := RunDisable(&w, DisableOptions{DryRun: true, Purge: true})
	if rc != 0 {
		t.Fatalf("--purge --dry-run on malformed conf should succeed (operator opted in to discard), got %d. Output:\n%s",
			rc, w.String())
	}
}

// devnullWriter swallows writes — used when test cases don't care
// about output formatting.
type devnullWriter struct{}

func (devnullWriter) Write(p []byte) (int, error) { return len(p), nil }
