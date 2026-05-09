package kernsec

import (
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
	origConf := ConfPath
	origSysctl := SysctlPath
	ConfPath = filepath.Join(confDir, "kernsec.conf")
	SysctlPath = filepath.Join(sysctlDir, "99-cfm-kernsec.conf")
	t.Cleanup(func() {
		ConfPath = origConf
		SysctlPath = origSysctl
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

func TestPurgeManagedFiles_RemovesBoth(t *testing.T) {
	confDir, sysctlDir := withTempConfPath(t)

	// Pre-create both files.
	if err := os.WriteFile(ConfPath, []byte("tier = 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SysctlPath, []byte("# managed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// And a backup file alongside — must NOT be removed by purge.
	bak := SysctlPath + BackupSuffix
	if err := os.WriteFile(bak, []byte("# old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := purgeManagedFiles(devnullWriter{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ConfPath); !os.IsNotExist(err) {
		t.Errorf("conf still exists after purge: %v", err)
	}
	if _, err := os.Stat(SysctlPath); !os.IsNotExist(err) {
		t.Errorf("sysctl file still exists after purge: %v", err)
	}
	if _, err := os.Stat(bak); err != nil {
		t.Errorf("backup removed by purge (should be left in place): %v", err)
	}
	// Make sure we didn't leak files into the temp dirs.
	for _, dir := range []string{confDir, sysctlDir} {
		entries, _ := os.ReadDir(dir)
		// The sysctlDir keeps the .bak file; confDir should be empty.
		if dir == confDir && len(entries) != 0 {
			t.Errorf("confDir has stray entries after purge: %v", entries)
		}
	}
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
	c, src := loadConfForDisable()
	if c.Tier != 0 {
		t.Errorf("got tier %d, want 0", c.Tier)
	}
	if !strings.Contains(src, "no conf") {
		t.Errorf("source should signal absence: %q", src)
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
	got, _ := loadConfForDisable()
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

// devnullWriter swallows writes — used when test cases don't care
// about output formatting.
type devnullWriter struct{}

func (devnullWriter) Write(p []byte) (int, error) { return len(p), nil }
