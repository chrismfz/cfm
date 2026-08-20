package kernsec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// legacyKSPPConf is the sysctl block the old scripts/kspp.sh wrote to
// /etc/sysctl.d/99-kspp.conf — the concrete file that re-broke cPanel's
// DNS Zone Editor after a reboot by re-applying fs.protected_regular=2
// over kernsec's =1 (99-kspp.conf sorts AFTER 99-cfm-kernsec.conf).
const legacyKSPPConf = `# Managed by KSPP hardening script
kernel.kptr_restrict=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
net.core.bpf_jit_harden=2
`

// fsProtectedRegularRule is the applied-rule fixture: kernsec pins
// fs.protected_regular=1.
var fsProtectedRegularRule = SysctlRule{
	ID: "KSEC-SCT-kspp.fs-004", Group: "kspp.fs", Tier: Tier1,
	Key: "fs.protected_regular", Value: "1",
}

// setupForeignScan redirects SysctlPath into a fresh tempdir (writing
// kernsec's own drop-in there) and points legacySysctlConf at a
// non-existent path so the scan stays hermetic. Returns the tempdir.
func setupForeignScan(t *testing.T) string {
	t.Helper()
	if !sysctlExists("fs.protected_regular") {
		t.Skip("kernel does not expose fs.protected_regular")
	}
	tmp := t.TempDir()
	origSysctl, origLegacy := SysctlPath, legacySysctlConf
	SysctlPath = filepath.Join(tmp, "99-cfm-kernsec.conf")
	legacySysctlConf = filepath.Join(tmp, "no-such-sysctl.conf")
	t.Cleanup(func() { SysctlPath, legacySysctlConf = origSysctl, origLegacy })
	if err := os.WriteFile(SysctlPath, []byte("fs.protected_regular = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return tmp
}

func TestParseSysctlAssignment(t *testing.T) {
	tests := []struct {
		in           string
		wantKey, val string
		ok           bool
	}{
		{"fs.protected_regular=2", "fs.protected_regular", "2", true},
		{"  fs.protected_regular  =  2  ", "fs.protected_regular", "2", true},
		{"-fs.protected_regular = 2", "fs.protected_regular", "2", true}, // leading '-' ignore-errors marker
		{"# fs.protected_regular = 2", "", "", false},                    // comment
		{"; fs.protected_regular = 2", "", "", false},                    // ini-style comment
		{"", "", "", false},                     // blank
		{"   ", "", "", false},                  // whitespace only
		{"fs.protected_regular", "", "", false}, // no '='
		{"= 2", "", "", false},                  // empty key
		{"kernel.core_pattern=|/bin/false", "kernel.core_pattern", "|/bin/false", true},
		// sysctl.conf(5): '/' and '.' separators are interchangeable —
		// the key is normalised to dotted form so it matches the allowlist.
		{"fs/protected_regular = 2", "fs.protected_regular", "2", true},
	}
	for _, tc := range tests {
		k, v, ok := parseSysctlAssignment(tc.in)
		if ok != tc.ok || k != tc.wantKey || v != tc.val {
			t.Errorf("parseSysctlAssignment(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.in, k, v, ok, tc.wantKey, tc.val, tc.ok)
		}
	}
}

func TestDetectForeignSysctlConflicts_KSPPConf(t *testing.T) {
	tmp := setupForeignScan(t)
	kspp := filepath.Join(tmp, "99-kspp.conf")
	if err := os.WriteFile(kspp, []byte(legacyKSPPConf), 0o644); err != nil {
		t.Fatal(err)
	}

	conflicts := detectForeignSysctlConflicts([]SysctlRule{fsProtectedRegularRule})
	if len(conflicts) != 1 {
		t.Fatalf("want 1 conflict, got %d: %+v", len(conflicts), conflicts)
	}
	c := conflicts[0]
	if c.Key != "fs.protected_regular" || c.Found != "2" || c.Want != "1" {
		t.Errorf("conflict = %+v, want fs.protected_regular found=2 want=1", c)
	}
	if filepath.Base(c.File) != "99-kspp.conf" {
		t.Errorf("conflict file = %s, want 99-kspp.conf", c.File)
	}
	if c.Line != 6 { // 1-based: fs.protected_regular=2 is the 6th line
		t.Errorf("conflict line = %d, want 6", c.Line)
	}
}

func TestDetectForeignSysctlConflicts_SlashSeparatorKey(t *testing.T) {
	tmp := setupForeignScan(t)
	// A foreign file using the slash separator sysctl.conf(5) accepts —
	// must still be detected against the dotted allowlist.
	if err := os.WriteFile(filepath.Join(tmp, "99-slash.conf"),
		[]byte("fs/protected_regular = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conflicts := detectForeignSysctlConflicts([]SysctlRule{fsProtectedRegularRule})
	if len(conflicts) != 1 || conflicts[0].Key != "fs.protected_regular" || conflicts[0].Found != "2" {
		t.Fatalf("slash-separated key not detected: %+v", conflicts)
	}
}

func TestDetectForeignSysctlConflicts_NoConflictWhenValueMatches(t *testing.T) {
	tmp := setupForeignScan(t)
	// A foreign file that already agrees with kernsec — not a conflict.
	if err := os.WriteFile(filepath.Join(tmp, "50-ok.conf"),
		[]byte("fs.protected_regular = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectForeignSysctlConflicts([]SysctlRule{fsProtectedRegularRule}); len(got) != 0 {
		t.Fatalf("want 0 conflicts when value already matches, got %+v", got)
	}
}

func TestDetectForeignSysctlConflicts_IgnoresCommentedAndOtherKeys(t *testing.T) {
	tmp := setupForeignScan(t)
	body := "# fs.protected_regular = 2\nkernel.kptr_restrict = 1\nfs.protected_symlinks = 0\n"
	if err := os.WriteFile(filepath.Join(tmp, "60-misc.conf"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Only fs.protected_regular is reconcile-eligible; it appears only
	// commented out here → no conflict.
	if got := detectForeignSysctlConflicts([]SysctlRule{fsProtectedRegularRule}); len(got) != 0 {
		t.Fatalf("want 0 conflicts (commented + non-eligible keys), got %+v", got)
	}
}

func TestDetectForeignSysctlConflicts_ExcludesOwnFile(t *testing.T) {
	setupForeignScan(t)
	// Even a (buggy) =2 in kernsec's OWN drop-in must never be reported
	// as a foreign conflict — self is excluded by path.
	if err := os.WriteFile(SysctlPath, []byte("fs.protected_regular = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range detectForeignSysctlConflicts([]SysctlRule{fsProtectedRegularRule}) {
		if absOrSame(c.File) == absOrSame(SysctlPath) {
			t.Fatalf("kernsec's own file was flagged as a foreign conflict: %+v", c)
		}
	}
}

func TestDetectForeignSysctlConflicts_NotAppliedKeyIsIgnored(t *testing.T) {
	tmp := setupForeignScan(t)
	if err := os.WriteFile(filepath.Join(tmp, "99-kspp.conf"),
		[]byte("fs.protected_regular=2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// No applied rule for the key (e.g. tier=0 / disable) → nothing to
	// reconcile; foreign files are left alone.
	if got := detectForeignSysctlConflicts(nil); len(got) != 0 {
		t.Fatalf("want 0 conflicts when key isn't applied, got %+v", got)
	}
}

func TestDetectForeignSysctlConflicts_LegacySysctlConf(t *testing.T) {
	if !sysctlExists("fs.protected_regular") {
		t.Skip("kernel does not expose fs.protected_regular")
	}
	tmp := t.TempDir()
	origSysctl, origLegacy := SysctlPath, legacySysctlConf
	SysctlPath = filepath.Join(tmp, "99-cfm-kernsec.conf")
	legacySysctlConf = filepath.Join(tmp, "etc-sysctl.conf")
	t.Cleanup(func() { SysctlPath, legacySysctlConf = origSysctl, origLegacy })
	if err := os.WriteFile(SysctlPath, []byte("fs.protected_regular = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacySysctlConf, []byte("fs.protected_regular = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conflicts := detectForeignSysctlConflicts([]SysctlRule{fsProtectedRegularRule})
	// File is the canonicalised path (EvalSymlinks may rewrite the
	// tempdir prefix on hosts where /tmp is a symlink), so compare by
	// base name rather than exact string.
	if len(conflicts) != 1 || filepath.Base(conflicts[0].File) != "etc-sysctl.conf" {
		t.Fatalf("want 1 conflict in legacy /etc/sysctl.conf, got %+v", conflicts)
	}
}

// TestDetectForeignSysctlConflicts_SymlinkedDropInDedup reproduces the
// Debian/Ubuntu layout where /etc/sysctl.d/99-sysctl.conf is a symlink
// to /etc/sysctl.conf. The glob match and legacySysctlConf are the same
// underlying file, so the scan must dedup them to a single conflict and
// (critically) neutralise the real target without replacing the symlink.
func TestDetectForeignSysctlConflicts_SymlinkedDropInDedup(t *testing.T) {
	if !sysctlExists("fs.protected_regular") {
		t.Skip("kernel does not expose fs.protected_regular")
	}
	tmp := t.TempDir()
	origSysctl, origLegacy := SysctlPath, legacySysctlConf
	SysctlPath = filepath.Join(tmp, "99-cfm-kernsec.conf")
	legacySysctlConf = filepath.Join(tmp, "sysctl.conf")
	t.Cleanup(func() { SysctlPath, legacySysctlConf = origSysctl, origLegacy })
	if err := os.WriteFile(SysctlPath, []byte("fs.protected_regular = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The real target carries the conflict.
	if err := os.WriteFile(legacySysctlConf, []byte("fs.protected_regular = 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A drop-in symlink to it (the Debian/Ubuntu 99-sysctl.conf shape).
	link := filepath.Join(tmp, "99-sysctl.conf")
	if err := os.Symlink(legacySysctlConf, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	conflicts := detectForeignSysctlConflicts([]SysctlRule{fsProtectedRegularRule})
	if len(conflicts) != 1 {
		t.Fatalf("symlink + target must dedup to 1 conflict, got %d: %+v", len(conflicts), conflicts)
	}

	neutraliseForeignSysctls(&bytes.Buffer{}, conflicts)

	// The symlink must still BE a symlink (not clobbered into a file).
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("neutralise replaced the distro symlink with a regular file")
	}
	// And the real target's active line is neutralised.
	body, _ := os.ReadFile(legacySysctlConf)
	if _, _, ok := firstAssignment(string(body), "fs.protected_regular"); ok {
		t.Errorf("real target still has an active fs.protected_regular:\n%s", body)
	}
}

func TestNeutraliseForeignSysctls_KSPPConf(t *testing.T) {
	tmp := setupForeignScan(t)
	kspp := filepath.Join(tmp, "99-kspp.conf")
	if err := os.WriteFile(kspp, []byte(legacyKSPPConf), 0o600); err != nil {
		t.Fatal(err)
	}

	var w bytes.Buffer
	conflicts := detectForeignSysctlConflicts([]SysctlRule{fsProtectedRegularRule})
	neutraliseForeignSysctls(&w, conflicts)

	got, err := os.ReadFile(kspp)
	if err != nil {
		t.Fatal(err)
	}
	gotStr := string(got)

	// The active fs.protected_regular=2 line is gone; a commented copy
	// and a marker remain.
	if k, _, ok := firstAssignment(gotStr, "fs.protected_regular"); ok {
		t.Fatalf("fs.protected_regular still active after neutralise (key %q); file:\n%s", k, gotStr)
	}
	if !strings.Contains(gotStr, "neutralised by cfm kernsec") {
		t.Errorf("marker comment missing; file:\n%s", gotStr)
	}
	if !strings.Contains(gotStr, "# fs.protected_regular=2") {
		t.Errorf("original line not preserved as a comment; file:\n%s", gotStr)
	}
	// Every OTHER KSPP line survives untouched.
	for _, keep := range []string{
		"kernel.kptr_restrict=2",
		"fs.protected_hardlinks=1",
		"fs.protected_fifos=2",
		"net.core.bpf_jit_harden=2",
	} {
		if !strings.Contains(gotStr, keep) {
			t.Errorf("unrelated line %q was lost; file:\n%s", keep, gotStr)
		}
	}

	// A one-shot backup with the ORIGINAL content exists.
	bak, err := os.ReadFile(kspp + BackupSuffix)
	if err != nil {
		t.Fatalf("backup not written: %v", err)
	}
	if string(bak) != legacyKSPPConf {
		t.Errorf("backup content != original\n got: %q\nwant: %q", bak, legacyKSPPConf)
	}
	// Original mode preserved.
	if st, err := os.Stat(kspp); err == nil {
		if st.Mode().Perm() != 0o600 {
			t.Errorf("mode not preserved: got %o want 600", st.Mode().Perm())
		}
	}

	if !strings.Contains(w.String(), "foreign reconcile") {
		t.Errorf("operator output missing reconcile line:\n%s", w.String())
	}
}

func TestNeutraliseForeignSysctls_Idempotent(t *testing.T) {
	tmp := setupForeignScan(t)
	kspp := filepath.Join(tmp, "99-kspp.conf")
	if err := os.WriteFile(kspp, []byte(legacyKSPPConf), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := []SysctlRule{fsProtectedRegularRule}

	neutraliseForeignSysctls(&bytes.Buffer{}, detectForeignSysctlConflicts(rule))
	afterFirst, _ := os.ReadFile(kspp)

	// Second pass: detect must find nothing (the active line is now
	// commented) and neutralise must not change the file again.
	if got := detectForeignSysctlConflicts(rule); len(got) != 0 {
		t.Fatalf("second detect found conflicts (not idempotent): %+v", got)
	}
	neutraliseForeignSysctls(&bytes.Buffer{}, detectForeignSysctlConflicts(rule))
	afterSecond, _ := os.ReadFile(kspp)
	if !bytes.Equal(afterFirst, afterSecond) {
		t.Errorf("file changed on second neutralise pass (not idempotent)\nfirst:\n%s\nsecond:\n%s",
			afterFirst, afterSecond)
	}
}

// TestNeutraliseForeignSysctls_NoStrayBackupWhenLineChanged locks in
// that a foreign file whose offending line no longer re-parses to the
// detected conflict (a race between detect and neutralise) is left
// completely untouched — no rewrite AND no stray .cfm-kernsec.bak.
func TestNeutraliseForeignSysctls_NoStrayBackupWhenLineChanged(t *testing.T) {
	tmp := setupForeignScan(t)
	f := filepath.Join(tmp, "70-race.conf")
	// On disk the value already agrees with kernsec (=1); no real
	// conflict here...
	if err := os.WriteFile(f, []byte("fs.protected_regular = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// ...but hand a STALE conflict (Found=2) as if detect had seen =2
	// before the file changed under us.
	stale := []foreignConflict{{
		File: f, Line: 1, Key: "fs.protected_regular", Found: "2", Want: "1", Reason: "x",
	}}
	neutraliseForeignSysctls(&bytes.Buffer{}, stale)

	if _, err := os.Stat(f + BackupSuffix); err == nil {
		t.Error("stray .cfm-kernsec.bak written for a file that was never edited")
	}
	got, _ := os.ReadFile(f)
	if string(got) != "fs.protected_regular = 1\n" {
		t.Errorf("file was modified despite no matching conflict: %q", got)
	}
}

func TestClassifyCheckResult_ForeignConflictIsDrift(t *testing.T) {
	if got := classifyCheckResult(driftResult{ForeignSysctlConflicts: 1}); got != 1 {
		t.Errorf("foreign conflict should classify as drift (exit 1), got %d", got)
	}
	// A read error still wins over a foreign conflict (indeterminate).
	if got := classifyCheckResult(driftResult{ForeignSysctlConflicts: 1, SysctlReadErr: os.ErrPermission}); got != 2 {
		t.Errorf("read-error should take precedence (exit 2), got %d", got)
	}
}

// TestApplyWrites_NeutralisesForeignConflict drives the full applyWrites
// path (the production wiring) and asserts the leftover foreign
// fs.protected_regular=2 is neutralised as a side effect of apply.
func TestApplyWrites_NeutralisesForeignConflict(t *testing.T) {
	if !sysctlExists("fs.protected_regular") {
		t.Skip("kernel does not expose fs.protected_regular")
	}
	tmp := t.TempDir()
	origSysctl, origMod, origLegacy := SysctlPath, ModprobePath, legacySysctlConf
	SysctlPath = filepath.Join(tmp, "99-cfm-kernsec.conf")
	ModprobePath = filepath.Join(tmp, "modprobe.cfm-kernsec.conf")
	legacySysctlConf = filepath.Join(tmp, "no-such.conf")
	t.Cleanup(func() {
		SysctlPath, ModprobePath, legacySysctlConf = origSysctl, origMod, origLegacy
	})

	kspp := filepath.Join(tmp, "99-kspp.conf")
	if err := os.WriteFile(kspp, []byte(legacyKSPPConf), 0o644); err != nil {
		t.Fatal(err)
	}

	// ResolvedSet whose ApplySysctls() yields the fs.protected_regular
	// rule (matched by ID against AllSysctls()).
	rs := ResolvedSet{Sysctls: []ResolvedRule{
		{ID: "KSEC-SCT-kspp.fs-004", Kind: KindSysctl, Decision: Apply},
	}}

	var w bytes.Buffer
	rc := applyWrites(
		&w, &fakeBootBackend{},
		RenderSysctlFile(rs.ApplySysctls()),
		[]byte("# modprobe\n"),
		nil, nil, ApplyOptions{NoRefresh: true},
		"",
		func() error { return nil },
		rs,
	)
	if rc != 0 {
		t.Fatalf("applyWrites rc=%d, output:\n%s", rc, w.String())
	}
	got, _ := os.ReadFile(kspp)
	if k, _, ok := firstAssignment(string(got), "fs.protected_regular"); ok {
		t.Fatalf("apply left fs.protected_regular active (%q):\n%s", k, got)
	}
}

// firstAssignment returns the first ACTIVE assignment of key in body.
func firstAssignment(body, key string) (k, v string, ok bool) {
	for _, ln := range strings.Split(body, "\n") {
		if pk, pv, pok := parseSysctlAssignment(ln); pok && pk == key {
			return pk, pv, true
		}
	}
	return "", "", false
}
