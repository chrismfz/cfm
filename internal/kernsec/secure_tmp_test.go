package kernsec

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseSecureTmpSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"16G", 16 << 30, false},
		{"4g", 4 << 30, false},
		{"  8G  ", 8 << 30, false},
		{"4GB", 4 << 30, false},
		{"512M", 512 << 20, false},
		{"2048m", 2048 << 20, false},
		{"512MB", 512 << 20, false},
		{"", 0, true},
		{"0G", 0, true},
		{"-4G", 0, true},
		{"4", 0, true},   // no unit
		{"4K", 0, true},  // unsupported unit
		{"4TB", 0, true}, // unsupported unit
		{"banana", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSecureTmpSize(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v (value %v)", err, tc.wantErr, got)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %d want %d", got, tc.want)
			}
		})
	}
}

func TestSecureTmpOptions_Validate(t *testing.T) {
	// Below the 1G floor.
	if err := (SecureTmpOptions{SizeBytes: 512 << 20}).validate(); err == nil {
		t.Error("validate should reject 512M (under 1G floor)")
	}
	// Above the 256G ceiling.
	if err := (SecureTmpOptions{SizeBytes: 257 << 30}).validate(); err == nil {
		t.Error("validate should reject 257G (over 256G ceiling)")
	}
	// In-range.
	if err := (SecureTmpOptions{SizeBytes: 16 << 30}).validate(); err != nil {
		t.Errorf("validate rejected 16G: %v", err)
	}
}

func TestPreflightSecureTmp_Blockers(t *testing.T) {
	// Pre-flight should call out each refusal independently so the
	// operator sees the full list, not just the first hit. Build a
	// host facts struct with every problem set and assert all of them
	// surface.
	opts := SecureTmpOptions{SizeBytes: 16 << 30}
	env := secureTmpEnvFacts{
		TmpIsSeparate:    true,
		VarTmpIsSeparate: true,
		FstabHasTmp:      true,
		FstabHasVarTmp:   true,
		DeviceExists:     true,
		FreeBytes:        4 << 30, // not enough; also will fail >50% rule
	}
	got := preflightSecureTmp(opts, env)
	for _, want := range []string{
		"/tmp is already a separate mount",
		"/var/tmp is already a separate mount",
		"/etc/fstab already has an entry for /tmp",
		"/etc/fstab already has an entry for /var/tmp",
		"/var/tmpDSK already exists",
		"not enough free space",
	} {
		var found bool
		for _, b := range got {
			if strings.Contains(b, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("blocker %q missing from preflight output: %v", want, got)
		}
	}
}

func TestPreflightSecureTmp_HappyPath(t *testing.T) {
	opts := SecureTmpOptions{SizeBytes: 8 << 30}
	env := secureTmpEnvFacts{
		FreeBytes: 100 << 30, // 100G free — request is 8% of free space
	}
	if got := preflightSecureTmp(opts, env); len(got) != 0 {
		t.Errorf("happy-path host should have 0 blockers, got %d: %v", len(got), got)
	}
}

func TestPreflightSecureTmp_RefusesOverHalfOfFree(t *testing.T) {
	// 8G requested on a host with 10G free → 80% of free space.
	// Must be rejected even though there is technically enough room
	// for the file + headroom (10G > 8G+1G).
	opts := SecureTmpOptions{SizeBytes: 8 << 30}
	env := secureTmpEnvFacts{FreeBytes: 10 << 30}
	got := preflightSecureTmp(opts, env)
	var sawPctRule bool
	for _, b := range got {
		if strings.Contains(b, "of available free space") {
			sawPctRule = true
		}
	}
	if !sawPctRule {
		t.Errorf("expected the >50%%-of-free refusal; got %v", got)
	}
}

func TestPreflightSecureTmp_HeadroomEnforced(t *testing.T) {
	// 8G requested on a host with exactly 8G free → no 1G headroom
	// → refused (not enough free space), even though the 50% rule
	// would otherwise fire too.
	opts := SecureTmpOptions{SizeBytes: 8 << 30}
	env := secureTmpEnvFacts{FreeBytes: 8 << 30}
	got := preflightSecureTmp(opts, env)
	var sawFreeRule bool
	for _, b := range got {
		if strings.Contains(b, "not enough free space") {
			sawFreeRule = true
		}
	}
	if !sawFreeRule {
		t.Errorf("expected the headroom/free-space refusal; got %v", got)
	}
}

func TestPreflightSecureTmp_StatfsUnknownDoesNotPanic(t *testing.T) {
	// FreeBytes = -1 means statfs(2) failed. We must skip both the
	// free-space and percent rules rather than divide by zero.
	opts := SecureTmpOptions{SizeBytes: 8 << 30}
	env := secureTmpEnvFacts{FreeBytes: -1}
	got := preflightSecureTmp(opts, env)
	for _, b := range got {
		if strings.Contains(b, "not enough free space") || strings.Contains(b, "of available free space") {
			t.Errorf("statfs-failed host should skip space-related blockers; got %q", b)
		}
	}
}

func TestSecureTmpFstabLines_BothEntriesPresent(t *testing.T) {
	lines := secureTmpFstabLines()
	if len(lines) != 2 {
		t.Fatalf("want 2 fstab lines (loop + bind), got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], SecureTmpDevicePath) ||
		!strings.Contains(lines[0], "loop") ||
		!strings.Contains(lines[0], "nodev,nosuid,noexec") {
		t.Errorf("first line should declare the loop mount with the hardening opts; got %q", lines[0])
	}
	if !strings.Contains(lines[1], "/var/tmp") || !strings.Contains(lines[1], "bind") {
		t.Errorf("second line should declare the /var/tmp bind; got %q", lines[1])
	}
}

func TestRunSecureTmp_DryRunPrintsPlanAndDoesNotExecute(t *testing.T) {
	// Stub the env reader so the dry-run produces a deterministic
	// plan without depending on the test host's actual filesystem.
	origEnv := secureTmpEnv
	t.Cleanup(func() { secureTmpEnv = origEnv })
	secureTmpEnv = func() (secureTmpEnvFacts, error) {
		return secureTmpEnvFacts{FreeBytes: 100 << 30}, nil
	}
	// runCmd must NEVER fire during a dry-run.
	origRun := runCmd
	t.Cleanup(func() { runCmd = origRun })
	runCmd = func(name string, args ...string) error {
		t.Fatalf("dry-run invoked runCmd(%s %v)", name, args)
		return nil
	}

	var w bytes.Buffer
	rc := RunSecureTmp(&w, SecureTmpOptions{SizeBytes: 8 << 30, DryRun: true})
	if rc != 0 {
		t.Fatalf("dry-run rc=%d, want 0\n%s", rc, w.String())
	}
	out := w.String()
	for _, want := range []string{
		"size:",
		"device:",
		SecureTmpDevicePath,
		"fstab entries to append:",
		"(dry-run; nothing written)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run output missing %q\n%s", want, out)
		}
	}
}

func TestRunSecureTmp_RefusesWhenAlreadyInstalled(t *testing.T) {
	// /var/tmpDSK already exists → refuse, regardless of root /
	// dry-run state.
	origEnv := secureTmpEnv
	t.Cleanup(func() { secureTmpEnv = origEnv })
	secureTmpEnv = func() (secureTmpEnvFacts, error) {
		return secureTmpEnvFacts{
			DeviceExists: true,
			FreeBytes:    100 << 30,
		}, nil
	}

	var w bytes.Buffer
	rc := RunSecureTmp(&w, SecureTmpOptions{SizeBytes: 8 << 30, DryRun: true})
	if rc == 0 {
		t.Errorf("expected non-zero rc when /var/tmpDSK already exists\n%s", w.String())
	}
	if !strings.Contains(w.String(), "/var/tmpDSK already exists") {
		t.Errorf("expected blocker mentioning the existing device; got:\n%s", w.String())
	}
}

func TestHumanBytes(t *testing.T) {
	tests := map[int64]string{
		1 << 30:        "1G",
		4 << 30:        "4G",
		(3 << 30) / 2:  "1.5G",
		512 << 20:      "512M",
		(3 << 20) / 2:  "1.5M",
		0:              "0B",
		-1:             "?",
	}
	for in, want := range tests {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
