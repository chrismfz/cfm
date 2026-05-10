package kernsec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTempMonitorPaths redirects MonitorServicePath + MonitorTimerPath
// to per-test temp files.
func withTempMonitorPaths(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	origSvc := MonitorServicePath
	origTmr := MonitorTimerPath
	MonitorServicePath = filepath.Join(dir, "cfm-kernsec-check.service")
	MonitorTimerPath = filepath.Join(dir, "cfm-kernsec-check.timer")
	t.Cleanup(func() {
		MonitorServicePath = origSvc
		MonitorTimerPath = origTmr
	})
}

func TestRenderMonitorService_ContainsBinaryAndCheck(t *testing.T) {
	got := string(RenderMonitorService("/usr/local/bin/cfm"))

	wantContains := []string{
		"# Managed by cfm kernsec",
		"[Unit]",
		"Description=cfm kernsec drift check",
		"[Service]",
		"Type=oneshot",
		"ExecStart=/usr/local/bin/cfm kernsec apply --check",
		"StandardOutput=journal",
		// Exit 2 = "could not determine state"; the systemd unit must
		// treat it as success so the timer keeps retrying without
		// flagging the unit as Failed. See classifyCheckResult.
		"SuccessExitStatus=2",
	}
	for _, s := range wantContains {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q in:\n%s", s, got)
		}
	}
}

func TestRenderMonitorService_HonoursBinaryPath(t *testing.T) {
	got := string(RenderMonitorService("/opt/cfm/bin/cfm"))
	if !strings.Contains(got, "ExecStart=/opt/cfm/bin/cfm kernsec apply --check") {
		t.Errorf("ExecStart did not pick up custom binary path:\n%s", got)
	}
}

func TestRenderMonitorTimer_DefaultsToDaily(t *testing.T) {
	got := string(RenderMonitorTimer(""))
	if !strings.Contains(got, "OnCalendar=daily") {
		t.Errorf("empty interval should default to daily:\n%s", got)
	}
}

func TestRenderMonitorTimer_HonoursInterval(t *testing.T) {
	got := string(RenderMonitorTimer("hourly"))
	if !strings.Contains(got, "OnCalendar=hourly") {
		t.Errorf("custom interval missing:\n%s", got)
	}
}

func TestRenderMonitorTimer_StableShape(t *testing.T) {
	got := string(RenderMonitorTimer("daily"))
	wantContains := []string{
		"# Managed by cfm kernsec",
		"[Unit]",
		"Description=cfm kernsec drift check (periodic)",
		"[Timer]",
		"OnCalendar=daily",
		"Persistent=true",
		"RandomizedDelaySec=1h",
		"Unit=cfm-kernsec-check.service",
		"[Install]",
		"WantedBy=timers.target",
	}
	for _, s := range wantContains {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q in:\n%s", s, got)
		}
	}
}

func TestRenderMonitor_Idempotent(t *testing.T) {
	a := RenderMonitorTimer("daily")
	b := RenderMonitorTimer("daily")
	if !bytes.Equal(a, b) {
		t.Error("RenderMonitorTimer not deterministic")
	}
	c := RenderMonitorService("/usr/bin/cfm")
	d := RenderMonitorService("/usr/bin/cfm")
	if !bytes.Equal(c, d) {
		t.Error("RenderMonitorService not deterministic")
	}
}

func TestMonitorInstalled_FalseWhenAbsent(t *testing.T) {
	withTempMonitorPaths(t)
	if MonitorInstalled() {
		t.Error("MonitorInstalled returned true with no timer file")
	}
}

func TestMonitorInstalled_TrueWhenPresent(t *testing.T) {
	withTempMonitorPaths(t)
	if err := os.WriteFile(MonitorTimerPath, []byte("# managed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !MonitorInstalled() {
		t.Error("MonitorInstalled returned false after creating timer file")
	}
}

func TestRunMonitor_DryRunEnableNoWrites(t *testing.T) {
	withTempMonitorPaths(t)

	var out bytes.Buffer
	rc := RunMonitor(&out, MonitorOptions{
		Action:    "enable",
		Interval:  "hourly",
		CFMBinary: "/usr/local/bin/cfm",
		DryRun:    true,
	})
	if rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	o := out.String()
	wantContains := []string{
		"--dry-run",
		"interval: hourly",
		"ExecStart=/usr/local/bin/cfm kernsec apply --check",
		"OnCalendar=hourly",
		"(dry-run; nothing written)",
	}
	for _, s := range wantContains {
		if !strings.Contains(o, s) {
			t.Errorf("missing %q in dry-run output:\n%s", s, o)
		}
	}
	// Nothing should land on disk.
	if _, err := os.Stat(MonitorServicePath); !os.IsNotExist(err) {
		t.Error("dry-run wrote service file")
	}
	if _, err := os.Stat(MonitorTimerPath); !os.IsNotExist(err) {
		t.Error("dry-run wrote timer file")
	}
}

func TestRunMonitor_UnknownActionReturns2(t *testing.T) {
	withTempMonitorPaths(t)
	var out bytes.Buffer
	rc := RunMonitor(&out, MonitorOptions{Action: "banana"})
	if rc != 2 {
		t.Errorf("unknown action: rc=%d, want 2", rc)
	}
}

func TestRunMonitor_EmptyActionReturns2(t *testing.T) {
	withTempMonitorPaths(t)
	var out bytes.Buffer
	rc := RunMonitor(&out, MonitorOptions{Action: ""})
	if rc != 2 {
		t.Errorf("empty action: rc=%d, want 2", rc)
	}
}

func TestValidateMonitorBinary(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "clean absolute path", path: "/usr/bin/cfm", wantErr: false},
		{name: "deeply nested clean path", path: "/opt/cfm/bin/cfm", wantErr: false},
		{name: "empty rejected", path: "", wantErr: true},
		{name: "relative rejected", path: "cfm", wantErr: true},
		{name: "tilde rejected as relative", path: "~/cfm", wantErr: true},
		{name: "embedded space rejected", path: "/opt/My CFM/cfm", wantErr: true},
		{name: "embedded tab rejected", path: "/opt/cfm\tbin/cfm", wantErr: true},
		{name: "embedded newline rejected (smuggling)", path: "/opt/cfm\nExecStart=/bin/sh", wantErr: true},
		{name: "embedded NUL rejected", path: "/opt/cfm\x00", wantErr: true},
		{name: "embedded double-quote rejected", path: `/opt/cfm"/cfm`, wantErr: true},
		{name: "embedded backslash rejected", path: `/opt/cfm\bin/cfm`, wantErr: true},
		{name: "embedded dollar rejected", path: "/opt/cfm$/cfm", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMonitorBinary(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateMonitorBinary(%q) err=%v, wantErr=%v", tc.path, err, tc.wantErr)
			}
		})
	}
}

func TestValidateMonitorInterval(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		wantErr bool
	}{
		{name: "daily shorthand", val: "daily", wantErr: false},
		{name: "hourly shorthand", val: "hourly", wantErr: false},
		{name: "weekly shorthand", val: "weekly", wantErr: false},
		{name: "calendar spec time", val: "*-*-* 03:00:00", wantErr: false},
		{name: "weekday range", val: "Mon..Fri 09:00", wantErr: false},
		{name: "every 30 minutes", val: "*:0/30", wantErr: false},
		{name: "empty rejected", val: "", wantErr: true},
		{name: "newline injection rejected", val: "daily\nExecStart=/bin/sh", wantErr: true},
		{name: "carriage return rejected", val: "daily\r", wantErr: true},
		{name: "NUL rejected", val: "daily\x00", wantErr: true},
		{name: "semicolon rejected (unit-file separator)", val: "daily;OnFailure=evil", wantErr: true},
		{name: "equals rejected (would smuggle directive)", val: "daily=hourly", wantErr: true},
		{name: "dollar rejected", val: "daily$VAR", wantErr: true},
		{name: "tab rejected", val: "daily\t", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMonitorInterval(tc.val)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateMonitorInterval(%q) err=%v, wantErr=%v", tc.val, err, tc.wantErr)
			}
		})
	}
}

func TestRunMonitor_RejectsBadBinaryPath(t *testing.T) {
	withTempMonitorPaths(t)
	var out bytes.Buffer
	rc := RunMonitor(&out, MonitorOptions{
		Action:    "enable",
		CFMBinary: "/opt/My CFM/cfm",
		Interval:  "daily",
		DryRun:    true,
	})
	if rc != 1 {
		t.Fatalf("expected rc=1 on bad binary path, got %d. Output:\n%s", rc, out.String())
	}
	if !strings.Contains(out.String(), "whitespace or control character") {
		t.Errorf("expected operator-facing message about whitespace; got:\n%s", out.String())
	}
}

func TestRunMonitor_RejectsNewlineInjectionInterval(t *testing.T) {
	withTempMonitorPaths(t)
	var out bytes.Buffer
	rc := RunMonitor(&out, MonitorOptions{
		Action:    "enable",
		CFMBinary: "/usr/bin/cfm",
		Interval:  "daily\nExecStart=/bin/sh",
		DryRun:    true,
	})
	if rc != 1 {
		t.Fatalf("expected rc=1 on newline-injected interval, got %d. Output:\n%s", rc, out.String())
	}
	if !strings.Contains(out.String(), "OnCalendar") {
		t.Errorf("expected operator-facing message about OnCalendar; got:\n%s", out.String())
	}
}

func TestRunMonitor_DryRunRemoveWithoutFiles(t *testing.T) {
	withTempMonitorPaths(t)
	var out bytes.Buffer
	rc := RunMonitor(&out, MonitorOptions{Action: "remove", DryRun: true})
	if rc != 0 {
		t.Fatalf("dry-run remove without files: rc=%d, want 0", rc)
	}
	o := out.String()
	if !strings.Contains(o, "(dry-run; nothing executed)") {
		t.Errorf("missing dry-run marker in:\n%s", o)
	}
}
