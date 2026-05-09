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
