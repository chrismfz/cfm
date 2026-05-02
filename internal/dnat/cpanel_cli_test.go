package dnat

import (
	"bytes"
	"io"
	"os/exec"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureStreams(t *testing.T, fn func()) (string, string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr
	defer func() {
		os.Stdout, os.Stderr = origOut, origErr
	}()

	fn()
	_ = wOut.Close()
	_ = wErr.Close()
	var bout, berr bytes.Buffer
	_, _ = io.Copy(&bout, rOut)
	_, _ = io.Copy(&berr, rErr)
	return bout.String(), berr.String()
}

func TestNormalizePanelArgs_AcceptsFlagAndKeyValue(t *testing.T) {
	got, err := normalizePanelArgs([]string{"on", "mode=direct-cpsrvd", "priority=-101", "challenge=guard-only"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"on", "--mode", "direct-cpsrvd", "--priority", "-101", "--challenge", "guard-only"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v want %v", got, want)
	}
}


func TestChallengeShortcuts(t *testing.T) {
	gotOn, err := normalizePanelArgs([]string{"on", "--challenge", "forced"})
	if err != nil || strings.Join(gotOn, " ") != "on --challenge forced" {
		t.Fatalf("unexpected normalize for forced: %v %v", gotOn, err)
	}
	gotOff, err := normalizePanelArgs([]string{"on", "--challenge", "off"})
	if err != nil || strings.Join(gotOff, " ") != "on --challenge off" {
		t.Fatalf("unexpected normalize for off: %v %v", gotOff, err)
	}
}

func TestBuildPanelChallengeStatus_AfterApplyForced(t *testing.T) {
	st := buildPanelChallengeStatus("forced", "forced", true)
	if st.RequestedMode != "forced" {
		t.Fatalf("requested=%q", st.RequestedMode)
	}
	if !st.Enforced {
		t.Fatalf("expected enforced")
	}
}

func TestBuildPanelChallengeStatus_AfterApplyOff(t *testing.T) {
	st := buildPanelChallengeStatus("off", "off", true)
	if st.RequestedMode != "off" {
		t.Fatalf("requested=%q", st.RequestedMode)
	}
	if !st.Enforced {
		t.Fatalf("expected enforced")
	}
}

func TestBuildPanelChallengeStatus_MismatchWarningState(t *testing.T) {
	st := buildPanelChallengeStatus("forced", "forced", false)
	if st.Enforced {
		t.Fatalf("expected enforced=false")
	}
	if st.MismatchCause == "" {
		t.Fatalf("expected mismatch warning cause")
	}
}

func TestNormalizePanelArgs_RejectsUnknownKeyValue(t *testing.T) {
	_, err := normalizePanelArgs([]string{"on", "foo=bar"})
	if err == nil || !strings.Contains(err.Error(), "unsupported key=value") {
		t.Fatalf("expected unsupported key=value error, got %v", err)
	}
}

func TestPanelHelpSnapshots(t *testing.T) {
	_, errOut := captureStreams(t, func() {
		code := runPanelCLI([]string{"help"}, nil)
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
	})
	for _, token := range []string{
		"Commands: status, on, off",
		"cfm dnat cpanel challenge on",
		"cfm dnat cpanel challenge off",
		"Migration: existing scripts using --challenge guard-only",
		"Modes: auto, chain-imunify, direct-cpsrvd, fallback",
		"Priority guidance: -101 (CFM-first), -99 (Imunify-first)",
		"Challenge options: off, guard-only, forced (default: guard-only)",
	} {
		if !strings.Contains(errOut, token) {
			t.Fatalf("help output missing %q\n%s", token, errOut)
		}
	}
}

func TestPanelOnHelpSnapshot(t *testing.T) {
	out, _ := captureStreams(t, func() {
		code := runPanelCLI([]string{"on", "--help"}, nil)
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
	})
	for _, token := range []string{
		"Usage: cfm dnat cpanel on",
		"Modes: auto, chain-imunify, direct-cpsrvd, fallback",
		"Priority guidance: -101 (CFM-first), -99 (Imunify-first)",
		"Challenge options: off, guard-only, forced (default: guard-only)",
		"mode=direct-cpsrvd",
		"priority=-101",
	} {
		if !strings.Contains(out, token) {
			t.Fatalf("on help output missing %q\n%s", token, out)
		}
	}
}

func TestChallengeModeFromActiveConfig(t *testing.T) {
	tmp := t.TempDir()
	cfg := filepath.Join(tmp, "cfm-panel-listeners.conf")
	content := `server { set $cfm_panel_challenge_mode "guard-only"; access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`
	if err := os.WriteFile(cfg, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	mode, loaded, path := panelListenerGuardStateFromPaths([]string{cfg})
	if mode != "guard-only" {
		t.Fatalf("mode=%q", mode)
	}
	if !loaded {
		t.Fatalf("expected lua guard loaded")
	}
	if path != cfg {
		t.Fatalf("path=%q", path)
	}
}

func TestChallengeModeDefaultReflected(t *testing.T) {
	tmp := t.TempDir()
	prev := panelChallengeModeStatePath
	panelChallengeModeStatePath = filepath.Join(tmp, "panel_challenge_mode")
	t.Cleanup(func() { panelChallengeModeStatePath = prev })
	if got := loadPersistedPanelChallengeMode(); got != "" {
		t.Fatalf("expected empty persisted mode, got %q", got)
	}
	if defaultPanelChallengeMode != "guard-only" {
		t.Fatalf("unexpected default %q", defaultPanelChallengeMode)
	}
}

func TestPanelChallengeOn_ForcedUpdatesActiveConfigAndReloadsAngie(t *testing.T) {
	tmp := t.TempDir()
	listenerPath := filepath.Join(tmp, "cfm-panel-listeners.conf")
	content := `server { set $cfm_panel_challenge_mode "guard-only"; access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`
	if err := os.WriteFile(listenerPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls []string
	origExec := execCommand
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "angie" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}
	t.Cleanup(func() { execCommand = origExec })

	if err := applyPanelChallengeModeToPaths("forced", []string{listenerPath}); err != nil {
		t.Fatalf("apply forced mode: %v", err)
	}
	mode, loaded, path := panelListenerGuardStateFromPaths([]string{listenerPath})
	if mode != "forced" || !loaded || path != listenerPath {
		t.Fatalf("listener guard state mismatch: mode=%q loaded=%v path=%q", mode, loaded, path)
	}

	if err := reloadPanelListenerService(); err != nil {
		t.Fatalf("reload listener service: %v", err)
	}
	if len(calls) == 0 || calls[0] != "systemctl reload angie" {
		t.Fatalf("expected first reload command to be Angie reload, got %v", calls)
	}
}

func TestInvalidChallengeModeRejected(t *testing.T) {
	_, errOut := captureStreams(t, func() {
		code := runPanelCLI([]string{"status", "--challenge", "bogus"}, nil)
		if code != 2 {
			t.Fatalf("expected code 2, got %d", code)
		}
	})
	if !strings.Contains(errOut, "unsupported challenge mode") {
		t.Fatalf("expected validation error, got: %s", errOut)
	}
}

func TestPanelStatusSnapshotOmitsRecentHitFields(t *testing.T) {
	out, _ := captureStreams(t, func() {
		code := runPanelCLI([]string{"status"}, nil)
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
	})
	for _, forbidden := range []string{
		"Recent listener hits (last 15m, from access log ingestion):",
		"recent_hits_15m=",
		"last_seen=",
	} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("status output unexpectedly contained %q\n%s", forbidden, out)
		}
	}
	for _, required := range []string{
		"Port 12083 listener=",
		"firewall=",
		"Bridge socket (/var/run/cfm/cfm_nginx.sock):",
		"Ingest socket (/run/cfm/ingest.sock):",
	} {
		if !strings.Contains(out, required) {
			t.Fatalf("status output missing %q\n%s", required, out)
		}
	}
}


func TestChallengeShortcutRejectsUnknown(t *testing.T) {
	_, errOut := captureStreams(t, func() {
		code := runPanelCLI([]string{"challenge", "maybe"}, nil)
		if code != 2 {
			t.Fatalf("expected code 2, got %d", code)
		}
	})
	if !strings.Contains(errOut, "unknown challenge shortcut") {
		t.Fatalf("expected shortcut validation error, got: %s", errOut)
	}
}

func TestReadPanelPortAccessStats(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "challenge.access.log")
	log := strings.Join([]string{
		"2026-05-02 10:00:00 [challenge_http] ip=1.1.1.1 host=example.test:2083 method=GET uri=/xfercpanel port=12083 status=302 bytes=0 ms=1",
		"2026-05-02 10:04:00 [challenge_http] ip=1.1.1.1 host=example.test:2087 method=GET uri=/login port=12087 status=403 bytes=0 ms=1",
	}, "\n")
	if err := os.WriteFile(path, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 2, 10, 20, 0, 0, time.UTC)
	stats := readPanelPortAccessStats(path, now, 15*time.Minute)
	if stats.HitsRecent[12083] != 0 {
		t.Fatalf("expected 0 recent hits on 12083, got %d", stats.HitsRecent[12083])
	}
	if stats.HitsRecent[12087] != 0 {
		t.Fatalf("expected 0 recent hits on 12087, got %d", stats.HitsRecent[12087])
	}
	if stats.LastSeenByPort[12083].IsZero() {
		t.Fatalf("expected last_seen for 12083")
	}
	if !stats.XferRedirect2083Seen {
		t.Fatalf("expected xfer redirect marker")
	}
}
