package dnat

import (
	"bytes"
	"io"
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
	mode, loaded := panelListenerGuardStateFromPaths([]string{cfg})
	if mode != "guard-only" {
		t.Fatalf("mode=%q", mode)
	}
	if !loaded {
		t.Fatalf("expected lua guard loaded")
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
