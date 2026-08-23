package dnat

import (
	"bytes"
	"io"
	"os"
	"os/exec"
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
	got, err := normalizePanelArgs([]string{"on", "mode=direct-cpsrvd", "priority=-101", "challenge=forced"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"on", "--mode", "direct-cpsrvd", "--priority", "-101"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestChallengeShortcuts(t *testing.T) {
	gotOn, err := normalizePanelArgs([]string{"on", "--challenge", "forced"})
	if err != nil || strings.Join(gotOn, " ") != "on forced" {
		t.Fatalf("unexpected normalize for forced: %v %v", gotOn, err)
	}
	gotOff, err := normalizePanelArgs([]string{"on", "--challenge", "off"})
	if err != nil || strings.Join(gotOff, " ") != "on off" {
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

func TestBuildPanelChallengeStatus_CleanOnSemantics(t *testing.T) {
	st := buildPanelChallengeStatus(panelChallengeEnabledMode, panelChallengeEnabledMode, true)
	if !st.Enforced {
		t.Fatalf("expected ON profile to be enforced")
	}
}

func TestBuildPanelChallengeStatus_CleanOffSemantics(t *testing.T) {
	st := buildPanelChallengeStatus(panelChallengeDisabledMode, panelChallengeDisabledMode, true)
	if !st.Enforced {
		t.Fatalf("expected OFF profile to be enforced")
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
		"Modes: auto, chain-imunify, direct-cpsrvd, fallback",
		"Priority guidance: -101 (CFM-first), -99 (Imunify-first)",
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
	content := `server { set $cfm_panel_challenge_mode "off"; access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`
	if err := os.WriteFile(cfg, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	mode, loaded, path := panelListenerGuardStateFromPaths([]string{cfg})
	if mode != "off" {
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
	if got := loadPersistedPanelChallengeMode(); got != "off" {
		t.Fatalf("expected persisted mode off when unset, got %q", got)
	}
	if defaultPanelChallengeMode != "forced" {
		t.Fatalf("unexpected default %q", defaultPanelChallengeMode)
	}
}

func TestPanelChallengeOn_ForcedUpdatesActiveConfigAndReloadsAngie(t *testing.T) {
	tmp := t.TempDir()
	listenerPath := filepath.Join(tmp, "cfm-panel-listeners.conf")
	content := `server { set $cfm_panel_challenge_mode "off"; access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`
	if err := os.WriteFile(listenerPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	var calls []string
	origExec := execCommand
	origDetect := panelListenerServiceDetector
	panelListenerServiceDetector = func() string { return "angie" }
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "angie" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}
	t.Cleanup(func() {
		execCommand = origExec
		panelListenerServiceDetector = origDetect
	})

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
	var reloadCalls []string
	for _, call := range calls {
		if strings.Contains(call, " reload ") {
			reloadCalls = append(reloadCalls, call)
		}
	}
	if len(reloadCalls) == 0 || reloadCalls[0] != "systemctl reload angie" {
		t.Fatalf("expected first reload command to be Angie reload, got calls=%v reloadCalls=%v", calls, reloadCalls)
	}
}

func TestSetPanelChallengeModeInConfig_ReplacesAllOccurrences(t *testing.T) {
	input := strings.Join([]string{
		"server {",
		`  set $cfm_panel_challenge_mode "off";`,
		"}",
		"server {",
		`  set $cfm_panel_challenge_mode "off";`,
		"}",
		"server {",
		`  set $cfm_panel_challenge_mode "off";`,
		"}",
	}, "\n")

	got := setPanelChallengeModeInConfig(input, "forced")
	if strings.Count(got, `set $cfm_panel_challenge_mode "forced";`) != 3 {
		t.Fatalf("expected all listener blocks updated; got:\n%s", got)
	}
	if strings.Contains(got, `set $cfm_panel_challenge_mode "off";`) {
		t.Fatalf("found old mode after replacement; got:\n%s", got)
	}
}

func TestApplyPanelChallengeModeToPaths_NoReplacementIsNoOp(t *testing.T) {
	tmp := t.TempDir()
	listenerPath := filepath.Join(tmp, "cfm-panel-listeners.conf")
	content := `server { listen 443; }`
	if err := os.WriteFile(listenerPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	err := applyPanelChallengeModeToPaths("forced", []string{listenerPath})
	if err != nil {
		t.Fatalf("expected no-op apply to succeed, got %v", err)
	}
}

func TestApplyPanelChallengeModeToPaths_OnWhenAlreadyOnSucceeds(t *testing.T) {
	tmp := t.TempDir()
	listenerPath := filepath.Join(tmp, "cfm-panel-listeners.conf")
	content := `server { set $cfm_panel_challenge_mode "forced"; access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`
	if err := os.WriteFile(listenerPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := applyPanelChallengeModeToPaths("forced", []string{listenerPath}); err != nil {
		t.Fatalf("expected idempotent on apply to succeed, got %v", err)
	}
	b, err := os.ReadFile(listenerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `set $cfm_panel_challenge_mode "forced";`) {
		t.Fatalf("listener config should remain forced:\n%s", string(b))
	}
}

func TestApplyPanelChallengeModeToPaths_NoOpConfigApplyDoesNotFail(t *testing.T) {
	tmp := t.TempDir()
	listenerPath := filepath.Join(tmp, "cfm-panel-listeners.conf")
	content := `server { listen 443; }`
	if err := os.WriteFile(listenerPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := applyPanelChallengeModeToPaths("forced", []string{listenerPath}); err != nil {
		t.Fatalf("expected no-op config apply to succeed, got %v", err)
	}
}

func TestApplyPanelChallengeModeToPaths_OffWhenAlreadyOffSucceeds(t *testing.T) {
	tmp := t.TempDir()
	listenerPath := filepath.Join(tmp, "cfm-panel-listeners.conf")
	content := `server { set $cfm_panel_challenge_mode "off"; access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`
	if err := os.WriteFile(listenerPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := applyPanelChallengeModeToPaths("off", []string{listenerPath}); err != nil {
		t.Fatalf("expected idempotent off apply to succeed, got %v", err)
	}
}

func TestDeprecatedChallengeArgIsIgnored(t *testing.T) {
	_, errOut := captureStreams(t, func() {
		code := runPanelCLI([]string{"status", "--challenge", "bogus"}, nil)
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
	})
	if !strings.Contains(errOut, "deprecated and ignored") {
		t.Fatalf("expected deprecation warning, got: %s", errOut)
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
		"DNAT cpanel state:",
		"Policy: ",
		"Port 12083 listener=",
		"firewall=",
		"Bridge socket (/var/run/cfm/cfm_nginx.sock):",
		"Ingest socket (/run/cfm/ingest.sock):",
	} {
		if !strings.Contains(out, required) {
			t.Fatalf("status output missing %q\n%s", required, out)
		}
	}
	for _, forbidden := range []string{
		"Challenge mode requested (CLI):",
		"Challenge mode rendered (config):",
		"Challenge mode effective (runtime):",
		"Challenge mode source:",
		"Challenge mode enforced:",
	} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("status output unexpectedly contained stale field %q\n%s", forbidden, out)
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
	if !strings.Contains(errOut, "unknown deprecated challenge shortcut") {
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

func TestPanelOn_DefaultChallengeAppliesForcedAndPersists(t *testing.T) {
	tmp := t.TempDir()
	prevState := panelChallengeModeStatePath
	panelChallengeModeStatePath = filepath.Join(tmp, "panel_challenge_mode")
	t.Cleanup(func() { panelChallengeModeStatePath = prevState })

	cfgDir := filepath.Join(tmp, "configs")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(cfgDir, "cfm-panel-listeners.conf.in")
	content := `server { set $cfm_panel_challenge_mode "off"; access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua; }`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	origWD, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	origExec := execCommand
	execCommand = func(name string, args ...string) *exec.Cmd {
		if name == "systemctl" && len(args) == 2 && args[0] == "reload" && args[1] == "angie" {
			return exec.Command("sh", "-c", "exit 0")
		}
		return exec.Command("sh", "-c", "exit 1")
	}
	t.Cleanup(func() { execCommand = origExec })

	code := runPanelCLI([]string{"on"}, nil)
	if code == 0 {
		t.Fatalf("expected non-zero code in test env due missing nft/iptables dependencies")
	}

	// Intent must NOT be persisted when the on pipeline fails before
	// the firewall step succeeds. Otherwise a partial-apply leaves
	// intent=ON on disk and RestoreOnStartup silently re-applies DNAT
	// on the next daemon restart, undoing the rollback.
	if got := loadPersistedPanelChallengeMode(); got != "off" {
		t.Fatalf("persisted mode=%q want off (intent must not advance after failed on)", got)
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `set $cfm_panel_challenge_mode "forced";`) {
		t.Fatalf("listener config not rewritten to forced:\n%s", string(b))
	}
}

func TestCheckPanelLuaGuard_SelftestHookCleanExitIsTrue(t *testing.T) {
	tmp := t.TempDir()
	luaPath := filepath.Join(tmp, "cfm_panel.lua")
	if err := os.WriteFile(luaPath, []byte("function cfm_panel_selftest() return true end\nif os.getenv('CFM_PANEL_SELFTEST_ONLY') == '1' then return cfm_panel_selftest() end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeLua := filepath.Join(tmp, "lua")
	if err := os.WriteFile(fakeLua, []byte("#!/bin/sh\n[ \"$CFM_PANEL_SELFTEST_ONLY\" = 1 ] || exit 8\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	oldLookPath := lookPath
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		lookPath = oldLookPath
	})
	_ = os.Setenv("PATH", tmp)
	lookPath = exec.LookPath

	st := checkPanelLuaGuard(luaPath)
	if st.LoadState != "true" {
		t.Fatalf("LoadState=%q LoadError=%q", st.LoadState, st.LoadError)
	}
	if st.LoadError != "" {
		t.Fatalf("unexpected LoadError=%q", st.LoadError)
	}
}

func TestCheckPanelLuaGuard_MissingSelftestHookIsUnknownWithoutUserError(t *testing.T) {
	tmp := t.TempDir()
	luaPath := filepath.Join(tmp, "cfm_panel.lua")
	if err := os.WriteFile(luaPath, []byte("-- fake panel lua\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeLua := filepath.Join(tmp, "lua")
	if err := os.WriteFile(fakeLua, []byte("#!/bin/sh\necho CFM_PANEL_SELFTEST_HOOK_MISSING\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	oldLookPath := lookPath
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		lookPath = oldLookPath
	})
	_ = os.Setenv("PATH", tmp)
	lookPath = exec.LookPath

	st := checkPanelLuaGuard(luaPath)
	if st.LoadState != "unknown" {
		t.Fatalf("LoadState=%q LoadError=%q", st.LoadState, st.LoadError)
	}
	if st.LoadError != "" {
		t.Fatalf("unexpected missing hook LoadError=%q", st.LoadError)
	}
}

func setupPanelStatusLuaTest(t *testing.T, fakeResty string) string {
	t.Helper()
	tmp := t.TempDir()
	luaPath := filepath.Join(tmp, "cfm_panel.lua")
	if err := os.WriteFile(luaPath, []byte("function cfm_panel_selftest() return true end\nif os.getenv('CFM_PANEL_SELFTEST_ONLY') == '1' then return cfm_panel_selftest() end\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(tmp, "configs")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	listener := `server {
    set $cfm_panel_challenge_mode "forced";
    access_by_lua_file ` + luaPath + `;
    location = /__cfm_panel_decide { internal; }
}`
	if err := os.WriteFile(filepath.Join(cfgDir, "cfm-panel-listeners.conf.in"), []byte(listener), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "resty"), []byte(fakeResty), 0o755); err != nil {
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	oldLookPath := lookPath
	oldWD, _ := os.Getwd()
	oldState := panelChallengeModeStatePath
	panelChallengeModeStatePath = filepath.Join(tmp, "panel_challenge_mode")
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("PATH", tmp)
	lookPath = exec.LookPath
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		lookPath = oldLookPath
		_ = os.Chdir(oldWD)
		panelChallengeModeStatePath = oldState
	})
	return tmp
}

func TestPanelStatusSuppressesMissingSelftestHookWhenDecisionEndpointOK(t *testing.T) {
	setupPanelStatusLuaTest(t, "#!/bin/sh\necho CFM_PANEL_SELFTEST_HOOK_MISSING\nexit 0\n")

	out, _ := captureStreams(t, func() {
		code := runPanelCLI([]string{"status"}, nil)
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
	})
	if !strings.Contains(out, "Panel decision endpoint: OK") {
		t.Fatalf("expected decision endpoint OK, got:\n%s", out)
	}
	if strings.Contains(out, "cfm_panel_selftest hook is missing") || strings.Contains(out, "CFM_PANEL_SELFTEST_HOOK_MISSING") {
		t.Fatalf("status output should suppress missing hook warning when decision endpoint is OK:\n%s", out)
	}
}

func TestPanelStatusShowsRealLuaLoadError(t *testing.T) {
	setupPanelStatusLuaTest(t, "#!/bin/sh\necho \"syntax error near 'end'\" >&2\nexit 1\n")

	out, _ := captureStreams(t, func() {
		code := runPanelCLI([]string{"status"}, nil)
		if code != 0 {
			t.Fatalf("expected code 0, got %d", code)
		}
	})
	if !strings.Contains(out, "Panel decision endpoint: OK") {
		t.Fatalf("expected decision endpoint OK, got:\n%s", out)
	}
	if !strings.Contains(out, "Panel Lua load check error:") || !strings.Contains(out, "syntax error near 'end'") {
		t.Fatalf("expected real lua load error in output:\n%s", out)
	}
}
