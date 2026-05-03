package dnat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseManagedRuleLine(t *testing.T) {
	port, handle, ok := parseManagedRuleLine(`tcp dport 12082 ct state new accept comment "cfm_cpanel_dnat:12082" # handle 44`)
	if !ok || port != "12082" || handle != "44" {
		t.Fatalf("unexpected parse: ok=%v port=%s handle=%s", ok, port, handle)
	}
}

func TestParseManagedRuleLine_IgnoresUnmanaged(t *testing.T) {
	if _, _, ok := parseManagedRuleLine(`tcp dport 12082 accept comment "admin" # handle 55`); ok {
		t.Fatal("expected unmanaged rule to be ignored")
	}
}

func writeFakeFWCommands(t *testing.T, script string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	for _, bin := range []string{"nft", "firewall-cmd"} {
		path := filepath.Join(dir, bin)
		content := "#!/bin/sh\n" + script
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir, logPath
}

func TestEnsureNftPorts_DoesNotUseNftFileStdin(t *testing.T) {
	script := `
LOGFILE="` + "${FAKE_LOG}" + `"
printf "%s\n" "$0 $*" >> "$LOGFILE"
if [ "$1" = "-a" ] && [ "$2" = "list" ] && [ "$3" = "chain" ]; then
  exit 0
fi
exit 0
`
	dir, logPath := writeFakeFWCommands(t, script)
	t.Setenv("FAKE_LOG", logPath)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	changes, err := ensureNftPorts()
	if err != nil {
		t.Fatalf("ensureNftPorts failed: %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("expected nft add rule changes")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(data)
	if strings.Contains(calls, "nft -f -") {
		t.Fatalf("unexpected nft -f - call: %s", calls)
	}
}

func TestEnsureFirewalldPorts_AddsMissingAndSkipsPresent(t *testing.T) {
	script := `
LOGFILE="` + "${FAKE_LOG}" + `"
printf "%s\n" "$0 $*" >> "$LOGFILE"
port="${2%%/*}"
if [ "$1" = "--query-port" ]; then
  [ "$port" = "12082" ] && exit 0
  exit 1
fi
exit 0
`
	dir, logPath := writeFakeFWCommands(t, script)
	t.Setenv("FAKE_LOG", logPath)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	changes, err := ensureFirewalldPorts()
	if err != nil {
		t.Fatalf("ensureFirewalldPorts failed: %v", err)
	}
	if !containsChange(changes, "tcp/12082 already open") {
		t.Fatalf("missing already-open change: %v", changes)
	}
	if !containsChange(changes, "opened tcp/12083 (firewalld)") {
		t.Fatalf("missing opened change: %v", changes)
	}
	data, _ := os.ReadFile(logPath)
	calls := string(data)
	if !strings.Contains(calls, "firewall-cmd --add-port 12083/tcp") || !strings.Contains(calls, "firewall-cmd --permanent --add-port 12083/tcp") {
		t.Fatalf("expected add commands in call log: %s", calls)
	}
}

func TestRemoveFirewalldPorts_RemovesAndReportsNotFound(t *testing.T) {
	script := `
LOGFILE="` + "${FAKE_LOG}" + `"
printf "%s\n" "$0 $*" >> "$LOGFILE"
port="${2%%/*}"
if [ "$1" = "--query-port" ]; then
  [ "$port" = "12082" ] && exit 0
  exit 1
fi
exit 0
`
	dir, _ := writeFakeFWCommands(t, script)
	t.Setenv("FAKE_LOG", filepath.Join(dir, "calls.log"))
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	changes, err := removeFirewalldPorts()
	if err != nil {
		t.Fatalf("removeFirewalldPorts failed: %v", err)
	}
	if !containsChange(changes, "tcp/12082 removed") || !containsChange(changes, "tcp/12083 not found") {
		t.Fatalf("unexpected changes: %v", changes)
	}
}

func TestEnsureFirewalldPorts_ReturnsFirewallCommandError(t *testing.T) {
	script := `
if [ "$1" = "--query-port" ]; then exit 1; fi
if [ "$1" = "--add-port" ]; then echo boom; exit 2; fi
exit 0
`
	dir, _ := writeFakeFWCommands(t, script)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	changes, err := ensureFirewalldPorts()
	if err == nil {
		t.Fatal("expected error")
	}
	if len(changes) != 0 {
		t.Fatalf("expected no changes before first failure: %v", changes)
	}
	fwErr, ok := err.(*FirewallCommandError)
	if !ok {
		t.Fatalf("expected FirewallCommandError, got %T", err)
	}
	if fwErr.Backend != fwFirewalld {
		t.Fatalf("unexpected backend: %v", fwErr.Backend)
	}
}

func containsChange(changes []string, want string) bool {
	for _, c := range changes {
		if c == want {
			return true
		}
	}
	return false
}
