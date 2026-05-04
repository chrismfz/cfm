package dnat

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureNftPorts_UsesQuotedCommentToken(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "nft.log")
	nftPath := filepath.Join(tmp, "nft")
	script := "#!/bin/sh\n" +
		"echo \"$@\" >> \"" + logPath + "\"\n" +
		"if [ \"$1\" = \"-a\" ] && [ \"$2\" = \"list\" ]; then exit 0; fi\n" +
		"exit 0\n"
	if err := os.WriteFile(nftPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write nft stub: %v", err)
	}

	t.Setenv("PATH", tmp+":"+os.Getenv("PATH"))

	changes, err := ensureNftPorts()
	if err != nil {
		t.Fatalf("ensureNftPorts failed: %v", err)
	}
	if len(changes) == 0 {
		t.Fatal("expected at least one opened-port change")
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read nft log: %v", err)
	}
	if !strings.Contains(string(logData), `comment "cfm_cpanel_dnat:12082"`) {
		t.Fatalf("expected quoted comment token in nft command log, got:\n%s", string(logData))
	}
}

func TestNftParserAcceptsColonCommentUnquoted(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed in test environment")
	}
	script := `add table inet cfm_test
add chain inet cfm_test input { type filter hook input priority 0; policy accept; }
add rule inet cfm_test input tcp dport 12082 ct state new accept comment cfm_cpanel_dnat:12082`
	out := runOut("sh", "-c", "printf '%s\n' \""+strings.ReplaceAll(script, "\"", "\\\"")+"\" | nft -c -f -")
	if strings.Contains(strings.ToLower(out), "error") {
		t.Fatalf("nft parser rejected unquoted comment: %s", out)
	}
}

func TestParseManagedRuleLine_MatchesUnquotedCommentForRemoval(t *testing.T) {
	port, handle, ok := parseManagedRuleLine(`tcp dport 12082 ct state new accept comment cfm_cpanel_dnat:12082 # handle 44`)
	if !ok || port != "12082" || handle != "44" {
		t.Fatalf("unexpected parse for unquoted comment: ok=%v port=%s handle=%s", ok, port, handle)
	}
}
