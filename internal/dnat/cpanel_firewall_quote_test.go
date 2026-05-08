package dnat

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	if !strings.Contains(string(logData), `comment "cfm_cpanel_dnat:2082:12082"`) {
		t.Fatalf("expected quoted comment token in nft command log, got:\n%s", string(logData))
	}
}

func TestNftParserAcceptsColonCommentQuotedCanonical(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed in test environment")
	}
	script := `add table inet cfm_test
add chain inet cfm_test input { type filter hook input priority 0; policy accept; }
add rule inet cfm_test input tcp dport 12082 ct state new accept comment "cfm_cpanel_dnat:2082:12082"`
	out := runOut("sh", "-c", "printf '%s\n' \""+strings.ReplaceAll(script, "\"", "\\\"")+"\" | nft -c -f -")
	if strings.Contains(strings.ToLower(out), "error") {
		t.Fatalf("nft parser rejected quoted comment: %s", out)
	}
}

func TestEnsureNftPorts_DoesNotEmitUnquotedManagedCommentToken(t *testing.T) {
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

	if _, err := ensureNftPorts(); err != nil {
		t.Fatalf("ensureNftPorts failed: %v", err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read nft log: %v", err)
	}

	// Regression: managed comment values containing ':' must be quoted in generated argv.
	unquotedManaged := regexp.MustCompile(`(^|\s)comment cfm_cpanel_dnat:\d+:\d+(\s|$)`)
	if unquotedManaged.Match(logData) {
		t.Fatalf("found unquoted managed comment token in nft command log:\n%s", string(logData))
	}
}

func TestParseManagedRuleLine_MatchesUnquotedCommentForRemoval(t *testing.T) {
	port, handle, ok := parseManagedRuleLine(`ct state new ct status dnat ct original proto-dst 2082 tcp dport 12082 accept comment cfm_cpanel_dnat:2082:12082 # handle 44`)
	if !ok || port != "2082:12082" || handle != "44" {
		t.Fatalf("unexpected parse for unquoted comment: ok=%v port=%s handle=%s", ok, port, handle)
	}
}
