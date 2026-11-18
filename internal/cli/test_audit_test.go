package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `cfm config test` names a known key whose value the daemon ignores (a moved
// SSLCOLLECTOR_SOCK_PATH) instead of reporting the file OK; the stock line,
// quoted or with an inline comment, is fine.
func TestAuditCFMConfigReportsIgnoredValues(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "cfm.conf")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	rep, err := auditCFMConfig(write("SSLCOLLECTOR_SOCK_PATH = /run/other.sock\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.IgnoredValues) != 1 || !strings.Contains(rep.IgnoredValues[0], "line 1") || !strings.Contains(rep.IgnoredValues[0], "/run/other.sock is ignored") {
		t.Fatalf("IgnoredValues = %q", rep.IgnoredValues)
	}

	for _, ok := range []string{
		"SSLCOLLECTOR_SOCK_PATH = /var/run/sslcollector.sock\n",
		"SSLCOLLECTOR_SOCK_PATH = \"/var/run/sslcollector.sock\"\n",
		"SSLCOLLECTOR_SOCK_PATH = /var/run/sslcollector.sock # stock\n",
	} {
		rep, err := auditCFMConfig(write(ok))
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.IgnoredValues) != 0 {
			t.Errorf("%q: IgnoredValues = %q, want none", ok, rep.IgnoredValues)
		}
	}
}
