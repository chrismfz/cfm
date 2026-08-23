package detconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSectionsSemantics(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "detectors.conf")
	content := `# leading comment
[global]
DETECT_EVERY = 30s

[postfix_security]
ENABLED = 0
LOG_PATH = "/var/log/mail log with space.log"   ; inline comment

[exim_queues]
QUERY_RULES =
    db1 : 30s : notify
    ; comment inside block
    db2 : max=10 : reap

[mysql:special]
EVERY = 1m
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _, err := ReadSections(p)
	if err != nil {
		t.Fatal(err)
	}

	if got := s.Global["DETECT_EVERY"]; got != "30s" {
		t.Errorf("global key = %q", got)
	}
	ps := s.ByName["postfix_security"]
	if ps["ENABLED"] != "0" {
		t.Errorf("ENABLED = %q", ps["ENABLED"])
	}
	// NOTE the structural reader keeps the raw value minus outer-trimmed
	// quote characters (leading one here; inline-comment cutting is a
	// downstream reader's job — registry.go cleanScalar / kvLines).
	if want := `/var/log/mail log with space.log"   ; inline comment`; ps["LOG_PATH"] != want {
		t.Errorf("LOG_PATH = %q want %q", ps["LOG_PATH"], want)
	}
	lines := strings.Split(s.ByName["exim_queues"]["QUERY_RULES"], "\n")
	if len(lines) != 3 {
		t.Errorf("multiline continuation lost lines: %q", lines)
	}
	typ, inst := SplitTypeInstance("mysql:special")
	if typ != "mysql" || inst != "special" {
		t.Errorf("SplitTypeInstance = %q/%q", typ, inst)
	}
	if s.ByType["mysql"][0] != "mysql:special" {
		t.Errorf("ByType index wrong: %v", s.ByType["mysql"])
	}
}
