package detconf

import (
	"bytes"
	"log"
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
	// A quoted value followed only by an inline comment reads as the text
	// between the quotes (unquoteValue). It used to keep the closing quote
	// and the comment, which the quote-aware string readers then kept too.
	if want := `/var/log/mail log with space.log`; ps["LOG_PATH"] != want {
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

func TestUnquoteValue(t *testing.T) {
	for raw, want := range map[string]string{
		`"15m"            ; stage 3 enforcement TTL (or dryrun/permanent/no)`: `15m`,
		`"15m"         ; don't spam the same alert`:                           `15m`,
		`"15m" # note`:                `15m`,
		`"15m";note`:                  `15m`,
		`"a; b"   ; note`:             `a; b`, // a ';' inside the quotes is value
		`"curl,wget,python-requests"`: `curl,wget,python-requests`,
		`""`:                          ``,
		`15m`:                         `15m`,
		`15m ; note`:                  `15m ; note`,  // unquoted: the readers strip it, as before
		`"x" trailing`:                `x" trailing`, // not quote+comment: old reading
		`"unterminated ; note`:        `unterminated ; note`,
		`"`:                           ``,
		`https://example.com/x?a="b"`: `https://example.com/x?a="b`,
	} {
		if got := unquoteValue(raw); got != want {
			t.Errorf("unquoteValue(%q) = %q, want %q", raw, got, want)
		}
	}
}

// A secret whose effective value changed with unquoteValue is named once in
// the log, never with its value; a secret that reads as before is silent.
func TestWarnSecretReadChanged(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	warnSecretReadChanged("CHALLENGE_TOKEN", `"s3cr3tvalue" ; rotated`, "s3cr3tvalue")
	warnSecretReadChanged("CHALLENGE_TOKEN", `"s3cr3tvalue" ; rotated`, "s3cr3tvalue") // once per key
	warnSecretReadChanged("OPENRESTY_TOKEN", `"plain"`, "plain")                       // unchanged: silent
	warnSecretReadChanged("BLOCK", `"15m" ; note`, "15m")                              // not a secret: silent

	out := buf.String()
	if strings.Count(out, "CHALLENGE_TOKEN") != 1 {
		t.Fatalf("want exactly one warning for CHALLENGE_TOKEN, got %q", out)
	}
	if strings.Contains(out, "s3cr3tvalue") || strings.Contains(out, "OPENRESTY_TOKEN") || strings.Contains(out, "BLOCK") {
		t.Fatalf("warning leaked a value or named a key it should not: %q", out)
	}
}
