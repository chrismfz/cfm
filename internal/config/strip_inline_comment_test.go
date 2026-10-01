package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// An inline comment is a '#' or "//" after a space or tab (or starting the
// value), outside quotes. Before 2026-10 the rule wanted TWO whitespace
// characters in front, so the usual `KEY = "262144" # note` kept the comment,
// the value failed to parse and the default applied silently; a value with
// two " #" hung the parser.
func TestStripInlineComment(t *testing.T) {
	cases := map[string]string{
		`"262144" # minimum entries`: `"262144"`,
		`1 # on`:                     `1`,
		"1\t# on":                    `1`,
		"1\t// on":                   `1`,
		`x  # c`:                     `x`,
		`a // note`:                  `a`,
		`tok #a #b`:                  `tok`,
		`# note`:                     ``,
		`// note`:                    ``,
		`http://h/p`:                 `http://h/p`,
		`a#b`:                        `a#b`,
		`a//b`:                       `a//b`,
		`"a # b" # note`:             `"a # b"`,
		`'a // b'`:                   `'a // b'`,
		`"" # e.g. "alice,bob"`:      `""`,
		`{"a": "x #y"} # note`:       `{"a": "x #y"}`,
		`"a\" # b" # note`:           `"a\" # b"`,
		`"a", "b # c" # note`:        `"a", "b # c"`,
		`x, 'y # z' # note`:          `x, 'y # z'`,
		`don't # note`:               `don't`,
		`"unclosed # note`:           `"unclosed # note`,
		`plain`:                      `plain`,
		``:                           ``,
	}
	for in, want := range cases {
		done := make(chan string, 1)
		go func() { done <- stripInlineComment(in) }()
		select {
		case got := <-done:
			if got != want {
				t.Errorf("stripInlineComment(%q) = %q, want %q", in, got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("stripInlineComment(%q) does not return", in)
		}
	}
}

// A value with a one-space inline comment now applies.
func TestParseCFMConfInlineCommentValuesApply(t *testing.T) {
	cfg, err := ParseCFMConf(strings.NewReader(strings.Join([]string{
		`SYS_CT_MIN = "300000" # minimum entries`,
		`SYS_CT_MAX = 20000000 // maximum entries`,
		`THROTTLE_MODE = "dryrun" # watch first`,
		`SSLCOLLECTOR_SOCK_ENABLE = 1 # on`,
		`MCP_TOKEN = # set me`,
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SystemTweaks.CTMin != 300000 || cfg.SystemTweaks.CTMax != 20000000 {
		t.Errorf("SYS_CT_MIN/MAX = %d/%d, want 300000/20000000", cfg.SystemTweaks.CTMin, cfg.SystemTweaks.CTMax)
	}
	if cfg.Throttle.Mode != "dryrun" {
		t.Errorf("THROTTLE_MODE = %q, want dryrun", cfg.Throttle.Mode)
	}
	if !cfg.SSLCollectorSock.Enabled {
		t.Error("SSLCOLLECTOR_SOCK_ENABLE = 1 # on parsed as disabled")
	}
	if cfg.API.MCPToken != "" {
		t.Errorf("MCP_TOKEN = # set me parsed as %q, want empty", cfg.API.MCPToken)
	}
}

// No value in the shipped configs keeps comment text: every inline comment
// there is one the parser cuts.
func TestStockConfigsValuesCarryNoComment(t *testing.T) {
	for _, name := range []string{"cfm.conf", "cfm.api.conf.example"} {
		f, err := os.Open(filepath.Join("..", "..", "configs", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		s := bufio.NewScanner(f)
		for n := 1; s.Scan(); n++ {
			line := strings.TrimSpace(s.Text())
			if line == "" || isComment(line) {
				continue
			}
			_, v, ok := splitKV(line)
			if !ok {
				continue
			}
			val := trimQuotes(stripInlineComment(strings.TrimSpace(v)))
			if strings.Contains(val, " #") || strings.Contains(val, "\t#") || strings.Contains(val, " //") || strings.Contains(val, "\t//") {
				t.Errorf("%s:%d: value %q still carries a comment", name, n, val)
			}
		}
		_ = f.Close()
	}
}
