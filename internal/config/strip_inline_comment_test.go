package config

import (
	"testing"
	"time"
)

// A value with two " #" (or " //") used to hang ParseCFMConf: the scan for
// the next one found the same one forever. The rule itself is unchanged: a
// comment is cut only when its " #" / " //" follows whitespace (or starts the
// value).
func TestStripInlineCommentTerminates(t *testing.T) {
	cases := map[string]string{
		"tok #a #b":       "tok #a #b",
		"tok #a  #b":      "tok #a",
		"a //b //c":       "a //b //c",
		"a //b\t //c":     "a //b",
		"x  # c":          "x",
		"x # c":           "x # c",
		"http://h/p":      "http://h/p",
		" # only comment": "",
		"plain":           "plain",
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
