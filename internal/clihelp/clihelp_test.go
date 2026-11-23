package clihelp

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
)

func TestIsHelpArg(t *testing.T) {
	for _, s := range []string{"-h", "--help", "help"} {
		if !IsHelpArg(s) {
			t.Errorf("IsHelpArg(%q) = false", s)
		}
	}
	for _, s := range []string{"", "h", "-help", "HELP", "--h", "helps", "-- help"} {
		if IsHelpArg(s) {
			t.Errorf("IsHelpArg(%q) = true", s)
		}
	}
}

func TestFirstAnySub(t *testing.T) {
	cases := []struct {
		args            []string
		first, any, sub bool
	}{
		{nil, false, false, false},
		{[]string{"--help"}, true, true, true},
		{[]string{"help"}, true, true, true},
		{[]string{"add", "--help"}, false, true, true},
		{[]string{"add", "help"}, false, true, true},
		{[]string{"add", "x.com", "help"}, false, true, true},
		{[]string{"add", "x.com", "--reason", "help"}, false, true, false}, // a flag's value
		{[]string{"add", "x.com", "--ttl=1h", "help"}, false, true, true},
		{[]string{"add", "x.com", "--help"}, false, true, true}, // a flag is a flag anywhere
		{[]string{"add", "x.com", "-h"}, false, true, true},
		{[]string{"add", "--", "--help"}, false, false, false}, // after "--" nothing is a flag
		{[]string{"add", "x.com", "--reason", "nothing"}, false, false, false},
	}
	for _, c := range cases {
		if got := First(c.args); got != c.first {
			t.Errorf("First(%q) = %v, want %v", c.args, got, c.first)
		}
		if got := Any(c.args); got != c.any {
			t.Errorf("Any(%q) = %v, want %v", c.args, got, c.any)
		}
		if got := Sub(c.args); got != c.sub {
			t.Errorf("Sub(%q) = %v, want %v", c.args, got, c.sub)
		}
	}
}

func TestNoArgs(t *testing.T) {
	const usage = "usage: cfm thing"
	for _, h := range []string{"-h", "--help", "help"} {
		var out, errb bytes.Buffer
		rc, done := NoArgsTo(&out, &errb, "thing", usage, []string{h})
		if !done || rc != 0 || !strings.Contains(out.String(), usage) || errb.Len() != 0 {
			t.Errorf("%s: rc=%d done=%v out=%q err=%q", h, rc, done, out.String(), errb.String())
		}
	}
	var out, errb bytes.Buffer
	rc, done := NoArgsTo(&out, &errb, "thing", usage, []string{"--force"})
	if !done || rc != 2 || out.Len() != 0 || !strings.Contains(errb.String(), `unexpected argument "--force"`) {
		t.Errorf("other arg: rc=%d done=%v out=%q err=%q", rc, done, out.String(), errb.String())
	}
	if rc, done := NoArgsTo(&out, &errb, "thing", usage, nil); done || rc != 0 {
		t.Errorf("no arg: rc=%d done=%v, want the caller to go on", rc, done)
	}
}

// Parse refuses what the flag package leaves over: `kernsec apply help` read
// as `kernsec apply` with every default.
func TestParse(t *testing.T) {
	newFS := func(out io.Writer) (*flag.FlagSet, *bool) {
		fs := flag.NewFlagSet("apply", flag.ContinueOnError)
		fs.SetOutput(out)
		return fs, fs.Bool("dry-run", false, "")
	}
	for _, args := range [][]string{{"help"}, {"--dry-run", "help"}, {"-h"}, {"--help"}, {"--dry-run", "x", "--help"}} {
		var out bytes.Buffer
		fs, _ := newFS(&out)
		if err := Parse(fs, args); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("Parse(%q) = %v, want flag.ErrHelp", args, err)
		}
		if !strings.Contains(out.String(), "dry-run") {
			t.Errorf("Parse(%q) printed no usage: %q", args, out.String())
		}
	}
	fs, _ := newFS(io.Discard)
	if err := Parse(fs, []string{"now"}); !errors.Is(err, ErrUnexpectedArgs) {
		t.Errorf("Parse(now) = %v, want ErrUnexpectedArgs", err)
	}
	fs, dry := newFS(io.Discard)
	if err := Parse(fs, []string{"--dry-run"}); err != nil || !*dry {
		t.Errorf("Parse(--dry-run) = %v, dry=%v", err, *dry)
	}
}
