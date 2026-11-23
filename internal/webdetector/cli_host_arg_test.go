package webdetector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateCLIHost(t *testing.T) {
	cases := []struct {
		host string
		glob bool
		ok   bool
	}{
		{"--help", false, false},
		{"--", false, false},
		{"-x", false, false},
		{"-h", false, false},
		{"www.--help", false, false},
		{"", false, false},
		{"example.com.", false, true},
		{"example.com..", false, false},
		{".", false, false},
		{"a..b", false, false},
		{"bad_host.com", false, false},
		{"host/path", false, false},
		{"ex-.com", false, false},
		{strings.Repeat("a", 64) + ".com", false, false},
		{"*.", false, false},
		{"a.*.com", false, false},
		{"example.com", false, true},
		{"www.Example-1.gr", false, true},
		{"*.example.com", false, true},
		{"localhost", false, true},
		{"shop*.example.?r", true, true},
		{"shop[12].example.gr", true, true},
		{"shop[12].example.gr", false, false},
		{"*", true, true},
		{"--help", true, false},
		{"www.--help", true, false},
	}
	for _, c := range cases {
		err := validateCLIHost(c.host, c.glob)
		if (err == nil) != c.ok {
			t.Errorf("validateCLIHost(%q, glob=%v) err=%v, want ok=%v", c.host, c.glob, err, c.ok)
		}
	}
}

// Every host-taking subcommand runs the shared check before any API call: a
// help word prints the usage and returns nil, a flag is a usage error, and
// neither reaches the daemon. The incident: `challenge add --help` armed
// challenges for "--help" and "www.--help"; `challenge remove -- --help`
// removed host "--". A command that creates state also refuses a
// non-hostname; one that reads or clears an existing record does not (it must
// still clear the incident's "www.--help", or an automatic challenge keyed on
// a Host header with an underscore).
func TestWebtopHostArgGuard(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","host":"example.com"}`))
	}))
	defer ts.Close()

	type cmd struct {
		run      func(args []string) error
		existing bool // reads/clears an existing record: only a flag is refused
	}
	chal := func(sub string, tail ...string) func([]string) error {
		return func(a []string) error {
			return runChallengeWebTop(ts.URL, append(append([]string{sub}, a...), tail...))
		}
	}
	cache := func(sub string, tail ...string) func([]string) error {
		return func(a []string) error {
			return runSiteCacheWebTop(ts.URL, append(append([]string{sub}, a...), tail...))
		}
	}
	attack := func(sub string) func([]string) error {
		return func(a []string) error { return runAttackWebTop(ts.URL, append([]string{sub}, a...)) }
	}
	cmds := map[string]cmd{
		"challenge add":            {chal("add"), false},
		"challenge tier":           {chal("tier", "v1"), false},
		"challenge lockdown":       {chal("lockdown", "on"), false},
		"challenge exclude add":    {func(a []string) error { return runChallengeWebTop(ts.URL, append([]string{"exclude", "add"}, a...)) }, false},
		"attack on":                {attack("on"), false},
		"site-cache set":           {cache("set", "--micro", "off"), false},
		"challenge remove":         {chal("remove"), true},
		"challenge status":         {chal("status"), true},
		"challenge host":           {chal("host"), true},
		"challenge exclude remove": {func(a []string) error { return runChallengeWebTop(ts.URL, append([]string{"exclude", "remove"}, a...)) }, true},
		"attack off":               {attack("off"), true},
		"site-cache get":           {cache("get"), true},
		"site-cache off":           {cache("off"), true},
		"site-cache remove":        {cache("remove"), true},
		"site-cache purge":         {cache("purge"), true},
		"site-cache stats":         {cache("stats"), true},
	}

	cases := []struct {
		name string
		args []string
		// wantErr for a create command; an existing-record command errs only
		// when flagErr.
		wantErr, flagErr bool
	}{
		{"--help", []string{"--help"}, false, false},
		{"-h", []string{"-h"}, false, false},
		{"help", []string{"help"}, false, false},
		{"--", []string{"--", "--help"}, true, true},
		{"-x", []string{"-x"}, true, true},
		{"www.--help", []string{"www.--help"}, true, false},
		{"underscore", []string{"bad_host.example"}, true, false},
	}
	for name, c := range cmds {
		for _, tc := range cases {
			calls.Store(0)
			err := c.run(tc.args)
			wantErr := tc.wantErr
			if c.existing {
				wantErr = tc.flagErr
			}
			reached := calls.Load() != 0
			switch {
			case wantErr:
				// Refused by the guard: a usage error, no API call.
				if err == nil || !strings.Contains(err.Error(), "usage:") {
					t.Errorf("%s %v: err=%v, want a usage error", name, tc.args, err)
				}
				if reached {
					t.Errorf("%s %v: reached the API", name, tc.args)
				}
			case isCLIHelpArg(tc.args[0]):
				if err != nil || reached {
					t.Errorf("%s %v: err=%v reached=%v, want usage only", name, tc.args, err, reached)
				}
			default:
				// Accepted: the call reaches the API (the fake server's
				// answer may not fit the command; that error is not ours).
				if !reached {
					t.Errorf("%s %v: accepted but never reached the API (err=%v)", name, tc.args, err)
				}
			}
		}
		// A valid host reaches the API on every command.
		calls.Store(0)
		_ = c.run([]string{"example.com"})
		if calls.Load() == 0 {
			t.Errorf("%s example.com: never reached the API", name)
		}
	}
}

// The dispatchers answer a help word with usage, without calling the API.
func TestWebtopDispatcherHelp(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()
	for _, h := range []string{"--help", "-h", "help"} {
		if err := runChallengeWebTop(ts.URL, []string{h}); err != nil {
			t.Errorf("challenge %s: %v", h, err)
		}
		if err := runAttackWebTop(ts.URL, []string{h}); err != nil {
			t.Errorf("attack %s: %v", h, err)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("help reached the API %d time(s)", n)
	}
}

// The exclude value and --scope hosts: add checks the grammar (with the
// stores' glob metacharacters), remove refuses only a flag; a --scope help
// word is a plain error, never a usage print; a path value only must not look
// like a flag.
func TestGenericExcludeHostGuard(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()
	bad := [][]string{
		{"add", "/p/", "--type", "path", "--scope", "--help"},
		{"add", "/p/", "--type", "path", "--scope", "help"},
		{"add", "/p/", "--type", "path", "--scope", "www.--help"},
		{"remove", "/p/", "--type", "path", "--scope", "--help"},
		{"add", "-x", "--type", "path"},
		{"add", "bad_host.example"},
		{"remove", "-x"},
	}
	for _, a := range bad {
		calls.Store(0)
		if err := runGenericExclude(ts.URL, "challenge", "exclude", a); err == nil {
			t.Errorf("%v: accepted", a)
		}
		if calls.Load() != 0 {
			t.Errorf("%v: reached the API", a)
		}
	}
	good := []struct {
		prefix string
		args   []string
	}{
		{"challenge", []string{"add", "/images/.tmb/", "--type", "path", "--scope", "example.gr"}},
		{"waf", []string{"add", "*.example.gr"}},
		{"waf", []string{"add", "shop[12].example.?r"}},
		{"waf", []string{"remove", "bad_host.example"}},
		{"challenge", []string{"remove", "/p/", "--type", "path", "--scope", "old_host.example"}},
	}
	for _, g := range good {
		calls.Store(0)
		if err := runGenericExclude(ts.URL, g.prefix, "exclude", g.args); err != nil {
			t.Errorf("%s %v: %v", g.prefix, g.args, err)
		}
		if calls.Load() != 1 {
			t.Errorf("%s %v: %d API calls, want 1", g.prefix, g.args, calls.Load())
		}
	}
}
