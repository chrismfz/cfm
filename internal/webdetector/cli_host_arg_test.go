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
// help word prints the usage and returns nil, a bad host is a usage error, and
// neither reaches the daemon. The incident: `challenge add --help` armed
// challenges for "--help" and "www.--help"; `challenge remove -- --help`
// removed host "--".
func TestWebtopHostArgGuard(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","host":"example.com"}`))
	}))
	defer ts.Close()

	cmds := map[string]func(args []string) error{
		"challenge add":    func(a []string) error { return runChallengeWebTop(ts.URL, append([]string{"add"}, a...)) },
		"challenge remove": func(a []string) error { return runChallengeWebTop(ts.URL, append([]string{"remove"}, a...)) },
		"challenge status": func(a []string) error { return runChallengeWebTop(ts.URL, append([]string{"status"}, a...)) },
		"challenge host":   func(a []string) error { return runChallengeWebTop(ts.URL, append([]string{"host"}, a...)) },
		"challenge tier": func(a []string) error {
			return runChallengeWebTop(ts.URL, append([]string{"tier"}, append(a, "v1")...))
		},
		"challenge lockdown": func(a []string) error {
			return runChallengeWebTop(ts.URL, append([]string{"lockdown"}, append(a, "on")...))
		},
		"challenge exclude add": func(a []string) error {
			return runChallengeWebTop(ts.URL, append([]string{"exclude", "add"}, a...))
		},
		"attack on":         func(a []string) error { return runAttackWebTop(ts.URL, append([]string{"on"}, a...)) },
		"attack off":        func(a []string) error { return runAttackWebTop(ts.URL, append([]string{"off"}, a...)) },
		"site-cache get":    func(a []string) error { return runSiteCacheWebTop(ts.URL, append([]string{"get"}, a...)) },
		"site-cache set":    func(a []string) error { return runSiteCacheWebTop(ts.URL, append([]string{"set"}, a...)) },
		"site-cache off":    func(a []string) error { return runSiteCacheWebTop(ts.URL, append([]string{"off"}, a...)) },
		"site-cache remove": func(a []string) error { return runSiteCacheWebTop(ts.URL, append([]string{"remove"}, a...)) },
		"site-cache purge":  func(a []string) error { return runSiteCacheWebTop(ts.URL, append([]string{"purge"}, a...)) },
	}

	cases := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"--help", []string{"--help"}, false},
		{"-h", []string{"-h"}, false},
		{"help", []string{"help"}, false},
		{"--", []string{"--", "--help"}, true},
		{"-x", []string{"-x"}, true},
		{"www.--help", []string{"www.--help"}, true},
		{"underscore", []string{"bad_host.example"}, true},
	}
	for cmd, run := range cmds {
		for _, c := range cases {
			calls.Store(0)
			err := run(c.args)
			if (err != nil) != c.wantErr {
				t.Errorf("%s %v: err=%v, wantErr=%v", cmd, c.args, err, c.wantErr)
			}
			if c.wantErr && err != nil && !strings.Contains(err.Error(), "usage:") {
				t.Errorf("%s %v: error %q carries no usage line", cmd, c.args, err)
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("%s %v: reached the API %d time(s)", cmd, c.args, n)
			}
		}
	}

	// A valid host still reaches the API.
	for _, cmd := range []string{"challenge add", "challenge remove", "site-cache purge", "attack off"} {
		calls.Store(0)
		_ = cmds[cmd]([]string{"example.com"})
		if calls.Load() == 0 {
			t.Errorf("%s example.com: never reached the API", cmd)
		}
	}
}

// The exclude --scope host goes through the same check; a path value only
// must not look like a flag.
func TestGenericExcludeHostGuard(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()
	bad := [][]string{
		{"add", "/p/", "--type", "path", "--scope", "--help"},
		{"add", "/p/", "--type", "path", "--scope", "www.--help"},
		{"add", "-x", "--type", "path"},
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
	calls.Store(0)
	if err := runGenericExclude(ts.URL, "challenge", "exclude", []string{"add", "/images/.tmb/", "--type", "path", "--scope", "example.gr"}); err != nil {
		t.Fatalf("valid path exclude: %v", err)
	}
	if err := runGenericExclude(ts.URL, "waf", "exclude", []string{"add", "*.example.gr"}); err != nil {
		t.Fatalf("valid wildcard host exclude: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("valid excludes: %d API calls, want 2", calls.Load())
	}
}
