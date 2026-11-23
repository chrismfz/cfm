package webdetector

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// muteStdout runs fn with os.Stdout discarded (the usage texts).
func muteStdout(t *testing.T, fn func()) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, r); close(done) }()
	os.Stdout = w
	defer func() {
		os.Stdout = old
		w.Close()
		<-done
	}()
	fn()
}

// Every `cfm webtop`, `cfm bots` and API-backed `cfm clam` command line
// answers -h, --help and help with its usage and makes no API call. Found
// 2026-11-23 (the survey after `webtop challenge add --help`): `bots block
// --help` installed an emergency rule for UA "--help", `webtop history prune
// --help` pruned 30 days, `waf clear`, `http3 enable|disable`, `rules remove`,
// `challenge-access remove` and `tokens revoke` POSTed with "--help" as the
// target, `clam sigignore add help` added the pattern "help", and the views
// (`analyze`, `ip`, `source`, …) fetched "--help".
func TestCLIHelpWordsMakeNoAPICall(t *testing.T) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		t.Errorf("API call on a help word: %s %s", r.Method, r.URL)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	webtop := [][]string{
		{}, {"analyze"}, {"hot"}, {"ip-top"}, {"text"}, {"long"}, {"live"}, {"source"}, {"user-info"},
		{"ip"}, {"ips"}, {"top"}, {"example.com"},
		{"challenge"}, {"challenge", "add"}, {"challenge", "remove"}, {"challenge", "status"},
		{"challenge", "tier"}, {"challenge", "lockdown"}, {"challenge", "exclude"}, {"challenge", "events"},
		{"challenge", "host"},
		{"attack"}, {"attack", "on"}, {"attack", "off"},
		{"waf"}, {"waf", "set"}, {"waf", "clear"}, {"waf", "status"}, {"waf", "profiles"},
		{"waf", "exclude"}, {"waf", "engine"}, {"waf", "rules"}, {"waf", "hit-rates"},
		{"rules"}, {"rules", "list"}, {"rules", "get"}, {"rules", "add"}, {"rules", "update"},
		{"rules", "remove"}, {"rules", "simulate"}, {"rules", "export"}, {"rules", "import"},
		{"http3"}, {"http3", "list"}, {"http3", "enable"}, {"http3", "disable"},
		{"challenge-access"}, {"challenge-access", "get"}, {"challenge-access", "add"},
		{"challenge-access", "update"}, {"challenge-access", "remove"}, {"challenge-access", "simulate"},
		{"site-cache"}, {"site-cache", "get"}, {"site-cache", "set"}, {"site-cache", "off"},
		{"site-cache", "remove"}, {"site-cache", "purge"}, {"site-cache", "stats"},
		{"history"}, {"history", "events"}, {"history", "summary"}, {"history", "outcomes"},
		{"history", "prune"}, {"history", "truncate"}, {"history", "waf-by-rule"}, {"history", "overview"},
		{"tokens"}, {"tokens", "list"}, {"tokens", "create"}, {"tokens", "revoke"}, {"tokens", "me"},
		{"clam"}, {"clam", "override"}, {"clam", "override", "add"}, {"clam", "sigignore"},
		{"clam", "sigignore", "add"}, {"clam", "sigignore", "remove"}, {"clam", "infections"},
	}
	bots := [][]string{{}, {"top"}, {"list"}, {"drill"}, {"block"}, {"throttle"}, {"remove"}, {"live"}}
	clamAPI := map[string]func(string, []string) error{
		"override":   RunClamOverride,
		"mode":       RunClamMode,
		"sigignore":  RunClamSigIgnore,
		"infections": RunClamInfections,
	}
	clamSubs := [][]string{{}, {"add"}, {"remove"}, {"list"}}

	check := func(label string, err error) {
		t.Helper()
		if err != nil && !strings.Contains(err.Error(), "usage") {
			t.Errorf("%s: err=%v, want the usage", label, err)
		}
		if n := calls.Swap(0); n != 0 {
			t.Errorf("%s: %d API call(s)", label, n)
		}
	}
	muteStdout(t, func() {
		for _, h := range []string{"-h", "--help", "help"} {
			for _, p := range webtop {
				args := append(append([]string{}, p...), h)
				check("webtop "+strings.Join(args, " "), RunWebTop(ts.URL, args))
			}
			for _, p := range bots {
				args := append(append([]string{}, p...), h)
				check("bots "+strings.Join(args, " "), RunBots(ts.URL, args))
			}
			for name, fn := range clamAPI {
				for _, p := range clamSubs {
					args := append(append([]string{}, p...), h)
					check("clam "+name+" "+strings.Join(args, " "), fn(ts.URL, args))
				}
			}
		}
		// A help flag later on the line is still a help request
		// (`history prune --days 7 --help` pruned).
		for _, args := range [][]string{
			{"history", "prune", "--days", "7", "--help"},
			{"history", "prune", "--days", "7", "help"},
			{"waf", "clear", "example.com", "help"},
			{"http3", "enable", "example.com", "help"},
			{"tokens", "revoke", "abc", "help"},
			// The families that answer their own help: a trailing help word
			// armed, removed or purged the host it followed.
			{"challenge", "add", "example.com", "--help"},
			{"challenge", "add", "example.com", "--ttl", "30m", "help"},
			{"challenge", "remove", "example.com", "--help"},
			{"challenge", "tier", "example.com", "v2", "-h"},
			{"attack", "on", "example.com", "--help"},
			{"site-cache", "set", "example.com", "--micro", "off", "--help"},
			{"site-cache", "purge", "example.com", "--help"},
			{"site-cache", "off", "example.com", "help"},
			{"rules", "remove", "5", "--help"},
			{"challenge-access", "remove", "5", "help"},
			{"waf", "exclude", "add", "/p/", "--help"},
			{"waf", "clear", "example.com", "--help"},
			{"bots", "block", "curl", "--ttl", "30m", "-h"},
		} {
			if args[0] == "bots" {
				check(strings.Join(args, " "), RunBots(ts.URL, args[1:]))
				continue
			}
			check("webtop "+strings.Join(args, " "), RunWebTop(ts.URL, args))
		}
	})
}
