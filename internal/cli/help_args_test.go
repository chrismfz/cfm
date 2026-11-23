package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"cfm/internal/clihttp"
	"cfm/internal/firewall"
	"cfm/internal/ttlban"
)

// trapBackend fails the test on any backend call: its embedded Backend is nil,
// so every method panics, and runTrapped turns the panic into the failure.
type trapBackend struct{ firewall.Backend }

// captureStdio runs fn with os.Stdout and os.Stderr redirected and returns
// what each received.
func captureStdio(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, _ := os.Pipe()
	re, we, _ := os.Pipe()
	os.Stdout, os.Stderr = wo, we
	outc, errc := make(chan string), make(chan string)
	go func() { b, _ := io.ReadAll(ro); outc <- string(b) }()
	go func() { b, _ := io.ReadAll(re); errc <- string(b) }()
	defer func() {
		os.Stdout, os.Stderr = oldOut, oldErr
	}()
	fn()
	wo.Close()
	we.Close()
	return <-outc, <-errc
}

// apiTrap is an httptest server that counts every request: a help word must
// make none.
func apiTrap(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		t.Errorf("API call on a help word: %s %s", r.Method, r.URL)
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

// Every internal/cli command prints its usage for -h, --help and help and
// does nothing else: no backend call (so nothing changes in nft), no table
// probe, no API call, no file under the config dir or /var/lib/cfm. Found
// 2026-11-23: `cfm reset --help` emptied table inet cfm, `cfm disable --help`
// deleted it, `cfm flush --help` freed every TTL ban.
func TestCLIHelpWordsPrintUsageAndDoNothing(t *testing.T) {
	srv, calls := apiTrap(t)
	defer func(old string) { EdgeBanBaseURL = old }(EdgeBanBaseURL)
	EdgeBanBaseURL = srv.URL
	clihttp.SetToken("test")
	stateFile := filepath.Join(t.TempDir(), "ttlbans.json")
	if err := os.WriteFile(stateFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer ttlban.SetPathForTest(stateFile)()

	type cmd struct {
		name   string
		prefix []string // the subcommand words before the help word
		usage  string   // what the usage must contain
		run    func(args []string, be firewall.Backend, cfgDir string, probe func() bool) int
	}
	cmds := []cmd{
		{"reset", nil, "usage: cfm reset", func(a []string, be firewall.Backend, _ string, _ func() bool) int { return RunReset(a, be) }},
		{"disable", nil, "usage: cfm disable", func(a []string, be firewall.Backend, _ string, _ func() bool) int { return RunDisable(a, be) }},
		{"flush", nil, "usage: cfm flush", func(a []string, be firewall.Backend, _ string, p func() bool) int { return RunFlush(a, be, p) }},
		{"block", nil, "usage: cfm block", RunBlock},
		{"unblock", nil, "usage: cfm unblock", RunUnblock},
		{"allow", nil, "usage: cfm allow", RunAllow},
		{"unallow", nil, "usage: cfm unallow", RunUnallow},
		{"list", nil, "usage: cfm list", func(a []string, be firewall.Backend, _ string, p func() bool) int { return RunList(a, be, p) }},
		{"allow-list", nil, "usage: cfm allow-list", func(a []string, be firewall.Backend, _ string, p func() bool) int { return RunAllowList(a, be, p) }},
		{"which", nil, "usage: cfm which", func(a []string, be firewall.Backend, d string, p func() bool) int { return RunWhich(a, be, d, srv.URL, p) }},
		{"asn", nil, "usage: cfm asn", func(a []string, _ firewall.Backend, _ string, _ func() bool) int { return RunASN(a) }},
		{"htpasswd", nil, "usage: cfm htpasswd", func(a []string, _ firewall.Backend, _ string, _ func() bool) int { return RunHtpasswd(a) }},
		{"test", nil, "usage: cfm test", func(a []string, _ firewall.Backend, _ string, _ func() bool) int { return RunTest(a) }},
		{"clam", nil, "cfm clam status", func(a []string, _ firewall.Backend, d string, _ func() bool) int { return RunClam(a, d) }},
		{"firewall", nil, "usage: cfm firewall", func(a []string, be firewall.Backend, d string, _ func() bool) int {
			return RunFirewall(a, be, d, "nft", "test")
		}},
		{"firewall status", []string{"status"}, "usage: cfm firewall status", func(a []string, be firewall.Backend, d string, _ func() bool) int {
			return RunFirewall(a, be, d, "nft", "test")
		}},
		{"firewall path", []string{"path"}, "usage: cfm firewall path", func(a []string, be firewall.Backend, d string, _ func() bool) int {
			return RunFirewall(a, be, d, "nft", "test")
		}},
	}
	// The clam subcommands that write cfm.conf (clam enable --help rewrote it).
	for _, sub := range [][]string{{"enable"}, {"disable"}, {"hook", "enable"}, {"hook", "disable"}, {"scan", "on"}, {"scan", "off"}, {"mode", "inline"}, {"scope", "all"}, {"status"}} {
		cmds = append(cmds, cmd{"clam " + strings.Join(sub, " "), sub, "cfm clam status", func(a []string, _ firewall.Backend, d string, _ func() bool) int { return RunClam(a, d) }})
	}

	for _, c := range cmds {
		for _, h := range []string{"-h", "--help", "help"} {
			c, h := c, h
			t.Run(c.name+" "+h, func(t *testing.T) {
				cfgDir := t.TempDir()
				conf := filepath.Join(cfgDir, "cfm.conf")
				if err := os.WriteFile(conf, []byte("CLAMD_ENABLED = false\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				probe := func() bool { t.Errorf("table probe on a help word"); return true }
				args := append(append([]string{}, c.prefix...), h)
				var rc int
				out, errOut := captureStdio(t, func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("backend called on a help word: %v", r)
						}
					}()
					rc = c.run(args, trapBackend{}, cfgDir, probe)
				})
				if rc != 0 {
					t.Errorf("rc=%d, want 0\nstdout: %s\nstderr: %s", rc, out, errOut)
				}
				if !strings.Contains(out+errOut, c.usage) {
					t.Errorf("no usage (%q) in output\nstdout: %s\nstderr: %s", c.usage, out, errOut)
				}
				if b, _ := os.ReadFile(conf); string(b) != "CLAMD_ENABLED = false\n" {
					t.Errorf("cfm.conf changed: %q", b)
				}
				if ents, _ := os.ReadDir(cfgDir); len(ents) != 1 {
					t.Errorf("config dir written: %v", ents)
				}
				if _, err := os.Stat(stateFile); err != nil {
					t.Errorf("the saved TTL bans are gone: %v", err)
				}
			})
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d API call(s) on help words", n)
	}
}

// reset, disable and flush take no argument: anything else is refused, never
// run (they used to ignore their args).
func TestCLINoArgCommandsRefuseArguments(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "ttlbans.json")
	defer ttlban.SetPathForTest(stateFile)()
	run := map[string]func([]string) int{
		"reset":   func(a []string) int { return RunReset(a, trapBackend{}) },
		"disable": func(a []string) int { return RunDisable(a, trapBackend{}) },
		"flush":   func(a []string) int { return RunFlush(a, trapBackend{}, func() bool { return true }) },
	}
	for name, fn := range run {
		for _, args := range [][]string{{"now"}, {"--force"}, {"-y"}, {"--", "--help"}} {
			var rc int
			_, errOut := captureStdio(t, func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s %q: backend called: %v", name, args, r)
					}
				}()
				rc = fn(args)
			})
			if rc != 2 || !strings.Contains(errOut, fmt.Sprintf("%s: unexpected argument", name)) {
				t.Errorf("%s %q: rc=%d stderr=%q, want 2 and an unexpected-argument error", name, args, rc, errOut)
			}
		}
	}
}
