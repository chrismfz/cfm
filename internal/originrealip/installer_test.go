package originrealip

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The two edge installers run `cfm realip fix` through ensure_origin_realip and
// must never fail the install over it: the edge works either way. This runs the
// function from each script against a fake cfm.
func TestInstallersEnsureOriginRealIP(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	fnRe := regexp.MustCompile(`(?ms)^ensure_origin_realip\(\) \{.*?^\}\n`)
	for _, script := range []string{"install-angie.sh", "install-openresty.sh"} {
		src, err := os.ReadFile(filepath.Join("..", "..", "scripts", script))
		if err != nil {
			t.Fatal(err)
		}
		fn := fnRe.Find(src)
		if fn == nil {
			t.Fatalf("%s: no ensure_origin_realip function", script)
		}
		if !regexp.MustCompile(`(?m)^\s+ensure_origin_realip$`).Match(src) {
			t.Fatalf("%s: main never calls ensure_origin_realip", script)
		}

		cases := []struct {
			name    string
			cfmRC   string // "" = no cfm on PATH
			env     string
			want    string
			wantRun bool
		}{
			{"trusted", "0", "", "making the origin trust", true},
			{"manual step / failure", "1", "", "not set automatically", true},
			{"old cfm without the command", "2", "", "has no 'realip' command", true},
			{"cfm not installed", "", "", "cfm is not installed yet", false},
			{"skipped", "0", "CFM_SKIP_REALIP=1", "skipped", false},
		}
		for _, c := range cases {
			bin := t.TempDir()
			marker := filepath.Join(bin, "ran")
			if c.cfmRC != "" {
				fake := "#!/bin/sh\necho \"$@\" > " + marker + "\nexit " + c.cfmRC + "\n"
				if err := os.WriteFile(filepath.Join(bin, "cfm"), []byte(fake), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			prog := "set -euo pipefail\nlog() { echo \"[+] $*\"; }\nwarn() { echo \"[!] $*\"; }\n" + string(fn) + "ensure_origin_realip\necho END\n"
			bash, _ := exec.LookPath("bash")
			cmd := exec.Command(bash, "-c", prog)
			// PATH holds the fake cfm (if any) and nothing else: the function
			// uses only shell builtins, and a host's own /usr/bin/cfm must never
			// run `realip fix` from a test (it rewrites the web server config).
			cmd.Env = []string{"PATH=" + bin}
			if c.env != "" {
				cmd.Env = append(cmd.Env, c.env)
			}
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "END") {
				t.Errorf("%s/%s: the install must go on: err=%v\n%s", script, c.name, err, out)
				continue
			}
			if !strings.Contains(string(out), c.want) {
				t.Errorf("%s/%s: output lacks %q:\n%s", script, c.name, c.want, out)
			}
			b, _ := os.ReadFile(marker)
			if ran := strings.TrimSpace(string(b)) == "realip fix"; ran != c.wantRun {
				t.Errorf("%s/%s: ran `cfm realip fix` = %v, want %v", script, c.name, ran, c.wantRun)
			}
		}
	}
}
