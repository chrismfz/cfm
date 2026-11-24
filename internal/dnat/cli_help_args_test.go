package dnat

import (
	"os"
	"testing"

	"cfm/internal/firewall"
)

// helpTrapBackend fails the test on any backend call (its embedded Backend is
// nil, so every method panics; the test's recover reports it).
type helpTrapBackend struct{ firewall.Backend }

// Every `cfm dnat` (and so `cfm edge on|off|panel`) command line answers -h,
// --help and help with its usage and touches no nft state.
func TestCLIHelpWordsTouchNothing(t *testing.T) {
	SetConfigDir(t.TempDir())
	t.Cleanup(func() { SetConfigDir("") })
	old, oldErr := os.Stdout, os.Stderr
	os.Stdout, _ = os.Open(os.DevNull)
	os.Stderr, _ = os.Open(os.DevNull)
	defer func() { os.Stdout, os.Stderr = old, oldErr }()

	subs := [][]string{
		{}, {"on"}, {"off"}, {"on", "--priority", "-101"},
		{"bypass"}, {"bypass", "add"}, {"bypass", "remove"}, {"bypass", "list"},
		{"cpanel"}, {"panel"}, {"cpanel", "on"}, {"cpanel", "off"}, {"cpanel", "status"},
		{"cpanel", "mode"}, {"cpanel", "priority"}, {"cpanel", "bypass", "add"}, {"panel", "on"},
		// A help word after the target: `bypass add <IP> --help` added it.
		{"bypass", "add", "198.51.100.0/24"}, {"bypass", "remove", "198.51.100.7"},
		{"cpanel", "bypass", "add", "198.51.100.0/24"}, {"cpanel", "bypass", "remove", "198.51.100.7"},
	}
	for _, h := range []string{"-h", "--help", "help"} {
		for _, s := range subs {
			args := append(append([]string{}, s...), h)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("dnat %q: backend called on a help word: %v", args, r)
					}
				}()
				if rc := RunCLI(args, helpTrapBackend{}); rc != 0 {
					t.Errorf("dnat %q: rc=%d, want 0 (usage)", args, rc)
				}
			}()
		}
	}
}
