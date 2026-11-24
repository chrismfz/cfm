package status

import (
	"os"
	"testing"

	"cfm/internal/firewall"
)

// trapBackend fails the test on any backend call (nil embedded Backend).
type trapBackend struct{ firewall.Backend }

// `cfm status help` ran the whole status (the flag parse stopped at "help");
// a leading help word prints the usage and reads nothing from nft.
func TestRunHelpWordsReadNothing(t *testing.T) {
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()
	for _, h := range []string{"-h", "--help", "help"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("status %s: backend called: %v", h, r)
				}
			}()
			Run([]string{h}, trapBackend{})
		}()
	}
}
