//go:build linux

package nft

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNFTBinary puts an `nft` script first in PATH so the test never touches
// the host's ruleset. It logs every invocation in order (args, then any
// script fed on stdin) and answers `-a list chain inet cfm input` with listing.
func fakeNFTBinary(t *testing.T, listing string) (logPath string) {
	t.Helper()
	return fakeNFTBinaryFailing(t, listing, "")
}

// fakeNFTBinaryFailing is fakeNFTBinary, but a script (`nft -f -`) containing
// failOn exits 1.
func fakeNFTBinaryFailing(t *testing.T, listing, failOn string) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "nft.log")
	listPath := filepath.Join(dir, "listing")
	if err := os.WriteFile(listPath, []byte(listing), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "ARGS $*" >> %[1]q
if [ "$1" = "-f" ]; then
	in=$(cat); printf '%%s\n' "$in" >> %[1]q
	if [ -n %[3]q ] && printf '%%s' "$in" | grep -qF %[3]q; then exit 1; fi
	exit 0
fi
if [ "$*" = "-a list chain inet cfm input" ]; then cat %[2]q; exit 0; fi
exit 0
`, logPath, listPath, failOn)
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// DNATOff removes the redirect table before the accepts (removed first, a
// redirect that then failed to go would drop every web connection at the
// default drop), and removes both engines' web accept tags.
func TestDNATOff_RemovesTheRedirectBeforeItsAccepts(t *testing.T) {
	log := fakeNFTBinary(t, `table inet cfm {
	chain input { # handle 1
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080" # handle 21
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_edge_dnat_accept:web_http_tcp:80:9080" # handle 22
		tcp dport 12083 ct state new ct status dnat ct original proto-dst 2083 accept comment "cfm_cpanel_dnat:2083:12083" # handle 23
	}
}
`)
	if err := New().DNATOff("inet", "cfm_redirect"); err != nil {
		t.Fatalf("DNATOff: %v", err)
	}
	b, err := os.ReadFile(log) // #nosec G304 -- test temp file
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	table := strings.Index(got, "delete table inet cfm_redirect")
	rule := strings.Index(got, "delete rule inet cfm input handle")
	if table < 0 || rule < 0 || table > rule {
		t.Fatalf("want the table deleted first, then the accepts:\n%s", got)
	}
	for _, h := range []string{"21", "22"} {
		if !strings.Contains(got, "delete rule inet cfm input handle "+h) {
			t.Errorf("web accept handle %s not removed:\n%s", h, got)
		}
	}
	if strings.Contains(got, "handle 23") {
		t.Errorf("removed the panel accept:\n%s", got)
	}
}

// Once the redirect is gone its accepts match nothing, so a failed cleanup
// must not fail DNATOff: `cfm dnat off` would then skip persisting intent
// OFF, and the daemon's failsafe would turn DNAT back on.
func TestDNATOff_LeftoverAcceptsAreNotAnError(t *testing.T) {
	log := fakeNFTBinaryFailing(t, `table inet cfm {
	chain input { # handle 1
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080" # handle 21
	}
}
`, "delete rule")
	if err := New().DNATOff("inet", "cfm_redirect"); err != nil {
		t.Fatalf("DNATOff: %v; a leftover accept is inert once the redirect is gone", err)
	}
	b, _ := os.ReadFile(log) // #nosec G304 -- test temp file
	if got := string(b); !strings.Contains(got, "delete table inet cfm_redirect") || !strings.Contains(got, "delete rule inet cfm input handle 21") {
		t.Fatalf("want the table deleted and the accept delete attempted:\n%s", got)
	}
}
