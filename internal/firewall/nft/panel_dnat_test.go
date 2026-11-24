//go:build linux

package nft

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/firewall"
)

func TestPanelDNATScriptCoversCanonicalMappings(t *testing.T) {
	script := panelDNATScript(-101)
	for _, m := range firewall.PanelDNATMappings() {
		want := fmt.Sprintf("tcp dport %d dnat to :%d", m.From, m.To)
		if !strings.Contains(script, want) {
			t.Fatalf("panel DNAT script missing %q:\n%s", want, script)
		}
	}
	if got, want := strings.Count(script, " dnat to :"), len(firewall.PanelDNATMappings()); got != want {
		t.Fatalf("panel DNAT script has %d mappings, want %d:\n%s", got, want, script)
	}
}

// PanelDNATOff reports a failed delete (it used to drop it, so `cfm edge
// panel off` returned 0 with the redirect still in place: rigel, 2026-11-23),
// and an absent table is already off.
func TestPanelDNATOffReportsAFailedDelete(t *testing.T) {
	for _, tc := range []struct {
		name, stderr string
		rc           int
		wantErr      bool
	}{
		{"deleted", "", 0, false},
		{"absent", "Error: Could not process rule: No such file or directory", 1, false},
		{"busy", "Error: Could not process rule: Device or resource busy", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			script := fmt.Sprintf("#!/bin/sh\ncat >/dev/null\n[ -n %q ] && echo %q >&2\nexit %d\n", tc.stderr, tc.stderr, tc.rc)
			if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			err := New().PanelDNATOff()
			if (err != nil) != tc.wantErr {
				t.Fatalf("PanelDNATOff() = %v, want error: %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "resource busy") {
				t.Errorf("the error must carry nft's message: %v", err)
			}
		})
	}
}
