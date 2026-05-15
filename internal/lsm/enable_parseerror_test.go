//go:build linux

package lsm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunEnable_ParseErrorIsSurfacedNotMasked is a regression test for
// the bug spotted on the EL9 host: enable was swallowing the parse
// error from loadStatusConf and proceeding against DefaultConf
// (every policy DefaultMode=ModeDisabled), which then surfaced as
// the misleading "every policy has mode=disabled" error.
//
// The new behaviour: surface the parse error and refuse to proceed.
// We can't fully exercise RunEnable (it needs root + a real kernel)
// but we can run the entry point through to the conf check and
// assert the right message comes out before the privilege gate.
func TestRunEnable_ParseErrorIsSurfacedNotMasked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("RunEnable returns early on non-root before reaching the conf check; this test requires root")
	}
	// Skip when this runner can't pass preflight — RunEnable bails on
	// the preflight FAIL path before getting to the conf check we want
	// to exercise. The check itself is straightforward enough that
	// hosts which CAN run BPF LSM will exercise it cleanly.
	if !RunPreflight().OK {
		t.Skip("preflight FAIL on this host; cannot reach the conf-check path")
	}

	tmp := t.TempDir()
	conf := filepath.Join(tmp, "lsm.conf")
	// Garbage that ParseConf rejects: unknown [allow] key — the same
	// shape that bit the live host (allow_script_prefix appended to
	// a conf parsed by a binary that didn't yet know the key).
	if err := os.WriteFile(conf, []byte(
		"enabled = true\n[allow]\nallow_made_up_key = /nope\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := ConfPath
	ConfPath = conf
	t.Cleanup(func() { ConfPath = saved })

	var buf bytes.Buffer
	rc := RunEnable(&buf, EnableOptions{AssumeYes: true})
	if rc == 0 {
		t.Errorf("expected non-zero rc on parse error; got 0, output:\n%s", buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "Could not parse") {
		t.Errorf("expected 'Could not parse' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "allow_made_up_key") {
		t.Errorf("expected the unknown-key name in error message, got:\n%s", out)
	}
	if strings.Contains(out, "every policy in") && strings.Contains(out, "mode=disabled") {
		t.Errorf("regression: enable fell through to the misleading 'mode=disabled' message:\n%s", out)
	}
}
