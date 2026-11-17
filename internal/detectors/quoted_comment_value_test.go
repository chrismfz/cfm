package detectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// `KEY = "value" ; comment` must read as the value for every reader. The
// stock [cfm_endpoints] BLOCK = "15m" ; … read as block mode "no" (the
// string reader kept the comment), so the detector never banned.
func TestQuotedValueWithInlineCommentReadsAsValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "detectors.conf")
	content := `[cfm_endpoints]
BLOCK = "15m"            ; stage 3 enforcement TTL (or dryrun/permanent/no)
COOLDOWN = "15m"         ; don't spam the same alert
MODE = "journal"   # where to read
ALLOW_NETS = "10.0.0.0/8, 192.168.0.0/16"   ; trusted
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	secs, err := ReadSectionsFile(p)
	if err != nil {
		t.Fatal(err)
	}
	kv := secs.ByName["cfm_endpoints"]
	pol := parseBlockPolicy(kv)
	if pol.Mode != "ttl" || pol.TTL != 15*time.Minute {
		t.Fatalf("BLOCK: mode=%s ttl=%s, want ttl 15m (raw %q)", pol.Mode, pol.TTL, kv["BLOCK"])
	}
	if got := kvDur(kv, "COOLDOWN", 0); got != 15*time.Minute {
		t.Errorf("COOLDOWN = %s, want 15m", got)
	}
	if got := kvStrClean(kv, "MODE", ""); got != "journal" {
		t.Errorf("MODE = %q, want journal", got)
	}
	if got := kvStrClean(kv, "ALLOW_NETS", ""); got != "10.0.0.0/8, 192.168.0.0/16" {
		t.Errorf("ALLOW_NETS = %q", got)
	}
}

// The `+=` append path (overlay one-liners, where operators comment most)
// goes through the same reader before joinAppend: the appended item must be
// the text between the quotes, never `192.168.0.0/16" ; office`.
func TestQuotedAppendWithInlineCommentReadsAsValue(t *testing.T) {
	p := filepath.Join(t.TempDir(), "detectors.conf")
	content := `[global]
IGNORE_NETS = 10.0.0.0/8
IGNORE_NETS += "192.168.0.0/16"   ; office
`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	secs, err := ReadSectionsFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := kvStrClean(secs.Global, "IGNORE_NETS", ""), "10.0.0.0/8, 192.168.0.0/16"; got != want {
		t.Fatalf("IGNORE_NETS = %q, want %q", got, want)
	}
}
