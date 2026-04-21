package configio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSerializePreservesUnknown(t *testing.T) {
	in := `# pre
[notifier]
enabled = true
unknown_key = keep

[channel "ops"]
type = slack
enabled = true
webhook_url = https://x
x_extra = y

[custom "thing"]
a = b
`
	cfg, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	out := SerializeDeterministic(cfg)
	if !strings.Contains(out, "[custom \"thing\"]") || !strings.Contains(out, "a = b") {
		t.Fatalf("unknown section not preserved: %s", out)
	}
	if !strings.Contains(out, "unknown_key = keep") || !strings.Contains(out, "x_extra = y") {
		t.Fatalf("unknown keys not preserved: %s", out)
	}
}

func TestWriteFileCreatesBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notify.conf")
	if err := os.WriteFile(p, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteFile(p, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "notify.conf.bak-") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected backup file, entries=%v", entries)
	}
}
