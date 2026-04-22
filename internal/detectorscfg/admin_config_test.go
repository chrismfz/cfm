package detectorscfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAdminConfig_ParsesCommentExamples(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "detectors.conf")
	content := `
[global]
ENRICH=1

;@example id=mailcow_postfix title="Mailcow postfix baseline" section=postfix_security
;ENABLED = 0
;BLOCK = permanent
;WINDOW = "30m"

;@example id=mailcow_postfix_leniency title="Mailcow postfix leniency baseline" section=postfix_security.leniency
;MATCH_COUNTRY = "GR,CY"
;BLOCK = "10m"

[postfix_security]
ENABLED = 1
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write detectors.conf: %v", err)
	}

	cfg, path, err := LoadAdminConfig(dir)
	if err != nil {
		t.Fatalf("LoadAdminConfig returned error: %v", err)
	}
	if path != cfgPath {
		t.Fatalf("expected path %q, got %q", cfgPath, path)
	}
	if len(cfg.Examples) != 2 {
		t.Fatalf("expected 2 examples, got %d", len(cfg.Examples))
	}

	first := cfg.Examples[0]
	if first.ID != "mailcow_postfix" {
		t.Fatalf("expected first example id mailcow_postfix, got %q", first.ID)
	}
	if first.Kind != "core" {
		t.Fatalf("expected core kind, got %q", first.Kind)
	}
	if first.Keys["ENABLED"] != "0" {
		t.Fatalf("expected ENABLED key to be parsed, got %q", first.Keys["ENABLED"])
	}

	second := cfg.Examples[1]
	if second.Kind != "leniency" {
		t.Fatalf("expected leniency kind, got %q", second.Kind)
	}
	if second.Keys["MATCH_COUNTRY"] != "GR,CY" {
		t.Fatalf("expected MATCH_COUNTRY key to be parsed, got %q", second.Keys["MATCH_COUNTRY"])
	}
}

func TestRenderAdminConfig_RoundTripPreservesCommentsAndOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "detectors.conf")
	content := strings.TrimLeft(`
# preamble

[global]
ENRICH = 1 ; keep inline

[postfix_security]
; section comment
ENABLED = 1 ; important

BLOCK = permanent
# keep this too
WINDOW = 30m
`, "\n")
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write detectors.conf: %v", err)
	}

	cfg, _, err := LoadAdminConfig(dir)
	if err != nil {
		t.Fatalf("LoadAdminConfig returned error: %v", err)
	}

	rendered, err := RenderAdminConfig(dir, cfg)
	if err != nil {
		t.Fatalf("RenderAdminConfig returned error: %v", err)
	}

	if rendered != content {
		t.Fatalf("expected unchanged render to preserve comments and ordering.\nexpected:\n%s\ngot:\n%s", content, rendered)
	}
}

func TestRenderAdminConfig_AppendsNewKeysAfterExistingOrder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "detectors.conf")
	content := strings.TrimLeft(`
[postfix_security]
WINDOW = 30m
ENABLED = 1 ; keep inline
`, "\n")
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write detectors.conf: %v", err)
	}

	cfg, _, err := LoadAdminConfig(dir)
	if err != nil {
		t.Fatalf("LoadAdminConfig returned error: %v", err)
	}
	cfg.Core[0].Keys["BLOCK"] = "permanent"

	rendered, err := RenderAdminConfig(dir, cfg)
	if err != nil {
		t.Fatalf("RenderAdminConfig returned error: %v", err)
	}

	want := strings.TrimLeft(`
[postfix_security]
WINDOW = 30m
ENABLED = 1 ; keep inline
BLOCK = permanent

[global]
`, "\n")
	if rendered != want {
		t.Fatalf("expected key append behavior.\nexpected:\n%s\ngot:\n%s", want, rendered)
	}
}
