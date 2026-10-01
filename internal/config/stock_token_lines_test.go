package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"cfm/internal/hostsecrets"
)

// The stock cfm.conf ships SSLCOLLECTOR_SOCK_TOKEN as a weak placeholder: the
// token lives in /var/lib/cfm/secrets (hostsecrets), never in a shipped file
// (a real value would be one secret for the fleet). The line must stay, not
// empty: after a rollback an older binary rewrites the value in place with a
// `KEY\s*=\s*` regex, which on an empty value runs across the newline and
// overwrites the next line.
func TestStockCfmConfTokenLineIsAPlaceholder(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "configs", "cfm.conf"))
	if err != nil {
		t.Skipf("configs/cfm.conf: %v", err)
	}
	m := regexp.MustCompile(`(?m)^SSLCOLLECTOR_SOCK_TOKEN[ \t]*=[ \t]*(.*)$`).FindAllSubmatch(b, -1)
	if len(m) != 1 {
		t.Fatalf("stock cfm.conf has %d SSLCOLLECTOR_SOCK_TOKEN lines, want exactly 1", len(m))
	}
	v := strings.TrimSpace(string(m[0][1]))
	switch {
	case v == "":
		t.Fatal("SSLCOLLECTOR_SOCK_TOKEN is empty in stock; an older binary mangles an empty line, keep placeholder")
	case hostsecrets.IsStrongToken(v):
		t.Fatalf("SSLCOLLECTOR_SOCK_TOKEN = %q is a real token in stock; per-host tokens are never shipped", v)
	}
}
