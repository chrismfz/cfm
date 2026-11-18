package config

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// The edge connects to the fixed socket only, so cfm.conf cannot move the
// daemon's: a different SSLCOLLECTOR_SOCK_PATH is ignored with a warning, and
// the stock line (the fixed path) is accepted silently.
func TestParseCFMConf_SSLCollectorSockPathIsFixed(t *testing.T) {
	var logs bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	defer func() { log.SetOutput(oldWriter); log.SetFlags(oldFlags) }()

	cfg, err := ParseCFMConf(strings.NewReader("SSLCOLLECTOR_SOCK_PATH = /run/other.sock\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSLCollectorSock.SockPath != SSLCollectorSockPath {
		t.Fatalf("SockPath = %q, want the fixed %q", cfg.SSLCollectorSock.SockPath, SSLCollectorSockPath)
	}
	if !strings.Contains(logs.String(), "SSLCOLLECTOR_SOCK_PATH=/run/other.sock ignored") {
		t.Fatalf("expected a warning, got %q", logs.String())
	}

	logs.Reset()
	cfg, err = ParseCFMConf(strings.NewReader("SSLCOLLECTOR_SOCK_PATH = /var/run/sslcollector.sock\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSLCollectorSock.SockPath != SSLCollectorSockPath || strings.Contains(logs.String(), "SSLCOLLECTOR_SOCK_PATH") {
		t.Fatalf("stock line: SockPath=%q logs=%q", cfg.SSLCollectorSock.SockPath, logs.String())
	}
}
