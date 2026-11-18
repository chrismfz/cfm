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
	forget := func() { warnedIgnoredValue.Range(func(k, _ any) bool { warnedIgnoredValue.Delete(k); return true }) }
	forget() // once per process: start from a clean slate
	t.Cleanup(forget)
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
	if !strings.Contains(logs.String(), "SSLCOLLECTOR_SOCK_PATH=/run/other.sock is ignored") {
		t.Fatalf("expected a warning, got %q", logs.String())
	}

	// Once per process: a second parse (a reload, a CLI command) stays quiet.
	logs.Reset()
	if _, err := ParseCFMConf(strings.NewReader("SSLCOLLECTOR_SOCK_PATH = /run/other.sock\n")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "SSLCOLLECTOR_SOCK_PATH") {
		t.Fatalf("warned twice: %q", logs.String())
	}
	// A DIFFERENT ignored value (edited, then a reload) warns again.
	if _, err := ParseCFMConf(strings.NewReader("SSLCOLLECTOR_SOCK_PATH = /run/third.sock\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "/run/third.sock is ignored") {
		t.Fatalf("a new value must warn again, got %q", logs.String())
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
