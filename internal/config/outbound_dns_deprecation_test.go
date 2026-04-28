package config

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestParseCFMConf_OutboundDNSDeprecatedKeysIgnoredWithWarning(t *testing.T) {
	var logs bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	}()

	cfg, err := ParseCFMConf(strings.NewReader(`
OUTBOUND_ENABLED=1
OUTBOUND_DNS_PER_MIN=999
OUTBOUND_DNS_DEBUG_ENABLED=1
OUTBOUND_DNS_DEBUG_SAMPLE_COUNT=777
OUTBOUND_DNS_DEBUG_DURATION_SEC=66
OUTBOUND_DNS_DEBUG_DIR=/tmp/old-dns-debug
`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cfg.Outbound.Enabled {
		t.Fatal("expected OUTBOUND_ENABLED to be parsed")
	}
	if got := logs.String(); !strings.Contains(got, "OUTBOUND_DNS_* is deprecated and ignored; DNS outbound detector has been removed") {
		t.Fatalf("expected deprecation warning log, got %q", got)
	}
}

func TestIsKnownKey_OutboundDNSDeprecationWindow(t *testing.T) {
	for _, key := range []string{
		"OUTBOUND_DNS_PER_MIN",
		"OUTBOUND_DNS_DEBUG_ENABLED",
		"OUTBOUND_DNS_DEBUG_SAMPLE_COUNT",
		"OUTBOUND_DNS_DEBUG_DURATION_SEC",
		"OUTBOUND_DNS_DEBUG_DIR",
	} {
		if !IsKnownKey(key) {
			t.Fatalf("expected deprecated key %s to remain known during deprecation window", key)
		}
	}
	for _, key := range []string{
		"OUTBOUND_DNS_UNIQ_DST_MIN",
		"OUTBOUND_DNS_SEVERITY_MODE",
		"OUTBOUND_DNS_NXDOMAIN_RATIO_ALERT",
	} {
		if IsKnownKey(key) {
			t.Fatalf("expected removed key %s to be unknown", key)
		}
	}
}
