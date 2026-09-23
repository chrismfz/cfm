package config

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// An unrecognised THROTTLE_MODE is a bounded (ttl) block with a warning, not
// a permanent one: the reference cfm.conf shipped "tlt", which made every
// throttle autoblock a permanent ban.
func TestThrottleMode_UnknownMeansTTL(t *testing.T) {
	var logs bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	defer func() { log.SetOutput(oldWriter); log.SetFlags(oldFlags) }()

	for _, tc := range []struct{ in, want string }{
		{`"tlt"`, "ttl"},
		{`"bogus"`, "ttl"},
		{`"TTL"`, "ttl"},
		{`"permanent"`, "permanent"},
		{`"alert"`, "alert"},
		{`"dryrun"`, "dryrun"},
	} {
		logs.Reset()
		cfg, err := ParseCFMConf(strings.NewReader("THROTTLE_MODE = " + tc.in + "\n"))
		if err != nil {
			t.Fatalf("parse %s: %v", tc.in, err)
		}
		cfg.SetDefaults()
		if cfg.Throttle.Mode != tc.want {
			t.Errorf("THROTTLE_MODE = %s -> %q, want %q", tc.in, cfg.Throttle.Mode, tc.want)
		}
		warned := strings.Contains(logs.String(), "THROTTLE_MODE")
		if invalid := tc.in == `"tlt"` || tc.in == `"bogus"`; warned != invalid {
			t.Errorf("THROTTLE_MODE = %s: warned=%v, want %v (%q)", tc.in, warned, invalid, logs.String())
		}
	}
}

// The reference config's mode is a valid one.
func TestThrottleMode_ReferenceConfigIsValid(t *testing.T) {
	cfg := loadReferenceConf(t)
	if cfg.Throttle.Mode != "ttl" {
		t.Errorf("reference cfm.conf THROTTLE_MODE = %q, want \"ttl\"", cfg.Throttle.Mode)
	}
}

func loadReferenceConf(t *testing.T) *Config {
	t.Helper()
	f, err := os.Open("../../configs/cfm.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cfg, err := ParseCFMConf(f)
	if err != nil {
		t.Fatalf("parse reference cfm.conf: %v", err)
	}
	cfg.SetDefaults()
	return cfg
}
