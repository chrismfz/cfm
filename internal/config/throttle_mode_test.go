package config

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// captureLog sends the standard logger to a buffer for the test and forgets
// the THROTTLE_MODE values already warned about.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	throttleModeWarned.Clear()
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		throttleModeWarned.Clear()
	})
	return &logs
}

func throttleMode(t *testing.T, conf string) string {
	t.Helper()
	cfg, err := ParseCFMConf(strings.NewReader(conf))
	if err != nil {
		t.Fatalf("parse %q: %v", conf, err)
	}
	cfg.SetDefaults()
	return cfg.Throttle.Mode
}

// An unrecognised THROTTLE_MODE is a bounded (ttl) block with a warning, not
// a permanent one: the reference cfm.conf shipped "tlt", which made every
// throttle autoblock a permanent ban.
func TestThrottleMode_UnknownMeansTTL(t *testing.T) {
	logs := captureLog(t)
	for _, tc := range []struct{ in, want string }{
		{`"tlt"`, "ttl"},
		{`"bogus"`, "ttl"},
		{`"TTL"`, "ttl"},
		{`"permanent"`, "permanent"},
		{`"alert"`, "alert"},
		{`"dryrun"`, "dryrun"},
		{`""`, "permanent"},
		{`" "`, "permanent"}, // blank is unset, not unrecognised
	} {
		logs.Reset()
		if got := throttleMode(t, "THROTTLE_MODE = "+tc.in+"\n"); got != tc.want {
			t.Errorf("THROTTLE_MODE = %s -> %q, want %q", tc.in, got, tc.want)
		}
		warned := strings.Contains(logs.String(), "THROTTLE_MODE")
		if invalid := tc.in == `"tlt"` || tc.in == `"bogus"`; warned != invalid {
			t.Errorf("THROTTLE_MODE = %s: warned=%v, want %v (%q)", tc.in, warned, invalid, logs.String())
		}
	}
	if throttleMode(t, "") != "permanent" {
		t.Error("no THROTTLE_MODE line should mean permanent")
	}
}

// cfm.conf is parsed per request on some paths, so an unrecognised mode is
// warned about once per process, not per parse.
func TestThrottleMode_WarnsOncePerValue(t *testing.T) {
	logs := captureLog(t)
	for i := 0; i < 3; i++ {
		throttleMode(t, "THROTTLE_MODE = \"tlt\"\n")
	}
	throttleMode(t, "THROTTLE_MODE = \"bogus\"\n")
	if n := strings.Count(logs.String(), `THROTTLE_MODE "tlt"`); n != 1 {
		t.Errorf("tlt warned %d times, want once:\n%s", n, logs.String())
	}
	if n := strings.Count(logs.String(), `THROTTLE_MODE "bogus"`); n != 1 {
		t.Errorf("bogus warned %d times, want once:\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "THROTTLE_TTL=86400s") {
		t.Errorf("warning should name the TTL used: %q", logs.String())
	}
}

// The reference config's mode is a valid one, as written: parsing it must not
// warn (an unrecognised mode would also end up "ttl").
func TestThrottleMode_ReferenceConfigIsValid(t *testing.T) {
	logs := captureLog(t)
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
	if cfg.Throttle.Mode != "ttl" {
		t.Errorf("reference cfm.conf THROTTLE_MODE = %q, want \"ttl\"", cfg.Throttle.Mode)
	}
	if strings.Contains(logs.String(), "THROTTLE_MODE") {
		t.Errorf("reference cfm.conf THROTTLE_MODE is not a valid mode: %s", logs.String())
	}
}
