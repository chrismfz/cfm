package configdrift

import (
	"reflect"
	"testing"

	"cfm/internal/detconf"
)

func TestDiffDetectorsSections(t *testing.T) {
	stock := detconf.Sections{
		Global: detconf.KV{"DETECT_RATE": "30"},
		ByName: map[string]detconf.KV{
			"global":           {"DETECT_RATE": "30"},
			"postfix_security": {"ENABLED": "1", "EVERY": "2m", "NEW_KEY": "1"},
			"waf_security":     {"ENABLED": "1", "DRY_RUN": "1", "CVE": "1"},
		},
	}
	live := detconf.Sections{
		Global: detconf.KV{"DETECT_RATE": "45"}, // value drift, deliberate
		ByName: map[string]detconf.KV{
			"global":           {"DETECT_RATE": "45"},
			"postfix_security": {"ENABLED": "1", "EVERY": "2m", "OPERATOR_EXTRA": "x"},
			"cpanel":           {"ENABLED": "1"},
		},
	}

	rep := DiffDetectorsSections(stock, live)

	if !reflect.DeepEqual(rep.MissingSections, []string{"waf_security"}) {
		t.Errorf("MissingSections=%v want [waf_security]", rep.MissingSections)
	}
	wantKey := KeyRef{Section: "postfix_security", Key: "NEW_KEY"}
	found := false
	for _, k := range rep.MissingKeys {
		if k == wantKey {
			found = true
		}
	}
	if !found || len(rep.MissingKeys) != 1 {
		t.Errorf("MissingKeys=%v want exactly %v", rep.MissingKeys, wantKey)
	}
	if rep.ValueDiffs != 1 { // global DETECT_RATE only
		t.Errorf("ValueDiffs=%d want 1 (samples=%+v)", rep.ValueDiffs, rep.ValueSamples)
	}
	if len(rep.ExtraSections) != 1 || rep.ExtraSections[0] != "cpanel" {
		t.Errorf("ExtraSections=%v", rep.ExtraSections)
	}
	found = false
	for _, k := range rep.ExtraKeys {
		if k.Section == "postfix_security" && k.Key == "OPERATOR_EXTRA" {
			found = true
		}
	}
	if !found {
		t.Errorf("ExtraKeys missing OPERATOR_EXTRA: %+v", rep.ExtraKeys)
	}
}

func TestDiffDetectorsSectionsIdentical(t *testing.T) {
	s := detconf.Sections{
		ByName: map[string]detconf.KV{
			"global":   {"A": "1"},
			"ssh_auth": {"ENABLED": "1"},
		},
	}
	rep := DiffDetectorsSections(s, s)
	if len(rep.MissingSections)+len(rep.MissingKeys)+len(rep.ExtraSections)+len(rep.ExtraKeys)+rep.ValueDiffs != 0 {
		t.Fatalf("identical inputs produced drift: %+v", rep)
	}
}

func TestDiffFlat(t *testing.T) {
	isKnown := func(k string) bool {
		switch k {
		case "AUTH_TOKEN", "MCP", "CHALLENGE_MODE", "NOT_A_CFM_KEY":
			return k != "NOT_A_CFM_KEY"
		}
		return false
	}
	stock := `
# AUTH_TOKEN = keep secret prose here
CHALLENGE_MODE = auto
# MCP = on   (new in this release)
NOT_A_CFM_KEY = whatever prose with = sign
`
	live := `
AUTH_TOKEN = abc123
CHALLENGE_MODE = strict
`
	rep := DiffFlat(stock, live, isKnown)
	if !reflect.DeepEqual(rep.MissingKeys, []string{"MCP"}) {
		t.Errorf("MissingKeys=%v want [MCP]", rep.MissingKeys)
	}
	if rep.StockKeys != 3 || rep.LiveKeys != 2 {
		t.Errorf("StockKeys=%d LiveKeys=%d want 3/2", rep.StockKeys, rep.LiveKeys)
	}
}

func TestDiffFlatCommentedLiveCountsAsSeen(t *testing.T) {
	isKnown := func(k string) bool { return k == "FOO" }
	stock := "# FOO = 1\n"
	live := "# FOO = 0   ; deliberately off\n"
	rep := DiffFlat(stock, live, isKnown)
	if len(rep.MissingKeys) != 0 || rep.LiveKeys != 1 {
		t.Fatalf("deliberately-commented live key flagged missing: %+v", rep)
	}
}
