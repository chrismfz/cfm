package detectors

import (
	"path/filepath"
	"testing"
	"time"
)

func TestApplyBuiltinLeniency(t *testing.T) {
	secs := Sections{ByName: map[string]KV{
		"global":                       {},
		"modsec":                       {"BLOCK": "permanent"},
		"ssh_auth":                     {},
		"custom:ssh_file":              {},
		"challenge_solver_farm":        {}, // LeniencySupported: false
		loginBruteforceType:            {},
		"dovecot_auth":                 {},
		"dovecot_auth.leniency":        {"MATCH_COUNTRY": "GR", "BLOCK": "1h"},
		"ftpd":                         {},
		"ftpd.leniency":                {"ENABLED": "0", "MATCH_COUNTRY": "GR"},
		"cpanel":                       {},
		"cpanel.leniency":              {"MATCH_COUNTRY": "", "BLOCK": "5m"},
		"not_a_registered_type_at_all": {},
	}}
	applyBuiltinLeniency(&secs)

	for _, name := range []string{"modsec", "ssh_auth", "custom:ssh_file"} {
		lp := parseLeniencyPolicy(secs.ByName[name+".leniency"])
		if lp == nil || len(lp.Countries) != 2 || lp.Countries[0] != "GR" || lp.Countries[1] != "CY" ||
			len(lp.ASNs) != 0 || lp.Pol.Mode != "ttl" || lp.Pol.TTL != 15*time.Minute ||
			!lp.SendToAPI || lp.SendToBlocklist != "lenient" {
			t.Errorf("%s: built-in leniency %+v", name, lp)
		}
	}
	for _, name := range []string{"challenge_solver_farm", loginBruteforceType, "global", "not_a_registered_type_at_all"} {
		if _, ok := secs.ByName[name+".leniency"]; ok {
			t.Errorf("%s got a built-in leniency", name)
		}
	}
	// A written companion stays as written.
	if lp := parseLeniencyPolicy(secs.ByName["dovecot_auth.leniency"]); lp == nil ||
		len(lp.Countries) != 1 || lp.Pol.TTL != time.Hour || lp.SendToBlocklist != "" {
		t.Errorf("written dovecot leniency changed: %+v", lp)
	}
	// ENABLED = 0 turns it off.
	if lp := parseLeniencyPolicy(secs.ByName["ftpd.leniency"]); lp != nil {
		t.Errorf("ftpd ENABLED = 0 left a leniency: %+v", lp)
	}
	// No criteria (cfm-admin's "Add leniency companion"): GR/CY, the
	// operator's own values kept.
	if lp := parseLeniencyPolicy(secs.ByName["cpanel.leniency"]); lp == nil ||
		len(lp.Countries) != 2 || lp.Pol.TTL != 5*time.Minute || lp.SendToBlocklist != "lenient" {
		t.Errorf("empty cpanel leniency: %+v", lp)
	}
}

// Every section of the reference config that bans gets a leniency, written
// or built in: a Greek customer is never banned with a section's full policy
// and reported to the fleet blocklist.
func TestReferenceConfigEveryBanningSectionIsLenient(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "detectors.conf")
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Skipf("reference config: %v", err)
	}
	applyBuiltinLoginBruteforce(&secs)
	applyBuiltinLeniency(&secs)
	types := builtinLeniencyTypes()
	types[loginBruteforceType] = true
	for name, kv := range secs.ByName {
		typ, _ := SplitTypeInstance(name)
		if !types[typ] {
			continue
		}
		switch sectionBlockPolicy(name, kv).Mode {
		case "no", "dryrun":
			continue
		}
		lp := parseLeniencyPolicy(secs.ByName[name+".leniency"])
		if lp == nil {
			t.Errorf("[%s] bans with no leniency", name)
			continue
		}
		gr := false
		for _, c := range lp.Countries {
			gr = gr || c == "GR"
		}
		if !gr {
			t.Errorf("[%s] leniency does not match GR: %v", name, lp.Countries)
		}
		if lp.SendToAPI && lp.SendToBlocklist != "lenient" {
			t.Errorf("[%s] leniency reports GR to the fleet blacklist", name)
		}
		if lp.Pol.Mode == "permanent" {
			t.Errorf("[%s] leniency is permanent", name)
		}
	}
	// [modsec] bans for 30 days, not for ever: a scanner's address moves on,
	// and a permanent fleet entry outlives it on whoever gets it next.
	if pol := sectionBlockPolicy("modsec", secs.ByName["modsec"]); pol.Mode != "ttl" || pol.TTL != 30*24*time.Hour {
		t.Errorf("[modsec] BLOCK = %+v, want 30d", pol)
	}
}

func TestSofterPolicy(t *testing.T) {
	ttl := func(d time.Duration) blockPolicy { return blockPolicy{Mode: "ttl", TTL: d, Cooldown: time.Minute} }
	perm := blockPolicy{Mode: "permanent"}
	for _, c := range []struct {
		name         string
		section, len blockPolicy
		wantMode     string
		wantTTL      time.Duration
	}{
		{"permanent section, 15m leniency", perm, ttl(15 * time.Minute), "ttl", 15 * time.Minute},
		{"1h section, 15m leniency", ttl(time.Hour), ttl(15 * time.Minute), "ttl", 15 * time.Minute},
		{"10m section, 15m leniency: not lengthened", ttl(10 * time.Minute), ttl(15 * time.Minute), "ttl", 10 * time.Minute},
		{"1h section, permanent leniency: the section's TTL", ttl(time.Hour), perm, "ttl", time.Hour},
		{"dryrun section stays dryrun", blockPolicy{Mode: "dryrun"}, ttl(15 * time.Minute), "dryrun", 0},
		{"leniency no-block", perm, blockPolicy{Mode: "no"}, "no", 0},
		{"leniency dryrun", perm, blockPolicy{Mode: "dryrun"}, "dryrun", 0},
	} {
		got := softerPolicy(c.section, c.len)
		if got.Mode != c.wantMode || got.TTL != c.wantTTL {
			t.Errorf("%s: %+v, want %s %s", c.name, got, c.wantMode, c.wantTTL)
		}
	}
}
