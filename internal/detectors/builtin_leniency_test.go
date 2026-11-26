package detectors

import (
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/detectors/core"
	"cfm/internal/enrich"
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

// lenientSetFake is sinkSetFake that also takes lenient reports.
type lenientSetFake struct {
	*sinkSetFake
	lenient []int // ReportLenient TTLs (seconds)
}

func (f *lenientSetFake) ReportLenient(_, _, _, _ string, ttl int) error {
	f.lenient = append(f.lenient, ttl)
	return nil
}

// Through the sink: a GR address under the built-in leniency is banned 15m
// and reported to the lenient list only; a dryrun section stays dryrun; a
// per-alert block_ttl does not lengthen the lenient ban.
func TestSectionSinkBuiltinLeniency(t *testing.T) {
	orig := leniencyGeo
	leniencyGeo = func(_ *enrich.Enricher, ip string) enrich.Result {
		if ip == "10.9.0.1" {
			return enrich.Result{CountryISO: "GR", Country: "Greece"}
		}
		return enrich.Result{CountryISO: "US"}
	}
	defer func() { leniencyGeo = orig }()
	lp := parseLeniencyPolicy(builtinLeniencyDefaults())
	// No mmdb, and private addresses: no DNS (PTR is only asked for a
	// routable one).
	enr, err := enrich.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	run := func(pol blockPolicy, ip string, extra map[string]string) (*lenientSetFake, map[string]string) {
		fw := &lenientSetFake{sinkSetFake: &sinkSetFake{left: map[string]time.Duration{}}}
		in := &capturingSink{}
		s := &sectionSink{section: "modsec", pol: pol, fw: fw, inner: in, enr: enr, leniency: lp, last: map[string]time.Time{}}
		s.Publish(core.Alert{When: time.Now(), Kind: "MODSEC/403", Key: ip, Extra: extra})
		if len(in.got) != 1 {
			t.Fatalf("%d alerts out", len(in.got))
		}
		return fw, in.got[0].Extra
	}

	perm := blockPolicy{Mode: "permanent", Cooldown: 30 * time.Minute}
	fw, ex := run(perm, "10.9.0.1", nil)
	if got := fw.left["10.9.0.1"]; got != 15*time.Minute || ex["leniency"] != "yes" {
		t.Errorf("GR under a permanent section: ban %s leniency=%q", got, ex["leniency"])
	}
	if len(fw.reports) != 0 || len(fw.lenient) != 1 || fw.lenient[0] != 900 {
		t.Errorf("GR report: blacklist %v lenient %v", fw.reports, fw.lenient)
	}

	fw, _ = run(perm, "10.9.0.2", nil)
	if got, ok := fw.left["10.9.0.2"]; !ok || got != 0 || len(fw.reports) != 1 || len(fw.lenient) != 0 {
		t.Errorf("foreign under a permanent section: ban %s/%v, reports %v lenient %v", got, ok, fw.reports, fw.lenient)
	}

	fw, ex = run(blockPolicy{Mode: "dryrun"}, "10.9.0.1", nil)
	if len(fw.left) != 0 || ex["blocked"] != "dryrun" {
		t.Errorf("GR under a dryrun section: bans %v blocked=%q", fw.left, ex["blocked"])
	}

	fw, _ = run(blockPolicy{Mode: "ttl", TTL: 12 * time.Hour}, "10.9.0.1", map[string]string{"block_ttl": "12h"})
	if got := fw.left["10.9.0.1"]; got != 15*time.Minute {
		t.Errorf("GR with a 12h block_ttl: ban %s, want 15m", got)
	}
	fw, _ = run(blockPolicy{Mode: "ttl", TTL: 12 * time.Hour}, "10.9.0.1", map[string]string{"block_ttl": "5m"})
	if got := fw.left["10.9.0.1"]; got != 5*time.Minute {
		t.Errorf("GR with a 5m block_ttl: ban %s, want 5m", got)
	}
}
