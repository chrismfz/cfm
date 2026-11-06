package detectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/edgeban"
)

// The built-in section a node runs without one in its detectors.conf must be
// the stock section, leniency included: otherwise the same release bans
// differently by install date.
func TestLoginBruteforceDefaultsMatchReferenceConfig(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "detectors.conf")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("detectors.conf not found: %v", err)
	}
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]KV{
		loginBruteforceType:               loginBruteforceDefaults(),
		loginBruteforceType + ".leniency": loginBruteforceLeniencyDefaults(),
	} {
		got, ok := secs.ByName[name]
		if !ok {
			t.Fatalf("[%s] missing from the reference config", name)
		}
		for k, v := range want {
			if g := kvStrClean(got, k, "<absent>"); g != v {
				t.Errorf("[%s] %s = %q, built-in default %q", name, k, g, v)
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok && kvStrClean(got, k, "") != "" {
				t.Errorf("[%s] %s is set in the reference config but not in the built-in default", name, k)
			}
		}
	}
	if def := sectionBlockDefaults[loginBruteforceType]; def["BLOCK"] != loginBruteforceDefaults()["BLOCK"] ||
		def["BLOCK_COOLDOWN"] != loginBruteforceDefaults()["BLOCK_COOLDOWN"] {
		t.Errorf("sectionBlockDefaults %v differ from the built-in section", def)
	}
}

func TestApplyBuiltinLoginBruteforce(t *testing.T) {
	// Absent: the defaults and the GR/CY leniency.
	secs := Sections{ByName: map[string]KV{"global": {}}}
	applyBuiltinLoginBruteforce(&secs)
	kv := secs.ByName[loginBruteforceType]
	if kvStrClean(kv, "SITE_FAILS", "") != "5" || kvStrClean(kv, "SITES", "") != "5" {
		t.Fatalf("built-in section: %v", kv)
	}
	pol := sectionBlockPolicy(loginBruteforceType, kv)
	if pol.Mode != "ttl" || pol.TTL != 3*24*time.Hour {
		t.Fatalf("built-in block policy: %+v", pol)
	}
	lp := parseLeniencyPolicy(secs.ByName[loginBruteforceType+".leniency"])
	if lp == nil || lp.SendToAPI || lp.Pol.Mode != "ttl" || lp.Pol.TTL != 10*time.Minute ||
		len(lp.Countries) != 2 || lp.Countries[0] != "GR" || lp.Countries[1] != "CY" {
		t.Fatalf("built-in leniency: %+v", lp)
	}

	// Written by the operator (cfm-admin's "Add" writes no leniency): the
	// section as is, the GR/CY leniency added.
	secs = Sections{ByName: map[string]KV{loginBruteforceType: {"ENABLED": "0"}}}
	applyBuiltinLoginBruteforce(&secs)
	if len(secs.ByName) != 2 || secs.ByName[loginBruteforceType]["ENABLED"] != "0" ||
		parseLeniencyPolicy(secs.ByName[loginBruteforceType+".leniency"]) == nil {
		t.Fatalf("operator section: %v", secs.ByName)
	}
	// cfm-admin's "Add leniency companion" writes no criteria: GR/CY still,
	// with the operator's own values kept.
	secs = Sections{ByName: map[string]KV{loginBruteforceType: {}, loginBruteforceType + ".leniency": {"MATCH_COUNTRY": "", "BLOCK": "30m"}}}
	applyBuiltinLoginBruteforce(&secs)
	lp = parseLeniencyPolicy(secs.ByName[loginBruteforceType+".leniency"])
	if lp == nil || len(lp.Countries) != 2 || lp.Pol.TTL != 30*time.Minute {
		t.Fatalf("an empty leniency: %+v", lp)
	}
	// Only ENABLED = 0 turns it off.
	secs = Sections{ByName: map[string]KV{loginBruteforceType: {}, loginBruteforceType + ".leniency": {"ENABLED": "0", "MATCH_COUNTRY": "GR"}}}
	applyBuiltinLoginBruteforce(&secs)
	if parseLeniencyPolicy(secs.ByName[loginBruteforceType+".leniency"]) != nil {
		t.Fatalf("ENABLED = 0 left a leniency: %v", secs.ByName)
	}
	// A section without BLOCK still bans like the built-in one.
	if pol := sectionBlockPolicy(loginBruteforceType, KV{}); pol.Mode != "ttl" || pol.TTL != 3*24*time.Hour {
		t.Fatalf("written section without BLOCK: %+v", pol)
	}
	// A named instance counts as written too.
	secs = Sections{ByName: map[string]KV{loginBruteforceType + ":strict": {"SITE_FAILS": "3"}}}
	applyBuiltinLoginBruteforce(&secs)
	if _, added := secs.ByName[loginBruteforceType]; added {
		t.Fatal("built-in section added next to a written instance")
	}
	if secs.ByName[loginBruteforceType+":strict.leniency"] == nil {
		t.Fatal("no leniency added to the written instance")
	}
	// A leniency written on its own is kept; the section is still added.
	secs = Sections{ByName: map[string]KV{loginBruteforceType + ".leniency": {"MATCH_COUNTRY": "GR", "BLOCK": "1h"}}}
	applyBuiltinLoginBruteforce(&secs)
	if secs.ByName[loginBruteforceType] == nil || secs.ByName[loginBruteforceType+".leniency"]["BLOCK"] != "1h" {
		t.Fatalf("operator leniency replaced: %v", secs.ByName)
	}
}

func TestLoginBruteforceIsAWebSection(t *testing.T) {
	// Its bans must reach the edge: a brute forcer behind Cloudflare never
	// meets the nft drop.
	if !edgeban.WebSection(loginBruteforceType) {
		t.Fatal("login_bruteforce bans are not enforced at the edge")
	}
	for _, inst := range []string{"login_bruteforce:strict", "login_bruteforce strict"} {
		if !edgeban.WebSection(inst) {
			t.Fatalf("instance %q bans are not enforced at the edge", inst)
		}
	}
	if edgeban.WebSection("login_bruteforcex") || edgeban.WebSection("ssh_auth:x") {
		t.Fatal("WebSection matches too much")
	}
}

func TestLoginBruteforceWrittenSectionKeepsTheProxyASNs(t *testing.T) {
	// A minimal written section must not ban a Sucuri edge.
	if got := kvStrClean(KV{}, "ALLOW_ASNS", loginBruteforceProxyASNs); got != loginBruteforceProxyASNs {
		t.Fatalf("default ALLOW_ASNS: %q", got)
	}
	if loginBruteforceDefaults()["ALLOW_ASNS"] != loginBruteforceProxyASNs {
		t.Fatal("the built-in section and the code default differ")
	}
}
