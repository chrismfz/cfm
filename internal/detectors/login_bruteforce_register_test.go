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
		loginBruteforceType:              loginBruteforceDefaults(),
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
	if pol.Mode != "ttl" || pol.TTL != 90*24*time.Hour {
		t.Fatalf("built-in block policy: %+v", pol)
	}
	lp := parseLeniencyPolicy(secs.ByName[loginBruteforceType+".leniency"])
	if lp == nil || lp.SendToAPI || lp.Pol.Mode != "ttl" || lp.Pol.TTL != 10*time.Minute ||
		len(lp.Countries) != 2 || lp.Countries[0] != "GR" || lp.Countries[1] != "CY" {
		t.Fatalf("built-in leniency: %+v", lp)
	}

	// Written by the operator, even disabled and without leniency: as is.
	secs = Sections{ByName: map[string]KV{loginBruteforceType: {"ENABLED": "0"}}}
	applyBuiltinLoginBruteforce(&secs)
	if len(secs.ByName) != 1 || secs.ByName[loginBruteforceType]["ENABLED"] != "0" {
		t.Fatalf("operator section changed: %v", secs.ByName)
	}
	// A section without BLOCK still bans like the built-in one.
	if pol := sectionBlockPolicy(loginBruteforceType, KV{}); pol.Mode != "ttl" || pol.TTL != 90*24*time.Hour {
		t.Fatalf("written section without BLOCK: %+v", pol)
	}
	// A named instance counts as written too.
	secs = Sections{ByName: map[string]KV{loginBruteforceType + ":strict": {"SITE_FAILS": "3"}}}
	applyBuiltinLoginBruteforce(&secs)
	if _, added := secs.ByName[loginBruteforceType]; added {
		t.Fatal("built-in section added next to a written instance")
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
}
