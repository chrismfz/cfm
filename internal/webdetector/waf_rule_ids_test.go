package webdetector

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestWAFRuleIDs_LuaParity asserts the Go-side mirror in waf_rule_ids.go
// matches the canonical RULE_IDS table in configs/lua/cfm_waf.lua. Drift
// here would silently break the panel/CLI rule glossary and (in PR B) per-
// vhost exclusion validation.
//
// We parse cfm_waf.lua's RULE_IDS block with a small regex rather than
// shelling out to luajit — keeps the test self-contained.
func TestWAFRuleIDs_LuaParity(t *testing.T) {
	luaPath := findCFMRoot(t) + "/configs/lua/cfm_waf.lua"
	src, err := os.ReadFile(luaPath)
	if err != nil {
		t.Fatalf("read %s: %v", luaPath, err)
	}

	// Extract the table body between `local RULE_IDS = {` and the matching `}`.
	start := strings.Index(string(src), "local RULE_IDS = {")
	if start < 0 {
		t.Fatalf("RULE_IDS table not found in %s", luaPath)
	}
	tail := string(src[start:])
	// First closing brace ends the table (no nested braces inside).
	end := strings.Index(tail, "\n}")
	if end < 0 {
		t.Fatalf("RULE_IDS table close not found")
	}
	block := tail[:end]

	// Lines look like:  rule_traversal               = 101,
	// Comment lines start with `--` and are skipped.
	entryRe := regexp.MustCompile(`^\s*(rule_[a-z0-9_]+)\s*=\s*(\d+)\s*,?\s*(?:--.*)?$`)

	luaIDs := map[string]int{}
	for _, line := range strings.Split(block, "\n") {
		if m := entryRe.FindStringSubmatch(line); m != nil {
			id, _ := strconv.Atoi(m[2])
			if _, dup := luaIDs[m[1]]; dup {
				t.Errorf("duplicate Lua RULE_IDS key: %s", m[1])
			}
			luaIDs[m[1]] = id
		}
	}
	if len(luaIDs) == 0 {
		t.Fatalf("no entries parsed from RULE_IDS block")
	}

	// Build a map from the Go side for comparison.
	goIDs := map[string]int{}
	for _, r := range wafRuleIDs {
		if _, dup := goIDs[r.Name]; dup {
			t.Errorf("duplicate Go wafRuleIDs entry: %s", r.Name)
		}
		goIDs[r.Name] = r.ID
	}

	// Symmetric diff.
	for name, luaID := range luaIDs {
		goID, ok := goIDs[name]
		if !ok {
			t.Errorf("Lua has %s=%d but Go mirror is missing it", name, luaID)
			continue
		}
		if goID != luaID {
			t.Errorf("ID drift on %s: Lua=%d Go=%d", name, luaID, goID)
		}
	}
	for name, goID := range goIDs {
		if _, ok := luaIDs[name]; !ok {
			t.Errorf("Go mirror has %s=%d but Lua RULE_IDS is missing it", name, goID)
		}
	}
}

// TestWAFRuleIDs_NoRenumber pins a few load-bearing IDs so an accidental
// renumber during refactor is caught by the test, not by an operator
// whose --rule 320 exclusion silently starts skipping the wrong rule.
func TestWAFRuleIDs_NoRenumber(t *testing.T) {
	pinned := map[string]int{
		"rule_traversal":         101,
		"rule_bad_ua":            201,
		"rule_sqli":              301,
		"rule_xss":               302,
		"rule_rce":               320,
		"rule_proxy_header_sqli": 321,
		"rule_upload_filename":   401,
		"rule_auth_burst":        501,
		"rule_xmlrpc_pingback":   511,
		"rule_ssrf":              701,
		"rule_debug_toggles":     801,
	}
	for name, want := range pinned {
		r, ok := WAFRuleByName(name)
		if !ok {
			t.Errorf("missing rule %s", name)
			continue
		}
		if r.ID != want {
			t.Errorf("renumber detected: %s ID=%d, expected pinned %d", name, r.ID, want)
		}
	}
}

// TestWAFRuleIDs_GroupingDigits sanity-checks that every rule's first digit
// matches its semantic group (catches "I added a rule but used the wrong
// 100-block" mistakes).
func TestWAFRuleIDs_GroupingDigits(t *testing.T) {
	for _, r := range wafRuleIDs {
		if r.ID < 100 || r.ID > 999 {
			t.Errorf("rule %s has out-of-range ID %d (must be 100-999)", r.Name, r.ID)
		}
		group := r.ID / 100
		if _, ok := wafRuleGroupNames[group]; !ok {
			t.Errorf("rule %s ID=%d uses unknown group digit %d", r.Name, r.ID, group)
		}
	}
}

// TestHandleWAFRules_Smoke hits the endpoint and asserts the JSON shape the
// panel + CLI rely on (rules array sorted, groups map populated).
func TestHandleWAFRules_Smoke(t *testing.T) {
	e := &Engine{}

	req := httptest.NewRequest("GET", "/api/v1/waf/rules", nil)
	ctx := context.WithValue(req.Context(), CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleAdmin)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	e.handleWAFRules(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	var out struct {
		Rules  []WAFRule         `json:"rules"`
		Groups map[string]string `json:"groups"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
	}
	if len(out.Rules) < 30 {
		t.Errorf("expected ~39 rules, got %d", len(out.Rules))
	}
	for i := 1; i < len(out.Rules); i++ {
		if out.Rules[i].ID < out.Rules[i-1].ID {
			t.Errorf("rules not sorted by ID at index %d", i)
			break
		}
	}
	if out.Groups["1"] != "path" || out.Groups["3"] != "injection" {
		t.Errorf("unexpected groups map: %+v", out.Groups)
	}
	// Spot-check one rule is fully populated.
	r, ok := WAFRuleByName("rule_rce")
	if !ok || r.ID != 320 || r.GroupName != "injection" {
		t.Errorf("rule_rce lookup wrong: %+v ok=%v", r, ok)
	}
}

// findCFMRoot walks up from this test file until it finds a directory
// containing both go.mod and configs/lua/cfm_waf.lua. Lets the test run
// regardless of the working directory `go test` was invoked from.
func findCFMRoot(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	dir := filepath.Dir(here)
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "configs", "lua", "cfm_waf.lua")); err == nil {
				return dir
			}
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not locate cfm repo root from %s", here)
	return ""
}
