package detectors

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/hostsecrets"
)

// TestReferenceConfigMatchesRuntimeDefaults pins stock values in
// configs/detectors.conf that must equal what a node runs when its conffile
// predates the key (the Go default), or that must ship in their safe state.
//
// A node whose detectors.conf was seeded before a key existed runs the Go
// default; a node seeded later runs the stock value. When the two differ, the
// same release behaves differently per node depending on install date, and
// nothing reports it. Each value below was found drifting on 2026-09-30:
//
//   - HISTORY_RETENTION_DAYS shipped 7 while the code default is 30;
//   - HISTORY_PRUNE_EVERY shipped "1", which is not a Go duration, so every
//     node silently fell back to the 1h default (the absurd fallback below
//     makes that fail instead of pass);
//   - [mysql_governor] shipped MODE = enforce with another server's tenant
//     rules, so a fresh install would kill queries under rules written for a
//     different fleet; the code default and the section's own header say
//     monitor;
//   - [global] IGNORE_IPS/IGNORE_NETS carried a per-host example address. These
//     lists also feed the edge self-origin bypass (cfm_selfip.lua: the WHOLE CFM
//     stack, WAF included, is skipped for them), so every entry must parse and
//     must stay private, loopback or our own network;
//   - CHALLENGE_EXCLUDE_FILE was documented under [webdetector], where the
//     manager never reads it (it reads [global]).
func TestReferenceConfigMatchesRuntimeDefaults(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "detectors.conf")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("detectors.conf not found at %s: %v", path, err)
	}
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Fatalf("ReadSectionsFile: %v", err)
	}

	wd := secs.ByName["webdetector"]
	if got := kvInt(wd, "HISTORY_RETENTION_DAYS", -1); got != 30 {
		t.Errorf("[webdetector] HISTORY_RETENTION_DAYS = %d, want 30 (the Go default in webdetector_register.go)", got)
	}
	if got := kvDur(wd, "HISTORY_PRUNE_EVERY", 999*time.Hour); got != time.Hour {
		t.Errorf("[webdetector] HISTORY_PRUNE_EVERY = %s, want 1h (a value that fails to parse reads as the fallback)", got)
	}

	// The per-host tokens are generated into /var/lib/cfm/secrets
	// (hostsecrets), never shipped: a real value would be one secret for the
	// fleet. The key line stays inside [webdetector] with a WEAK placeholder,
	// which the daemon ignores and an older binary (after a rollback) replaces
	// in place. A MISSING line is appended by that binary at the end of the
	// file, into whatever section is last (the 2026-09-30 speedhost reload
	// loop); an EMPTY one is worse: its `KEY\s*=\s*` regex runs across the
	// newline and overwrites the next line, leaving the key empty.
	for _, key := range []string{"CHALLENGE_TOKEN", "OPENRESTY_TOKEN"} {
		v, ok := wd[key]
		switch {
		case !ok:
			t.Errorf("[webdetector] %s line is missing from stock; keep it as placeholder (rollback safety)", key)
		case strings.TrimSpace(v) == "":
			t.Errorf("[webdetector] %s is empty in stock; an older binary mangles an empty line, keep placeholder", key)
		case hostsecrets.IsStrongToken(v):
			t.Errorf("[webdetector] %s = %q is a real token in stock; per-host tokens are generated, never shipped", key, v)
		}
	}

	gov, ok := secs.ByName["mysql_governor"]
	if !ok {
		t.Fatal("[mysql_governor] section missing from detectors.conf")
	}
	if got := kvStrClean(gov, "MODE", ""); got != "monitor" {
		t.Errorf("[mysql_governor] MODE = %q, want monitor: enforce is a per-host decision, never a shipped default", got)
	}
	for _, key := range []string{"QUERY_RULES", "CONN_RULES"} {
		for _, line := range kvLines(gov, key) {
			user := strings.TrimSpace(strings.SplitN(line, ":", 2)[0])
			if !strings.Contains(user, "*") {
				t.Errorf("[mysql_governor] %s ships a rule for the exact user %q; stock carries wildcard rules only (per-tenant rules are per host)", key, user)
			}
		}
	}

	ssh := secs.ByName["ssh_auth"]
	for key, want := range map[string]int{
		"AUTHFAIL_IP":   sshDefaultAuthFailIP,
		"AUTHFAIL_USER": sshDefaultAuthFailUser,
		"DDOS_IP":       sshDefaultDDOSIP,
	} {
		if got := kvInt(ssh, key, -1); got != want {
			t.Errorf("[ssh_auth] %s = %d in stock, code default is %d; a node without the key runs the code default", key, got, want)
		}
	}
	// Every per-type BLOCK default must reproduce the stock section's policy.
	for typ := range sectionBlockDefaults {
		kv, ok := secs.ByName[typ]
		if !ok {
			t.Errorf("[%s] has a sectionBlockDefaults entry but no stock section", typ)
			continue
		}
		stockPol := parseBlockPolicy(kv)
		codePol := sectionBlockPolicy(typ, KV{})
		if stockPol != codePol {
			t.Errorf("[%s] stock BLOCK policy %+v != code default %+v (sectionBlockDefaults)", typ, stockPol, codePol)
		}
	}

	health := secs.ByName["health"]
	if got := kvInt(health, "TMP_PCT", -1); got != healthDefaultTmpPct {
		t.Errorf("[health] TMP_PCT = %d in stock, code default is %d", got, healthDefaultTmpPct)
	}
	if got := kvDur(health, "TMP_CLEAN_OLDER", 999*time.Hour); got != healthDefaultTmpCleanOlder {
		t.Errorf("[health] TMP_CLEAN_OLDER = %s in stock, code default is %s", got, healthDefaultTmpCleanOlder)
	}

	g := secs.Global
	// manager.go reads CHALLENGE_EXCLUDE_FILE from [global] only. Stock used
	// to document it under [webdetector], where it is silently ignored and
	// works only while the value equals the built-in default path.
	if got := kvStrClean(g, "CHALLENGE_EXCLUDE_FILE", ""); got != "/etc/cfm/webdetector_challenge_exclude.txt" {
		t.Errorf("[global] CHALLENGE_EXCLUDE_FILE = %q, want the default path; the manager reads it from [global] only", got)
	}
	if _, ok := wd["CHALLENGE_EXCLUDE_FILE"]; ok {
		t.Error("[webdetector] CHALLENGE_EXCLUDE_FILE is set; nothing reads it there (manager.go reads [global])")
	}

	for _, tok := range splitIgnoreList(kvStrClean(g, "IGNORE_IPS", "")) {
		ip := net.ParseIP(tok)
		if ip == nil {
			t.Errorf("[global] IGNORE_IPS entry %q is not an IP; the parser would drop it silently", tok)
			continue
		}
		if !ip.IsLoopback() {
			t.Errorf("[global] IGNORE_IPS entry %q is not loopback; a single host here bypasses the whole CFM stack on every node (networks belong in IGNORE_NETS)", tok)
		}
	}
	ownNet := mustCIDR(t, "84.54.49.0/24")
	for _, tok := range splitIgnoreList(kvStrClean(g, "IGNORE_NETS", "")) {
		ip, n, err := net.ParseCIDR(tok)
		if err != nil {
			t.Errorf("[global] IGNORE_NETS entry %q is not a CIDR; the parser would drop it silently", tok)
			continue
		}
		if n.String() != tok {
			t.Errorf("[global] IGNORE_NETS entry %q is not a network address (means %s)", tok, n)
		}
		if !ip.IsPrivate() && !ip.IsLoopback() && n.String() != ownNet.String() {
			t.Errorf("[global] IGNORE_NETS entry %q is neither private nor our own network", tok)
		}
	}
}

func splitIgnoreList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == ';'
	})
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return n
}
