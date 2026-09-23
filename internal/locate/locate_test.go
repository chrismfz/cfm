package locate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cfm/internal/ipquery"
)

func mustQuery(t *testing.T, arg string) *query {
	t.Helper()
	q, err := parseQuery(arg)
	if err != nil {
		t.Fatalf("parseQuery(%q): %v", arg, err)
	}
	return q
}

func TestMatchesEntry(t *testing.T) {
	cases := []struct {
		arg, entry string
		want       bool
	}{
		// plain IP query
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4", "1.2.3.5", false},
		{"1.2.3.4", "1.2.3.0/24", true}, // blocked as part of a subnet
		{"1.2.3.4", "1.2.4.0/24", false},
		{"1.2.3.4", "1.2.3.1-1.2.3.10", true}, // nft interval
		{"1.2.3.4", "1.2.3.5-1.2.3.10", false},
		// CIDR query
		{"1.2.3.0/24", "1.2.3.4", true},    // host inside queried net
		{"1.2.3.0/24", "1.2.0.0/16", true}, // overlapping nets
		{"1.2.3.0/24", "9.9.9.0/24", false},
		{"1.2.3.0/24", "1.2.3.250-1.2.4.5", true},
		// v6
		{"2001:db8::1", "2001:db8::/64", true},
		{"2001:db8::1", "2001:db9::/64", false},
		{"2001:db8::1", "2001:db8::1", true},
		// family mismatch
		{"1.2.3.4", "2001:db8::/64", false},
		// junk entries never match
		{"1.2.3.4", "", false},
		{"1.2.3.4", "not-an-ip", false},
		{"1.2.3.4", "abc-def", false},
	}
	for _, c := range cases {
		q := mustQuery(t, c.arg)
		idx := ipquery.NewIndex[Location]()
		idx.Add(c.entry, Location{Match: c.entry})
		if got := len(idx.Match(q.Query)) > 0; got != c.want {
			t.Errorf("matchesEntry(arg=%s, entry=%s) = %v, want %v", c.arg, c.entry, got, c.want)
		}
	}
}

func TestParseQueryRejectsJunk(t *testing.T) {
	for _, bad := range []string{"", "nope", "1.2.3", "1.2.3.0/99"} {
		if _, err := parseQuery(bad); err == nil {
			t.Errorf("parseQuery(%q) should fail", bad)
		}
	}
}

// scanOne scans content as a list file and matches one query against it.
func scanOne(content string, q *query) []Location {
	idx := ipquery.NewIndex[Location]()
	scanListFile(strings.NewReader(content), "csf", "csf.deny", ActionBlock, idx)
	return matchAll(idx, []*query{q})[0]
}

func TestScanListFile(t *testing.T) {
	content := `# CSF deny file
1.2.3.4 # lfd: (smtpauth) Failed SMTP AUTH login
10.0.0.0/8 # manual block
5.6.7.8
tcp|in|d=22|s=9.9.9.9 # advanced rule
`
	q := mustQuery(t, "1.2.3.4")
	locs := scanOne(content, q)
	if len(locs) != 1 {
		t.Fatalf("want 1 hit, got %d: %+v", len(locs), locs)
	}
	if locs[0].Reason != "lfd: (smtpauth) Failed SMTP AUTH login" {
		t.Errorf("reason = %q", locs[0].Reason)
	}

	// subnet containment
	q = mustQuery(t, "10.20.30.40")
	locs = scanOne(content, q)
	if len(locs) != 1 || locs[0].Match != "10.0.0.0/8" {
		t.Fatalf("subnet containment failed: %+v", locs)
	}

	// csf advanced syntax
	q = mustQuery(t, "9.9.9.9")
	locs = scanOne(content, q)
	if len(locs) != 1 || locs[0].Match != "9.9.9.9" {
		t.Fatalf("advanced-syntax match failed: %+v", locs)
	}

	// CIDR query finds hosts inside it
	q = mustQuery(t, "5.6.7.0/24")
	locs = scanOne(content, q)
	if len(locs) != 1 || locs[0].Match != "5.6.7.8" {
		t.Fatalf("cidr-query match failed: %+v", locs)
	}
}

func TestScanCSFTempFile(t *testing.T) {
	content := `1781097784|1.2.3.4|*|in|3600|lfd - *Port Scan* detected
1781097785|4.3.2.1|80|in|600|manual temp ban
`
	q := mustQuery(t, "1.2.3.4")
	idx := ipquery.NewIndex[Location]()
	scanCSFTempFile(strings.NewReader(content), "csf.tempban", ActionBlock, idx)
	locs := matchAll(idx, []*query{q})[0]
	if len(locs) != 1 {
		t.Fatalf("want 1 hit, got %d: %+v", len(locs), locs)
	}
	if !strings.Contains(locs[0].Reason, "Port Scan") || !strings.Contains(locs[0].Reason, "since ") {
		t.Errorf("reason = %q", locs[0].Reason)
	}
}

// withCSF makes csf look installed (or not) for the test.
func withCSF(t *testing.T, installed bool) {
	t.Helper()
	orig := csfInstalled
	csfInstalled = func() bool { return installed }
	t.Cleanup(func() { csfInstalled = orig })
}

func TestSearchCSFFromDirs(t *testing.T) {
	withCSF(t, true)
	etc := t.TempDir()
	data := t.TempDir()
	if err := os.WriteFile(filepath.Join(etc, "csf.deny"), []byte("1.2.3.0/24 # bad net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "csf.tempban"), []byte("1781097784|1.2.3.4|*|in|3600|lfd temp\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	q := mustQuery(t, "1.2.3.4")
	all, why := searchCSF(Options{CSFDir: etc, CSFDataDir: data}, []*query{q})
	if why != "" {
		t.Fatalf("unexpected skip: %s", why)
	}
	locs := all[0]
	if len(locs) != 2 {
		t.Fatalf("want 2 hits (deny subnet + tempban), got %d: %+v", len(locs), locs)
	}

	// missing dir = not installed
	if _, why := searchCSF(Options{CSFDir: filepath.Join(etc, "nope")}, []*query{q}); why != "not installed" {
		t.Errorf("want 'not installed', got %q", why)
	}

	// Files left behind by an uninstall enforce nothing: no csf binary, no
	// csf source, whatever /etc/csf still holds.
	withCSF(t, false)
	if all, why := searchCSF(Options{CSFDir: etc, CSFDataDir: data}, []*query{q}); why != "not installed" || all != nil {
		t.Errorf("leftover csf files: locs %+v, why %q; want 'not installed'", all, why)
	}
}

func TestSearchCFMDeny(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfm.deny"), []byte("# comment\n8.8.0.0/16 # bulk\n1.1.1.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	all, err := searchCFMDeny(dir, []*query{mustQuery(t, "8.8.4.4")})
	if err != nil {
		t.Fatal(err)
	}
	if locs := all[0]; len(locs) != 1 || locs[0].Match != "8.8.0.0/16" || locs[0].Source != "cfm.deny" {
		t.Fatalf("unexpected: %+v", all)
	}
	// absent file is not an error
	all, err = searchCFMDeny(t.TempDir(), []*query{mustQuery(t, "8.8.4.4")})
	if err != nil || all != nil {
		t.Fatalf("absent file: locs=%v err=%v", all, err)
	}
}

func TestParseF2BBannedDump(t *testing.T) {
	out := `[{'sshd': ['1.2.3.4', '10.0.0.0/24']}, {'recidive': []}]`
	jails, ok := parseF2BBannedDump(out)
	if !ok {
		t.Fatal("parse failed")
	}
	if len(jails["sshd"]) != 2 || jails["sshd"][0] != "1.2.3.4" || jails["sshd"][1] != "10.0.0.0/24" {
		t.Errorf("sshd = %v", jails["sshd"])
	}
	if entries, present := jails["recidive"]; !present || len(entries) != 0 {
		t.Errorf("recidive = %v (present=%v)", entries, present)
	}

	// matching incl. subnet containment
	locs := matchF2BJails(jails, []*query{mustQuery(t, "10.0.0.7")})[0]
	if len(locs) != 1 || locs[0].List != "sshd" || locs[0].Match != "10.0.0.0/24" {
		t.Errorf("match: %+v", locs)
	}

	// non-dump output is rejected so the fallback path kicks in
	if _, ok := parseF2BBannedDump("Usage: fail2ban-client ..."); ok {
		t.Error("usage text should not parse as a dump")
	}

	// unquoted range entries keep their dash
	jails, ok = parseF2BBannedDump(`[{'sshd': [1.2.3.4-1.2.3.10]}]`)
	if !ok || len(jails["sshd"]) != 1 || jails["sshd"][0] != "1.2.3.4-1.2.3.10" {
		t.Errorf("unquoted range: %v", jails["sshd"])
	}

	// a dict missing its ':' must not leak entries into the previous jail
	jails, ok = parseF2BBannedDump(`[{'sshd': ['1.2.3.4']}, {'broken' ['5.6.7.8']}]`)
	if !ok {
		t.Fatal("parse failed")
	}
	for _, e := range jails["sshd"] {
		if e == "5.6.7.8" {
			t.Errorf("entry leaked across dict boundary into sshd: %v", jails["sshd"])
		}
	}
}

func TestScanListFileLongLine(t *testing.T) {
	// one >64KB junk line must not abort scanning of later entries
	long := strings.Repeat("x", 80*1024)
	content := long + "\n1.2.3.4 # after the long line\n"
	q := mustQuery(t, "1.2.3.4")
	locs := scanOne(content, q)
	if len(locs) != 1 {
		t.Fatalf("entry after long line was lost: %+v", locs)
	}
}

func TestParseF2BStatusFallback(t *testing.T) {
	status := "Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, recidive\n"
	jails := parseF2BJailList(status)
	if len(jails) != 2 || jails[0] != "sshd" || jails[1] != "recidive" {
		t.Fatalf("jails = %v", jails)
	}
	jailStatus := "Status for the jail: sshd\n|- Filter\n`- Actions\n   `- Banned IP list:\t1.2.3.4 5.6.7.8\n"
	banned := parseF2BBannedLine(jailStatus)
	if len(banned) != 2 || banned[0] != "1.2.3.4" {
		t.Fatalf("banned = %v", banned)
	}
}

func TestParseImunifyList(t *testing.T) {
	// lowercase keys + items wrapper (what agents emit)
	raw := []byte(`{"items": [
	  {"ip": "1.2.3.4", "purpose": "drop", "comment": "incident", "expiration": 1781097784},
	  {"ip": "10.0.0.0", "netmask": 8, "purpose": "captcha", "comment": "", "expiration": 0},
	  {"ip": "5.5.5.5", "purpose": "white", "comment": "trusted", "expiration": 0}
	], "counts": 3}`)
	items := parseImunifyList(raw)
	if len(items) != 3 {
		t.Fatalf("items = %d", len(items))
	}

	locs := matchImunifyItems(items, []*query{mustQuery(t, "1.2.3.4")})[0]
	if len(locs) != 1 || locs[0].Action != ActionBlock || locs[0].List != "drop (BLACK)" {
		t.Fatalf("drop match: %+v", locs)
	}
	if !strings.Contains(locs[0].Reason, "incident") || !strings.Contains(locs[0].Reason, "expires") {
		t.Errorf("reason = %q", locs[0].Reason)
	}

	// netmask containment → GRAY challenge
	locs = matchImunifyItems(items, []*query{mustQuery(t, "10.9.8.7")})[0]
	if len(locs) != 1 || locs[0].Action != ActionChallenge || locs[0].Match != "10.0.0.0/8" {
		t.Fatalf("captcha match: %+v", locs)
	}

	// uppercase keys (as the docs table shows)
	rawUpper := []byte(`[{"IP": "9.9.9.9", "PURPOSE": "white", "COMMENT": "doc-style", "EXPIRATION": 0}]`)
	items = parseImunifyList(rawUpper)
	if len(items) != 1 || items[0].Purpose != "white" {
		t.Fatalf("uppercase parse: %+v", items)
	}

	if items := parseImunifyList([]byte("not json")); items != nil {
		t.Errorf("junk should yield nil, got %+v", items)
	}
}
