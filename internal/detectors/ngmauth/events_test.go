package ngmauth

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// readEventFixture loads testdata/ngm_auth_events.txt: EVENT -> bucket name.
func readEventFixture(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "ngm_auth_events.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) != 2 {
			t.Fatalf("bad fixture line %q", line)
		}
		m[fs[0]] = fs[1]
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return m
}

var bucketNames = map[eventBucket]string{
	bucketInteractive: "interactive",
	bucketToken:       "token",
}

// TestNGMEventFixture pins abuseEvents to the fixture of NGM's events, both
// ways, and (with NGM_SRC set to an ngm checkout) the fixture to NGM's code.
func TestNGMEventFixture(t *testing.T) {
	fx := readEventFixture(t)
	for ev, b := range abuseEvents {
		if fx[ev] != bucketNames[b] {
			t.Errorf("abuseEvents[%s] = %s, fixture says %q", ev, bucketNames[b], fx[ev])
		}
	}
	for ev, b := range fx {
		if b == "ignore" {
			if _, ok := abuseEvents[ev]; ok {
				t.Errorf("fixture ignores %s but abuseEvents counts it", ev)
			}
			continue
		}
		if _, ok := abuseEvents[ev]; !ok {
			t.Errorf("fixture counts %s (%s) but abuseEvents does not", ev, b)
		}
	}
	for ev := range stepUpEvents {
		if abuseEvents[ev] != bucketInteractive {
			t.Errorf("step-up event %s is not in the interactive bucket", ev)
		}
	}

	src := os.Getenv("NGM_SRC")
	if src == "" {
		t.Log("NGM_SRC unset: not scanning an ngm checkout")
		return
	}
	literal := regexp.MustCompile(`authLog\(\s*"([A-Z_]+)"`)
	stepUp := regexp.MustCompile(`\b(?:stepUp|mailboxStepUp)\([^"\n]*?"([A-Z_]+)"`)
	seen := 0
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		check := func(ev string) {
			seen++
			if _, ok := fx[ev]; !ok {
				t.Errorf("NGM emits %s (%s) but testdata/ngm_auth_events.txt does not classify it", ev, p)
			}
		}
		for _, m := range literal.FindAllStringSubmatch(s, -1) {
			check(m[1])
		}
		for _, m := range stepUp.FindAllStringSubmatch(s, -1) {
			check(m[1] + "_FAIL")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Fatalf("NGM_SRC=%s: found no authLog call sites; wrong directory?", src)
	}
}

// Step-up re-auth failures count in the interactive buckets; their account-
// state refusals do not.
func TestStepUpFailuresCount(t *testing.T) {
	alerts := runOnce(t, AuthConfig{
		AuthFailPerIP:   3,
		AuthFailPerUser: 100,
		AdminFailPerIP:  100,
	}, []string{
		`2026-11-18T10:00:00Z ip=1.2.3.4 event=PASSWORD_CHANGE_FAIL role=user user="bob" reason="reauth_failed"`,
		`2026-11-18T10:00:01Z ip=1.2.3.4 event=MFA_DISABLE_FAIL role=user user="bob" reason="reauth_failed"`,
		`2026-11-18T10:00:02Z ip=1.2.3.4 event=RECOVERY_SET_FAIL role=mailbox user="bob@x.gr" reason="reauth_failed"`,
		`2026-11-18T10:00:03Z ip=5.6.7.8 event=PASSWORD_CHANGE_FAIL role=user user="amy" reason="account_disabled"`,
		`2026-11-18T10:00:04Z ip=5.6.7.8 event=PASSWORD_CHANGE_FAIL role=user user="amy" reason="account_suspended"`,
		`2026-11-18T10:00:05Z ip=5.6.7.8 event=MFA_DISABLE_FAIL role=user user="amy" reason="account_suspended"`,
	})
	var hit bool
	for _, al := range alerts {
		if al.Extra["ip"] == "5.6.7.8" {
			t.Fatalf("account-state refusals counted: %s", al.Kind)
		}
		if al.Kind == "NGM/AUTHFAIL" && al.Extra["ip"] == "1.2.3.4" && al.Count == 3 {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("3 step-up failures did not fire NGM/AUTHFAIL for 1.2.3.4: %v", alerts)
	}
}

// Neither DYNDNS_DENY (a suspended account's valid token reads badauth too)
// nor API_ACCOUNT_DENIED (a valid token refused an account) is counted.
func TestValidTokenRefusalsNotCounted(t *testing.T) {
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines,
			`2026-11-18T10:00:00Z ip=1.1.1.1 event=DYNDNS_DENY role=- user="dyndns" reason="badauth"`,
			`2026-11-18T10:00:01Z ip=4.4.4.4 event=API_ACCOUNT_DENIED role=reseller user="carol" reason="api token owner 7; not one of its accounts"`)
	}
	if alerts := runOnce(t, AuthConfig{AuthFailPerIP: 2, AuthFailPerUser: 2, AdminFailPerIP: 2, TokenFailPerIP: 1}, lines); len(alerts) != 0 {
		t.Fatalf("got %d alerts %v, want none", len(alerts), alerts)
	}
}

// ADMIN_IP = 0 turns the privileged bucket off; it never borrows AUTHFAIL_IP.
func TestAdminBucketOffAtZero(t *testing.T) {
	var lines []string
	for i := 0; i < 4; i++ {
		lines = append(lines, `2026-11-18T10:00:00Z ip=1.2.3.4 event=FAIL role=admin user="root" reason="bad_password"`)
	}
	for _, al := range runOnce(t, AuthConfig{AuthFailPerIP: 2, AuthFailPerUser: 100, AdminFailPerIP: 0}, lines) {
		if al.Kind == "NGM/ADMIN" {
			t.Fatalf("ADMIN_IP=0 still fired NGM/ADMIN: %+v", al)
		}
	}
}
