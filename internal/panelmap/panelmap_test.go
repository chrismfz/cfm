package panelmap

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeFixtures points the package paths at temp files for the test and
// restores them after.
func writeFixtures(t *testing.T, userDataDomains, userDomains string) {
	t.Helper()
	tmp := t.TempDir()
	udd := filepath.Join(tmp, "userdatadomains")
	ud := filepath.Join(tmp, "userdomains")
	if err := os.WriteFile(udd, []byte(userDataDomains), 0o644); err != nil {
		t.Fatalf("write userdatadomains: %v", err)
	}
	if err := os.WriteFile(ud, []byte(userDomains), 0o644); err != nil {
		t.Fatalf("write userdomains: %v", err)
	}
	oldUDD, oldUD := UserDataDomainsPath, UserDomainsPath
	UserDataDomainsPath, UserDomainsPath = udd, ud
	t.Cleanup(func() { UserDataDomainsPath, UserDomainsPath = oldUDD, oldUD })
}

func TestParseOwnerLine(t *testing.T) {
	cases := []struct {
		line string
		udd  bool
		host string
		own  string
		ok   bool
	}{
		{"mysite.com: own", false, "mysite.com", "own", true},
		{"MySite.com:  Own ", false, "mysite.com", "own", true},
		{"shop.example.com: bob==sub==shop.example.com==/home/bob==...", true, "shop.example.com", "bob", true},
		{"blank", false, "", "", false},
		{": owner", false, "", "", false}, // empty host
		{"host:", false, "", "", false},   // empty owner
		{"", false, "", "", false},
	}
	for _, c := range cases {
		host, own, ok := parseOwnerLine(c.line, c.udd)
		if ok != c.ok || host != c.host || own != c.own {
			t.Errorf("parseOwnerLine(%q, udd=%v) = (%q,%q,%v), want (%q,%q,%v)",
				c.line, c.udd, host, own, ok, c.host, c.own, c.ok)
		}
	}
}

func TestHostOwners_PrecedenceAndFilter(t *testing.T) {
	writeFixtures(t,
		// userdatadomains: authoritative for shop + main
		"main.com: alice==std==main.com==/home/alice\nshop.com: alice==sub==shop.com==/home/alice\n",
		// userdomains: bob owns blog; also (pathological) lists main under carol,
		// which must NOT override the userdatadomains answer (alice).
		"blog.net: bob\nmain.com: carol\n",
	)
	got := HostOwners([]string{"main.com", "shop.com", "blog.net", "absent.com"})
	want := map[string]string{
		"main.com": "alice", // userdatadomains wins over userdomains' carol
		"shop.com": "alice",
		"blog.net": "bob", // only in userdomains
		// absent.com not present in either → omitted
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("HostOwners = %v, want %v", got, want)
	}
}

func TestHostOwners_Empty(t *testing.T) {
	writeFixtures(t, "main.com: alice==x\n", "")
	if got := HostOwners(nil); len(got) != 0 {
		t.Errorf("HostOwners(nil) = %v, want empty", got)
	}
}

func TestOwnerSet_UnionAcrossFiles(t *testing.T) {
	writeFixtures(t,
		"main.com: alice==std\n",
		"main.com: carol\nblog.net: bob\n",
	)
	// main.com listed under alice (udd) AND carol (ud) → both in the set;
	// blog.net → bob. Sorted, distinct.
	got := OwnerSet([]string{"main.com", "blog.net"})
	want := []string{"alice", "bob", "carol"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("OwnerSet = %v, want %v", got, want)
	}
}

func TestOwnerSet_NoMatch(t *testing.T) {
	writeFixtures(t, "main.com: alice==x\n", "")
	if got := OwnerSet([]string{"nope.com"}); got != nil {
		t.Errorf("OwnerSet(no match) = %v, want nil", got)
	}
}

func TestHostOwners_OversizedLineNotDropped(t *testing.T) {
	// A line longer than bufio.Scanner's 64 KiB default must still parse (else the
	// scan silently ends and the host — and any after it — is dropped, narrowing
	// scope). Uses a >64 KiB host followed by a normal one to prove the scan
	// continues past the big line too.
	bigHost := strings.Repeat("a", 70*1024) + ".com"
	writeFixtures(t, "", bigHost+": bigowner\nnormal.com: normalowner\n")
	got := HostOwners([]string{bigHost, "normal.com"})
	if got[bigHost] != "bigowner" {
		t.Errorf("oversized-line host dropped: %v", got[bigHost])
	}
	if got["normal.com"] != "normalowner" {
		t.Errorf("host after oversized line dropped (scan ended early): %v", got)
	}
}

func TestMissingFilesAreSilent(t *testing.T) {
	// Point at nonexistent paths.
	oldUDD, oldUD := UserDataDomainsPath, UserDomainsPath
	UserDataDomainsPath = filepath.Join(t.TempDir(), "does-not-exist-udd")
	UserDomainsPath = filepath.Join(t.TempDir(), "does-not-exist-ud")
	t.Cleanup(func() { UserDataDomainsPath, UserDomainsPath = oldUDD, oldUD })

	if got := HostOwners([]string{"x.com"}); len(got) != 0 {
		t.Errorf("HostOwners with missing files = %v, want empty", got)
	}
	if got := OwnerSet([]string{"x.com"}); got != nil {
		t.Errorf("OwnerSet with missing files = %v, want nil", got)
	}
}
