package panelmap

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func withUserDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := UserDataDir
	UserDataDir = dir
	t.Cleanup(func() { UserDataDir = old })
	return dir
}

func writeUserData(t *testing.T, root, user, domain, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, user), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, user, domain), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The case from qualityweb (2026-11-09): userdatadomains lists trimel.gr, the
// site's traffic is logged as www.trimel.gr, and the userdata file names the
// aliases. A parked domain's names come in through the main domain's alias list.
func TestWithWebAliases(t *testing.T) {
	root := withUserDataDir(t)
	writeUserData(t, root, "trimel", "trimel.gr",
		"---\ndocumentroot: /home/trimel/public_html\nserveralias: www.trimel.gr mail.trimel.gr parked.gr www.parked.gr\nservername: trimel.gr\n")
	got := WithWebAliases("trimel", []string{"Trimel.gr", "parked.gr", "shop.trimel.gr"})
	want := []string{"mail.trimel.gr", "parked.gr", "shop.trimel.gr", "trimel.gr",
		"www.parked.gr", "www.shop.trimel.gr", "www.trimel.gr"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

// Without a userdata file every domain still gets its www. name.
func TestWithWebAliasesNoUserData(t *testing.T) {
	withUserDataDir(t)
	got := WithWebAliases("nouser", []string{"a.gr", "www.b.gr"})
	want := []string{"a.gr", "www.a.gr", "www.b.gr"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// An alias outside the account's own domains never enters the scope, nor does
// a wildcard or a malformed name; a user name with a path separator reads no file.
func TestWithWebAliasesFailClosed(t *testing.T) {
	root := withUserDataDir(t)
	writeUserData(t, root, "acct", "mine.gr",
		"serveralias: www.mine.gr victim.gr www.victim.gr *.mine.gr notmine-mine.gr ../x mine.gr.evil.com\n")
	got := WithWebAliases("acct", []string{"mine.gr"})
	want := []string{"mine.gr", "www.mine.gr"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	writeUserData(t, root, "x", "y.gr", "serveralias: www.y.gr\n")
	if got := serverAliases("../x", "y.gr"); got != nil {
		t.Fatalf("path-separator user read a file: %v", got)
	}
	if got := WithWebAliases("acct", nil); len(got) != 0 {
		t.Fatalf("no domains must give no scope, got %v", got)
	}
}
