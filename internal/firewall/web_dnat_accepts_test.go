package firewall

import (
	"errors"
	"strings"
	"testing"
)

const webAcceptHTTP = `tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080"`
const webAcceptHTTPS = `tcp dport 9043 ct state new ct status dnat ct original proto-dst 443 accept comment "cfm_dnat_accept:web_https_tcp:443:9043"`

// webChain is an input chain with the two web accepts above the drop.
const webChain = `table inet cfm {
	chain input { # handle 1
		type filter hook input priority -50; policy accept;
		iif "lo" accept # handle 2
		ct state new tcp dport @tcp_in_ports accept # handle 30
		tcp dport 12083 ct state new ct status dnat ct original proto-dst 2083 accept comment "cfm_cpanel_dnat:2083:12083" # handle 40
		tcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment "cfm_dnat_accept:web_http_tcp:80:9080" # handle 50
		tcp dport 9043 ct state new ct status dnat ct original proto-dst 443 accept comment "cfm_dnat_accept:web_https_tcp:443:9043" # handle 51
		ct state new tcp dport 0-65535 drop # handle 60
		ct state new udp dport 0-65535 drop # handle 61
	}
}
`

// fakeAcceptOps records every command run; the listing is fixed.
func fakeAcceptOps(listing string, listErr error) (NFTTextOps, *[]string) {
	var ran []string
	return NFTTextOps{
		ListInput: func() (string, error) { return listing, listErr },
		Run:       func(cmd string) error { ran = append(ran, cmd); return nil },
	}, &ran
}

// The writes, without the idempotent table/chain declarations.
func acceptWrites(ran []string) string {
	var out []string
	for _, c := range ran {
		if !strings.HasPrefix(c, "add table") && !strings.HasPrefix(c, "add chain") {
			out = append(out, c)
		}
	}
	return strings.Join(out, "\n---\n")
}

var webWant = []string{webAcceptHTTP, webAcceptHTTPS}

// In place: nothing is written, so the accepts keep working and keep their
// handles across every reload.
func TestEnsureInputAccepts_InPlaceIsKept(t *testing.T) {
	ops, ran := fakeAcceptOps(webChain, nil)
	changes, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true)
	if err != nil || len(changes) != 0 || acceptWrites(*ran) != "" {
		t.Fatalf("err=%v changes=%v writes:\n%s", err, changes, acceptWrites(*ran))
	}
}

// A missing accept is inserted before the default drop.
func TestEnsureInputAccepts_MissingIsInsertedBeforeTheDrop(t *testing.T) {
	ops, ran := fakeAcceptOps(strings.Replace(webChain, "\t\t"+webAcceptHTTPS+" # handle 51\n", "", 1), nil)
	if _, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true); err != nil {
		t.Fatal(err)
	}
	if got := acceptWrites(*ran); got != "insert rule inet cfm input position 60 "+webAcceptHTTPS {
		t.Fatalf("got:\n%s", got)
	}
}

// One below the drop (never matched) is replaced: the insert runs first, the
// delete after it.
func TestEnsureInputAccepts_BelowTheDropIsReplaced(t *testing.T) {
	in := strings.Replace(webChain, "\t\t"+webAcceptHTTPS+" # handle 51\n", "", 1)
	in = strings.Replace(in, "\t\tct state new udp dport 0-65535 drop # handle 61\n",
		"\t\tct state new udp dport 0-65535 drop # handle 61\n\t\t"+webAcceptHTTPS+" # handle 70\n", 1)
	ops, ran := fakeAcceptOps(in, nil)
	if _, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true); err != nil {
		t.Fatal(err)
	}
	want := "insert rule inet cfm input position 60 " + webAcceptHTTPS + "\n---\ndelete rule inet cfm input handle 70"
	if got := acceptWrites(*ran); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// Duplicates, the other engine's tag and an accept for old ports go; the
// wanted ones stay where they are.
func TestEnsureInputAccepts_ExtrasAreDeleted(t *testing.T) {
	in := strings.Replace(webChain, "\t\tct state new tcp dport 0-65535 drop # handle 60\n",
		"\t\t"+webAcceptHTTP+" # handle 52\n"+
			"\t\ttcp dport 9080 ct state new ct status dnat ct original proto-dst 80 accept comment \"cfm_edge_dnat_accept:web_http_tcp:80:9080\" # handle 53\n"+
			"\t\ttcp dport 8080 ct state new ct status dnat ct original proto-dst 80 accept comment \"cfm_dnat_accept:web_http_tcp:80:8080\" # handle 54\n"+
			"\t\tct state new tcp dport 0-65535 drop # handle 60\n", 1)
	ops, ran := fakeAcceptOps(in, nil)
	if _, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true); err != nil {
		t.Fatal(err)
	}
	want := "delete rule inet cfm input handle 52\ndelete rule inet cfm input handle 53\ndelete rule inet cfm input handle 54"
	if got := acceptWrites(*ran); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

// New listener ports (DNATOn): with prune off the old accepts stay, since the
// redirect still points at them; the pruning call after the redirect moved
// deletes them.
func TestEnsureInputAccepts_NewPortsKeepOldUntilPruned(t *testing.T) {
	newHTTP := strings.ReplaceAll(webAcceptHTTP, "9080", "9081")
	ops, ran := fakeAcceptOps(webChain, nil)
	if _, err := EnsureInputAccepts(ops, []string{newHTTP, webAcceptHTTPS}, IsWebDNATAccept, false); err != nil {
		t.Fatal(err)
	}
	if got := acceptWrites(*ran); got != "insert rule inet cfm input position 60 "+newHTTP {
		t.Fatalf("prune off, got:\n%s", got)
	}
	ops, ran = fakeAcceptOps(webChain, nil)
	if _, err := EnsureInputAccepts(ops, []string{newHTTP, webAcceptHTTPS}, IsWebDNATAccept, true); err != nil {
		t.Fatal(err)
	}
	want := "insert rule inet cfm input position 60 " + newHTTP + "\n---\ndelete rule inet cfm input handle 50"
	if got := acceptWrites(*ran); got != want {
		t.Fatalf("prune on, got:\n%s\nwant:\n%s", got, want)
	}
}

// A delete that fails (another process removed the handle first) never undoes
// the insert, and the rest are still tried one by one.
func TestEnsureInputAccepts_FailedDeleteKeepsTheInsert(t *testing.T) {
	in := strings.Replace(webChain, "\t\t"+webAcceptHTTPS+" # handle 51\n", "", 1)
	in = strings.Replace(in, "\t\tct state new udp dport 0-65535 drop # handle 61\n",
		"\t\tct state new udp dport 0-65535 drop # handle 61\n\t\t"+webAcceptHTTPS+" # handle 70\n\t\t"+webAcceptHTTPS+" # handle 71\n", 1)
	var ran []string
	ops := NFTTextOps{
		ListInput: func() (string, error) { return in, nil },
		Run: func(cmd string) error {
			ran = append(ran, cmd)
			if strings.Contains(cmd, "handle 70") {
				return errors.New("Could not process rule: No such file or directory")
			}
			return nil
		},
	}
	changes, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true)
	if err != nil {
		t.Fatalf("a failed delete is not an error: %v", err)
	}
	got := acceptWrites(ran)
	want := "insert rule inet cfm input position 60 " + webAcceptHTTPS +
		"\n---\ndelete rule inet cfm input handle 70\ndelete rule inet cfm input handle 71" +
		"\n---\ndelete rule inet cfm input handle 70\n---\ndelete rule inet cfm input handle 71"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(strings.Join(changes, "\n"), "could not remove handle 70") {
		t.Fatalf("changes: %q", changes)
	}
}

// An accept is identified by its comment tag, so the form older nft prints
// (`proto-dst 0x50 [invalid type]`) is the same rule, kept, not replaced on
// every reload.
func TestEnsureInputAccepts_OlderNFTPrintFormIsKept(t *testing.T) {
	in := strings.Replace(webChain, "ct original proto-dst 80 accept", "ct original proto-dst 0x50 [invalid type] accept", 1)
	ops, ran := fakeAcceptOps(in, nil)
	if _, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true); err != nil {
		t.Fatal(err)
	}
	if got := acceptWrites(*ran); got != "" {
		t.Fatalf("replaced an accept nft printed differently:\n%s", got)
	}
}

// The panel accepts and everything else are someone else's: never deleted.
func TestEnsureInputAccepts_OnlyManagedRulesAreTouched(t *testing.T) {
	ops, ran := fakeAcceptOps(webChain, nil)
	if _, err := EnsureInputAccepts(ops, nil, IsWebDNATAccept, true); err != nil {
		t.Fatal(err)
	}
	if got := acceptWrites(*ran); got != "delete rule inet cfm input handle 50\ndelete rule inet cfm input handle 51" {
		t.Fatalf("got:\n%s", got)
	}
}

// No default drop yet: appended.
func TestEnsureInputAccepts_NoDropAppends(t *testing.T) {
	in := "table inet cfm {\n\tchain input { # handle 1\n\t\ttype filter hook input priority -50; policy accept;\n\t\tiif \"lo\" accept # handle 2\n\t}\n}\n"
	ops, ran := fakeAcceptOps(in, nil)
	if _, err := EnsureInputAccepts(ops, webWant[:1], IsWebDNATAccept, true); err != nil {
		t.Fatal(err)
	}
	if got := acceptWrites(*ran); got != "add rule inet cfm input "+webAcceptHTTP {
		t.Fatalf("got:\n%s", got)
	}
}

// A listing error writes nothing (fail closed).
func TestEnsureInputAccepts_ListErrorWritesNothing(t *testing.T) {
	ops, ran := fakeAcceptOps("", errors.New("timed out"))
	if _, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true); err == nil {
		t.Fatal("want an error")
	}
	if got := acceptWrites(*ran); got != "" {
		t.Fatalf("wrote a rule after a failed listing:\n%s", got)
	}
}

// In place, a reload runs the listing and nothing else: no table or chain
// declarations, no write.
func TestEnsureInputAccepts_InPlaceRunsNothing(t *testing.T) {
	ops, ran := fakeAcceptOps(webChain, nil)
	if _, err := EnsureInputAccepts(ops, webWant, IsWebDNATAccept, true); err != nil {
		t.Fatal(err)
	}
	if len(*ran) != 0 {
		t.Fatalf("ran %q", *ran)
	}
}
