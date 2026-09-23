package unblock

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// fakeTools puts the named scripts (and a systemctl that says every unit is
// active) first in PATH; each appends its argv to <dir>/calls. body is the
// script's text after that line.
func fakeTools(t *testing.T, tools map[string]string) (calls func() []string) {
	t.Helper()
	dir := t.TempDir()
	tools["systemctl"] = "exit 0"
	for name, body := range tools {
		script := fmt.Sprintf("#!/bin/sh\necho \"%s $*\" >> %q\n%s\n", name, filepath.Join(dir, "calls"), body)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		b, _ := os.ReadFile(filepath.Join(dir, "calls")) // #nosec G304 -- test temp file
		var out []string
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if l != "" && !strings.HasPrefix(l, "systemctl ") {
				out = append(out, l)
			}
		}
		return out
	}
}

func ips(ss ...string) []net.IP {
	var out []net.IP
	for _, s := range ss {
		out = append(out, net.ParseIP(s))
	}
	return out
}

func stepsOf(r *Result, src Source) []Step {
	var out []Step
	for _, s := range r.Steps {
		if s.Source == src {
			out = append(out, s)
		}
	}
	return out
}

// fail2ban's ban list is read once, and one unban run takes just the banned
// IPs — not one fail2ban-client per IP, and nothing for an IP it doesn't hold.
func TestDoMany_Fail2BanUnbansOnlyBanned(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"fail2ban-client": `case "$1" in banned) echo "[{'sshd': ['198.51.100.1', '10.0.0.0/24']}, {'recidive': ['198.51.100.2']}]";; esac`,
	})
	res := DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "198.51.100.3"), Options{})
	got := calls()
	if len(got) != 2 || got[0] != "fail2ban-client banned" || got[1] != "fail2ban-client unban 198.51.100.1 198.51.100.2" {
		t.Fatalf("fail2ban-client runs = %q", got)
	}
	if s := stepsOf(res["198.51.100.3"], SrcFail2Ban); len(s) != 1 || s[0].Action != ActionNotFound {
		t.Errorf("198.51.100.3 fail2ban steps = %+v, want not_found", s)
	}
	if s := stepsOf(res["198.51.100.1"], SrcFail2Ban); len(s) != 1 || s[0].Action != ActionChecked {
		t.Errorf("198.51.100.1 fail2ban steps = %+v", s)
	}
}

// Without the ban list (fail2ban < 0.11), every IP is unbanned, as before.
func TestDoMany_Fail2BanWithoutBanList(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"fail2ban-client": `case "$1" in banned) echo "Usage: fail2ban-client ..."; exit 255;; esac`,
	})
	DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2"), Options{})
	if got := calls(); len(got) != 2 || got[1] != "fail2ban-client unban 198.51.100.1 198.51.100.2" {
		t.Fatalf("fail2ban-client runs = %q", got)
	}
}

func imunifyList(entries ...string) string {
	return `echo '{"items":[` + strings.Join(entries, ",") + `]}'`
}

// imunify's list is read once; only listed IPs are deleted, many per run, and
// in a small batch every IP gets the white grace entry, as Do always gave it.
func TestDoMany_ImunifySmallBatch(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) ` + imunifyList(
			`{"ip":"198.51.100.1","purpose":"drop"}`,
			`{"ip":"198.51.100.2","netmask":32,"purpose":"captcha"}`,
			`{"ip":"198.51.100.0","netmask":24,"purpose":"drop"}`,
			`{"ip":"198.51.100.9","purpose":"white"}`) + `;; esac`,
	})
	grace := time.Hour
	DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "198.51.100.3"), Options{ImunifyWhiteTTL: &grace})
	got := calls()
	want := []string{
		"imunify360-agent ip-list local list --limit 10000 --json",
		"imunify360-agent ip-list local delete --purpose drop 198.51.100.1",
		"imunify360-agent ip-list local delete --purpose captcha 198.51.100.2",
	}
	if len(got) != 6 || strings.Join(got[:3], "|") != strings.Join(want, "|") {
		t.Fatalf("imunify runs = %q\nwant %q then three white adds", got, want)
	}
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
		if !strings.HasPrefix(got[3+i], "imunify360-agent ip-list local add --purpose white --comment CFM auto-unblock "+ip+" --expiration ") {
			t.Errorf("white add %d = %q", i, got[3+i])
		}
	}
}

// A mass unblock adds the white grace entry only for the IPs imunify itself
// was blocking: an add is one imunify360-agent run per IP.
func TestDoMany_ImunifyLargeBatchGraceOnlyForListed(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) ` + imunifyList(`{"ip":"10.0.0.5","purpose":"drop"}`) + `;; esac`,
	})
	var batch []net.IP
	for i := 1; i <= graceBatchMax+5; i++ {
		batch = append(batch, net.IPv4(10, 0, 0, byte(i)))
	}
	grace := time.Hour
	res := DoMany(context.Background(), batch, Options{ImunifyWhiteTTL: &grace})
	var adds, deletes int
	for _, c := range calls() {
		switch {
		case strings.Contains(c, " add "):
			adds++
			if !strings.Contains(c, " 10.0.0.5 ") {
				t.Errorf("white grace for an IP imunify wasn't blocking: %q", c)
			}
		case strings.Contains(c, " delete "):
			deletes++
		}
	}
	if adds != 1 || deletes != 1 {
		t.Errorf("%d white adds, %d deletes; want one of each (10.0.0.5)", adds, deletes)
	}
	if s := stepsOf(res["10.0.0.9"], SrcImunify); len(s) != 2 || !strings.Contains(s[1].Detail, "no white grace entry") {
		t.Errorf("10.0.0.9 imunify steps = %+v, want not-listed + no-grace", s)
	}
}

// A list at the cap may be missing entries: the IPs it didn't show are
// deleted blindly, as before.
func TestDoMany_ImunifyCappedListDeletesUnseen(t *testing.T) {
	var entries []string
	for i := 0; i < 10000; i++ {
		entries = append(entries, fmt.Sprintf(`{"ip":"172.16.%d.%d","purpose":"drop"}`, i/250, i%250+1))
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "list.json"), []byte(`{"items":[`+strings.Join(entries, ",")+"]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": fmt.Sprintf(`case "$*" in *" list "*) while IFS= read -r l; do echo "$l"; done < %q;; esac`, filepath.Join(dir, "list.json")),
	})
	DoMany(context.Background(), ips("172.16.0.1", "198.51.100.7"), Options{})
	got := strings.Join(calls(), "|")
	for _, want := range []string{
		"delete --purpose drop 172.16.0.1 198.51.100.7",
		"delete --purpose captcha 198.51.100.7",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("runs %q lack %q", got, want)
		}
	}
}

// cfm.deny is rewritten once for the batch, dropping just the batch's lines.
func TestRemoveFromFileMany(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfm.deny")
	content := "# header\n198.51.100.1 # autoblock: SYN flood\n198.51.100.2/32\n198.51.100.20\n10.0.0.0/8 # net\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	removed := removeFromFileMany(dir, "cfm.deny", ips("198.51.100.1", "198.51.100.2", "198.51.100.3"))
	if len(removed) != 2 || !removed["198.51.100.1"] || !removed["198.51.100.2"] {
		t.Errorf("removed = %v", removed)
	}
	b, _ := os.ReadFile(p) // #nosec G304 -- test temp file
	if string(b) != "# header\n198.51.100.20\n10.0.0.0/8 # net\n" {
		t.Errorf("cfm.deny now:\n%s", b)
	}
	st, _ := os.Stat(p)
	before := st.ModTime()
	time.Sleep(10 * time.Millisecond)
	if r := removeFromFileMany(dir, "cfm.deny", ips("192.0.2.1")); len(r) != 0 {
		t.Errorf("removed %v", r)
	}
	if st, _ := os.Stat(p); !st.ModTime().Equal(before) {
		t.Error("rewrote cfm.deny with nothing to remove")
	}
}

// feedBackend lists one feed host set and records the allow batch.
type feedBackend struct {
	firewall.Backend
	feed    []string
	allowed []firewall.BlockEntry
	batches int
}

func (b *feedBackend) ListTableTextNoDNS(string, string) (string, error) {
	return "table inet cfm {\n\tset block_ext_v4_hosts_MYBLOCK {\n\t\ttype ipv4_addr\n\t}\n}\n", nil
}
func (b *feedBackend) ListSetElementsRaw(string) ([]string, error) { return b.feed, nil }
func (b *feedBackend) RemoveBlockBatch([]net.IP) error             { return nil }
func (b *feedBackend) AddAllowBatch(e []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	b.batches++
	b.allowed = append(b.allowed, e...)
	return firewall.BlockBatchResult{Added: len(e)}, nil
}

// The feed sets are read once for the batch, and the feed-origin IPs are
// allowed in one batch that never shortens an allow already there.
func TestDoMany_FeedOriginAllowedInOneBatch(t *testing.T) {
	fakeTools(t, map[string]string{})
	be := &feedBackend{feed: []string{"198.51.100.1", "198.51.100.3"}}
	ttl := 4 * time.Hour
	res := DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "198.51.100.3"), Options{BE: be, TempWhitelist: true, AllowTTL: &ttl})
	if be.batches != 1 || len(be.allowed) != 2 || be.allowed[0].TTL != ttl || be.allowed[0].Permanent {
		t.Fatalf("allow batches %d: %+v", be.batches, be.allowed)
	}
	if r := res["198.51.100.1"]; len(r.FromFeeds) != 1 || r.FromFeeds[0] != "MYBLOCK" || !r.Whitelisted {
		t.Errorf("198.51.100.1: feeds %v whitelisted %v", r.FromFeeds, r.Whitelisted)
	}
	if r := res["198.51.100.2"]; len(r.FromFeeds) != 0 || r.Whitelisted {
		t.Errorf("198.51.100.2 is in no feed: %+v", r)
	}
}
