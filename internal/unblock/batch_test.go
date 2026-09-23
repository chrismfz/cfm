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
// active) alone on PATH, so no real tool is ever reached; each appends its
// argv to <dir>/calls. body is the script's text after that line.
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
	t.Setenv("PATH", dir)
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

// Every IP is unbanned from fail2ban in one fail2ban-client run, not one run
// per IP — and not only the IPs banned right now: an unban also clears the
// ban history bantime.increment reads, as the per-IP unban always did.
func TestDoMany_Fail2BanOneRun(t *testing.T) {
	calls := fakeTools(t, map[string]string{"fail2ban-client": ""})
	res := DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "2001:db8::1"), Options{})
	if got := calls(); len(got) != 1 || got[0] != "fail2ban-client unban 198.51.100.1 198.51.100.2 2001:db8::1" {
		t.Fatalf("fail2ban-client runs = %q", got)
	}
	if s := stepsOf(res["198.51.100.2"], SrcFail2Ban); len(s) != 1 || s[0].Action != ActionChecked || s[0].Detail != "one run for 3 IPs" {
		t.Errorf("198.51.100.2 fail2ban steps = %+v", s)
	}
}

func imunifyList(entries ...string) string {
	return `echo '{"items":[` + strings.Join(entries, ",") + `]}'`
}

// imunify's list is read once; only listed IPs are deleted, many per run and
// one address family per run — an IPv6 IP by the /64 imunify lists it as, one
// delete for the IPs of one /64 — and in a small batch every IP gets the white
// grace entry, as Do always gave it, except an IP already on the white list
// (an operator's entry isn't replaced by a timed one) and an IPv6 IP whose /64
// imunify wasn't blocking (the entry would allow the whole /64). The entries
// are in imunify's own shape: netmask is the mask (4294967295 for one IPv4
// address), not a prefix length.
func TestDoMany_ImunifySmallBatch(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) ` + imunifyList(
			`{"ip":"198.51.100.1","netmask":4294967295,"purpose":"drop"}`,
			`{"ip":"198.51.100.2","netmask":4294967295,"purpose":"captcha"}`,
			`{"ip":"198.51.100.0/24","netmask":4294967040,"purpose":"drop"}`,
			`{"ip":"2001:db8:1:2::/64","netmask":340282366920938463444927863358058659840,"purpose":"drop"}`,
			`{"ip":"198.51.100.9","netmask":4294967295,"purpose":"white"}`) + `;; esac`,
	})
	grace := time.Hour
	res := DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.9",
		"2001:db8:1:2::7", "2001:db8:1:2::8", "2001:db8:9::1"), Options{ImunifyWhiteTTL: &grace})
	got := calls()
	want := []string{
		"imunify360-agent ip-list local list --limit 10000 --json",
		"imunify360-agent ip-list local delete --purpose drop 198.51.100.1",
		"imunify360-agent ip-list local delete --purpose drop 2001:db8:1:2::/64",
		"imunify360-agent ip-list local delete --purpose captcha 198.51.100.2",
	}
	if len(got) != 8 || strings.Join(got[:4], "|") != strings.Join(want, "|") {
		t.Fatalf("imunify runs = %q\nwant %q then four white adds", got, want)
	}
	for i, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "2001:db8:1:2::/64"} {
		if !strings.HasPrefix(got[4+i], "imunify360-agent ip-list local add --purpose white --comment CFM auto-unblock "+ip+" --expiration ") {
			t.Errorf("white add %d = %q", i, got[4+i])
		}
	}
	if s := stepsOf(res["198.51.100.3"], SrcImunify); len(s) != 2 || s[0].Action != ActionNotFound ||
		!strings.Contains(s[0].Detail, "covering 198.51.100.0/24 (drop) is left alone") {
		t.Errorf("198.51.100.3 (only in a /24) imunify steps = %+v, want not_found (the /24 stays) then the white add", s)
	}
	if s := stepsOf(res["198.51.100.9"], SrcImunify); len(s) != 2 || !strings.Contains(s[1].Detail, "already on the local white list as 198.51.100.9") {
		t.Errorf("198.51.100.9 (white) imunify steps = %+v, want no add", s)
	}
	for _, ip := range []string{"2001:db8:1:2::7", "2001:db8:1:2::8"} {
		if s := stepsOf(res[ip], SrcImunify); len(s) != 2 || s[0].Detail != "one run for 2 IPs" || s[0].Action != ActionChecked {
			t.Errorf("%s imunify steps = %+v, want the shared /64 delete and grace entry", ip, s)
		}
	}
	if s := stepsOf(res["2001:db8:9::1"], SrcImunify); len(s) != 2 || !strings.Contains(s[1].Detail, "would allow the whole network") {
		t.Errorf("2001:db8:9::1 (its /64 not blocked) imunify steps = %+v, want no grace", s)
	}
}

// A mass unblock adds the white grace entry only for the IPs imunify itself
// was blocking — on its own entry or by a covering network: an add is one
// imunify360-agent run per IP.
func TestDoMany_ImunifyLargeBatchGraceOnlyForListed(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) ` + imunifyList(
			`{"ip":"10.0.0.5","netmask":4294967295,"purpose":"drop"}`,
			`{"ip":"10.0.0.16/30","netmask":4294967292,"purpose":"captcha"}`) + `;; esac`,
	})
	var batch []net.IP
	for i := 1; i <= graceBatchMax+5; i++ {
		batch = append(batch, net.IPv4(10, 0, 0, byte(i)))
	}
	grace := time.Hour
	res := DoMany(context.Background(), batch, Options{ImunifyWhiteTTL: &grace})
	var adds []string
	var deletes int
	for _, c := range calls() {
		switch f := strings.Fields(c); {
		case strings.Contains(c, " add "):
			adds = append(adds, f[len(f)-3])
		case strings.Contains(c, " delete "):
			deletes++
			if c != "imunify360-agent ip-list local delete --purpose drop 10.0.0.5" {
				t.Errorf("delete %q", c)
			}
		}
	}
	if strings.Join(adds, " ") != "10.0.0.5 10.0.0.16 10.0.0.17 10.0.0.18 10.0.0.19" || deletes != 1 {
		t.Errorf("white adds %v, %d deletes; want adds for the IPs imunify blocked and one delete", adds, deletes)
	}
	if s := stepsOf(res["10.0.0.9"], SrcImunify); len(s) != 2 || !strings.Contains(s[1].Detail, "no white grace entry") {
		t.Errorf("10.0.0.9 imunify steps = %+v, want not-listed + no-grace", s)
	}
}

// A list that isn't one (here an object without "items") is unreadable, not
// empty: every IP is deleted blindly, as before, and an IPv6 IP gets no grace
// entry, since imunify wasn't seen blocking its /64.
func TestDoMany_ImunifyUnreadableListDeletesBlindly(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) echo '{"result":"error"}';; esac`,
	})
	grace := time.Hour
	res := DoMany(context.Background(), ips("198.51.100.1", "2001:db8::1"), Options{ImunifyWhiteTTL: &grace})
	got := strings.Join(calls(), "|")
	for _, want := range []string{
		"delete --purpose drop 198.51.100.1|",
		"delete --purpose drop 2001:db8::/64|",
		"delete --purpose captcha 198.51.100.1|",
		"delete --purpose captcha 2001:db8::/64|",
		"add --purpose white --comment CFM auto-unblock 198.51.100.1 --expiration ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("runs %q lack %q", got, want)
		}
	}
	if strings.Count(got, " add ") != 1 {
		t.Errorf("runs %q: want one white add (the IPv4 IP)", got)
	}
	if s := stepsOf(res["2001:db8::1"], SrcImunify); len(s) != 4 || !strings.Contains(s[0].Detail, "local list unreadable") {
		t.Errorf("2001:db8::1 imunify steps = %+v", s)
	}
}

// A list at the cap may be missing entries: the IPs it didn't show are
// deleted blindly, as before.
func TestDoMany_ImunifyCappedListDeletesUnseen(t *testing.T) {
	var entries []string
	for i := 0; i < 10000; i++ {
		entries = append(entries, fmt.Sprintf(`{"ip":"172.16.%d.%d","netmask":4294967295,"purpose":"drop"}`, i/250, i%250+1))
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "list.json"), []byte(`{"items":[`+strings.Join(entries, ",")+"]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": fmt.Sprintf(`case "$*" in *" list "*) while IFS= read -r l; do echo "$l"; done < %q;; esac`, filepath.Join(dir, "list.json")),
	})
	DoMany(context.Background(), ips("172.16.0.1", "198.51.100.7", "2001:db8::9", "2001:db8::a"), Options{})
	got := strings.Join(calls(), "|")
	for _, want := range []string{
		"delete --purpose drop 172.16.0.1 198.51.100.7|",
		"delete --purpose drop 2001:db8::/64|",
		"delete --purpose captcha 198.51.100.7|",
		"delete --purpose captcha 2001:db8::/64",
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
	removed, err := removeFromFileMany(dir, "cfm.deny", ips("198.51.100.1", "198.51.100.2", "198.51.100.3"))
	if err != nil || len(removed) != 2 || !removed["198.51.100.1"] || !removed["198.51.100.2"] {
		t.Errorf("removed = %v", removed)
	}
	b, _ := os.ReadFile(p) // #nosec G304 -- test temp file
	if string(b) != "# header\n198.51.100.20\n10.0.0.0/8 # net\n" {
		t.Errorf("cfm.deny now:\n%s", b)
	}
	st, _ := os.Stat(p)
	before := st.ModTime()
	time.Sleep(10 * time.Millisecond)
	if r, err := removeFromFileMany(dir, "cfm.deny", ips("192.0.2.1")); err != nil || len(r) != 0 {
		t.Errorf("removed %v, err %v", r, err)
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

// A cfm.deny it can't read to the end is left as is, and the step says so:
// writing back what was read would drop every line after the unreadable one.
func TestRemoveFromFileMany_UnreadableLineKeepsFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfm.deny")
	content := "198.51.100.1\n" + strings.Repeat("x", 2<<20) + "\n198.51.100.2\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	res := DoMany(context.Background(), ips("198.51.100.1"), Options{ConfigDir: dir})
	if s := stepsOf(res["198.51.100.1"], SrcCFMDeny); len(s) != 1 || s[0].Action != ActionError {
		t.Errorf("cfm.deny steps = %+v, want an error", s)
	}
	if b, _ := os.ReadFile(p); string(b) != content { // #nosec G304 -- test temp file
		t.Error("cfm.deny was rewritten")
	}
}

// failingBatchBackend fails the batch remove and records the per-IP ones.
type failingBatchBackend struct {
	firewall.Backend
	removed []string
}

func (b *failingBatchBackend) ListTableTextNoDNS(string, string) (string, error) {
	return "", fmt.Errorf("no feed sets here")
}
func (b *failingBatchBackend) RemoveBlockBatch([]net.IP) error {
	return fmt.Errorf("read inet cfm block_v6: No such file or directory")
}
func (b *failingBatchBackend) RemoveBlock(ip net.IP) error {
	b.removed = append(b.removed, ip.String())
	return nil
}

// A batch remove that fails (a block set missing, a set changing under every
// attempt) falls back to one remove per IP, which tolerates what the batch
// didn't: the IPs still leave the sets, and the unblock isn't reported done
// while they stay blocked.
func TestDoMany_NFTBatchFailureFallsBackPerIP(t *testing.T) {
	fakeTools(t, map[string]string{})
	be := &failingBatchBackend{}
	res := DoMany(context.Background(), ips("198.51.100.1", "2001:db8::1"), Options{BE: be})
	if len(be.removed) != 2 {
		t.Fatalf("per-IP removes %v, want both IPs", be.removed)
	}
	for ip, r := range res {
		if s := stepsOf(r, SrcNFT); len(s) != 1 || s[0].Action != ActionRemoved || !r.WasBlocked ||
			!strings.Contains(s[0].Detail, "after the batch failed: read inet cfm block_v6") {
			t.Errorf("%s nft steps = %+v", ip, s)
		}
	}
}

// imunify's splashscreen (anti-bot) list blocks too: a listed IP is deleted
// from it and, IPv6 included, counts as blocked for the grace entry.
func TestDoMany_ImunifySplashscreen(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) ` + imunifyList(
			`{"ip":"2001:db8:1:2::/64","netmask":340282366920938463444927863358058659840,"purpose":"splashscreen"}`) + `;; esac`,
	})
	grace := time.Hour
	DoMany(context.Background(), ips("2001:db8:1:2::7"), Options{ImunifyWhiteTTL: &grace})
	got := calls()
	if len(got) != 3 || got[1] != "imunify360-agent ip-list local delete --purpose splashscreen 2001:db8:1:2::/64" ||
		!strings.HasPrefix(got[2], "imunify360-agent ip-list local add --purpose white --comment CFM auto-unblock 2001:db8:1:2::/64 ") {
		t.Errorf("imunify runs = %q", got)
	}
}

// A list that says it holds more than it returned (max_count), or has an
// entry it couldn't read, may be missing the IP: unseen IPs are deleted
// blindly from drop and captcha.
func TestDoMany_ImunifyIncompleteListDeletesUnseen(t *testing.T) {
	for name, list := range map[string]string{
		"max_count":         `echo '{"items":[{"ip":"10.0.0.1","netmask":4294967295,"purpose":"drop"}],"max_count":7}'`,
		"unreadable entry":  imunifyList(`{"ip":"10.0.0.1","netmask":4294967295,"purpose":"drop"}`, `{"netmask":4294967295,"purpose":"drop"}`),
		"entry, no purpose": imunifyList(`{"ip":"10.0.0.1","netmask":4294967295,"purpose":"drop"}`, `{"ip":"10.0.0.2","netmask":4294967295}`),
	} {
		t.Run(name, func(t *testing.T) {
			calls := fakeTools(t, map[string]string{"imunify360-agent": `case "$*" in *" list "*) ` + list + `;; esac`})
			res := DoMany(context.Background(), ips("10.0.0.1", "10.0.0.2"), Options{})
			got := strings.Join(calls(), "|")
			for _, want := range []string{"delete --purpose drop 10.0.0.1 10.0.0.2|", "delete --purpose captcha 10.0.0.2"} {
				if !strings.Contains(got, want) {
					t.Errorf("runs %q lack %q", got, want)
				}
			}
			if s := stepsOf(res["10.0.0.2"], SrcImunify); len(s) == 0 || !strings.Contains(s[0].Detail, "local list incomplete") {
				t.Errorf("10.0.0.2 imunify steps = %+v", s)
			}
		})
	}
}

// A delete run for several entries that fails is run again one entry per
// run: the entry imunify refuses fails alone, the others are deleted.
func TestDoMany_ImunifyFailedRunRetriedPerEntry(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) ` + imunifyList(
			`{"ip":"10.0.0.1","netmask":4294967295,"purpose":"drop"}`,
			`{"ip":"10.0.0.2","netmask":4294967295,"purpose":"drop"}`) + `;;
*delete*10.0.0.2*) echo "IP 10.0.0.2 not found"; exit 1;; esac`,
	})
	res := DoMany(context.Background(), ips("10.0.0.1", "10.0.0.2"), Options{})
	got := calls()
	want := []string{
		"imunify360-agent ip-list local delete --purpose drop 10.0.0.1 10.0.0.2",
		"imunify360-agent ip-list local delete --purpose drop 10.0.0.1",
		"imunify360-agent ip-list local delete --purpose drop 10.0.0.2",
	}
	if len(got) != 4 || strings.Join(got[1:], "|") != strings.Join(want, "|") {
		t.Fatalf("imunify runs = %q, want the list then %q", got, want)
	}
	if s := stepsOf(res["10.0.0.1"], SrcImunify); len(s) != 1 || s[0].Action != ActionChecked || !strings.HasPrefix(s[0].Detail, "alone, after a run for 2 IPs failed") {
		t.Errorf("10.0.0.1 imunify steps = %+v", s)
	}
	if s := stepsOf(res["10.0.0.2"], SrcImunify); len(s) != 1 || s[0].Action != ActionError {
		t.Errorf("10.0.0.2 imunify steps = %+v", s)
	}
}

// CFM's own earlier grace entry is refreshed; an operator's white entry is
// left alone.
func TestDoMany_ImunifyGraceRefreshesOwnEntryOnly(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) ` + imunifyList(
			`{"ip":"10.0.0.1","netmask":4294967295,"purpose":"white","comment":"CFM auto-unblock"}`,
			`{"ip":"10.0.0.2","netmask":4294967295,"purpose":"white","comment":"office"}`) + `;; esac`,
	})
	grace := time.Hour
	DoMany(context.Background(), ips("10.0.0.1", "10.0.0.2"), Options{ImunifyWhiteTTL: &grace})
	var adds []string
	for _, c := range calls() {
		if strings.Contains(c, " add ") {
			adds = append(adds, c)
		}
	}
	if len(adds) != 1 || !strings.Contains(adds[0], " 10.0.0.1 ") {
		t.Errorf("white adds = %q, want only 10.0.0.1's refresh", adds)
	}
}

// halfAllowBackend fails the IPv6 allow batch.
type halfAllowBackend struct {
	feedBackend
}

func (b *halfAllowBackend) AddAllowBatch(e []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	if e[0].IP.To4() == nil {
		return firewall.BlockBatchResult{}, fmt.Errorf("read inet cfm allow_v6: No such file or directory")
	}
	return b.feedBackend.AddAllowBatch(e)
}

// The allow batch runs per address family: a family whose set can't be read
// fails only its own IPs.
func TestDoMany_FeedAllowPerFamily(t *testing.T) {
	fakeTools(t, map[string]string{})
	be := &halfAllowBackend{feedBackend{feed: []string{"198.51.100.1", "2001:db8::1"}}}
	res := DoMany(context.Background(), ips("198.51.100.1", "2001:db8::1"), Options{BE: be, TempWhitelist: true})
	if !res["198.51.100.1"].Whitelisted || res["2001:db8::1"].Whitelisted {
		t.Errorf("whitelisted: v4 %v, v6 %v; want v4 only", res["198.51.100.1"].Whitelisted, res["2001:db8::1"].Whitelisted)
	}
	if be.batches != 1 || !be.allowed[0].Permanent {
		t.Errorf("v4 batch: %d batches, %+v", be.batches, be.allowed)
	}
}

// An IPv6 line written with /32 is a network, not the IP: only /128 is.
func TestRemoveFromFileMany_IPv6HostSuffix(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfm.deny")
	if err := os.WriteFile(p, []byte("2001:db8::1/32\n2001:db8::1/128\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := removeFromFileMany(dir, "cfm.deny", ips("2001:db8::1")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "2001:db8::1/32\n" { // #nosec G304 -- test temp file
		t.Errorf("cfm.deny now %q", b)
	}
}

// A country entry has no address and isn't an IP entry: it doesn't make the
// list incomplete. A warning imunify writes to stderr doesn't make the list
// unreadable either: only stdout is parsed.
func TestDoMany_ImunifyCountryEntryAndStderrWarning(t *testing.T) {
	calls := fakeTools(t, map[string]string{
		"imunify360-agent": `case "$*" in *" list "*) echo "WARNING: deprecated option" >&2; ` + imunifyList(
			`{"ip":"10.0.0.1","netmask":4294967295,"purpose":"drop"}`,
			`{"ip":null,"country":{"code":"CN"},"type":"country","purpose":"drop"}`) + `;; esac`,
	})
	res := DoMany(context.Background(), ips("10.0.0.1", "10.0.0.2"), Options{})
	got := calls()
	if len(got) != 2 || got[1] != "imunify360-agent ip-list local delete --purpose drop 10.0.0.1" {
		t.Errorf("imunify runs = %q, want the list then 10.0.0.1's delete alone", got)
	}
	if s := stepsOf(res["10.0.0.2"], SrcImunify); len(s) != 1 || s[0].Action != ActionNotFound {
		t.Errorf("10.0.0.2 imunify steps = %+v, want not listed", s)
	}
}

func TestImunifyEntryKey(t *testing.T) {
	for entry, want := range map[string]string{
		"198.51.100.1":            "198.51.100.1",
		"198.51.100.1/32":         "198.51.100.1",
		"198.51.100.0/24":         "",
		"2001:db8:1:2::/64":       "2001:db8:1:2::/64",
		"2001:db8:1:2::7":         "2001:db8:1:2::/64",
		"2001:db8:1:2::7/128":     "2001:db8:1:2::/64",
		"2001:db8::/48":           "",
		"::ffff:198.51.100.1/128": "198.51.100.1",
		"::ffff:198.51.100.0/120": "",
		"::ffff:0:0/96":           "",
		"not an address":          "",
	} {
		if got := imunifyEntryKey(entry); got != want {
			t.Errorf("imunifyEntryKey(%q) = %q, want %q", entry, got, want)
		}
	}
}

// unreadableFeedBackend lists feed sets it can't dump whole; HasElem answers
// for failAt probes, then fails.
type unreadableFeedBackend struct {
	feedBackend
	holds  string
	probes int
	failAt int
}

func (b *unreadableFeedBackend) ListSetElementsRaw(string) ([]string, error) {
	return nil, fmt.Errorf("nft -j list set: timed out")
}
func (b *unreadableFeedBackend) HasElem(_, elem string) (bool, error) {
	b.probes++
	if b.failAt > 0 && b.probes >= b.failAt {
		return false, fmt.Errorf("nft get element: timed out")
	}
	return elem == b.holds, nil
}

// A feed set that can't be read whole is probed IP by IP; when a probe fails
// too, the IPs left unprobed get an error step instead of passing for
// unblocked while the feed may still block them.
func TestDoMany_FeedSetUnreadable(t *testing.T) {
	fakeTools(t, map[string]string{})
	be := &unreadableFeedBackend{holds: "198.51.100.2"}
	res := DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "198.51.100.3"), Options{BE: be})
	if r := res["198.51.100.2"]; len(r.FromFeeds) != 1 || r.FromFeeds[0] != "MYBLOCK" {
		t.Errorf("probed feed IP: feeds %v", r.FromFeeds)
	}

	be = &unreadableFeedBackend{failAt: 2}
	res = DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "198.51.100.3"), Options{BE: be})
	if be.probes != 2 {
		t.Errorf("%d probes, want the failing one to stop them", be.probes)
	}
	if s := stepsOf(res["198.51.100.1"], SrcFeeds); len(s) != 0 {
		t.Errorf("198.51.100.1 (probed, not held) feed steps = %+v", s)
	}
	for _, ip := range []string{"198.51.100.2", "198.51.100.3"} {
		if s := stepsOf(res[ip], SrcFeeds); len(s) != 1 || s[0].Action != ActionError || !strings.Contains(s[0].Err, "block_ext_v4_hosts_MYBLOCK: nft get element: timed out") {
			t.Errorf("%s feed steps = %+v", ip, s)
		}
	}
}

// flakyAllowBackend fails any allow batch of more than one entry, and a
// single entry for failIP.
type flakyAllowBackend struct {
	feedBackend
	failIP string
}

func (b *flakyAllowBackend) AddAllowBatch(e []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	if len(e) > 1 || e[0].IP.String() == b.failIP {
		return firewall.BlockBatchResult{}, fmt.Errorf("set changed under every attempt")
	}
	return b.feedBackend.AddAllowBatch(e)
}

// A failed allow batch is retried one entry per batch until one fails too;
// the entries after that keep its error.
func TestDoMany_FeedAllowBatchFallsBackPerEntry(t *testing.T) {
	fakeTools(t, map[string]string{})
	be := &flakyAllowBackend{feedBackend: feedBackend{feed: []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}}, failIP: "198.51.100.2"}
	res := DoMany(context.Background(), ips("198.51.100.1", "198.51.100.2", "198.51.100.3"), Options{BE: be, TempWhitelist: true})
	if !res["198.51.100.1"].Whitelisted || res["198.51.100.2"].Whitelisted || res["198.51.100.3"].Whitelisted {
		t.Errorf("whitelisted: %v %v %v; want only the first", res["198.51.100.1"].Whitelisted, res["198.51.100.2"].Whitelisted, res["198.51.100.3"].Whitelisted)
	}
}
