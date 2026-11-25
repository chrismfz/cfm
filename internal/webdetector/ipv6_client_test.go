package webdetector

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/firewall"
)

func TestGroupIPAggs(t *testing.T) {
	type a struct{ n int }
	per := map[string]*a{
		"2001:db8:1:2::a": {1},
		"2001:db8:1:2::b": {5},
		"2001:db8:1:2::c": {2},
		"2001:db8:1:3::a": {1},
		"203.0.113.7":     {4},
		"203.0.113.8":     {4},
	}
	got, groups := groupIPAggs(per, func(d, s *a) { d.n += s.n }, func(x *a) int { return x.n }, func() *a { return &a{} })
	if len(got) != 4 || got["2001:db8:1:2::b"].n != 8 || got["203.0.113.7"].n != 4 || got["203.0.113.8"].n != 4 {
		t.Fatalf("grouped: %v", got)
	}
	if g := groups["2001:db8:1:2::b"]; g.client != "2001:db8:1:2::/64" || strings.Join(g.addrs, ",") != "2001:db8:1:2::b,2001:db8:1:2::c,2001:db8:1:2::a" {
		t.Fatalf("group: %+v", g)
	}
	if g := groups["2001:db8:1:3::a"]; g.client != "2001:db8:1:3::/64" || len(g.addrs) != 1 {
		t.Fatalf("a single address of a /64: %+v", g)
	}
	if _, ok := groups["203.0.113.7"]; ok {
		t.Fatal("IPv4 grouped")
	}
	// A guarded /64 stays per address (as its ban).
	firewall.SetClientNetExempt("wd-test", func(p netip.Prefix) bool { return p.String() == "2001:db8:1:2::/64" })
	t.Cleanup(func() { firewall.SetClientNetExempt("wd-test", nil) })
	got, groups = groupIPAggs(per, func(d, s *a) { d.n += s.n }, func(x *a) int { return x.n }, func() *a { return &a{} })
	if got["2001:db8:1:2::b"].n != 5 || got["2001:db8:1:2::a"] == nil || groups["2001:db8:1:2::b"].client != "" {
		t.Fatalf("guarded /64 grouped: %v %v", got, groups)
	}
	// Capped addresses per client.
	many := map[string]*a{}
	for i := 0; i < 40; i++ {
		many[fmt.Sprintf("2001:db8:9:9::%x", i+1)] = &a{i + 1}
	}
	got, groups = groupIPAggs(many, func(d, s *a) { d.n += s.n }, func(x *a) int { return x.n }, func() *a { return &a{} })
	if len(got) != 1 || got["2001:db8:9:9::28"].n != 820 || len(groups["2001:db8:9:9::28"].addrs) != maxClientAddrs {
		t.Fatalf("many: %d rows, %+v", len(got), groups)
	}
}

// 404s from three addresses of one /64, each under IP404_COUNT, are one
// client over it: the row names its busiest address and its /64. IPv4
// addresses never add up.
func TestIP404FloodCountsAnIPv6ClientsSlash64(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, IP404Count: 3})
	now := float64(time.Now().Unix())
	hit := func(ip string, i int) {
		e.ingest(LogRec{TS: now + float64(i), IP: ip, Host: "example.com", Method: "get", URI: fmt.Sprintf("/missing-%d", i), Status: 404, UA: "ua"}, "raw")
	}
	hit("2001:db8:1:2::a", 0)
	hit("2001:db8:1:2::b", 1)
	hit("2001:db8:1:2::b", 2)
	hit("203.0.113.7", 3)
	hit("203.0.113.8", 4)
	hit("203.0.113.8", 5)
	var v6 *IPSignals
	for i, r := range e.IPShort(0) {
		if strings.HasPrefix(r.IP, "203.0.113.") {
			for _, reason := range r.Reasons {
				if strings.HasPrefix(reason, "404_flood") {
					t.Fatalf("IPv4 addresses added up: %+v", r)
				}
			}
		}
		if r.Client == "2001:db8:1:2::/64" {
			v6 = &e.IPShort(0)[i]
		}
	}
	if v6 == nil || v6.IP != "2001:db8:1:2::b" || len(v6.Addrs) != 2 {
		t.Fatalf("the /64 row: %+v", v6)
	}
	flood := false
	for _, reason := range v6.Reasons {
		flood = flood || strings.HasPrefix(reason, "404_flood")
	}
	if !flood {
		t.Fatalf("no 404_flood for the /64: %v", v6.Reasons)
	}
}

// The vhost uniqIP count counts clients: a client rotating inside its /64
// is one, not a crowd.
func TestUniqueIPsCountsClients(t *testing.T) {
	counts := map[string]int{"2001:db8:1:2::a": 1, "2001:db8:1:2::b": 1, "2001:db8:1:2::c": 1, "203.0.113.7": 1, "203.0.113.8": 1}
	if n := countedUniqueIPs(counts, nil); n != 3 {
		t.Fatalf("unique = %d, want 3 (one /64, two IPv4)", n)
	}
	if n := countedUniqueIPs(counts, map[string]int{"203.0.113.7": 1, "2001:db8:1:2::a": 1}); n != 2 {
		t.Fatalf("with exempt = %d, want 2", n)
	}
}

// A /64 over a per-IP challenge threshold is challenged on each of its
// addresses; only one of the alerts notifies.
func TestChallengeFansOutToTheClientsAddresses(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, ChallengeIPMalformedMin: 3, ChallengeNotify: true})
	now := float64(time.Now().Unix())
	for i, ip := range []string{"2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:1:2::b", "2001:db8:1:2::c"} {
		e.ingest(LogRec{TS: now + float64(i), IP: ip, Host: "example.com", Method: "get", URI: "/x", Status: 400, UA: "ua"}, "raw")
	}
	out := make(chan core.Alert, 16)
	e.emitIPChallenges(time.Now(), out)
	close(out)
	got := map[string]string{}
	for a := range out {
		if a.Extra["rule"] != "CHALLENGE_MALFORMED" {
			continue
		}
		if a.Extra["client"] != "2001:db8:1:2::/64" {
			t.Fatalf("alert without its client: %+v", a.Extra)
		}
		got[a.Key] = a.Extra["challenge_notify"]
	}
	notifying := 0
	for _, n := range got {
		if n != "0" {
			notifying++
		}
	}
	if len(got) != 3 || notifying != 1 {
		t.Fatalf("challenged %v, want all three, one notifying", got)
	}
}

// The challenge server's page limit holds an IPv6 client as its /64: a new
// address of it does not get a fresh burst.
func TestChallengeServerLimitsAnIPv6ClientsSlash64(t *testing.T) {
	s := &ChallengeServer{}
	for i := 0; i < rlPageBurst; i++ {
		if ok, _, _ := s.rlAllow(fmt.Sprintf("2001:db8:1:2::%x", i+1), rlKindPage); !ok {
			t.Fatalf("request %d limited early", i+1)
		}
	}
	if ok, _, banned := s.rlAllow("2001:db8:1:2::ffff", rlKindPage); ok || !banned {
		t.Fatalf("a fresh address of the /64: ok=%v banned=%v, want limited", ok, banned)
	}
	if ok, _, _ := s.rlAllow("2001:db8:1:3::1", rlKindPage); !ok {
		t.Fatal("another /64 limited")
	}
	if ok, _, _ := s.rlAllow("203.0.113.7", rlKindPage); !ok {
		t.Fatal("IPv4 limited")
	}
}

// Every per-IP challenge aggregator of emitIPChallenges groups an IPv6
// client and judges each member through its own gates (uniq paths/hosts,
// CHALLENGE_PATHS, the thresholds, malformed, UA churn); the unit tests drive
// malformed and CHALLENGE_PATHS.
func TestEveryPerIPChallengeAggregatorGroupsClients(t *testing.T) {
	b, err := os.ReadFile("challenge_rules.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if n := strings.Count(src, "groupIPAggs("); n != 5 {
		t.Fatalf("groupIPAggs calls: %d, want 5", n)
	}
	if n := strings.Count(src, "expandClients("); n != 4 { // CHALLENGE_PATHS expands its ranked candidates
		t.Fatalf("expandClients calls: %d, want 4", n)
	}
	for _, call := range []string{"tk.can(", "tk.take(", "tk.notify("} {
		if n := strings.Count(src, call); n != 5 {
			t.Fatalf("%s calls: %d, want 5", call, n)
		}
	}
}

// emitIPBlocks bans an IPv6 client once per cooldown, whichever of its
// addresses is the busiest that tick, and names it (the ban takes the /64).
func TestEmitIPBlocksOncePerClient(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, IP404Count: 3})
	now := float64(time.Now().Unix())
	hit := func(ip string, i int) {
		e.ingest(LogRec{TS: now + float64(i), IP: ip, Host: "example.com", Method: "get", URI: fmt.Sprintf("/missing-%d", i), Status: 404, UA: "ua"}, "raw")
	}
	hit("2001:db8:1:2::a", 0)
	hit("2001:db8:1:2::a", 1)
	hit("2001:db8:1:2::b", 2)
	tick := func() []core.Alert {
		out := make(chan core.Alert, 8)
		e.emitIPBlocks(time.Now(), out)
		close(out)
		var got []core.Alert
		for a := range out {
			got = append(got, a)
		}
		return got
	}
	got := tick()
	if len(got) != 1 || got[0].Extra["ip"] != "2001:db8:1:2::a" || got[0].Extra["client"] != "2001:db8:1:2::/64" {
		t.Fatalf("first tick: %+v", got)
	}
	for i := 3; i < 8; i++ {
		hit("2001:db8:1:2::c", i) // ::c is now the busiest
	}
	if got := tick(); len(got) != 0 {
		t.Fatalf("the same client inside the cooldown: %+v", got)
	}
}

// Every member of a grouped client goes through its own gates: an excluded
// address (however busy) is not challenged and shields no neighbour, and
// the members beyond each client's first are bounded per tick.
func TestChallengeMembersOwnGatesAndBudget(t *testing.T) {
	malformed := func(e *Engine, ips ...string) {
		now := float64(time.Now().Unix())
		for i, ip := range ips {
			e.ingest(LogRec{TS: now + float64(i), IP: ip, Host: "example.com", Method: "get", URI: "/x", Status: 400, UA: "ua"}, "raw")
		}
	}
	drain := func(e *Engine) map[string]core.Alert {
		out := make(chan core.Alert, 1024)
		e.emitIPChallenges(time.Now(), out)
		close(out)
		got := map[string]core.Alert{}
		for a := range out {
			if a.Extra["rule"] == "CHALLENGE_MALFORMED" {
				got[a.Key] = a
			}
		}
		return got
	}
	cfg := Config{Every: time.Second, Window: 2 * time.Minute, ChallengeIPMalformedMin: 3, ChallengeNotify: true}

	e := NewEngine(cfg)
	e.chalExcludeFunc = func(ip, host, ua, asn, ptr, rule string) (string, bool) {
		return "monitor", ip == "2001:db8:1:2::b"
	}
	malformed(e, "2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:1:2::b", "2001:db8:1:2::b", "2001:db8:1:2::c")
	got := drain(e)
	if _, ok := got["2001:db8:1:2::b"]; ok || got["2001:db8:1:2::a"].Key == "" || got["2001:db8:1:2::c"].Key == "" {
		t.Fatalf("the excluded busiest address shielded its neighbours or was challenged: %v", keys(got))
	}
	if n := got["2001:db8:1:2::a"].Extra["challenge_notify"] + got["2001:db8:1:2::c"].Extra["challenge_notify"]; strings.Count(n, "0") != 1 {
		t.Fatalf("notify flags %q, want exactly one of the two notifying", n)
	}

	e = NewEngine(cfg)
	var ips []string
	for c := 0; c < 5; c++ { // 5 clients x 16 members: past the budget
		for i := 0; i < maxClientAddrs; i++ {
			ips = append(ips, fmt.Sprintf("2001:db8:%x:1::%x", c, i+1))
		}
	}
	malformed(e, ips...)
	if n := len(drain(e)); n != 5+maxExtraMembersPerTick {
		t.Fatalf("challenged %d members, want %d (each client's first + the budget)", n, 5+maxExtraMembersPerTick)
	}
}

func keys(m map[string]core.Alert) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A new malpath hit from another address of a /64 is challenged on its own
// gate, though an earlier, busier address of the /64 was challenged already
// and the new address alone is under the rule's count (CHALLENGE_PATHS carries
// the v2 mark and the clearance revoke).
func TestChallengePathsNewMemberHitIsChallenged(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, ChallengePathsEnabled: true, ChallengePathsList: []string{"2:/.env"}, ChallengePathsCount: 2})
	t0 := float64(time.Now().Unix())
	hit := func(ts float64, ip string) {
		e.ingest(LogRec{TS: ts, IP: ip, Host: "example.com", Method: "get", URI: "/.env", Status: 404, UA: "ua"}, "raw")
	}
	tick := func(at time.Time) []string {
		out := make(chan core.Alert, 32)
		e.emitIPChallenges(at, out)
		close(out)
		var got []string
		for a := range out {
			if a.Extra["rule"] == "CHALLENGE_PATHS" {
				got = append(got, a.Key)
			}
		}
		return got
	}
	hit(t0, "2001:db8:1:2::1")
	hit(t0+1, "2001:db8:1:2::1")
	if got := tick(time.Now()); len(got) != 1 || got[0] != "2001:db8:1:2::1" {
		t.Fatalf("first tick: %v", got)
	}
	hit(t0+10, "2001:db8:1:2::9")
	got := tick(time.Now().Add(10 * time.Second))
	found := false
	for _, k := range got {
		found = found || k == "2001:db8:1:2::9"
	}
	if !found {
		t.Fatalf("the new member's malpath hit was not challenged: %v", got)
	}
}

// A member past the section's budget keeps its malpath hit for the next tick
// (its emit gate is written only once it is judged), and the topN ranking
// takes one candidate per client, so a few /64s never crowd out another
// address's malpath hit.
func TestChallengePathsBudgetAndRanking(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, ChallengePathsEnabled: true, ChallengePathsList: []string{"/.env"}, ChallengePathsCount: 1})
	t0 := float64(time.Now().Add(-time.Minute).Unix()) // hits before the ticks
	n := 0
	for c := 0; c < 5; c++ { // 5 clients x 16 members: past the budget
		for i := 0; i < maxClientAddrs; i++ {
			e.ingest(LogRec{TS: t0 + float64(n)/100, IP: fmt.Sprintf("2001:db8:%x:1::%x", c, i+1), Host: "example.com", Method: "get", URI: "/.env", Status: 404, UA: "ua"}, "raw")
			n++
		}
	}
	e.ingest(LogRec{TS: t0 + 2, IP: "203.0.113.9", Host: "example.com", Method: "get", URI: "/.env", Status: 404, UA: "ua"}, "raw")
	tick := func(at time.Time) map[string]bool {
		out := make(chan core.Alert, 256)
		e.emitIPChallenges(at, out)
		close(out)
		got := map[string]bool{}
		for a := range out {
			if a.Extra["rule"] == "CHALLENGE_PATHS" {
				got[a.Key] = true
			}
		}
		return got
	}
	first := tick(time.Now())
	if !first["203.0.113.9"] {
		t.Fatal("the IPv4 hitter was crowded out of the ranking by the /64s' members")
	}
	if len(first) != 1+5+maxExtraMembersPerTick {
		t.Fatalf("first tick challenged %d, want %d", len(first), 1+5+maxExtraMembersPerTick)
	}
	seen := first
	for k := 1; k <= 3; k++ { // the budget refills each tick: every hitter in turn
		for ip := range tick(time.Now().Add(time.Duration(k) * 10 * time.Second)) {
			if seen[ip] {
				t.Fatalf("%s challenged twice for one hit", ip)
			}
			seen[ip] = true
		}
	}
	if len(seen) != 1+5*maxClientAddrs {
		t.Fatalf("over the ticks %d challenged, want every hitter (%d): a member past the budget lost its hit", len(seen), 1+5*maxClientAddrs)
	}
}

// Each of the other per-IP challenge rules judges a /64's members on the
// client's counts: three addresses, each under the rule alone, are all
// challenged together (unique paths, the no-UA threshold, UA churn).
func TestPerIPChallengeRulesJudgeTheClient(t *testing.T) {
	cases := []struct {
		rule string
		cfg  Config
		rec  func(i int) (uri, ua string)
	}{
		{"CHALLENGE_UNIQPATHS_IP", Config{ChallengeIPUniqPathsEnabled: true, ChallengeIPUniqPathsMin: 3}, func(i int) (string, string) { return fmt.Sprintf("/p%d", i), "ua" }},
		{"CHALLENGE_NO_UA", Config{ChallengeIPNoUAMin: 3}, func(i int) (string, string) { return "/x", "" }},
		{"CHALLENGE_UNIQUA", Config{ChallengeIPUniqUAMin: 3}, func(i int) (string, string) { return "/x", fmt.Sprintf("ua%d", i) }},
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			cfg := c.cfg
			cfg.Every, cfg.Window, cfg.ChallengeNotify = time.Second, 2*time.Minute, true
			e := NewEngine(cfg)
			t0 := float64(time.Now().Add(-time.Minute).Unix())
			for i, ip := range []string{"2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:1:2::c"} {
				uri, ua := c.rec(i)
				e.ingest(LogRec{TS: t0 + float64(i), IP: ip, Host: "example.com", Method: "get", URI: uri, Status: 404, UA: ua}, "raw")
			}
			e.ingest(LogRec{TS: t0, IP: "203.0.113.7", Host: "example.com", Method: "get", URI: "/x", Status: 404, UA: "ua"}, "raw")
			out := make(chan core.Alert, 32)
			e.emitIPChallenges(time.Now(), out)
			close(out)
			got := map[string]bool{}
			notifying := 0
			for a := range out {
				if a.Extra["rule"] != c.rule {
					continue
				}
				got[a.Key] = true
				if a.Extra["challenge_notify"] != "0" {
					notifying++
				}
			}
			if len(got) != 3 || got["203.0.113.7"] || notifying != 1 {
				t.Fatalf("challenged %v (%d notifying), want the three /64 members, one notifying", got, notifying)
			}
		})
	}
}

// A client's new address is judged though 16 older ones fill its window
// (the members are its most recent, not its busiest).
func TestChallengePathsSeventeenthAddress(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, ChallengePathsEnabled: true, ChallengePathsList: []string{"/.env"}, ChallengePathsCount: 1})
	t0 := float64(time.Now().Add(-time.Minute).Unix())
	hit := func(ts float64, ip string) {
		e.ingest(LogRec{TS: ts, IP: ip, Host: "example.com", Method: "get", URI: "/.env", Status: 404, UA: "ua"}, "raw")
	}
	for i := 0; i < maxClientAddrs; i++ {
		hit(t0+float64(i), fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	tick := func(at time.Time) map[string]bool {
		out := make(chan core.Alert, 64)
		e.emitIPChallenges(at, out)
		close(out)
		got := map[string]bool{}
		for a := range out {
			if a.Extra["rule"] == "CHALLENGE_PATHS" {
				got[a.Key] = true
			}
		}
		return got
	}
	if n := len(tick(time.Now())); n != maxClientAddrs {
		t.Fatalf("first tick: %d challenged, want %d", n, maxClientAddrs)
	}
	hit(t0+30, "2001:db8:1:2::ff")
	if got := tick(time.Now().Add(10 * time.Second)); !got["2001:db8:1:2::ff"] {
		t.Fatalf("the client's 17th address was not challenged: %v", got)
	}
}

// CHALLENGE_NO_UA counts pages, never static files: an integration fetching a
// shop's product images with no User-Agent (vol2.gr's e|connect bridge) was
// challenged, and its WooCommerce REST calls got the challenge page for ten
// minutes. A query cannot make a page look like a file.
func TestNoUAChallengeSkipsStaticFiles(t *testing.T) {
	run := func(uris []string) bool { return noUAChallenged(t, uris, 200) }
	if !noUAChallenged(t, []string{"/composer.json", "/.vscode/sftp.json", "/config.json"}, 404) {
		t.Fatal("a no-UA scanner probing missing json files was not challenged: a static MISS must still count")
	}
	if !run([]string{"/shop/", "/product/a/", "/product/b/"}) {
		t.Fatal("three pages with no User-Agent were not challenged: pages must still count")
	}
	var images []string
	for i := 0; i < 10; i++ {
		images = append(images, fmt.Sprintf("/s1images/item_%d_05.jpg", i))
	}
	if run(images) {
		t.Fatal("ten image HEADs with no User-Agent challenged the IP: static files the site has must not count")
	}
	if !run([]string{"/shop/?x=/a.jpg", "/product/a/?f=b.css", "/product/b/?y=/c.png"}) {
		t.Fatal("pages whose query ends in a file extension were not challenged: the query must not hide a page")
	}
}

// noUAChallenged reports whether uris, fetched with no User-Agent and
// answered with status, earn the IP a CHALLENGE_NO_UA.
func noUAChallenged(t *testing.T, uris []string, status int) bool {
	t.Helper()
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, ChallengeIPNoUAMin: 3, ChallengeNotify: true})
	t0 := float64(time.Now().Add(-time.Minute).Unix())
	for i, u := range uris {
		e.ingest(LogRec{TS: t0 + float64(i), IP: "194.48.152.107", Host: "vol2.gr", Method: "head", URI: u, Status: status, UA: ""}, "raw")
	}
	out := make(chan core.Alert, 32)
	e.emitIPChallenges(time.Now(), out)
	close(out)
	for a := range out {
		if a.Extra["rule"] == "CHALLENGE_NO_UA" {
			return true
		}
	}
	return false
}
