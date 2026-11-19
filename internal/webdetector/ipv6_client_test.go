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
// addresses; only the busiest one notifies.
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
	if len(got) != 3 || got["2001:db8:1:2::b"] == "0" || got["2001:db8:1:2::a"] != "0" || got["2001:db8:1:2::c"] != "0" {
		t.Fatalf("challenged %v, want all three, the busiest (::b) notifying", got)
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
// client and fans its challenge out (uniq paths/hosts, CHALLENGE_PATHS, the
// thresholds, malformed, UA churn); the unit tests above drive malformed.
func TestEveryPerIPChallengeAggregatorGroupsClients(t *testing.T) {
	b, err := os.ReadFile("challenge_rules.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if n := strings.Count(src, "groupIPAggs("); n != 5 {
		t.Fatalf("groupIPAggs calls: %d, want 5", n)
	}
	if n := strings.Count(src, "e.fanOutChallenge("); n != 5 {
		t.Fatalf("fanOutChallenge calls: %d, want 5", n)
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

// The busiest address's exclude decides for the client (an excluded busiest
// address fans out nothing, so no client is challenged with nobody
// notified), its alert goes out before the fan-out's, and the fan-out of one
// tick is bounded.
func TestChallengeFanOutOrderAndBounds(t *testing.T) {
	malformed := func(e *Engine, ips ...string) {
		now := float64(time.Now().Unix())
		for i, ip := range ips {
			e.ingest(LogRec{TS: now + float64(i), IP: ip, Host: "example.com", Method: "get", URI: "/x", Status: 400, UA: "ua"}, "raw")
		}
	}
	drain := func(e *Engine, n int) []core.Alert {
		out := make(chan core.Alert, n)
		e.emitIPChallenges(time.Now(), out)
		close(out)
		var got []core.Alert
		for a := range out {
			if a.Extra["rule"] == "CHALLENGE_MALFORMED" {
				got = append(got, a)
			}
		}
		return got
	}
	cfg := Config{Every: time.Second, Window: 2 * time.Minute, ChallengeIPMalformedMin: 3, ChallengeNotify: true}

	e := NewEngine(cfg)
	e.chalExcludeFunc = func(ip, host, ua, asn, ptr, rule string) (string, bool) {
		return "monitor", ip == "2001:db8:1:2::b"
	}
	malformed(e, "2001:db8:1:2::a", "2001:db8:1:2::b", "2001:db8:1:2::b", "2001:db8:1:2::c")
	if got := drain(e, 16); len(got) != 0 {
		t.Fatalf("an excluded busiest address fanned out: %+v", got)
	}

	// 20 addresses into a 4-slot channel: the busiest address's alert is
	// the first one in it.
	e = NewEngine(cfg)
	ips := []string{"2001:db8:1:2::bad", "2001:db8:1:2::bad"}
	for i := 0; i < 20; i++ {
		ips = append(ips, fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	malformed(e, ips...)
	if got := drain(e, 4); len(got) == 0 || got[0].Key != "2001:db8:1:2::bad" || got[0].Extra["challenge_notify"] == "0" {
		t.Fatalf("the busiest address's alert is not first: %+v", got)
	}

	// The budget: at most maxFanOutPerTick fan-out alerts a tick.
	e = NewEngine(cfg)
	ips = nil
	for c := 0; c < 5; c++ { // 5 clients x 15 others: past the cap
		for i := 0; i < maxClientAddrs; i++ {
			ips = append(ips, fmt.Sprintf("2001:db8:%x:1::%x", c, i+1))
		}
		ips = append(ips, fmt.Sprintf("2001:db8:%x:1::1", c), fmt.Sprintf("2001:db8:%x:1::1", c))
	}
	malformed(e, ips...)
	got := drain(e, 1024)
	fan := 0
	for _, a := range got {
		if a.Extra["challenge_notify"] == "0" {
			fan++
		}
	}
	if fan > maxFanOutPerTick || len(got)-fan != 5 {
		t.Fatalf("fan-out %d (cap %d), busiest %d (want 5)", fan, maxFanOutPerTick, len(got)-fan)
	}
}

// A fan-out's gate is its own per rule: an address fanned out for one rule
// still emits its own alert for another rule the same tick (CHALLENGE_PATHS
// and its v2 mark must not be pre-empted by another rule's fan-out).
func TestFanOutNeverPreemptsAnAddressesOwnRule(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, ChallengeIPMalformedMin: 3, ChallengeIPUniqUAMin: 3, ChallengeNotify: true})
	now := float64(time.Now().Unix())
	rec := func(i int, ip, ua string, status int) {
		e.ingest(LogRec{TS: now + float64(i), IP: ip, Host: "example.com", Method: "get", URI: "/x", Status: status, UA: ua}, "raw")
	}
	// ::a is the busiest malformed sender; ::b is fanned out for it, and is
	// itself the client's busiest UA rotator.
	rec(0, "2001:db8:1:2::a", "ua", 400)
	rec(1, "2001:db8:1:2::a", "ua", 400)
	rec(2, "2001:db8:1:2::a", "ua", 400)
	rec(3, "2001:db8:1:2::b", "ua1", 400)
	rec(4, "2001:db8:1:2::b", "ua2", 200)
	rec(5, "2001:db8:1:2::b", "ua3", 200)
	out := make(chan core.Alert, 32)
	e.emitIPChallenges(time.Now(), out)
	close(out)
	var malfB, uaB bool
	for a := range out {
		if a.Key != "2001:db8:1:2::b" {
			continue
		}
		switch a.Extra["rule"] {
		case "CHALLENGE_MALFORMED":
			malfB = a.Extra["challenge_notify"] == "0"
		case "CHALLENGE_UNIQUA":
			uaB = true
		}
	}
	if !malfB || !uaB {
		t.Fatalf("::b fanned out for MALFORMED=%v, its own UNIQUA alert=%v; want both", malfB, uaB)
	}
}
