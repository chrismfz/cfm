package webdetector

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"testing"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
)

// setBypass sets the bridge's IGNORE_IPS predicate as SetBypassFunc does,
// without asking the edge ban list for a rebuild (the tests count rebuilds).
func setBypass(b *NginxBridge, fn func(string) bool) {
	if fn == nil {
		b.bypassFn.Store(nil)
		return
	}
	b.bypassFn.Store(&fn)
}

// scanCounter counts the keys a sync looks at (the bypass check is asked once per
// key): a rebuild asks it for every ban, a change for the changed keys only.
func scanCounter(b *NginxBridge) *int {
	n := new(int)
	setBypass(b, func(string) bool { *n++; return false })
	return n
}

// A ban, an unban and a reconcile's drop reach the edge by looking up the
// changed keys only: with 58 000 bans, the rebuild every change used to
// cost (453 times in 3 hours on earth, ~150 ms each) is gone. A change that
// moves every answer (the kill switch, the allow sets) still rebuilds.
func TestEdgeBanChangesWithoutARebuild(t *testing.T) {
	var ips []string
	for i := 0; i < 200; i++ {
		ips = append(ips, fmt.Sprintf("10.9.%d.%d", i/250, i%250+1))
	}
	s := installEdgeBans(t, ips...)
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	_, first, _ := pollEdgeBan(t, b, url.Values{}, "tok")
	if len(first.IPs) != 200 {
		t.Fatalf("first poll: %d bans, want 200", len(first.IPs))
	}
	scans := scanCounter(b)

	ttl := time.Hour
	s.Add(net.ParseIP("198.51.100.7"), &ttl, "waf_security", false)
	_, ch, raw := pollEdgeBan(t, b, at(first), "tok")
	if ch.Full || ch.Set["198.51.100.7"] == 0 || *scans != 1 {
		t.Fatalf("a ban: %s, %d keys looked at; want the ban alone, 1 key", raw, *scans)
	}
	*scans = 0
	s.Remove("10.9.0.1")
	_, ch2, raw := pollEdgeBan(t, b, at(ch), "tok")
	if len(ch2.Del) != 1 || ch2.Del[0] != "10.9.0.1" || *scans != 0 {
		t.Fatalf("an unban: %s, %d keys looked at; want the delete, no scan", raw, *scans)
	}
	// A reconcile that drops a ban nft no longer holds (and keeps the rest).
	var blocks []firewall.SetElementTimed
	for _, ip := range ips[2:] {
		blocks = append(blocks, firewall.SetElementTimed{Elem: ip})
	}
	blocks = append(blocks, firewall.SetElementTimed{Elem: "198.51.100.7", Expires: time.Hour})
	s.Reconcile(edgeban.Snapshot{Blocks: blocks, ReadAt: time.Now().Add(time.Second)})
	_, ch3, raw := pollEdgeBan(t, b, at(ch2), "tok")
	if len(ch3.Del) != 1 || ch3.Del[0] != "10.9.0.2" || *scans > 2 {
		t.Fatalf("a reconcile's drop: %s, %d keys looked at; want 10.9.0.2 deleted, no rebuild", raw, *scans)
	}
	// The kill switch moves every answer: the list is rebuilt (and emptied).
	*scans = 0
	edgeban.SetEnabled(false)
	_, off, raw := pollEdgeBan(t, b, at(ch3), "tok")
	edgeban.SetEnabled(true)
	if len(off.Del) != 199 {
		t.Fatalf("EDGE_BAN=0: %d deletes, want all 199 (%.200s)", len(off.Del), raw)
	}
}

// The edge says how many entries its dict holds a list of (cap=), and the
// list is capped there: the longest bans kept, permanent first. An edge
// that does not say gets the legacy 20 000. A new ban while bans are left
// out rebuilds, so the longest still win.
func TestEdgeBanCapFollowsTheEdge(t *testing.T) {
	s := installEdgeBans(t, "192.0.2.1") // permanent
	for i, d := range []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour, 4 * time.Hour} {
		s.Add(net.ParseIP(fmt.Sprintf("192.0.2.%d", i+10)), &d, "waf_security", false)
	}
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	if st := b.EdgeBanStatus(); st.Cap != edgeBanLegacyCap {
		t.Fatalf("no report: cap %d, want the legacy %d", st.Cap, edgeBanLegacyCap)
	}
	q := url.Values{"cap": {"3"}}
	_, first, raw := pollEdgeBan(t, b, q, "tok")
	want := map[string]bool{"192.0.2.1": true, "192.0.2.13": true, "192.0.2.12": true}
	if len(first.IPs) != 3 {
		t.Fatalf("cap=3: %s", raw)
	}
	for ip := range first.IPs {
		if !want[ip] {
			t.Errorf("cap=3 kept %s; want the permanent ban and the two longest", ip)
		}
	}
	if st := b.EdgeBanStatus(); st.Cap != 3 || !st.LeftOut {
		t.Errorf("status cap=%d left_out=%v, want 3 and true", st.Cap, st.LeftOut)
	}
	// A longer ban while bans are left out: rebuilt, the shortest kept one goes.
	d := 5 * time.Hour
	s.Add(net.ParseIP("192.0.2.20"), &d, "waf_security", false)
	q2 := at(first)
	q2.Set("cap", "3")
	_, ch, raw := pollEdgeBan(t, b, q2, "tok")
	if ch.Set["192.0.2.20"] == 0 || len(ch.Del) != 1 || ch.Del[0] != "192.0.2.12" {
		t.Fatalf("a longer ban over the cap: %s, want +192.0.2.20 -192.0.2.12", raw)
	}
	// An unban while bans are left out: the freed slot goes to the longest
	// left-out ban at once.
	s.Remove("192.0.2.13")
	q5 := at(ch)
	q5.Set("cap", "3")
	_, fr, raw := pollEdgeBan(t, b, q5, "tok")
	if len(fr.Del) != 1 || fr.Del[0] != "192.0.2.13" || fr.Set["192.0.2.12"] == 0 {
		t.Fatalf("an unban over the cap: %s, want -192.0.2.13 +192.0.2.12", raw)
	}
	ch = fr
	// A larger dict (a bigger cap) rebuilds with room for every ban.
	q3 := at(ch)
	q3.Set("cap", strconv.Itoa(1000))
	_, all, raw := pollEdgeBan(t, b, q3, "tok")
	if len(all.Set) != 2 || b.EdgeBanStatus().LeftOut {
		t.Fatalf("cap=1000: %s, want the 2 left out added", raw)
	}
	// A report past edgeBanFeedMax is bounded.
	q4 := at(all)
	q4.Set("cap", strconv.Itoa(10*edgeBanFeedMax))
	pollEdgeBan(t, b, q4, "tok")
	if st := b.EdgeBanStatus(); st.Cap != edgeBanFeedMax {
		t.Errorf("cap past the bound: %d, want %d", st.Cap, edgeBanFeedMax)
	}
}

// Whatever the order of bans, unbans, reconciles and expiries, the edge's
// copy built from the changes equals the list a rebuild would publish.
func TestEdgeBanChangesMatchARebuild(t *testing.T) {
	s := installEdgeBans(t)
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	setBypass(b, func(ip string) bool { return ip == "10.0.0.7" }) // IGNORE_IPS
	r := rand.New(rand.NewSource(3))
	edge := map[string]int64{}
	q := url.Values{"cap": {"100000"}}
	apply := func(rep edgeBanReply) {
		if rep.Full {
			edge = map[string]int64{}
			for ip, e := range rep.IPs {
				edge[ip] = e
			}
		}
		for ip, e := range rep.Set {
			edge[ip] = e
		}
		for _, ip := range rep.Del {
			delete(edge, ip)
		}
		q = at(rep)
		q.Set("cap", "100000")
	}
	t.Cleanup(func() { firewall.SetClientNetExempt("test_ignore", nil) })
	_, rep, _ := pollEdgeBan(t, b, q, "tok")
	apply(rep)
	for round := 0; round < 400; round++ {
		ip := fmt.Sprintf("10.0.0.%d", r.Intn(40))
		if r.Intn(4) == 0 {
			ip = fmt.Sprintf("2001:db8:%d::9", r.Intn(12)) // a client: its /64 is the ban
		}
		switch r.Intn(7) {
		case 0, 1:
			d := time.Duration(1+r.Intn(5)) * time.Hour
			s.AddElem(edgeKey(ip), &d, "waf_security", r.Intn(4) == 0)
		case 2:
			s.AddElem(edgeKey(ip), nil, "manual", false)
		case 3:
			s.Remove(ip)
		case 5:
			// The allow sets change (a new generation): one network allowed.
			var blocks []firewall.SetElementTimed
			for _, it := range edgeban.List() {
				blocks = append(blocks, firewall.SetElementTimed{Elem: it.IP})
			}
			s.Reconcile(edgeban.Snapshot{Blocks: blocks, ReadAt: time.Now().Add(time.Second),
				Allows: []string{fmt.Sprintf("10.0.0.%d/31", 2*r.Intn(20)), fmt.Sprintf("2001:db8:%d::/64", r.Intn(12))}})
		case 6:
			// An IPv6 /64 exempted by a check outside the store (IGNORE_NETS).
			n := r.Intn(12)
			firewall.SetClientNetExempt("test_ignore", func(p netip.Prefix) bool {
				return p == netip.MustParsePrefix(fmt.Sprintf("2001:db8:%d::/64", n))
			})
			b.edgeBanResync()
		case 4:
			// A reconcile from nft's view: every stored ban, less one.
			var blocks []firewall.SetElementTimed
			for _, it := range edgeban.List() {
				if it.IP != ip {
					blocks = append(blocks, firewall.SetElementTimed{Elem: it.IP})
				}
			}
			s.Reconcile(edgeban.Snapshot{Blocks: blocks, ReadAt: time.Now().Add(time.Second)})
		}
		_, rep, _ := pollEdgeBan(t, b, q, "tok")
		apply(rep)
		j := &b.edgeBanJournal
		j.mu.Lock()
		want, _ := b.edgeBanCurrent(100000)
		j.mu.Unlock()
		if len(want) != len(edge) {
			t.Fatalf("round %d: the edge holds %d bans, a rebuild %d", round, len(edge), len(want))
		}
		for k, e := range want {
			if got, ok := edge[k]; !ok || got != e {
				t.Fatalf("round %d: %s on the edge %d/%v, a rebuild %d", round, k, got, ok, e)
			}
		}
	}
}

// One ban against 60 000 held: the change applied alone, against the whole
// list rebuilt (what every ban cost before the change log; earth,
// 2026-11-25: ~150 ms).
func BenchmarkEdgeBanSyncOneBan(b *testing.B) {
	s := edgeban.New("")
	var blocks []firewall.SetElementTimed
	ttl := 7 * 24 * time.Hour
	for i := 0; i < 60000; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		s.Add(net.ParseIP(ip), &ttl, "waf_security", false)
		blocks = append(blocks, firewall.SetElementTimed{Elem: ip, Expires: ttl})
	}
	s.Reconcile(edgeban.Snapshot{Blocks: blocks, ReadAt: time.Now().Add(time.Second)})
	edgeban.SetDefault(s)
	b.Cleanup(func() { edgeban.SetDefault(nil) })
	for _, mode := range []string{"changes", "rebuild"} {
		b.Run(mode, func(b *testing.B) {
			br := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
			j := &br.edgeBanJournal
			j.edgeCap = 100000
			j.mu.Lock()
			br.edgeBanSync(j, time.Now())
			j.mu.Unlock()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s.Add(net.ParseIP(fmt.Sprintf("172.16.%d.%d", (i/256)%256, i%256)), &ttl, "waf_security", true)
				j.mu.Lock()
				if mode == "rebuild" {
					j.recheck = time.Time{}
				}
				br.edgeBanSync(j, time.Now())
				j.mu.Unlock()
			}
		})
	}
}

// edgeKey is the store key an automatic ban of ip takes: an IPv6 client's
// /64, else the address.
func edgeKey(ip string) string {
	if a := net.ParseIP(ip); a != nil && a.To4() == nil {
		p, _ := netip.ParseAddr(ip)
		pp, _ := p.Prefix(64)
		return pp.String()
	}
	return ip
}

// In production a rebuild a poll asks for runs beside it: the poll answers
// at once with the changes applied so far, and the rebuilt list reaches the
// edge on the next poll.
func TestEdgeBanRebuildBesideThePoll(t *testing.T) {
	edgeBanRebuildAsync = true
	t.Cleanup(func() { edgeBanRebuildAsync = false })
	s := installEdgeBans(t, "192.0.2.1", "192.0.2.2")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	_, first, _ := pollEdgeBan(t, b, url.Values{}, "tok") // the first rebuild: in the poll
	if len(first.IPs) != 2 {
		t.Fatalf("first poll: %+v", first)
	}
	edgeban.SetEnabled(false) // moves every answer: a rebuild
	t.Cleanup(func() { edgeban.SetEnabled(true) })
	pollEdgeBan(t, b, at(first), "tok")
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.edgeBanJournal.mu.Lock()
		done := !b.edgeBanJournal.rebuilding && len(b.edgeBanJournal.published) == 0
		b.edgeBanJournal.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the rebuild beside the poll never landed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, r, raw := pollEdgeBan(t, b, at(first), "tok"); len(r.Del) != 2 {
		t.Fatalf("the next poll: %s, want both bans deleted", raw)
	}
	_ = s
}

// A cap report stands for polls that carry none for edgeBanCapGrace (an
// edge reload's old workers): no flip-flop between the two lists.
func TestEdgeBanCapGrace(t *testing.T) {
	installEdgeBans(t, "192.0.2.1")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	pollEdgeBan(t, b, url.Values{"cap": {"50000"}}, "tok")
	pollEdgeBan(t, b, url.Values{}, "tok")
	if c := b.EdgeBanStatus().Cap; c != 50000 {
		t.Fatalf("a poll without a report right after one: cap %d, want 50000", c)
	}
	b.edgeBanJournal.mu.Lock()
	b.edgeBanJournal.edgeCapAt = time.Now().Add(-edgeBanCapGrace - time.Second)
	b.edgeBanJournal.mu.Unlock()
	pollEdgeBan(t, b, url.Values{}, "tok")
	if c := b.EdgeBanStatus().Cap; c != edgeBanLegacyCap {
		t.Fatalf("no report for longer than the grace: cap %d, want %d", c, edgeBanLegacyCap)
	}
}

// A new IGNORE_IPS list (SetBypassFunc on a config reload) reaches the edge
// on the next poll, not at the 5-minute recheck.
func TestEdgeBanBypassChangeRebuilds(t *testing.T) {
	installEdgeBans(t, "192.0.2.1", "192.0.2.2")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	_, first, _ := pollEdgeBan(t, b, url.Values{}, "tok")
	b.SetBypassFunc(func(ip string) bool { return ip == "192.0.2.2" })
	if _, r, raw := pollEdgeBan(t, b, at(first), "tok"); len(r.Del) != 1 || r.Del[0] != "192.0.2.2" {
		t.Fatalf("after a new IGNORE_IPS: %s, want 192.0.2.2 deleted", raw)
	}
}

// A rebuild beside the polls brings its list up to the changes the polls
// applied while it was built: before, its publish journalled a ban made
// meanwhile as deleted and an unban as set again (each back ~5 s later).
func TestEdgeBanRebuildBesideKeepsTheChangesMeanwhile(t *testing.T) {
	edgeBanRebuildAsync = true
	t.Cleanup(func() { edgeBanRebuildAsync = false })
	s := installEdgeBans(t, "192.0.2.1", "192.0.2.2")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	_, first, _ := pollEdgeBan(t, b, url.Values{}, "tok")
	if len(first.IPs) != 2 {
		t.Fatalf("first poll: %+v", first)
	}
	// While the rebuild reads its list: a ban and an unban, which a poll
	// applies to the published list.
	var mid edgeBanReply
	once := true
	setBypass(b, func(string) bool {
		if once {
			once = false
			ttl := time.Hour
			s.Add(net.ParseIP("198.51.100.7"), &ttl, "waf_security", false)
			s.Remove("192.0.2.2")
			_, mid, _ = pollEdgeBan(t, b, at(first), "tok")
		}
		return false
	})
	b.edgeBanJournal.mu.Lock()
	b.edgeBanJournal.rebuilding = true
	capN := b.edgeBanJournal.edgeBanCap()
	b.edgeBanJournal.mu.Unlock()
	b.edgeBanRebuildBeside(capN)
	if mid.Set["198.51.100.7"] == 0 || len(mid.Del) != 1 {
		t.Fatalf("the poll meanwhile: %+v, want the ban set and 192.0.2.2 deleted", mid)
	}
	_, next, raw := pollEdgeBan(t, b, at(mid), "tok")
	if next.Full || len(next.Set) != 0 || len(next.Del) != 0 {
		t.Fatalf("the poll after the rebuild: %s, want no change (the rebuild reverted the poll's)", raw)
	}
	b.edgeBanJournal.mu.Lock()
	defer b.edgeBanJournal.mu.Unlock()
	if b.edgeBanJournal.rebuilding {
		t.Fatal("rebuilding still set after the publish")
	}
	if _, ok := b.edgeBanJournal.published["198.51.100.7"]; !ok {
		t.Fatal("the ban made meanwhile is not in the published list")
	}
	if _, ok := b.edgeBanJournal.published["192.0.2.2"]; ok {
		t.Fatal("the unban made meanwhile is back in the published list")
	}
}
