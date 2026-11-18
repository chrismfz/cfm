package webdetector

import (
	"testing"
	"time"

	"cfm/internal/detectors/core"
)

// subnetReemitEngine is an Engine whose one host bucket holds a hot /24: four
// members over the subnet thresholds on one vhost.
func subnetReemitEngine(ips ...string) *Engine {
	e := &Engine{}
	e.cfg.ChallengeSubnetEnabled = true
	e.cfg.ChallengeSubnetMinIPs = 3
	e.cfg.ChallengeSubnetMinReq = 1
	e.cfg.ChallengeSubnetMinUniqPath = 1
	e.cfg.ChallengeSubnetCap = 64
	e.cfg.ChallengeSubnetTTL = 20 * time.Minute
	e.subnetLastChalEmit = make(map[string]time.Time)
	e.subnetIPLastChalEmit = make(map[string]time.Time)

	sub := "202.46.62.0/24"
	b := bucketSW{
		subnetIPs:       map[string]map[string]struct{}{sub: {}},
		subnetUniqPaths: map[string]map[uint64]struct{}{sub: {1: {}, 2: {}}},
		subnetHostReqs:  map[string]map[string]int{sub: {"shop.gr": 40}},
	}
	for _, ip := range ips {
		b.subnetIPs[sub][ip] = struct{}{}
	}
	e.hosts = map[string]*hostState{"shop.gr": {buckets: []bucketSW{b}}}
	return e
}

func drainSubnetAlerts(out chan core.Alert) map[string]int {
	got := map[string]int{}
	for {
		select {
		case a := <-out:
			got[a.Key]++
		default:
			return got
		}
	}
}

// A hot subnet's members are challenged once, then refreshed only when half
// their TTL is spent — not on every 10s pair cooldown. qualityweb 2026-11-18:
// the same 200 Baidu IPs were re-emitted every ~10s (~31 000 history rows an
// hour) and the webdetector run timed out ~270 times a day.
func TestSubnetChallenge_MembersNotReemittedEveryCooldown(t *testing.T) {
	e := subnetReemitEngine("202.46.62.1", "202.46.62.2", "202.46.62.3", "202.46.62.4")
	out := make(chan core.Alert, 64)
	t0 := time.Unix(1_800_000_000, 0)

	e.emitSubnetChallenges(t0, out)
	if got := drainSubnetAlerts(out); len(got) != 4 {
		t.Fatalf("first pass: %d members challenged, want 4 (%v)", len(got), got)
	}

	// Past the 10s pair cooldown, well inside ttl/2: nothing re-emits.
	for _, dt := range []time.Duration{11 * time.Second, 2 * time.Minute, 9 * time.Minute} {
		e.emitSubnetChallenges(t0.Add(dt), out)
		if got := drainSubnetAlerts(out); len(got) != 0 {
			t.Fatalf("+%s: re-emitted %v, want none before ttl/2", dt, got)
		}
	}

	// At ttl/2 every member is refreshed once, keeping its challenge alive.
	e.emitSubnetChallenges(t0.Add(10*time.Minute+time.Second), out)
	if got := drainSubnetAlerts(out); len(got) != 4 {
		t.Fatalf("ttl/2 refresh: %d members, want 4 (%v)", len(got), got)
	}
}

// A NEW member of an already-challenged subnet is still caught on the next
// pair cooldown, not held back by its neighbours' refresh clock.
func TestSubnetChallenge_NewMemberCaughtOnNextCooldown(t *testing.T) {
	e := subnetReemitEngine("202.46.62.1", "202.46.62.2", "202.46.62.3")
	out := make(chan core.Alert, 64)
	t0 := time.Unix(1_800_000_000, 0)

	e.emitSubnetChallenges(t0, out)
	drainSubnetAlerts(out)

	sub := "202.46.62.0/24"
	e.hosts["shop.gr"].buckets[0].subnetIPs[sub]["202.46.62.9"] = struct{}{}
	e.emitSubnetChallenges(t0.Add(11*time.Second), out)
	got := drainSubnetAlerts(out)
	if len(got) != 1 || got["202.46.62.9"] != 1 {
		t.Fatalf("new member pass: %v, want only 202.46.62.9", got)
	}
}

// The per-member gate is keyed per vhost: the same IP on a second vhost of
// the subnet is challenged there too.
func TestSubnetIPEmitDue_PerHostAndPrune(t *testing.T) {
	e := &Engine{}
	now := time.Unix(1_800_000_000, 0)
	ttl := 20 * time.Minute
	if !e.subnetIPEmitDue("1.2.3.4|a.gr", now, ttl) {
		t.Fatal("first emit not due")
	}
	if e.subnetIPEmitDue("1.2.3.4|a.gr", now.Add(time.Minute), ttl) {
		t.Fatal("re-emit due before ttl/2")
	}
	if !e.subnetIPEmitDue("1.2.3.4|b.gr", now.Add(time.Minute), ttl) {
		t.Fatal("same IP on another vhost not due")
	}
	if !e.subnetIPEmitDue("1.2.3.4|a.gr", now.Add(ttl/2), ttl) {
		t.Fatal("refresh at ttl/2 not due")
	}
}
