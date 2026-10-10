package webdetector

import (
	"context"
	"fmt"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

// feed403s makes ip cross IP403_COUNT on non-static paths (a shop answering
// 403 to ?add_to_wishlist= links, as on orion 2026-10-02..10).
func feed403s(e *Engine, ip string, n int) {
	now := float64(time.Now().Unix())
	for i := 0; i < n; i++ {
		e.ingest(LogRec{
			TS: now + float64(i), IP: ip, Host: "shop.example", Method: "get",
			URI:    fmt.Sprintf("/shop/item-%d/?add_to_wishlist=%d", i, i),
			Status: 403, UA: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		}, "raw")
	}
}

func drainKeys(out chan core.Alert) map[string]string {
	got := map[string]string{}
	for {
		select {
		case a := <-out:
			got[a.Key] = string(a.Kind)
		default:
			return got
		}
	}
}

// A FCrDNS-verified crawler crossing a 403/404 flood is not banned (its 403s are
// the origin's answers to a crawl); an unverified client with the same pattern,
// and one whose PTR only CLAIMS a crawler, still are.
func TestEmitIPBlocksSparesVerifiedGoodBots(t *testing.T) {
	const crawler, spoof, plain = "66.249.66.1", "198.51.100.20", "203.0.113.9"
	ptrs := map[string]string{
		crawler: "crawl-66-249-66-1.googlebot.com",
		spoof:   "crawl-198-51-100-20.googlebot.com", // forward-confirm fails
		plain:   "host-203-0-113-9.example.net",
	}
	prev := banGoodBot
	banGoodBot = newBanGoodBot()
	banGoodBot.verify = func(ptr, ip string) (string, bool) {
		if ip == crawler && ptr == ptrs[crawler] {
			return "googlebot", true
		}
		return "", true
	}
	t.Cleanup(func() { banGoodBot = prev })

	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, IP403Count: 5})
	e.banPTRFn = func(ip string) (string, bool) { return ptrs[ip], true }
	for _, ip := range []string{crawler, spoof, plain} {
		feed403s(e, ip, 8)
	}
	out := make(chan core.Alert, 16)
	e.emitIPBlocks(time.Now(), out)
	got := drainKeys(out)

	if k, ok := got[crawler]; ok {
		t.Errorf("verified Googlebot banned (%s)", k)
	}
	if got[spoof] != "WEB/403" {
		t.Errorf("spoofed crawler PTR: %q, want WEB/403 (forward-confirm failed)", got[spoof])
	}
	if got[plain] != "WEB/403" {
		t.Errorf("plain client: %q, want WEB/403", got[plain])
	}
}

// Parity with the solver-farm finding's good_bots: an operator exclude-file
// verify_fcrdns=1 PTR rule (chalGoodBotFunc) exempts too, for a PTR the
// canonical list does not claim; its forward-confirms share the tick budget.
func TestEmitIPBlocksSparesOperatorFileGoodBots(t *testing.T) {
	const bot = "203.0.113.50"
	prev := banGoodBot
	banGoodBot = newBanGoodBot()
	banGoodBot.verify = func(string, string) (string, bool) { return "", true }
	t.Cleanup(func() { banGoodBot = prev })

	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute, IP403Count: 5})
	e.banPTRFn = func(string) (string, bool) { return "crawler-1.uptime.example.org", true }
	calls := 0
	e.chalGoodBotFunc = func(ip, ptr string, budget *int) (string, bool) {
		calls++
		if budget == nil || *budget <= 0 {
			t.Errorf("no forward-confirm budget passed")
		}
		return "example.org", ip == bot && ptr == "crawler-1.uptime.example.org"
	}
	feed403s(e, bot, 8)
	out := make(chan core.Alert, 4)
	e.emitIPBlocks(time.Now(), out)
	if got := drainKeys(out); len(got) != 0 || calls != 1 {
		t.Errorf("operator-file crawler: alerts %v calls %d, want none and one file check", got, calls)
	}
}

// A reverse lookup that fails is inconclusive, never "no PTR": a crawler whose
// verdict expired (still inside the stale grace) keeps it through a DNS blip,
// and the shared cache keeps the verdict too.
func TestGoodBotForBanKeepsAGracedVerdictThroughAFailedPTRLookup(t *testing.T) {
	const crawler = "66.249.66.2"
	gb := newBanGoodBot()
	gb.verify = func(ptr, ip string) (string, bool) { return "googlebot", true }
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute})
	e.nginxBridge = &NginxBridge{goodBot: gb}

	t0 := time.Now()
	e.banPTRFn = func(string) (string, bool) { return "crawl-66-249-66-2.googlebot.com", true }
	if got := e.goodBotForBan(context.Background(), crawler, nil, t0); got != "googlebot" {
		t.Fatalf("first verify: %q", got)
	}
	later := t0.Add(goodBotIPPosTTL + time.Minute) // expired, inside the grace
	e.banPTRFn = func(string) (string, bool) { return "", false }
	if got := e.goodBotForBan(context.Background(), crawler, nil, later); got != "googlebot" {
		t.Errorf("failed PTR lookup: %q, want the graced verdict kept", got)
	}
	if got := gb.verified(crawler, nil, later); got != "googlebot" {
		t.Errorf("shared cache after the failed lookup: %q, want the verdict still there", got)
	}
}

// An IP the ban check found definitively not a crawler is not looked up again
// on every cooldown (a flooder behind Cloudflare stays in IPShort, and a slow
// reverse zone cost up to 2 s per lookup on the detector tick); a failed
// lookup is not remembered.
func TestGoodBotForBanRemembersDefinitiveNegatives(t *testing.T) {
	e := NewEngine(Config{Every: time.Second, Window: 2 * time.Minute})
	e.nginxBridge = &NginxBridge{goodBot: newBanGoodBot()}
	lookups := map[string]int{}
	e.banPTRFn = func(ip string) (string, bool) {
		lookups[ip]++
		switch ip {
		case "203.0.113.1":
			return "", true // no PTR
		case "203.0.113.2":
			return "host-2.isp.example", true // a PTR no rule claims
		}
		return "", false // lookup failed
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
			if got := e.goodBotForBan(context.Background(), ip, nil, now.Add(time.Duration(i)*30*time.Second)); got != "" {
				t.Fatalf("%s: %q", ip, got)
			}
		}
	}
	if lookups["203.0.113.1"] != 1 || lookups["203.0.113.2"] != 1 {
		t.Errorf("definitive negatives looked up again: %v", lookups)
	}
	if lookups["203.0.113.3"] != 3 {
		t.Errorf("failed lookup remembered: %v (want 3 tries)", lookups)
	}
	if e.goodBotForBan(context.Background(), "203.0.113.1", nil, now.Add(banNotBotTTL+time.Minute)); lookups["203.0.113.1"] != 2 {
		t.Errorf("negative not re-checked after the TTL: %v", lookups)
	}
}
