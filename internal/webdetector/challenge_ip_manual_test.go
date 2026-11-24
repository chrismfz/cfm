package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func manualIPReq(role, path, body string) *http.Request {
	ctx := context.WithValue(context.WithValue(context.Background(), CtxAuthnKey{}, true), CtxRoleKey{}, role)
	return httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(ctx)
}

func TestChallengeIPManual(t *testing.T) {
	resetUnsolvedHold(t, "log")
	e := &Engine{nginxBridge: NewNginxBridge("/tmp/cfm-test-manual-ip.sock", "tok", time.Minute, time.Minute)}
	b := e.nginxBridge
	b.SetBypassFunc(func(ip string) bool { return ip == "192.0.2.1" })
	b.BlockIP("192.0.2.2", time.Hour)

	call := func(h http.HandlerFunc, role, path, body string) (int, manualIPChallengeResult) {
		rr := httptest.NewRecorder()
		h(rr, manualIPReq(role, path, body))
		var out manualIPChallengeResult
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	if code, _ := call(e.handleChallengeIPAdd, CtxRoleScoped, "/api/v1/challenge/ip/add", `{"ips":["203.0.113.5"]}`); code != http.StatusForbidden {
		t.Fatalf("scoped caller: %d, want 403", code)
	}
	if code, _ := call(e.handleChallengeIPAdd, CtxRoleAdmin, "/api/v1/challenge/ip/add", `{"ips":[]}`); code != http.StatusBadRequest {
		t.Fatalf("no IPs: %d, want 400", code)
	}
	many := `{"ips":[` + strings.TrimSuffix(strings.Repeat(`"203.0.113.9",`, manualIPChallengeMax+1), ",") + `]}`
	if code, _ := call(e.handleChallengeIPAdd, CtxRoleAdmin, "/api/v1/challenge/ip/add", many); code != http.StatusBadRequest {
		t.Fatalf("over the cap: %d, want 400", code)
	}

	code, out := call(e.handleChallengeIPAdd, CtxRoleAdmin, "/api/v1/challenge/ip/add",
		`{"ips":["203.0.113.5","203.0.113.5"," 2001:db8::1 ","nope","192.0.2.1","192.0.2.2"],"ttl_seconds":60,"reason":"chrome152 scraper"}`)
	if code != http.StatusOK {
		t.Fatalf("add: %d", code)
	}
	if len(out.Done) != 2 || out.Done[0] != "203.0.113.5" || out.Done[1] != "2001:db8::1" {
		t.Fatalf("done = %v, want the two valid, de-duplicated addresses", out.Done)
	}
	if len(out.Skipped) != 3 || out.TTLSeconds != int(manualIPChallengeMinTTL/time.Second) {
		t.Fatalf("skipped = %+v ttl = %d, want 3 skips (not an IP, IGNORE, blocked) and the 5m floor", out.Skipped, out.TTLSeconds)
	}
	en, ok := ipEntry(b, "203.0.113.5")
	if !ok || en.Action != "challenge" || en.Reason != manualIPChallengeReason {
		t.Fatalf("entry = %+v, want a manual_ip challenge", en)
	}
	if blk, _ := ipEntry(b, "192.0.2.2"); blk.Action != "block" {
		t.Fatalf("the block was replaced: %+v", blk)
	}
	if !b.ClearanceRevoked("203.0.113.5") {
		t.Fatal("a cleared client would walk past the manual challenge: clearance not revoked")
	}
	// A live, longer challenge is never shortened and keeps its reason.
	b.ChallengeIPWithReason("198.51.100.7", 3*time.Hour, "waf")
	if code, out := call(e.handleChallengeIPAdd, CtxRoleAdmin, "/api/v1/challenge/ip/add", `{"ips":["198.51.100.7"],"ttl_seconds":3600}`); code != http.StatusOK || len(out.Done) != 0 || len(out.Skipped) != 1 {
		t.Fatalf("a longer live challenge: done=%v skipped=%+v", out.Done, out.Skipped)
	}
	if !b.ClearanceRevoked("198.51.100.7") {
		t.Fatal("an IP skipped as already challenged kept its clearance")
	}
	b.ChallengeIPWithReason("198.51.100.8", 10*time.Minute, "waf")
	// A shorter live challenge is extended, and reported apart from Done: an
	// undo of Done must not lift a challenge the operator did not set.
	if _, out := call(e.handleChallengeIPAdd, CtxRoleAdmin, "/api/v1/challenge/ip/add", `{"ips":["198.51.100.8"],"ttl_seconds":3600}`); len(out.Done) != 0 || len(out.Extended) != 1 {
		t.Fatalf("a shorter live challenge: done=%v extended=%v, want it extended, not in done", out.Done, out.Extended)
	}
	if en, _ := ipEntry(b, "198.51.100.8"); en.Reason != "waf" || time.Until(en.Expires) < 50*time.Minute {
		t.Fatalf("extended entry = %+v, want its own reason and ~1h", en)
	}
	// It is an ordinary per-IP challenge: the unsolved-challenge hold counts it.
	if r := b.NoteUnsolvedChallengeView("203.0.113.5", "shop.example", time.Now()); !r.Counted {
		t.Fatal("the unsolved-challenge hold does not see the manual challenge")
	}

	code, out = call(e.handleChallengeIPRemove, CtxRoleAdmin, "/api/v1/challenge/ip/remove", `{"ips":["203.0.113.5","198.51.100.1","192.0.2.2"]}`)
	if code != http.StatusOK || len(out.Done) != 1 || len(out.Skipped) != 2 {
		t.Fatalf("remove: %d done=%v skipped=%+v", code, out.Done, out.Skipped)
	}
	if _, ok := ipEntry(b, "203.0.113.5"); ok {
		t.Fatal("remove left the challenge")
	}
	if b.ClearanceRevoked("203.0.113.5") {
		t.Fatal("remove left the clearance revoked")
	}
	if blk, _ := ipEntry(b, "192.0.2.2"); blk.Action != "block" {
		t.Fatal("remove lifted a block")
	}
}
