package webdetector

import (
	"testing"
	"time"
)

// The sibling rule is the security boundary of this feature: it decides which
// second hostname a solved challenge is allowed to travel to. It must be the
// apex↔www pair and nothing else, because the alternative — a cookie Domain —
// cannot be limited that way and would reach webmail/cpanel/whm.
func TestClearanceSiblingIsOnlyTheWWWPair(t *testing.T) {
	for in, want := range map[string]string{
		"example.gr":          "www.example.gr",
		"www.example.gr":      "example.gr",
		"EXAMPLE.GR":          "www.example.gr", // normalised first
		"example.gr:443":      "www.example.gr", // port stripped
		"example.co.uk":       "www.example.co.uk",
		"www.example.co.uk":   "example.co.uk",
		"shop.example.gr":     "www.shop.example.gr",
		"www.shop.example.gr": "shop.example.gr",
	} {
		if got := clearanceSibling(in); got != want {
			t.Errorf("clearanceSibling(%q) = %q, want %q", in, got, want)
		}
	}

	// A panel hostname must never be reachable FROM its apex. These are the
	// names the whole design exists to protect: on a cPanel box they are
	// different surfaces with different auth, and a clearance that hopped to
	// them would be a real widening.
	for _, apex := range []string{"example.gr", "www.example.gr"} {
		sib := clearanceSibling(apex)
		for _, panel := range []string{
			"webmail.example.gr", "cpanel.example.gr", "whm.example.gr",
			"mail.example.gr", "webdisk.example.gr", "cpcontacts.example.gr",
		} {
			if sib == panel {
				t.Fatalf("clearanceSibling(%q) = %q — clearance must never hop to a panel host", apex, panel)
			}
		}
	}

	// And a panel hostname's own sibling is the meaningless "www." form, which
	// HasExactHost will refuse in practice. Assert the shape anyway so nobody
	// "helpfully" broadens the rule to strip arbitrary leading labels.
	if got := clearanceSibling("webmail.example.gr"); got != "www.webmail.example.gr" {
		t.Errorf("clearanceSibling(webmail) = %q; the rule must add www., never strip webmail.", got)
	}
}

func TestClearanceSiblingRefusesHostsWithNoPair(t *testing.T) {
	for _, in := range []string{
		"",              // nothing
		"localhost",     // bare label
		"192.0.2.10",    // IPv4 literal — "www.192.0.2.10" is not a host
		"[2001:db8::1]", // IPv6 literal
		"2001:db8::1",
		"www.",  // degenerate
		"www.x", // stripping leaves a bare label
	} {
		if got := clearanceSibling(in); got != "" {
			t.Errorf("clearanceSibling(%q) = %q, want \"\"", in, got)
		}
	}
}

// A handoff token must not be usable as a clearance cookie and vice versa. They
// are signed with the same key, so the version tag is the only thing keeping
// them apart — if someone ever "unifies" the payloads this test is the alarm.
func TestHandoffAndClearanceTokensAreNotInterchangeable(t *testing.T) {
	t.Setenv("OPENRESTY_TOKEN", "test-secret-for-handoff-parity")
	now := time.Now().UTC()
	exp := now.Add(handoffTokenTTL)
	const ip, host, scope = "203.0.113.9", "www.example.gr", "web"

	h := issueHandoffToken(ip, host, scope, exp)
	if h == "" {
		t.Fatal("issueHandoffToken returned empty")
	}
	if !verifyHandoffToken(h, ip, host, scope, now) {
		t.Fatal("a freshly minted handoff token must verify")
	}
	if verifyClearanceToken(h, ip, host, scope, now) {
		t.Error("a handoff token verified as CLEARANCE — the version tag is not separating them")
	}

	c := issueClearanceToken(ip, host, scope, now.Add(time.Hour))
	if verifyHandoffToken(c, ip, host, scope, now) {
		t.Error("a clearance token verified as a HANDOFF token")
	}
}

// The token binds address, host and scope. Each of those is load-bearing: the
// token travels in a URL and therefore in the edge access log, so anything it
// does not bind is something a reader of that log could reuse.
func TestHandoffTokenBindsAddressHostAndScope(t *testing.T) {
	t.Setenv("OPENRESTY_TOKEN", "test-secret-for-handoff-binding")
	now := time.Now().UTC()
	const ip, host, scope = "203.0.113.9", "www.example.gr", "web"
	tok := issueHandoffToken(ip, host, scope, now.Add(handoffTokenTTL))

	// Positive case first, and not as a courtesy: without a signing key every
	// verify below returns false and the whole test passes while asserting
	// nothing. This line is what stops it being vacuous.
	if tok == "" || !verifyHandoffToken(tok, ip, host, scope, now) {
		t.Fatal("the token must verify for the exact tuple it was minted for")
	}

	if verifyHandoffToken(tok, "198.51.100.4", host, scope, now) {
		t.Error("accepted from a different address")
	}
	if verifyHandoffToken(tok, ip, "webmail.example.gr", scope, now) {
		t.Error("accepted for a different host — this is the panel-hop the design forbids")
	}
	if verifyHandoffToken(tok, ip, host, "panel:2083", now) {
		t.Error("accepted for a different scope")
	}
	if verifyHandoffToken(tok, ip, host, scope, now.Add(handoffTokenTTL+time.Second)) {
		t.Error("accepted after expiry")
	}
	if verifyHandoffToken("", ip, host, scope, now) || verifyHandoffToken("not-base64!!", ip, host, scope, now) {
		t.Error("accepted a malformed token")
	}
}

// The handoff endpoint takes `next` from the query string of a URL that was
// built on another host. If it forwarded that verbatim it would be an open
// redirect that also hands out clearance.
func TestSafeHandoffNextRefusesAnythingButASameHostPath(t *testing.T) {
	for in, want := range map[string]string{
		"/forum/ucp.php?mode=register": "/forum/ucp.php?mode=register",
		"/":                            "/",
		"":                             "/",
		"//evil.example/x":             "/", // protocol-relative
		"https://evil.example/x":       "/",
		"http://evil.example/x":        "/",
		"evil.example/x":               "/", // no leading slash
		"/ok\r\nSet-Cookie: x=1":       "/", // header splitting
		"/ok\nX: 1":                    "/",
	} {
		if got := safeHandoffNext(in); got != want {
			t.Errorf("safeHandoffNext(%q) = %q, want %q", in, got, want)
		}
	}
}

// The redirect URL is the one place in the flow that changes host, so it must
// be absolute, must target the sibling, and must carry both parameters.
func TestHandoffRedirectURLTargetsTheSibling(t *testing.T) {
	got := handoffRedirectURL("www.example.gr", "TOK", "/forum/ucp.php?mode=register")
	const wantPrefix = "https://www.example.gr" + clearanceHandoffPath + "?"
	if len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("handoffRedirectURL = %q, want prefix %q", got, wantPrefix)
	}
	for _, frag := range []string{"t=TOK", "next=%2Fforum%2Fucp.php%3Fmode%3Dregister"} {
		if !contains(got, frag) {
			t.Errorf("handoffRedirectURL = %q, missing %q", got, frag)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
