package webdetector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Clearance handoff: carry a solved challenge across the apex↔www pair.
//
// WHY THIS EXISTS
//
// A clearance cookie is host-only (no Domain attribute) and the token is bound
// to the exact host, so clearance minted on `example.gr` is not clearance on
// `www.example.gr`. That is deliberate — but almost every site canonicalises one
// to the other with a 301 from the origin, and CFM sits *in front* of that
// redirect. The result, observed in production on 2026-07-29:
//
//	GET  example.gr/x        -> challenge -> solved, cookie for example.gr
//	GET  example.gr/x        -> origin 301 -> www.example.gr/x
//	GET  www.example.gr/x    -> no clearance here -> challenge AGAIN
//
// A real user loops until they give up, and every loop iteration is a genuine
// solve — which is why `challenge_cookie_discard` read nine of them in
// thirty-six seconds as a client discarding its cookie and banned a CGNAT
// address carrying real subscribers.
//
// WHY NOT JUST SET Domain=example.gr
//
// Because the cookie Domain attribute is a suffix match and cannot express
// "apex and www, nothing else". Both ways of using it break a cPanel box:
//
//   - Domain on the apex/www pair only: the browser then holds TWO cookies
//     named cfm_clearance (one host-only for webmail.example.gr, one
//     domain-wide) and sends both. nginx's $cookie_cfm_clearance returns only
//     the FIRST, so webmail can read the wrong one, fail host_mismatch, and
//     loop forever — the same bug moved somewhere worse.
//   - Domain everywhere: apex and webmail overwrite each other's cookie and
//     ping-pong between challenges.
//
// So the fix does not touch Domain at all. After a solve on H the client is
// sent through the sibling's handoff endpoint once, which mints a host-only
// clearance there and forwards to the original destination. Exactly one sibling
// is ever involved, every cookie stays host-only, and the flow terminates by
// construction: the handoff endpoint never issues another handoff.

const (
	clearanceHandoffPath = "/__cfm_clearance_handoff"

	// handoffTokenTTL bounds how long a handoff token in a URL is worth
	// anything. It travels in a query string, so it lands in the edge access
	// log; thirty seconds is ample for one redirect and short enough that a
	// leaked log line is not a usable credential.
	handoffTokenTTL = 30 * time.Second

	// handoffTokenVersion is deliberately NOT "1". A handoff token and a
	// clearance token are signed with the same key, so the version tag is what
	// stops one being replayed as the other: verifyClearanceToken requires
	// V=="1" and this payload can never satisfy it.
	handoffTokenVersion = "h1"
)

// clearanceSibling returns the apex↔www counterpart of host, or "" when the
// pair does not apply.
//
// The rule is deliberately narrow: strip a leading "www." or add one, and
// nothing else. `webmail.example.gr` has no sibling here, which is the whole
// point — this must never widen clearance to a panel or mail hostname.
//
// An IP literal has no sibling: `www.203.0.113.7` is not a host, and a client
// reaching a vhost by address is not being canonicalised anywhere.
func clearanceSibling(host string) string {
	h := normalizeClearanceHost(host)
	if h == "" {
		return ""
	}
	if net.ParseIP(h) != nil {
		return ""
	}
	if rest, ok := strings.CutPrefix(h, "www."); ok {
		// www.example.gr -> example.gr, but only when something real is left.
		if strings.Count(rest, ".") < 1 || rest == "" {
			return ""
		}
		return rest
	}
	// example.gr -> www.example.gr. Requires at least one dot, so a bare label
	// ("localhost", a container name) is left alone.
	if strings.Count(h, ".") < 1 {
		return ""
	}
	return "www." + h
}

// issueHandoffToken mints the one-hop token carried in the handoff URL. It
// binds the client address, the TARGET host (the sibling, not the host that
// solved), and the scope, so it grants exactly the clearance the solve earned
// and only to the client that earned it.
func issueHandoffToken(ip, targetHost, scope string, exp time.Time) string {
	key := clearanceSecretKey()
	if len(key) == 0 {
		return ""
	}
	p := clearancePayload{
		V:     handoffTokenVersion,
		Exp:   exp.Unix(),
		IP:    ip,
		Host:  normalizeClearanceHost(targetHost),
		Scope: scope,
		Nonce: randomCookieValue(),
	}
	payload := fmt.Sprintf("%s|%d|%s|%s|%s|%s", p.V, p.Exp, p.IP, p.Host, p.Scope, p.Nonce)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	p.HMAC = hex.EncodeToString(mac.Sum(nil))
	b, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(b)
}

// verifyHandoffToken is the mirror of issueHandoffToken. It is intentionally a
// separate function rather than a flag on verifyClearanceToken: the two token
// kinds must not be interchangeable, and a shared code path with a boolean is
// exactly how they would become so.
func verifyHandoffToken(tok, ip, host, scope string, now time.Time) bool {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil {
		return false
	}
	var p clearancePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return false
	}
	if p.V != handoffTokenVersion || p.Exp <= now.Unix() || strings.TrimSpace(p.Nonce) == "" {
		return false
	}
	if p.IP != ip || normalizeClearanceHost(p.Host) != normalizeClearanceHost(host) || p.Scope != scope {
		return false
	}
	key := clearanceSecretKey()
	if len(key) == 0 {
		return false
	}
	payload := fmt.Sprintf("%s|%d|%s|%s|%s|%s", p.V, p.Exp, p.IP, normalizeClearanceHost(p.Host), p.Scope, p.Nonce)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	want := mac.Sum(nil)
	got, err := hex.DecodeString(p.HMAC)
	if err != nil || len(got) != len(want) {
		return false
	}
	return hmac.Equal(got, want)
}

// handoffRedirectURL builds the absolute URL the verify handler 303s to.
//
// Absolute is required — this is the one redirect in the flow that must change
// host. next is carried as a query parameter and is re-validated on arrival;
// it is never trusted to be a path just because it was one when it left.
func handoffRedirectURL(sibling, tok, next string) string {
	q := url.Values{}
	q.Set("t", tok)
	q.Set("next", next)
	return "https://" + sibling + clearanceHandoffPath + "?" + q.Encode()
}

// safeHandoffNext constrains the forwarded destination to a same-host absolute
// path. Anything else — a scheme, a protocol-relative "//evil.example", a bare
// word — collapses to "/". Without this the handoff endpoint would be an open
// redirect that also happens to hand out clearance.
func safeHandoffNext(next string) string {
	n := strings.TrimSpace(next)
	if n == "" || !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") {
		return "/"
	}
	if strings.ContainsAny(n, "\r\n") {
		return "/"
	}
	return n
}
