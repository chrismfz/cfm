package webdetector

// challenge_cdn_cache.go — the challenge server's defences against a CDN that
// caches what it answers.
//
// The incident (mars, anastasiadi.gr, 2026-10-19): a vhost behind Cloudflare
// whose Cache Rule overrides the origin's Cache-Control ("Edge TTL: ignore
// cache-control header") cached CFM's challenge page itself. The page was then
// served from Cloudflare to every visitor of that URL, carrying another
// visitor's token and no cfm_chal cookie (Cloudflare drops Set-Cookie from a
// cached copy), so the solves failed with missing_cookie / bad_token. A
// visitor who did solve, on a fresh page, was sent back to next and got the
// cached challenge again, and again: ~30 solves in two minutes, until the
// challenge rate limit banned an ordinary OTE customer. No CFM decision was
// challenging them at the time (src=- on every solve).
//
// CFM cannot reconfigure a tenant's CDN, so the challenge server:
//   - serves the challenge page only at /__cfm_challenge (a content URL such as
//     "/" gets a redirect to it instead), so a cached copy of a content URL is
//     never a page holding another client's token;
//   - marks every response no-store for CDNs too (setNoStore);
//   - breaks the loop: a CLEARED client bounced back to the page for the same
//     target within the breaker window is sent to next once more with a fresh
//     cfm_nc query parameter, which a CDN keying on the query string has never
//     cached, instead of being served the PoW again (cdnBustNext). Once per
//     target per window: a further bounce gets the page;
//   - counts those bounces per host and distinct client IP over 24 h
//     (noteCDNCachedChallenge; web scope only: the panel listeners sit behind
//     no CDN), which edge_health reports as the cdn-cached-challenge check and
//     whats_wrong surfaces, so the operator learns which tenant's CDN to fix.
//
// HONEST LIMITS:
//   - a CDN that overrides no-store ignores the CDN headers too (they help
//     only where the origin's headers are respected);
//   - one that ignores the query string in its cache key defeats the
//     cache-bust (the bounce then ends at the page, as before);
//   - one that also caches /__cfm_challenge?next=X (a host-wide rule keyed on
//     the query) defeats all of it, the page's own retry URL included, and
//     no bounce reaches the origin, so the edge_health check stays silent;
//   - a cached redirect at a content URL still sends every visitor of that URL
//     to the challenge until the CDN entry expires: the fix is the CDN's own
//     rule, which the edge_health finding names;
//   - the count is a heuristic: a cleared bounce without a CDN (several tabs
//     on one target, a validator disagreement such as a bridge-token rotation
//     window) counts too, and the latter can hit many IPs at once.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// setNoStore marks a challenge-server response uncacheable for the browser
// and for a CDN in front of the edge. CDN-Cache-Control (RFC 9213) and
// Cloudflare-CDN-Cache-Control target the CDN alone; a CDN that respects the
// origin's headers stops caching the challenge even under a "cache everything"
// rule. One that overrides them ignores these too (see the file header).
func setNoStore(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("CDN-Cache-Control", "no-store")
	h.Set("Cloudflare-CDN-Cache-Control", "no-store")
}

// cdnBustParam is the query parameter cdnBustNext adds. The origin ignores
// it; its only job is to make the URL one no cache has seen.
const cdnBustParam = "cfm_nc"

// cdnBustNext returns next with a fresh cfm_nc parameter, or "" for a next
// that is not a same-origin path. An existing cfm_nc is REPLACED, not kept: a
// busted URL ends up in address bars, bookmarks and shared links, and a CDN
// caches that exact URL too. The caller bounds the busts (one per target per
// window), so a fresh value can never loop. next is the server-normalized
// target (normalizeChallengeNext); the rest of its query is kept byte for byte.
//
// It also returns "" for a next carrying a fragment (a cfm_nc after the '#'
// never reaches the server; the edge never builds one, only a crafted
// next=%23 does) and when the result would exceed maxNextLen (the bounce would
// then normalize to "/" and land the visitor on the homepage).
func cdnBustNext(next string) string {
	if _, err := url.ParseRequestURI(next); err != nil || !strings.HasPrefix(next, "/") ||
		!isSameOriginPath(next) || strings.Contains(next, "#") {
		return ""
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	path, query, _ := strings.Cut(next, "?")
	kept := make([]string, 0, 4)
	for _, kv := range strings.Split(query, "&") {
		if kv == "" {
			continue
		}
		if k, _, _ := strings.Cut(kv, "="); k == cdnBustParam {
			continue
		}
		kept = append(kept, kv)
	}
	kept = append(kept, cdnBustParam+"="+hex.EncodeToString(b[:]))
	out := path + "?" + strings.Join(kept, "&")
	if len(out) > maxNextLen {
		return ""
	}
	return out
}

// CDNCacheSuspect is one host whose cleared visitors were bounced back to the
// challenge page: the sign of a CDN serving a cached challenge or redirect.
// IPs is the number of DISTINCT clients bounced in the last 24 h (an IPv4
// address, an IPv6 /64: cdnSuspectClient), which is what edge_health
// thresholds on: the host is the client's own Host header (the web servers
// are `server_name _`), so a single client could otherwise pump the count for
// any name. Three proxies still can; the finding says "likely" for that. Bounces and First cover the whole
// current run (it lasts while any of its IPs is inside the window), so they
// can span more than 24 h.
type CDNCacheSuspect struct {
	Host    string    `json:"host"`
	IPs     int       `json:"ips"`
	Bounces int       `json:"bounces"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

const (
	cdnSuspectWindow     = 24 * time.Hour
	cdnSuspectMaxHosts   = 256
	cdnSuspectMaxIPsHost = 64 // past this, a host is suspect whatever else comes
)

type cdnSuspectEntry struct {
	ips     map[string]time.Time // client IP -> its last bounce
	bounces int
	first   time.Time
	last    time.Time
}

var cdnSuspects = struct {
	mu    sync.Mutex
	hosts map[string]*cdnSuspectEntry
}{hosts: map[string]*cdnSuspectEntry{}}

// pruneLocked drops the IPs whose last bounce left the window and reports
// whether anything is left.
func (e *cdnSuspectEntry) pruneLocked(now time.Time) bool {
	for ip, t := range e.ips {
		if now.Sub(t) > cdnSuspectWindow {
			delete(e.ips, ip)
		}
	}
	return len(e.ips) > 0
}

// cdnSuspectClient is the client key the tracker counts: the address itself
// for IPv4, its /64 for IPv6, where one subscriber holds the whole /64 and
// could otherwise count as any number of "distinct" clients.
func cdnSuspectClient(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	if p, err := a.Prefix(64); err == nil {
		return p.String()
	}
	return a.String()
}

// noteCDNCachedChallenge records one cleared bounce of ip on host. Bounded:
// past cdnSuspectMaxHosts it drops the stalest host, a host keeps at most
// cdnSuspectMaxIPsHost clients (IPv6 per /64, cdnSuspectClient), and the host
// is cut to 120 bytes (it is the client's own Host header).
func noteCDNCachedChallenge(host, ip string, now time.Time) {
	host = truncateForLog(strings.ToLower(strings.TrimSpace(host)), 120)
	ip = cdnSuspectClient(strings.TrimSpace(ip))
	if host == "" || ip == "" {
		return
	}
	cdnSuspects.mu.Lock()
	defer cdnSuspects.mu.Unlock()
	e := cdnSuspects.hosts[host]
	if e != nil && !e.pruneLocked(now) {
		delete(cdnSuspects.hosts, host) // the old run aged out: start afresh
		e = nil
	}
	if e == nil {
		if len(cdnSuspects.hosts) >= cdnSuspectMaxHosts {
			var oldest string
			for h, x := range cdnSuspects.hosts {
				if oldest == "" || x.last.Before(cdnSuspects.hosts[oldest].last) {
					oldest = h
				}
			}
			delete(cdnSuspects.hosts, oldest)
		}
		e = &cdnSuspectEntry{ips: map[string]time.Time{}, first: now}
		cdnSuspects.hosts[host] = e
	}
	if _, ok := e.ips[ip]; ok || len(e.ips) < cdnSuspectMaxIPsHost {
		e.ips[ip] = now
	}
	e.bounces++
	e.last = now
}

// CDNCachedChallengeHosts returns the hosts with a cleared bounce in the last
// 24 hours, the most distinct IPs first. edge_health reads it
// (cdn-cached-challenge). It is in-memory, so it starts empty after a daemon
// restart.
func CDNCachedChallengeHosts(now time.Time) []CDNCacheSuspect {
	cdnSuspects.mu.Lock()
	defer cdnSuspects.mu.Unlock()
	out := make([]CDNCacheSuspect, 0, len(cdnSuspects.hosts))
	for h, e := range cdnSuspects.hosts {
		if !e.pruneLocked(now) {
			delete(cdnSuspects.hosts, h)
			continue
		}
		out = append(out, CDNCacheSuspect{Host: h, IPs: len(e.ips), Bounces: e.bounces, First: e.first, Last: e.last})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IPs != out[j].IPs {
			return out[i].IPs > out[j].IPs
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// challengeHTTPServing counts the challenge server's live HTTP listeners (the
// v4 one; the v6 loopback twin shares its server). Zero means nothing here
// can bounce a client, so edge_health reports Check F as not measured rather
// than as all-clear.
var challengeHTTPServing atomic.Int32

// ChallengeServerServing reports whether the challenge server's HTTP listener
// is up in this process.
func ChallengeServerServing() bool { return challengeHTTPServing.Load() > 0 }

// resetCDNCachedChallengeForTest empties the tracker.
func resetCDNCachedChallengeForTest() {
	cdnSuspects.mu.Lock()
	cdnSuspects.hosts = map[string]*cdnSuspectEntry{}
	cdnSuspects.mu.Unlock()
}
