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
//     cached, instead of being served the PoW again (cdnBustNext; the edge
//     drops cfm_nc again before the origin on a plain path, cfm.lua
//     strip_cdn_bust_arg). Once per
//     target per window: a further bounce gets the page;
//   - counts those bounces per host and distinct client (an IPv4 address, an
//     IPv6 /64) over 24 h
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
//     window) counts too, and the latter can hit many IPs at once;
//   - a download leaves the tab on the challenge address, and each re-tap is
//     a cleared bounce with no cache involved: orion's mathematica.gr
//     (2026-10-21) has no CDN at all, and every bounce there was a PDF opened
//     on Android. So a bounce for a download target (cdnDownloadTarget) is
//     not counted, and one the edge marks as DIRECT (cdnRelayedHeader "0":
//     the TCP peer is the client itself) goes to a second list, cdnDirect,
//     which edge_health shows without warning. A direct bounce is a browser
//     re-opening the address (a download served from a script URL, which no
//     extension names), or a CDN the edge does not trust as a proxy (not in
//     trusted_proxies.conf), whose POP addresses then look like clients. The
//     warning is kept for the case the edge can tell: a trusted proxy (the
//     CDN) relayed the bounce. An edge conf from before the header sends
//     none, and its bounces are counted for the warning, as before.

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

// cdnRelayedHeader is the edge's answer to "did this request reach the edge
// through a trusted proxy?": the confs' location = /__cfm_challenge sets it to
// $xfp_trusted_peer, "1" when realip rewrote the client address (the peer is
// in trusted_proxies.conf), "0" when the peer is the client. The edge sets it
// itself, so a client cannot choose it on a current conf.
const cdnRelayedHeader = "X-CFM-Relayed"

// cdnRelayedCounts: whether a cleared bounce with this cdnRelayedHeader value
// counts toward the cdn-cached-challenge check. Only an explicit "0" (direct)
// is left out; an absent header is an edge conf from before it, which keeps
// counting every bounce, and "1" is a bounce through a CDN.
func cdnRelayedCounts(v string) bool {
	return strings.TrimSpace(v) != "0"
}

// cdnRelayedLogValue: the header for the log line, "-" when absent (an older
// edge conf), anything else but 0/1 shown as "?" (never the raw client text).
func cdnRelayedLogValue(v string) string {
	switch v = strings.TrimSpace(v); v {
	case "0", "1":
		return v
	case "":
		return "-"
	}
	return "?"
}

// cdnDownloadTarget: next names a file a browser downloads rather than shows
// (by its path's extension). A cleared bounce for one is not counted at all:
// the download leaves the tab on the challenge address, and the visitor's
// next tap on it is a cleared bounce with no cache involved (orion's
// mathematica.gr PDFs on Android, through a CDN or not). A CDN that caches the
// challenge caches the site's pages too, so the host still shows there.
func cdnDownloadTarget(next string) bool {
	p, _, _ := strings.Cut(next, "?")
	p, _, _ = strings.Cut(p, "#")
	if dp, err := url.PathUnescape(p); err == nil {
		p = dp
	}
	i := strings.LastIndexByte(p, '.')
	if i < 0 || strings.ContainsRune(p[i:], '/') {
		return false
	}
	return cdnDownloadExts[strings.ToLower(p[i+1:])]
}

var cdnDownloadExts = map[string]bool{
	"pdf": true, "zip": true, "rar": true, "7z": true, "gz": true, "tgz": true, "tar": true,
	"doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true,
	"odt": true, "ods": true, "odp": true, "rtf": true, "csv": true, "epub": true,
	"mp3": true, "mp4": true, "apk": true, "exe": true, "msi": true, "dmg": true, "iso": true,
}

// cdnBustParam is the query parameter cdnBustNext adds. Its only job is to
// make the URL one no cache has seen: the edge drops it before the origin
// (cfm.lua strip_cdn_bust_arg, same raw case-sensitive key), so an app that
// signs its URLs (Laravel signed routes) still sees the URL it signed.
const cdnBustParam = "cfm_nc"

// cdnBustNext returns next with a fresh cfm_nc parameter, or "" for a next
// that is not a same-origin path. An existing cfm_nc is REPLACED, not kept: a
// busted URL ends up in address bars, bookmarks and shared links, and a CDN
// caches that exact URL too. The caller bounds the busts (one per target per
// window), so a fresh value can never loop. next is the server-normalized
// target (normalizeChallengeNext); the rest of its query is kept byte for byte,
// empty pairs included.
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
	if query != "" {
		// Empty pairs are kept like every other byte: the edge drops only
		// the cfm_nc pairs again (cfm.lua strip_cdn_bust_arg), and the
		// origin must get the original query back (an HMAC over it).
		for _, kv := range strings.Split(query, "&") {
			if k, _, _ := strings.Cut(kv, "="); k == cdnBustParam {
				continue
			}
			kept = append(kept, kv)
		}
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
// thresholds on (the field keeps its name): the host is the client's own Host
// header (the web servers are `server_name _`), so a single client could
// otherwise pump the count for any name. Three proxies still can; the finding
// says "likely" for that. Bounces and First cover the whole current run (it
// lasts while any of its clients is inside the window), so they can span more
// than 24 h.
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
	ips     map[string]time.Time // client (cdnSuspectClient) -> its last bounce
	bounces int
	first   time.Time
	last    time.Time
}

// cdnTracker holds cleared bounces per host. Two of them: cdnSuspects for the
// bounces a trusted proxy relayed (or an edge conf too old to say), which
// edge_health warns on, and cdnDirect for the ones that reached the edge
// directly, which it only lists (see the file header).
type cdnTracker struct {
	mu    sync.Mutex
	hosts map[string]*cdnSuspectEntry
}

var (
	cdnSuspects = &cdnTracker{hosts: map[string]*cdnSuspectEntry{}}
	cdnDirect   = &cdnTracker{hosts: map[string]*cdnSuspectEntry{}}
)

// pruneLocked drops the clients whose last bounce left the window and reports
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

// noteCDNCachedChallenge records one cleared bounce of ip on host that a
// trusted proxy relayed (or an older edge conf could not say). Bounded: past
// cdnSuspectMaxHosts it drops the stalest host, a host keeps at most
// cdnSuspectMaxIPsHost clients (IPv6 per /64, cdnSuspectClient), and the host
// is cut to 120 bytes (it is the client's own Host header).
func noteCDNCachedChallenge(host, ip string, now time.Time) { cdnSuspects.note(host, ip, now) }

// noteDirectClearedBounce records one cleared bounce that reached the edge
// directly (X-CFM-Relayed: 0), with the same bounds.
func noteDirectClearedBounce(host, ip string, now time.Time) { cdnDirect.note(host, ip, now) }

func (t *cdnTracker) note(host, ip string, now time.Time) {
	host = truncateForLog(strings.ToLower(strings.TrimSpace(host)), 120)
	ip = cdnSuspectClient(strings.TrimSpace(ip))
	if host == "" || ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.hosts[host]
	if e != nil && !e.pruneLocked(now) {
		delete(t.hosts, host) // the old run aged out: start afresh
		e = nil
	}
	if e == nil {
		if len(t.hosts) >= cdnSuspectMaxHosts {
			var oldest string
			for h, x := range t.hosts {
				if oldest == "" || x.last.Before(t.hosts[oldest].last) {
					oldest = h
				}
			}
			delete(t.hosts, oldest)
		}
		e = &cdnSuspectEntry{ips: map[string]time.Time{}, first: now}
		t.hosts[host] = e
	}
	if _, ok := e.ips[ip]; ok || len(e.ips) < cdnSuspectMaxIPsHost {
		e.ips[ip] = now
	}
	e.bounces++
	e.last = now
}

func (t *cdnTracker) list(now time.Time) []CDNCacheSuspect {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]CDNCacheSuspect, 0, len(t.hosts))
	for h, e := range t.hosts {
		if !e.pruneLocked(now) {
			delete(t.hosts, h)
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

// CDNCachedChallengeHosts returns the hosts with a relayed cleared bounce in
// the last 24 hours, the most distinct clients first. edge_health warns on it
// (cdn-cached-challenge). It is in-memory, so it starts empty after a daemon
// restart.
func CDNCachedChallengeHosts(now time.Time) []CDNCacheSuspect { return cdnSuspects.list(now) }

// DirectClearedBounceHosts returns the hosts whose cleared visitors came back
// to the page DIRECTLY in the last 24 hours. edge_health lists them without a
// warning: a browser re-opening the challenge address, or a CDN the edge does
// not trust as a proxy (the file header).
func DirectClearedBounceHosts(now time.Time) []CDNCacheSuspect { return cdnDirect.list(now) }

// challengeHTTPServing counts the challenge server's live HTTP listeners (the
// primary one; the v6 loopback twin shares its server and is not counted).
// Zero means nothing here serves a challenge, so edge_health reports Check F
// as not measured (measured=false) unless the tracker still holds suspects.
var challengeHTTPServing atomic.Int32

// ChallengeServerServing reports whether the challenge server's HTTP listener
// is up in this process.
func ChallengeServerServing() bool { return challengeHTTPServing.Load() > 0 }

// resetCDNCachedChallengeForTest empties both trackers.
func resetCDNCachedChallengeForTest() {
	for _, t := range []*cdnTracker{cdnSuspects, cdnDirect} {
		t.mu.Lock()
		t.hosts = map[string]*cdnSuspectEntry{}
		t.mu.Unlock()
	}
}
