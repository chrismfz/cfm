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
//   - counts those bounces per host (noteCDNCachedChallenge), which edge_health
//     reports as the cdn-cached-challenge check and whats_wrong surfaces, so the
//     operator learns which tenant's CDN to fix.
//
// HONEST LIMITS: a CDN that overrides no-store ignores the CDN headers too
// (they help only where the origin's headers are respected), and one that
// ignores the query string in its cache key defeats the cache-bust (the bounce
// then ends at the page, as before). A cached redirect at a content URL still
// sends every visitor of that URL to the challenge until the CDN entry expires:
// the fix for that is the CDN's own rule, which the edge_health finding names.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
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

// cdnBustNext returns next with a fresh cfm_nc parameter appended, or ""
// when next already carries one (that bounce already tried a cache-bust; a
// second would only loop). next is the server-normalized same-origin target
// (normalizeChallengeNext); its existing query is kept byte for byte.
func cdnBustNext(next string) string {
	u, err := url.ParseRequestURI(next)
	if err != nil || !strings.HasPrefix(next, "/") || !isSameOriginPath(next) {
		return ""
	}
	if _, ok := u.Query()[cdnBustParam]; ok {
		return ""
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	sep := "?"
	if strings.Contains(next, "?") {
		sep = "&"
	}
	return next + sep + cdnBustParam + "=" + hex.EncodeToString(b[:])
}

// CDNCacheSuspect is one host whose cleared visitors were bounced back to the
// challenge page: the sign of a CDN serving a cached challenge or redirect.
type CDNCacheSuspect struct {
	Host  string    `json:"host"`
	Count int       `json:"count"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

const (
	cdnSuspectWindow   = 24 * time.Hour
	cdnSuspectMaxHosts = 256
)

var cdnSuspects = struct {
	mu    sync.Mutex
	hosts map[string]*CDNCacheSuspect
}{hosts: map[string]*CDNCacheSuspect{}}

// noteCDNCachedChallenge counts one cleared bounce for host. Bounded: past
// cdnSuspectMaxHosts it drops the stalest host, so a flood of Host headers
// cannot grow it (the host is the edge-stamped one, so it is a real vhost).
func noteCDNCachedChallenge(host string, now time.Time) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return
	}
	cdnSuspects.mu.Lock()
	defer cdnSuspects.mu.Unlock()
	e := cdnSuspects.hosts[host]
	if e != nil && now.Sub(e.Last) > cdnSuspectWindow {
		e = nil // the old run aged out: start counting afresh
	}
	if e == nil {
		if len(cdnSuspects.hosts) >= cdnSuspectMaxHosts {
			var oldest string
			for h, x := range cdnSuspects.hosts {
				if oldest == "" || x.Last.Before(cdnSuspects.hosts[oldest].Last) {
					oldest = h
				}
			}
			delete(cdnSuspects.hosts, oldest)
		}
		e = &CDNCacheSuspect{Host: host, First: now}
		cdnSuspects.hosts[host] = e
	}
	e.Count++
	e.Last = now
}

// CDNCachedChallengeHosts returns the hosts with a cleared bounce in the last
// 24 hours, the most bounces first. edge_health reads it (cdn-cached-challenge).
// It is in-memory, so it starts empty after a daemon restart.
func CDNCachedChallengeHosts(now time.Time) []CDNCacheSuspect {
	cdnSuspects.mu.Lock()
	defer cdnSuspects.mu.Unlock()
	out := make([]CDNCacheSuspect, 0, len(cdnSuspects.hosts))
	for h, e := range cdnSuspects.hosts {
		if now.Sub(e.Last) > cdnSuspectWindow {
			delete(cdnSuspects.hosts, h)
			continue
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// resetCDNCachedChallengeForTest empties the tracker.
func resetCDNCachedChallengeForTest() {
	cdnSuspects.mu.Lock()
	cdnSuspects.hosts = map[string]*CDNCacheSuspect{}
	cdnSuspects.mu.Unlock()
}
