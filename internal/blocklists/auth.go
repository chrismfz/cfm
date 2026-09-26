package blocklists

import (
	"fmt"
	"net/url"
	"strings"
)

// APIAuth is the node's cfm-web credential (cfm.conf API_URL + AUTH_TOKEN).
// The token is attached ONLY to feeds on the API_URL origin: a cfm.blocklists
// file also lists third-party feeds (Spamhaus, FireHOL, ...), and handing them
// the node's admin token would leak it.
type APIAuth struct {
	BaseURL string
	Token   string
}

func (a APIAuth) base() *url.URL {
	raw := strings.TrimSpace(a.BaseURL)
	if raw == "" {
		return nil
	}
	// Equivalent, for http/https, to the agent client's normalisation
	// (internal/agent normalize): a schemeless API_URL means https, or every other cfm-web call would work
	// while the feeds silently went tokenless.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

func (a APIAuth) host() string {
	if u := a.base(); u != nil {
		return u.Host
	}
	return ""
}

// tokenFor returns the token to send to target, or "" when target is not the
// API_URL origin. Same origin means same host (case-insensitive) and same
// effective port; the scheme must match, except that an http API_URL may be
// upgraded to https — never the reverse, so a token configured for TLS is
// never sent in clear.
func (a APIAuth) tokenFor(target *url.URL) string {
	tok := strings.TrimSpace(a.Token)
	b := a.base()
	if tok == "" || b == nil || target == nil {
		return ""
	}
	bs, ts := strings.ToLower(b.Scheme), strings.ToLower(target.Scheme)
	if ts != bs && !(bs == "http" && ts == "https") {
		return ""
	}
	if !strings.EqualFold(b.Hostname(), target.Hostname()) {
		return ""
	}
	if effPort(b, bs) != effPort(target, ts) {
		// An https upgrade of an http API_URL with the default port
		// lands on 443; accept that pairing.
		if !(bs == "http" && ts == "https" && b.Port() == "" && target.Port() == "") {
			return ""
		}
	}
	return tok
}

// mismatch explains why target gets no token ("" when it would get one).
func (a APIAuth) mismatch(target *url.URL) string {
	b := a.base()
	switch {
	case strings.TrimSpace(a.Token) == "":
		return "no AUTH_TOKEN configured"
	case b == nil:
		return "API_URL is empty or unparseable"
	case a.tokenFor(target) != "":
		return ""
	case strings.EqualFold(b.Hostname(), target.Hostname()):
		return fmt.Sprintf("feed %s://%s differs from API_URL %s://%s in scheme or port", target.Scheme, target.Host, b.Scheme, b.Host)
	default:
		return fmt.Sprintf("only feeds on the API_URL host %q get the token", b.Host)
	}
}

// looksLikeAPIFeed limits the "no Token sent" hint to feeds that plausibly
// are cfm-web's (the API_URL hostname, or its /blacklist.txt|/whitelist.txt
// under another name such as an IP), so a third party's own 401/403 never
// suggests handing it the token.
func (a APIAuth) looksLikeAPIFeed(target *url.URL) bool {
	if b := a.base(); b != nil && strings.EqualFold(b.Hostname(), target.Hostname()) {
		return true
	}
	p := strings.ToLower(target.Path)
	return strings.HasSuffix(p, "/blacklist.txt") || strings.HasSuffix(p, "/whitelist.txt")
}

func effPort(u *url.URL, scheme string) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
