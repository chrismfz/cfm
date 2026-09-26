package blocklists

import (
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
	if strings.TrimSpace(a.BaseURL) == "" {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(a.BaseURL))
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
