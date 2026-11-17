// Package goodbot is the FCrDNS good-bot registry: the canonical PTR suffix of
// each crawler CFM trusts (Googlebot, Bingbot, Applebot, Yandex, Meta, …) and
// the forward-confirm that turns a PTR claim into a verdict.
//
// It is a leaf package so every subsystem that exempts a crawler reads the
// SAME list: the web detector (challenge exemption, verified_bot traffic
// rules, its IP bans, the abuse-shadow counts) and the L4 flood autoblock in
// internal/firewall, which cannot import webdetector (webdetector imports
// firewall). Never keep a second copy of the list.
//
// Membership is never trust: a PTR anyone can set on their own address earns
// nothing until its name resolves back to the address.
package goodbot

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// PTRSuffixes maps a good bot's canonical PTR domain suffix to its name.
// Read-only after init.
var PTRSuffixes = map[string]string{
	".googlebot.com":      "googlebot",
	".google.com":         "google",
	".search.msn.com":     "bingbot",
	".crawl.yahoo.net":    "yahoo",
	".applebot.apple.com": "applebot",
	".yandex.com":         "yandex",
	".yandex.net":         "yandex",
	".yandex.ru":          "yandex",
	// Meta's crawler fleet (facebookexternalhit / meta-externalagent /
	// meta-externalads) and its forward proxies (fwdproxy-*.fbsv.net: link
	// previews, the in-app browser) reverse to *.fbsv.net and forward-confirm.
	// Added 2026-08-21 after CHALLENGE_SUBNET live-FP'd Meta's 57.141.20.0/24
	// on a shop vhost (60+ crawler IPs in one /24 tripped SUBNET_MIN_IPS).
	".fbsv.net": "meta",
}

// SuffixName reports the good-bot name whose canonical PTR suffix matches ptr,
// plus the normalised host (trimmed, lowercased, no trailing dot) to
// forward-confirm. This is the MATCH only: a caller that needs trust must
// forward-confirm (Verify).
func SuffixName(ptr string) (name, host string, ok bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ptr), "."))
	if host == "" {
		return "", "", false
	}
	for suf, nm := range PTRSuffixes {
		if strings.HasSuffix(host, suf) {
			return nm, host, true
		}
	}
	return "", host, false
}

// ForwardConfirms resolves host and reports whether any A/AAAA equals ip,
// with the resolver error exposed: err != nil is a transient failure
// (inconclusive), a nil err with matched=false a definitive non-match.
func ForwardConfirms(host, ip string) (matched bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return ForwardConfirmsWith(ctx, net.DefaultResolver.LookupHost, host, ip)
}

// ForwardConfirmsWith is ForwardConfirms over an injectable lookup (tests).
// A name that does not exist (NXDOMAIN / no address: IsNotFound) is an ANSWER,
// not a blip: the claimed crawler name can't confirm anything, so it is a
// definitive non-match. That is the natural spoof, a PTR of x.googlebot.com,
// a name nobody outside Google can create.
func ForwardConfirmsWith(ctx context.Context, lookup func(context.Context, string) ([]string, error), host, ip string) (matched bool, err error) {
	addrs, err := lookup(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		return false, err
	}
	want := net.ParseIP(ip)
	for _, a := range addrs {
		// Compare as parsed IPs so a non-canonical IPv6 spelling still matches.
		if ap := net.ParseIP(a); ap != nil && want != nil && ap.Equal(want) {
			return true, nil
		}
		if a == ip {
			return true, nil
		}
	}
	return false, nil
}

// Verify forward-confirms a good-bot-suffix PTR. name is the bot ("" = not a
// verified good bot); cacheable=false means inconclusive (a transient resolver
// failure), which a caller must neither cache nor take as a verdict either way.
// A PTR with no good-bot suffix returns ("", true) without any DNS.
func Verify(ptr, ip string) (name string, cacheable bool) {
	nm, host, ok := SuffixName(ptr)
	if !ok {
		return "", true
	}
	matched, err := ForwardConfirms(host, ip)
	if err != nil {
		return "", false
	}
	if matched {
		return nm, true
	}
	return "", true
}
