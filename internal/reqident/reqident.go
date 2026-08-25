// Package reqident derives the canonical client identity and effective scheme of
// an HTTP request as seen after CFM's trusted edge hop.
//
// Forwarded identity (X-Real-IP / X-Forwarded-For) and scheme
// (X-Forwarded-Proto) are trusted ONLY when the immediate socket peer is
// loopback. In CFM the OpenResty/Angie edge and the cPanel panel listeners
// always connect to the daemon from 127.0.0.1 / ::1 (they `proxy_bind
// 127.0.0.1`) after doing their own realip normalization, so a loopback peer is
// the one trustworthy signal that a canonical forwarded identity/scheme is
// present. A direct (non-loopback) client's forwarded headers are
// attacker-controlled and are ignored; a loopback edge that supplies an
// ambiguous or malformed forwarded address fails closed (ClientIP == nil)
// rather than inheriting loopback's trust.
//
// This is the single identity/scheme rule shared by the apiserver control plane
// (internal/apiserver) and the challenge server (internal/webdetector). It lives
// in its own leaf package so both can import it without an import cycle
// (apiserver already imports webdetector).
package reqident

import (
	"net"
	"net/http"
	"strings"
)

// Peer is the canonical identity of one HTTP request after the trusted edge hop.
type Peer struct {
	// ImmediateIP is the socket peer (r.RemoteAddr), or nil if unparseable.
	ImmediateIP net.IP
	// ClientIP is the effective client address. It equals ImmediateIP for a
	// direct request; for a loopback edge that forwarded a canonical address it
	// is that address; it is nil when a loopback, proxy-marked request carried
	// an ambiguous or malformed forwarded address (fail closed).
	ClientIP net.IP
	// TrustedProxy is true iff a loopback edge supplied a canonical forwarded
	// client IP that ClientIP now reflects.
	TrustedProxy bool
	// HadForwardedIdentity is true iff the request carried any proxy
	// client-identity header (X-Real-IP or X-Forwarded-For), regardless of
	// whether it resolved to a canonical IP. Lets callers classify the request
	// entry point without re-scanning the headers.
	HadForwardedIdentity bool
	// Scheme is the effective client-facing scheme, "http" or "https". A
	// forwarded X-Forwarded-Proto is applied only together with a canonical
	// forwarded client IP (i.e. when TrustedProxy is true) — the CFM edge always
	// authors the two headers together, so the scheme is only trusted when the
	// identity it belongs to is too; otherwise Scheme reflects r.TLS.
	Scheme string
}

// FromRequest derives the canonical Peer for r.
func FromRequest(r *http.Request) Peer {
	peer := Peer{Scheme: "http"}
	if r == nil {
		return peer
	}
	if r.TLS != nil {
		peer.Scheme = "https"
	}

	peer.HadForwardedIdentity = HasForwardedClientIdentity(r)
	peer.ImmediateIP = remoteIP(r.RemoteAddr)
	peer.ClientIP = peer.ImmediateIP
	if peer.ImmediateIP != nil && peer.ImmediateIP.IsLoopback() {
		if forwarded := trustedForwardedClientIP(r); forwarded != nil {
			peer.ClientIP = forwarded
			peer.TrustedProxy = true
			// Trust the forwarded scheme only together with a canonical forwarded
			// client IP: the edge sends X-Forwarded-Proto alongside X-Real-IP, so
			// a request that failed to yield one canonical client IP has no
			// trustworthy scheme either.
			if scheme := canonicalForwardedScheme(r.Header.Get("X-Forwarded-Proto")); scheme != "" {
				peer.Scheme = scheme
			}
		} else if peer.HadForwardedIdentity {
			// A proxy-marked request with an ambiguous/malformed client address
			// must fail closed rather than inheriting loopback's trust.
			peer.ClientIP = nil
		}
	}
	return peer
}

// ClientIPString returns the validated client IP as a string, or "" when none
// could be established. It never returns arbitrary forwarded text.
func ClientIPString(r *http.Request) string {
	if ip := FromRequest(r).ClientIP; ip != nil {
		return ip.String()
	}
	return ""
}

// HasForwardedClientIdentity reports whether r carries any proxy client-identity
// header (X-Real-IP or X-Forwarded-For). Used by callers that need to
// distinguish "no forwarded identity" from "forwarded identity that failed
// closed" (e.g. to classify the request entry point).
func HasForwardedClientIdentity(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.TrimSpace(r.Header.Get("X-Real-IP")) != "" ||
		strings.TrimSpace(r.Header.Get("X-Forwarded-For")) != ""
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	}
	return net.ParseIP(host)
}

// trustedForwardedClientIP returns the single canonical forwarded client IP, or
// nil. X-Real-IP wins over X-Forwarded-For; either carrying a comma (a
// multi-hop chain the edge should have collapsed) is rejected rather than
// guessed, so an ambiguous chain never becomes one client identity.
func trustedForwardedClientIP(r *http.Request) net.IP {
	if r == nil {
		return nil
	}
	if raw := strings.TrimSpace(r.Header.Get("X-Real-IP")); raw != "" {
		if strings.Contains(raw, ",") {
			return nil
		}
		return net.ParseIP(raw)
	}
	raw := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if raw == "" || strings.Contains(raw, ",") {
		return nil
	}
	return net.ParseIP(raw)
}

func canonicalForwardedScheme(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if strings.Contains(raw, ",") {
		return ""
	}
	switch raw {
	case "http", "https":
		return raw
	default:
		return ""
	}
}
