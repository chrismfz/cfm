// Package tlsfp parses the TLS ClientHello summary the edge stamps onto a
// request as X-CFM-TLS, and reduces it to a short stable id.
//
// The point of the signal: everything else CFM sees on a challenge solve is
// written by the client — the User-Agent, the cookies, the PoW solution, the
// timing. The TLS handshake is written by its TLS stack before any HTTP is
// sent. A client claiming "Chrome/118" whose handshake does not look like
// Chrome's is lying in a way no header edit can fix.
//
// This is a poor-man's JA3, not a JA4: the edge can report the cipher suites and
// curves the client offered plus the negotiated protocol and ALPN, but not the
// extension list or its order. Enough for a coherence check, and it needs no
// module or patched edge. See configs/lua/cfm_tlsfp.lua for the producer.
//
// LOG-FIRST, deliberately. Nothing here decides anything: the id exists so
// solves can be grouped and the fingerprint-to-UA mapping DERIVED from real
// traffic. Writing that mapping from memory is the mistake internal/uaplausible
// exists to warn about — the cipher names are also OpenSSL-build dependent, so a
// table lifted from another fleet would not even be comparable.
//
// TRUST BOUNDARY: the edge clears any client-supplied X-CFM-TLS before setting
// its own, so in edge mode the value is edge-generated. A client that reaches
// the daemon's listener directly (loopback / legacy DNAT) can still supply one.
// That is acceptable while this is log-only and the value is sanitised to a safe
// charset and bounded length — it means a client can write a fake fingerprint
// for its own log lines, nothing more. Revisit before anything scores on it.
package tlsfp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// maxHeader bounds what is parsed at all. The producer caps its output at 1024
// bytes; this leaves room for a future field without accepting an unbounded
// client-supplied string on the path that reaches a log line.
const maxHeader = 2048

// Print is a parsed ClientHello summary.
type Print struct {
	// Raw is the sanitised header value, kept so the full tuple can be written
	// once per distinct fingerprint instead of on every solve.
	Raw string
	// ID is 8 lowercase hex characters identifying the fingerprint.
	ID string

	Proto   string // negotiated TLS version
	Ciphers string // cipher suites the client offered
	Curves  string // curves the client offered
	ALPN    string // negotiated ALPN
	HTTP    string // HTTP/2.0 or HTTP/1.1
	// Resumed reports a resumed TLS session. It matters when reading the data:
	// a resumed handshake can carry thinner cipher/curve lists, so a reader must
	// be able to tell that apart from an unusual client.
	Resumed bool
}

// safe reports whether the value contains only characters the producer can
// emit. Anything else means the value did not come from the edge's sanitiser,
// so it is rejected outright rather than cleaned up — a value that needed
// cleaning is not a measurement of anything.
func safe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == '_', c == ':', c == '/', c == ',', c == '+', c == '|':
		default:
			return false
		}
	}
	return true
}

// Parse reads the X-CFM-TLS header. ok is false when the header is absent,
// malformed, or from a version this build does not understand — callers treat
// that as "no fingerprint", never as an error worth failing a request over.
func Parse(header string) (Print, bool) {
	h := strings.TrimSpace(header)
	if h == "" || len(h) > maxHeader || !safe(h) {
		return Print{}, false
	}
	f := strings.Split(h, "|")
	// version + protocol at minimum; the rest may be empty on an older edge
	// whose nginx lacks $ssl_curves or $ssl_alpn_protocol.
	if len(f) < 2 || f[0] != "1" {
		return Print{}, false
	}
	at := func(i int) string {
		if i < len(f) {
			return f[i]
		}
		return ""
	}
	p := Print{
		Raw:     h,
		Proto:   at(1),
		Ciphers: at(2),
		Curves:  at(3),
		ALPN:    at(4),
		HTTP:    at(5),
		Resumed: at(6) == "r",
	}
	if p.Proto == "" {
		return Print{}, false
	}
	p.ID = id(p)
	return p, true
}

// id hashes the parts that describe the CLIENT.
//
// HTTP version and session resumption are excluded on purpose. Both are
// per-request or per-session facts rather than properties of the client's TLS
// stack, so folding them in would split one client across several ids and
// destroy the grouping the id exists to provide.
func id(p Print) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"1", p.Proto, p.Ciphers, p.Curves, p.ALPN}, "|")))
	return hex.EncodeToString(sum[:4])
}
