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

	// Ciphers and Curves are the lists the client offered, with GREASE code
	// points removed — see stripGREASE for why that is mandatory rather than
	// tidy. Raw keeps the value exactly as the edge sent it, GREASE included, so
	// the evidence line is faithful while the analysis fields are comparable.
	Proto   string // negotiated TLS version
	Ciphers string // cipher suites the client offered, GREASE removed
	Curves  string // curves the client offered, GREASE removed
	ALPN    string // negotiated ALPN
	HTTP    string // HTTP/2.0 or HTTP/1.1
	// GREASE reports that at least one GREASE code point was stripped. Worth
	// recording during the log-first phase: it answers whether GREASE survives
	// OpenSSL's ClientHello parsing into these variables on this edge at all,
	// which decides how much the stripping is actually doing.
	GREASE bool
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
	ciphers, cipherGREASE := stripGREASE(at(2))
	curves, curveGREASE := stripGREASE(at(3))
	p := Print{
		Raw:     h,
		Proto:   at(1),
		Ciphers: ciphers,
		Curves:  curves,
		ALPN:    at(4),
		HTTP:    at(5),
		Resumed: at(6) == "r",
		GREASE:  cipherGREASE || curveGREASE,
	}
	if p.Proto == "" {
		return Print{}, false
	}
	p.ID = id(p)
	return p, true
}

// stripGREASE removes GREASE code points from a colon-separated cipher or curve
// list and reports whether any were found.
//
// This is not cosmetic — without it the whole signal would be close to useless.
// Chrome (and every stack that follows RFC 8701) inserts a GREASE value chosen
// at random per connection into its cipher list and its supported_groups, to
// keep middleboxes from ossifying on a fixed set. nginx renders values OpenSSL
// does not know as hex, so a GREASE value lands in $ssl_ciphers/$ssl_curves as
// 0x?a?a and CHANGES ON EVERY CONNECTION. Hashing it would give one real client
// up to 16x16 distinct ids, destroying the grouping the id exists for and
// filling the first_seen dictionary with noise until it hit its bound.
//
// This is exactly why JA4 strips GREASE and why the original JA3 was criticised
// for not doing so. Whether GREASE actually survives into these variables
// depends on how the edge's OpenSSL parses the ClientHello, which is one of the
// things the log-first phase is meant to establish — hence Print.GREASE, so the
// answer comes from the data rather than from an assumption either way.
//
// The list ORDER is untouched: it is the client's offered order, which is stable
// per stack and part of what makes the fingerprint discriminating. Only the
// randomised entries are dropped.
func stripGREASE(list string) (string, bool) {
	if list == "" {
		return "", false
	}
	parts := strings.Split(list, ":")
	kept := parts[:0]
	found := false
	for _, tok := range parts {
		if isGREASE(tok) {
			found = true
			continue
		}
		kept = append(kept, tok)
	}
	if !found {
		return list, false
	}
	return strings.Join(kept, ":"), true
}

// isGREASE reports whether tok is one of the 16 GREASE code points as nginx
// renders an unrecognised cipher suite or curve: 0x0a0a, 0x1a1a, … 0xfafa —
// two identical bytes whose low nibble is 0xa.
func isGREASE(tok string) bool {
	if len(tok) != 6 || tok[0] != '0' || (tok[1] != 'x' && tok[1] != 'X') {
		return false
	}
	hi1, lo1 := lowerHex(tok[2]), lowerHex(tok[3])
	hi2, lo2 := lowerHex(tok[4]), lowerHex(tok[5])
	if lo1 != 'a' || lo2 != 'a' || hi1 != hi2 {
		return false
	}
	return (hi1 >= '0' && hi1 <= '9') || (hi1 >= 'a' && hi1 <= 'f')
}

func lowerHex(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c + ('a' - 'A')
	}
	return c
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
