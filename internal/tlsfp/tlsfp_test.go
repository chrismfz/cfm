package tlsfp

import (
	"strings"
	"testing"
)

// A Chrome-shaped tuple in the exact wire format configs/lua/cfm_tlsfp.lua
// produces: version, protocol, offered ciphers, offered curves, ALPN, HTTP
// version, resumption flag.
const chromeTuple = "1|TLSv1.3|TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519:prime256v1:secp384r1|h2|HTTP/2.0|"

func TestParseChromeTuple(t *testing.T) {
	p, ok := Parse(chromeTuple)
	if !ok {
		t.Fatal("Parse returned ok=false for a well-formed tuple")
	}
	if p.Proto != "TLSv1.3" {
		t.Errorf("Proto = %q", p.Proto)
	}
	if !strings.HasPrefix(p.Ciphers, "TLS_AES_128_GCM_SHA256:") {
		t.Errorf("Ciphers = %q", p.Ciphers)
	}
	if p.Curves != "X25519:prime256v1:secp384r1" {
		t.Errorf("Curves = %q", p.Curves)
	}
	if p.ALPN != "h2" || p.HTTP != "HTTP/2.0" {
		t.Errorf("ALPN/HTTP = %q/%q", p.ALPN, p.HTTP)
	}
	if p.Resumed {
		t.Error("Resumed = true, want false for an empty resumption field")
	}
	if len(p.ID) != 8 {
		t.Fatalf("ID = %q, want 8 hex characters", p.ID)
	}
	for _, c := range p.ID {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("ID = %q is not lowercase hex", p.ID)
		}
	}
	if p.Raw != chromeTuple {
		t.Errorf("Raw = %q, want the header verbatim", p.Raw)
	}
}

func TestIDIsStableAndDiscriminating(t *testing.T) {
	base, _ := Parse(chromeTuple)

	same, _ := Parse(chromeTuple)
	if same.ID != base.ID {
		t.Errorf("same tuple produced %q and %q", base.ID, same.ID)
	}

	// A different cipher list is a different client stack.
	other, _ := Parse("1|TLSv1.3|TLS_AES_256_GCM_SHA384|X25519:prime256v1:secp384r1|h2|HTTP/2.0|")
	if other.ID == base.ID {
		t.Error("a different cipher list produced the same id")
	}
	// ...and so is a different curve list.
	curves, _ := Parse("1|TLSv1.3|TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519|h2|HTTP/2.0|")
	if curves.ID == base.ID {
		t.Error("a different curve list produced the same id")
	}
}

// HTTP version and session resumption are per-request/per-session facts, not
// properties of the client's TLS stack. Folding them into the id would split one
// client across several ids and destroy the grouping the id exists for.
func TestIDIgnoresPerRequestFields(t *testing.T) {
	base, _ := Parse(chromeTuple)
	for _, tuple := range []string{
		strings.Replace(chromeTuple, "|HTTP/2.0|", "|HTTP/1.1|", 1),
		chromeTuple + "r",
		strings.Replace(chromeTuple, "|HTTP/2.0|", "|HTTP/1.1|", 1) + "r",
	} {
		p, ok := Parse(tuple)
		if !ok {
			t.Fatalf("Parse(%q) = !ok", tuple)
		}
		if p.ID != base.ID {
			t.Errorf("id changed with a per-request field: %q vs %q (%q)", p.ID, base.ID, tuple)
		}
	}
	if p, _ := Parse(chromeTuple + "r"); !p.Resumed {
		t.Error("Resumed = false for a tuple ending in the resumption flag")
	}
}

// A value that needs cleaning did not come from the edge's sanitiser, so it is
// not a measurement of anything and must be rejected rather than tidied up. The
// header-splitting cases are the ones that matter: this value reaches a log line.
func TestUnsafeValuesAreRejected(t *testing.T) {
	for _, bad := range []string{
		"1|TLSv1.3|AES\r\nX-Injected: 1|X25519|h2|HTTP/2.0|",
		"1|TLSv1.3|AES\nfoo|X25519|h2|HTTP/2.0|",
		`1|TLSv1.3|"quoted"|X25519|h2|HTTP/2.0|`,
		"1|TLSv1.3|AES;rm -rf|X25519|h2|HTTP/2.0|",
		"1|TLSv1.3|AES X25519|h2|HTTP/2.0|",
		"1|TLSv1.3|café|X25519|h2|HTTP/2.0|",
	} {
		if p, ok := Parse(bad); ok {
			t.Errorf("Parse(%q) = ok, want rejected (got %+v)", bad, p)
		}
	}
}

func TestMalformedOrAbsentHeaders(t *testing.T) {
	for _, s := range []string{
		"",
		"   ",
		"TLSv1.3",                          // no version prefix
		"2|TLSv1.3|AES|X25519|h2|HTTP/2.0", // future wire version
		"1",                                // version only
		"1|",                               // empty protocol
		"1||AES|X25519|h2|HTTP/2.0|",       // empty protocol, fields present
		strings.Repeat("a", maxHeader+1),
	} {
		if _, ok := Parse(s); ok {
			t.Errorf("Parse(%q) = ok, want false", s)
		}
	}
}

// An older edge (nginx without $ssl_curves or $ssl_alpn_protocol) sends a short
// tuple. It must still parse and still yield an id, otherwise the whole signal
// disappears on exactly the hosts most likely to need a look.
func TestShortTupleFromOlderEdge(t *testing.T) {
	p, ok := Parse("1|TLSv1.2")
	if !ok {
		t.Fatal("a version+protocol tuple must parse")
	}
	if p.Proto != "TLSv1.2" || p.Ciphers != "" || p.Curves != "" {
		t.Errorf("unexpected fields: %+v", p)
	}
	if len(p.ID) != 8 {
		t.Errorf("ID = %q", p.ID)
	}
}

func TestRegistryAnnouncesOnce(t *testing.T) {
	r := NewRegistry(3)
	if !r.FirstSeen("aaaaaaaa") {
		t.Fatal("first sighting must announce")
	}
	if r.FirstSeen("aaaaaaaa") {
		t.Fatal("second sighting must not announce")
	}
	if r.FirstSeen("") {
		t.Fatal("an empty id must never announce")
	}
	if got := r.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1", got)
	}
}

// The id is derived from client-controlled bytes, so an unbounded registry is a
// memory bug: a client varying its ClientHello per connection would grow it
// without limit. Reaching the bound must be visible, not silent.
func TestRegistryIsBounded(t *testing.T) {
	r := NewRegistry(2)
	if !r.FirstSeen("a") || !r.FirstSeen("b") {
		t.Fatal("the first two ids must be admitted")
	}
	if r.Capped() {
		t.Fatal("Capped() = true before the bound was exceeded")
	}
	if r.FirstSeen("c") {
		t.Fatal("an id past the bound must not be admitted")
	}
	if !r.Capped() {
		t.Fatal("Capped() = false after refusing an id — the gap would be silent")
	}
	if got := r.Len(); got != 2 {
		t.Fatalf("Len = %d, want the bound", got)
	}
	// Ids already known keep working after the bound is hit.
	if r.FirstSeen("a") {
		t.Fatal("a known id announced again after the bound")
	}
}

func TestNilRegistryIsSafe(t *testing.T) {
	var r *Registry
	if r.FirstSeen("a") || r.Capped() || r.Len() != 0 {
		t.Fatal("a nil registry must be inert, not panic")
	}
}

// GREASE is the single most important normalisation here. RFC 8701 stacks —
// Chrome above all — insert a code point chosen at random per connection into
// the cipher list and the supported_groups, and nginx renders those as hex. Left
// in, one real client would produce up to 16x16 distinct ids: the grouping the
// id exists for would be gone and the first_seen dictionary would fill with
// noise. JA4 strips GREASE for exactly this reason.
func TestGREASEDoesNotChangeTheID(t *testing.T) {
	const base = "1|TLSv1.3|TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519:prime256v1|h2|HTTP/2.0|"
	want, ok := Parse(base)
	if !ok {
		t.Fatal("base tuple did not parse")
	}
	if want.GREASE {
		t.Error("GREASE reported on a tuple that has none")
	}

	// The same client on sixteen different connections: a different GREASE value
	// each time, in a different position, in either list, in either case.
	for _, tuple := range []string{
		"1|TLSv1.3|0x0a0a:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519:prime256v1|h2|HTTP/2.0|",
		"1|TLSv1.3|TLS_AES_128_GCM_SHA256:0x1a1a:ECDHE-RSA-AES128-GCM-SHA256|X25519:prime256v1|h2|HTTP/2.0|",
		"1|TLSv1.3|TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:0xfafa|X25519:prime256v1|h2|HTTP/2.0|",
		"1|TLSv1.3|TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256|0x9a9a:X25519:prime256v1|h2|HTTP/2.0|",
		"1|TLSv1.3|TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519:0xAAAA:prime256v1|h2|HTTP/2.0|",
		"1|TLSv1.3|0x7a7a:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519:prime256v1:0xdada|h2|HTTP/2.0|",
	} {
		got, ok := Parse(tuple)
		if !ok {
			t.Fatalf("Parse(%q) = !ok", tuple)
		}
		if got.ID != want.ID {
			t.Errorf("GREASE changed the id: %q vs %q for %q", got.ID, want.ID, tuple)
		}
		if !got.GREASE {
			t.Errorf("GREASE not reported for %q", tuple)
		}
		if got.Raw != tuple {
			t.Errorf("Raw was normalised; it must stay verbatim as the evidence line")
		}
		if strings.Contains(got.Ciphers, "0x") || strings.Contains(got.Curves, "0x") {
			t.Errorf("GREASE left in the analysis fields: %q / %q", got.Ciphers, got.Curves)
		}
	}
}

// Only the sixteen GREASE code points may be dropped. A genuine unknown cipher
// or curve rendered as hex is real signal — dropping it would erase exactly the
// oddity that makes an unusual stack recognisable.
func TestNonGREASEHexIsKept(t *testing.T) {
	for _, tok := range []string{"0x00ff", "0x001d", "0x0a0b", "0x1a2a", "0xaaab", "0x0a0", "0x0a0a0", "0xzaza"} {
		if isGREASE(tok) {
			t.Errorf("isGREASE(%q) = true, want false", tok)
		}
	}
	for _, tok := range []string{"0x0a0a", "0x1a1a", "0x9a9a", "0xaaaa", "0xfafa", "0xFAFA", "0X2a2A"} {
		if !isGREASE(tok) {
			t.Errorf("isGREASE(%q) = false, want true", tok)
		}
	}
	p, ok := Parse("1|TLSv1.3|0x00ff:AES128-SHA|0x001d:prime256v1|h2|HTTP/2.0|")
	if !ok {
		t.Fatal("Parse = !ok")
	}
	if p.Ciphers != "0x00ff:AES128-SHA" || p.Curves != "0x001d:prime256v1" {
		t.Fatalf("unknown-but-real hex was stripped: %q / %q", p.Ciphers, p.Curves)
	}
	if p.GREASE {
		t.Error("GREASE reported for ordinary unknown code points")
	}
}

// Stripping must not reorder what is left: the offered order is stable per stack
// and part of what makes the fingerprint discriminating.
func TestStripGREASEPreservesOrder(t *testing.T) {
	got, found := stripGREASE("a:0x0a0a:b:c:0xfafa:d")
	if !found {
		t.Error("found = false")
	}
	if got != "a:b:c:d" {
		t.Fatalf("stripGREASE = %q, want %q", got, "a:b:c:d")
	}
	if only, found := stripGREASE("0x0a0a"); only != "" || !found {
		t.Fatalf("an all-GREASE list gave %q/%v", only, found)
	}
	if s, found := stripGREASE(""); s != "" || found {
		t.Fatalf("empty list gave %q/%v", s, found)
	}
}

// TestTruncatedFieldIsFlaggedAndDistinct covers the case production hit on
// 2026-07-28: Meta's crawler offered a cipher list longer than the edge's field
// bound, so the edge cut it. Two things must hold, and neither is cosmetic.
//
// The print must be marked truncated, because a cut list can be shared by two
// different clients whose offers agree up to the bound — the id is real but it
// counts fewer distinct clients than it appears to, and a reader has to know.
//
// And the cut list must NOT hash equal to a client that genuinely offered
// exactly that shorter list. Without the TRUNC token in the hashed value they
// would collide, and the collision would be invisible: the same id, one from a
// long offer and one from a short one, with nothing in the log to separate them.
func TestTruncatedFieldIsFlaggedAndDistinct(t *testing.T) {
	const short = "1|TLSv1.3|TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519|h2|HTTP/2.0|."
	cut := "1|TLSv1.3|TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:TRUNC|X25519|h2|HTTP/2.0|."

	whole, ok := Parse(short)
	if !ok {
		t.Fatal("Parse(short) not ok")
	}
	if whole.Truncated {
		t.Error("an untruncated tuple must not be flagged truncated")
	}

	part, ok := Parse(cut)
	if !ok {
		t.Fatal("Parse(cut) not ok")
	}
	if !part.Truncated {
		t.Error("a tuple carrying the TRUNC token must be flagged truncated")
	}
	if part.ID == whole.ID {
		t.Errorf("a truncated list hashes equal to a genuinely shorter one (both %s); "+
			"the TRUNC token must stay in the hashed value", part.ID)
	}

	// The marker is also honoured on the curve list, which is the field a
	// post-quantum-heavy client is most likely to overrun next.
	curves, ok := Parse("1|TLSv1.3|TLS_AES_128_GCM_SHA256|X25519:prime256v1:TRUNC|h2|HTTP/2.0|.")
	if !ok {
		t.Fatal("Parse(curves) not ok")
	}
	if !curves.Truncated {
		t.Error("TRUNC in the curve list must flag the print truncated")
	}

	// A cipher merely *containing* the letters is not the marker — only a whole
	// token is, or a real suite name would start flagging prints at random.
	near, ok := Parse("1|TLSv1.3|TRUNCATED-CIPHER:AES128-SHA|X25519|h2|HTTP/2.0|.")
	if !ok {
		t.Fatal("Parse(near) not ok")
	}
	if near.Truncated {
		t.Error("a token that merely contains TRUNC must not flag the print")
	}
}
