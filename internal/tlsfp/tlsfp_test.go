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
