package hostsecrets

import (
	"strings"
	"testing"
)

// zwsp is U+200B (zero-width space). Go %q renders it as a \u escape, which
// LuaJIT cannot parse — the F55 trigger. Written as an escape so the source
// stays plain ASCII.
const zwsp = "​"

func TestLuaSafe(t *testing.T) {
	t.Parallel()
	safe := []string{
		"abcdef0123456789",                   // hex (the generated form)
		"AbC-_.~+/=Xyz012345",                // base64url-ish + punctuation
		strings.Repeat("a", 48),              // long alnum
		"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", // every graphical ASCII punct incl. \" and \\
	}
	for _, s := range safe {
		if !LuaSafe(s) {
			t.Errorf("LuaSafe(%q) = false, want true", s)
		}
	}
	unsafe := []string{
		"abc def",                            // space
		"abc\tdef",                           // tab
		"abc\ndef",                           // newline
		"abc\x00def",                         // NUL
		"abc\x1fdef",                         // control
		"abc\x7fdef",                         // DEL
		"abc" + zwsp + "def",                 // zero-width space (multibyte)
		"abc" + string(rune(0x00e9)) + "def", // é, non-ASCII accented rune
		"abc" + string(rune(0x00a0)) + "def", // non-breaking space
	}
	for _, s := range unsafe {
		if LuaSafe(s) {
			t.Errorf("LuaSafe(%q) = true, want false", s)
		}
	}
}

// A strong-length token that is not Lua-safe is weak, and GenerateToken's
// output always passes.
func TestIsStrongTokenAndGenerateToken(t *testing.T) {
	t.Parallel()
	if bad := strings.Repeat("a", 40) + zwsp + strings.Repeat("b", 8); IsStrongToken(bad) {
		t.Fatalf("IsStrongToken accepted a Lua-unsafe token")
	}
	for _, weak := range []string{"", "supersecret", "PLACEHOLDER", strings.Repeat("a", 31)} {
		if IsStrongToken(weak) {
			t.Errorf("IsStrongToken(%q) = true, want false", weak)
		}
	}
	if strong := strings.Repeat("a1b2c3d4", 6); !IsStrongToken(strong) {
		t.Fatalf("IsStrongToken rejected a strong Lua-safe token")
	}
	gen, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !IsStrongToken(gen) || len(gen) != 48 {
		t.Fatalf("GenerateToken returned a token IsStrongToken rejects: %q", gen)
	}
}
