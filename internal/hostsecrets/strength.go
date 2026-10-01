package hostsecrets

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// badTokens matches well-known placeholder values that must not be used in
// production. The check is case-insensitive and requires a full-string match.
var badTokens = regexp.MustCompile(`(?i)^(supersecret|changeme|secret|password|default|token|test|demo|placeholder)$`)

// LuaSafe reports whether s can be emitted verbatim into a generated Lua file
// via Go %q (cfm_token.lua, cfm_bridge_token.lua). It requires every byte to
// be a graphical ASCII char (0x21..0x7e): no whitespace, no control bytes, and
// no non-ASCII runes (audit F55). Go's %q renders a non-printable non-ASCII
// rune as \uXXXX / \UXXXXXXXX, which LuaJIT cannot parse (it expects \xHH or
// \u{...}), so a token containing e.g. a zero-width space would produce a Lua
// token file that fails to compile, taking edge<->collector (and
// edge<->bridge) auth down. Byte iteration is deliberate: any multi-byte UTF-8
// rune has bytes >= 0x80 and is rejected.
func LuaSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// IsStrongToken reports whether tok is strong: at least 32 characters, not a
// known placeholder, and Lua-safe. Resolve additionally requires Usable (the
// config cleaner's fixed point): a weak config value is not copied, and a weak
// token file is left alone and reported.
func IsStrongToken(tok string) bool {
	cur := strings.TrimSpace(tok)
	return len(cur) >= 32 && !badTokens.MatchString(cur) && LuaSafe(cur)
}

// GenerateToken returns a new random token: 24 bytes from crypto/rand as 48
// lowercase hex characters (strong and Lua-safe by construction).
func GenerateToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("hostsecrets: token generation failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}
