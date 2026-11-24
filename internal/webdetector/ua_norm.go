// internal/webdetector/ua_norm.go
//
// User-Agent normalization for the bot-top / UA emergency control surface.
//
// We avoid a curated bot table for v1. The heuristic is:
//   - Empty / "-" / pure whitespace → "-".
//   - If the UA does NOT start with the generic "mozilla" envelope, return
//     the first token before '/', ';' or whitespace, lowered. This catches
//     "curl/7.88", "python-requests/2.31", "ahrefsbot/7.0",
//     "facebookexternalhit/1.1" directly.
//   - If the UA starts with "mozilla", scan each top-level "(...)" group in
//     order and return the first inner token that contains a bot-family
//     marker substring (botMarkers). This catches Googlebot (desktop and
//     smartphone), Bingbot, SemrushBot, AhrefsBot, meta-externalagent,
//     facebookexternalhit, etc. while leaving real browsers untouched.
//   - Real browsers (Mozilla envelope with no bot marker) → "mozilla".
//
// The function is allocation-light and runs on every ingest event.
package webdetector

import "strings"

// botMarkers are substrings that, when present in an inner-envelope token,
// signal "this is a bot identifier, return it as the canonical name."
// All comparisons happen on the already-lowercased input.
var botMarkers = []string{
	"bot",
	"spider",
	"crawl",
	"agent",
	"fetch",
	"externalhit",
	"scrap",
	"preview",
	"embed",
	"monitor",
	"checker",
	"indexer",               // meta-webindexer
	"googleother",           // GoogleOther, in a Mozilla envelope
	"google-inspectiontool", // Search Console's fetcher
}

// NormalizeUA returns a stable short identifier for a User-Agent string.
// The returned identifier is lowercase, free of version numbers, and stable
// across minor UA variations from the same bot family.
//
// It works on bytes and is ASCII-only on purpose (trimASCIISpace,
// asciiLower): configs/lua/cfm_ua_emergency.lua normalize_ua is its edge
// twin, Lua's %s and string.lower know only ASCII, and both run
// scripts/tests/fixtures/ua_norm.txt. strings.TrimSpace / ToLower would also
// trim NBSP and fold non-ASCII letters, and the edge would key that UA
// differently from `cfm bots top`.
func NormalizeUA(ua string) string {
	s := trimASCIISpace(ua)
	if s == "" || s == "-" {
		return "-"
	}
	s = asciiLower(s)

	head := firstUAToken(s)
	if head == "" {
		return "-"
	}

	// Generic case: anything that isn't the "mozilla" envelope.
	if head != "mozilla" {
		return head
	}

	// Mozilla envelope: look inside every top-level "(...)" group, in order,
	// for a bot identifier. Not only the first: Meta's crawler (since
	// 2026-11, Chrome 145) and Googlebot smartphone put a full browser UA
	// first and declare themselves in a trailing "(compatible; …)" group, so
	// a first-group-only scan read them as "mozilla" and `cfm bots block
	// meta-externalagent` never matched. A group ends at its MATCHING ")"
	// (nested groups such as "(+https://…)" stay inside it), and a group
	// never closed runs to the end of the UA.
	i := 0
	for i < len(s) {
		lp := strings.IndexByte(s[i:], '(')
		if lp < 0 {
			break
		}
		lp += i
		end := len(s) // unclosed: the rest of the UA
		depth := 0
		for j := lp; j < len(s); j++ {
			if s[j] == '(' {
				depth++
			} else if s[j] == ')' {
				depth--
				if depth == 0 {
					end = j
					break
				}
			}
		}
		if tok := botTokenIn(s[lp+1 : end]); tok != "" {
			return tok
		}
		i = end + 1
	}
	return "mozilla"
}

// botTokenIn returns the first token of a ';' / ',' / '(' / ')' separated
// part of a group's text that carries a bot marker, or "". The split is
// done in place (no slice per group: this runs on every ingest event).
// Splitting on the parens too keeps a nested group's ")" out of a token.
func botTokenIn(inner string) string {
	start := 0
	for k := 0; k <= len(inner); k++ {
		if k < len(inner) {
			c := inner[k]
			if c != ';' && c != ',' && c != '(' && c != ')' {
				continue
			}
		}
		if tok := firstUAToken(trimASCIISpace(inner[start:k])); tok != "" && hasAnySubstring(tok, botMarkers) {
			return tok
		}
		start = k + 1
	}
	return ""
}

// trimASCIISpace trims the bytes Lua's %s matches (space, \t, \n, \v, \f,
// \r) and nothing else.
func trimASCIISpace(s string) string {
	isSp := func(c byte) bool { return c == ' ' || (c >= '\t' && c <= '\r') }
	a, b := 0, len(s)
	for a < b && isSp(s[a]) {
		a++
	}
	for b > a && isSp(s[b-1]) {
		b--
	}
	return s[a:b]
}

// asciiLower lowercases A-Z only, like Lua's string.lower in the C locale.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// firstUAToken returns the substring of `in` up to the first '/', ';',
// space, tab or '('. Used for splitting "name/version" style tokens.
//
// IMPORTANT: only space and tab are treated as token boundaries. We do
// NOT trim the result — that would silently strip
// \n \r \v \f from the tail, desyncing this from configs/lua/cfm_ua_emergency.lua
// whose pattern uses a literal space-and-tab character class. Callers
// that need leading/trailing whitespace trimmed pass the input through
// trimASCIISpace before calling here (NormalizeUA does this at the top,
// and botTokenIn on each part).
func firstUAToken(in string) string {
	end := len(in)
	for i, r := range in {
		if r == '/' || r == ';' || r == ' ' || r == '\t' || r == '(' {
			end = i
			break
		}
	}
	return in[:end]
}

func hasAnySubstring(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
