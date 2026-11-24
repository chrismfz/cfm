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
//   - If the UA starts with "mozilla", scan each "(...)" group in order and
//     return the first inner token that contains a bot-family marker
//     substring (bot, spider, crawl, agent, fetch, externalhit, scrap,
//     preview, embed, monitor, checker, indexer). This catches Googlebot, Bingbot, SemrushBot,
//     AhrefsBot, meta-externalagent, facebookexternalhit, etc. while
//     leaving real browsers untouched.
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
	"indexer", // meta-webindexer
}

// NormalizeUA returns a stable short identifier for a User-Agent string.
// The returned identifier is lowercase, free of version numbers, and stable
// across minor UA variations from the same bot family.
func NormalizeUA(ua string) string {
	s := strings.TrimSpace(ua)
	if s == "" || s == "-" {
		return "-"
	}
	s = strings.ToLower(s)

	head := firstUAToken(s)
	if head == "" {
		return "-"
	}

	// Generic case: anything that isn't the "mozilla" envelope.
	if head != "mozilla" {
		return head
	}

	// Mozilla envelope: look inside every "(...)" group, in order, for a bot
	// identifier. Not only the first: Meta's crawler (since 2026-11, Chrome
	// 145) and Googlebot smartphone put a full browser UA first and declare
	// themselves in a trailing "(compatible; …)" group, so a first-group-only
	// scan read them as "mozilla" and `cfm bots block meta-externalagent`
	// never matched. A nested "(" inside a group ("(+https://…)") ends the
	// scan at the first ")", which still leaves the bot token in the group.
	rest := s
	for {
		lp := strings.IndexByte(rest, '(')
		if lp < 0 {
			return "mozilla"
		}
		rp := strings.IndexByte(rest[lp:], ')')
		if rp < 0 {
			return "mozilla"
		}
		inner := rest[lp+1 : lp+rp]
		parts := strings.FieldsFunc(inner, func(r rune) bool {
			return r == ';' || r == ','
		})
		for _, p := range parts {
			tok := firstUAToken(strings.TrimSpace(p))
			if tok == "" {
				continue
			}
			if hasAnySubstring(tok, botMarkers) {
				return tok
			}
		}
		rest = rest[lp+rp+1:]
	}
}

// firstUAToken returns the substring of `in` up to the first '/', ';',
// space, tab or '('. Used for splitting "name/version" style tokens.
//
// IMPORTANT: only space and tab are treated as token boundaries. We do
// NOT call strings.TrimSpace on the result — that would silently strip
// \n \r \v \f from the tail, desyncing this from configs/lua/cfm_ua_emergency.lua
// whose pattern uses a literal space-and-tab character class. Callers
// that need leading/trailing whitespace trimmed pass the input through
// strings.TrimSpace before calling here (NormalizeUA does this at the
// top, and again on each inner-envelope part).
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
