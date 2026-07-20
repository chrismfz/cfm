package webdetector

import (
	"strings"
	"testing"
)

// TestJSStringLiteral_NoScriptBreakout pins the fix for the reflected XSS
// reported as CodeQL #565 (2026-05-09 triage). jsStringLiteral previously
// wrapped strconv.Quote, which leaves <, >, &, and U+2028/U+2029 unescaped.
// Inside <script>...</script>, the HTML parser tokenises </script>
// regardless of JavaScript context — so a single </script> in an
// attacker-controlled input closes the script tag and exposes raw HTML.
//
// The fix post-processes strconv.Quote output through a Replacer that
// rewrites those five bytes as \uXXXX escapes, valid in both JS and JSON.
//
// Each case asserts the dangerous bytes are absent from the output even
// when present in the input, plus that the surrounding double-quotes
// (strconv.Quote shape) and Go-level escape semantics are preserved.
func TestJSStringLiteral_NoScriptBreakout(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// banned bytes that must NOT appear in the output
		banned []string
	}{
		{
			name:   "script-tag breakout",
			in:     "/foo</script><img src=x onerror=alert(1)>",
			banned: []string{"<", ">"},
		},
		{
			name:   "ampersand entity",
			in:     "a&b",
			banned: []string{"&"},
		},
		{
			name:   "JS line separator (U+2028)",
			in:     "a b",
			banned: []string{" "},
		},
		{
			name:   "JS paragraph separator (U+2029)",
			in:     "a b",
			banned: []string{" "},
		},
		{
			name:   "combined payload",
			in:     "</script> <svg/onload=1>",
			banned: []string{"<", ">", " "},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := jsStringLiteral(tc.in)
			// Must remain a valid quoted string literal — strconv.Quote shape
			// preserved (leading and trailing ").
			if !strings.HasPrefix(out, `"`) || !strings.HasSuffix(out, `"`) {
				t.Fatalf("output not double-quoted: %q", out)
			}
			for _, b := range tc.banned {
				if strings.Contains(out, b) {
					t.Errorf("output %q must not contain banned byte sequence %q", out, b)
				}
			}
		})
	}
}

// TestJSStringLiteral_EscapesAreValidJSSyntax verifies the output uses the
// \uXXXX form for the rewritten bytes (lower-case hex, four digits) so a
// JSON.parse / JS parser treats them as the original code points at
// runtime.
func TestJSStringLiteral_EscapesAreValidJSSyntax(t *testing.T) {
	cases := map[string]string{
		"<":      `\u003c`,
		">":      `\u003e`,
		"&":      `\u0026`,
		"\u2028": `\u2028`,
		"\u2029": `\u2029`,
	}
	for in, want := range cases {
		out := jsStringLiteral(in)
		if !strings.Contains(out, want) {
			t.Errorf("jsStringLiteral(%q)=%q; want it to contain %q", in, out, want)
		}
	}
}
