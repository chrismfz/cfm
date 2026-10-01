package detconf

import "strings"

// CleanValue is the value cleaner every detectors.conf string reader applies
// (the detectors package's kvStrClean): inline comment stripped
// (StripInlineComment), space trimmed, surrounding quotes trimmed.
func CleanValue(v string) string {
	v = StripInlineComment(v)
	v = strings.TrimSpace(v)
	return strings.Trim(v, `"'`)
}

// Parsing Config Helper - remove comments.
// StripInlineComment removes trailing inline comments outside quotes.
// Delimiters:
//
//	;            → always a comment (outside quotes)
//	#            → always a comment (outside quotes)
//	//           → comment only if not part of "://", and starts at BOL or after whitespace
//
// Notes:
// - This is safe for file paths and service names.
// - It won't chop "https://..." because the '/' pair follows a ':'.
// - If you ever pass raw URLs here, keep the rule above or avoid using this cleaner for URL keys.
func StripInlineComment(s string) string {
	s = strings.TrimRight(s, "\r\n")
	inQuote := false
	var q byte
	prevNonSpace := -1

	for i := 0; i < len(s); i++ {
		c := s[i]

		// quote handling
		if c == '\'' || c == '"' {
			if !inQuote {
				inQuote = true
				q = c
			} else if q == c {
				inQuote = false
			}
			if c != ' ' && c != '\t' {
				prevNonSpace = i
			}
			continue
		}
		if inQuote {
			if c != ' ' && c != '\t' {
				prevNonSpace = i
			}
			continue
		}

		// outside quotes
		// 1) ';' or '#' → start of comment
		if c == ';' || c == '#' {
			return strings.TrimSpace(s[:i])
		}

		// 2) '//' → comment only if:
		//    - next char is '/', and
		//    - not part of "://", and
		//    - begins at start or is preceded by whitespace
		if c == '/' && i+1 < len(s) && s[i+1] == '/' {
			// if previous non-space is ':', it's likely a URL scheme (e.g., http://)
			if prevNonSpace >= 0 && s[prevNonSpace] == ':' {
				// treat as part of URL, not a comment
			} else {
				// require start-of-line or whitespace just before the '//'
				if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
					return strings.TrimSpace(s[:i])
				}
			}
		}

		if c != ' ' && c != '\t' {
			prevNonSpace = i
		}
	}
	return strings.TrimSpace(s)
}
