package detectors

import (
	"sync"
	"strings"
	core "cfm/internal/detectors/core"
	"cfm/internal/firewall"
	"time"
	"strconv"
)

type Options struct {
    CfgPath string
    Sink    core.Sink
    FW      firewall.Backend
}




type Factory func(sectionName string, kv KV, global KV) (core.PeriodicDetector, error)

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

func Register(typ string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[typ] = f
}

func getFactory(typ string) (Factory, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	f, ok := registry[typ]
	return f, ok
}







//Parsing Config Helper - remove comments//
// stripInlineComment removes trailing inline comments outside quotes.
// Delimiters:
//   ;            → always a comment (outside quotes)
//   #            → always a comment (outside quotes)
//   //           → comment only if not part of "://", and starts at BOL or after whitespace
//
// Notes:
// - This is safe for file paths and service names.
// - It won't chop "https://..." because the '/' pair follows a ':'.
// - If you ever pass raw URLs here, keep the rule above or avoid using this cleaner for URL keys.
func stripInlineComment(s string) string {
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

// kvStrClean = kvStr + inline-comment stripping + quote trimming.
func kvStrClean(kv KV, key, def string) string {
	val := kvStr(kv, key, def)
	val = stripInlineComment(val)
	val = strings.TrimSpace(val)
	val = strings.Trim(val, `"'`)
	return val
}




// other Config helpers
func kvBool(kv KV, key string, def bool) bool {
        v, ok := kv[strings.ToUpper(key)]
        if !ok { return def }
        switch strings.ToLower(v) {
        case "1","true","yes","on": return true
        case "0","false","no","off": return false
        }
        return def
}
func kvInt(kv KV, key string, def int) int {
        v, ok := kv[strings.ToUpper(key)]
        if !ok { return def }
        if n, err := strconv.Atoi(v); err == nil { return n }
        return def
}
func kvDur(kv KV, key string, def time.Duration) time.Duration {
        v, ok := kv[strings.ToUpper(key)]
        if !ok || v == "" { return def }
        if d, err := time.ParseDuration(v); err == nil { return d }
        return def
}
func kvStr(kv KV, key, def string) string {
        v, ok := kv[strings.ToUpper(key)]
        if !ok || v == "" { return def }
        return v
}



// kvFlt returns a float64 config value, with comment/quote stripping (via kvStrClean).
func kvFlt(kv KV, key string, def float64) float64 {
    s := kvStrClean(kv, key, "")
    if s == "" {
        return def
    }
    v, err := strconv.ParseFloat(s, 64)
    if err != nil {
        return def
    }
    return v
}
