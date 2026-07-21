package detectors

import (
	core "cfm/internal/detectors/core"
	"cfm/internal/firewall"
	webdet "cfm/internal/webdetector"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"cfm/internal/clam"
	"cfm/internal/logging"
)

type Options struct {
	CfgPath string
	Sink    core.Sink
	FW      firewall.Backend
}

var fwBackend firewall.Backend

func SetFW(be firewall.Backend) { // unexported is fine, same package
	fwBackend = be
}

// nginxBridge is used in OpenResty mode to enforce web challenges without nft DNAT sets.
var nginxBridge *webdet.NginxBridge

func SetNginxBridge(b *webdet.NginxBridge) {
	nginxBridge = b
}

var clamMgr clam.Enqueuer

func SetClamManager(m clam.Enqueuer) {
	clamMgr = m
}


var clamBridgeWired bool

func ResetClamBridgeWireState() {
	clamBridgeWired = false
}

// TryWireClamBridge re-applies clam -> nginx bridge binding.
// Safe to call repeatedly.
func TryWireClamBridge() bool {
	if nginxBridge == nil || clamMgr == nil || !clamMgr.Enabled() {
		clamBridgeWired = false
		return false
	}

	nginxBridge.SetClamManager(clamMgr, clamMgr.PendingDir(), clamMgr.InfectedDir())

	if !clamBridgeWired {
		logging.LogfCLAM("[clam] upload scanning wired to bridge")
	}
	clamBridgeWired = true
	return true
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

// RegisteredTypes returns a stable sorted list of registered detector section types.
func RegisteredTypes() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Parsing Config Helper - remove comments//
// stripInlineComment removes trailing inline comments outside quotes.
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
// cleanScalar prepares a raw config value for numeric / bool / duration
// parsing. It drops any inline "; comment" / "# comment" (a scalar value never
// contains ';' or '#' legitimately) and strips surrounding quotes/space.
//
// It deliberately does NOT use stripInlineComment's quote-aware scan: the
// section parser leaves an embedded quote when a *quoted* value carries an
// inline comment (`EVERY = "20s" ; note` is stored as `20s" ; note`), and a
// quote-aware scan would treat that stray quote as opening a string and never
// find the ';'. Cutting at the first ';'/'#' then trimming quotes yields `20s`.
//
// Without this, kvInt/kvBool/kvDur parsed the raw string, failed, and silently
// fell back to the default — so `SQLI = 1 ; note` (and, historically, the
// suspicious-vhost challenge thresholds and the /tmp cleanup gate) never took
// the configured value. See CLAUDE.md §5.
func cleanScalar(v string) string {
	if i := strings.IndexAny(v, ";#"); i >= 0 {
		v = v[:i]
	}
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

func kvBool(kv KV, key string, def bool) bool {
	v, ok := kv[strings.ToUpper(key)]
	if !ok {
		return def
	}
	switch strings.ToLower(cleanScalar(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}
func kvInt(kv KV, key string, def int) int {
	v, ok := kv[strings.ToUpper(key)]
	if !ok {
		return def
	}
	if n, err := strconv.Atoi(cleanScalar(v)); err == nil {
		return n
	}
	return def
}
// parseCfgDuration parses a detectors.conf duration value. It extends Go's
// time.ParseDuration with a "d" (days) unit — the stdlib parser stops at "h",
// so "7d"/"1d12h" would otherwise fail and silently fall back to the default.
//
// Every "<number>d" segment is expanded to its hour-equivalent (N days -> N*24
// h) and the fully-normalized string is handed to time.ParseDuration once.
// This keeps day support composable with the standard units (composites like
// "1d12h", fractional days like "1.5d") and reuses the stdlib's exact
// nanosecond arithmetic for everything else. Only lowercase "d" is recognised,
// matching Go's lowercase unit convention.
//
// This is the single duration parser for detectors.conf scalars: kvDur (EVERY/
// WINDOW/COOLDOWN/TIMEOUT/...), parseBlockPolicy (BLOCK) and the mysql
// QUERY_RULES MAX_TIME all route through it, so "d" means the same thing in
// every operator-writable duration field.
func parseCfgDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	// Fast path: no day unit -> stdlib handles the whole value unchanged.
	if !strings.Contains(s, "d") {
		return time.ParseDuration(s)
	}

	var b strings.Builder
	i := 0
	if s[0] == '+' || s[0] == '-' {
		b.WriteByte(s[0])
		i = 1
	}
	for i < len(s) {
		// number: digits and at most a decimal point
		numStart := i
		for i < len(s) && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.') {
			i++
		}
		num := s[numStart:i]
		// unit: everything up to the next number/sign (covers multi-byte "µs")
		unitStart := i
		for i < len(s) && !((s[i] >= '0' && s[i] <= '9') || s[i] == '.' || s[i] == '+' || s[i] == '-') {
			i++
		}
		unit := s[unitStart:i]

		if unit != "d" {
			b.WriteString(num)
			b.WriteString(unit)
			continue
		}
		if num == "" {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		// N days -> N*24 h. Keep integer days exact; fall back to float only
		// for the rare fractional case (e.g. "1.5d").
		if !strings.Contains(num, ".") {
			n, err := strconv.ParseInt(num, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			b.WriteString(strconv.FormatInt(n*24, 10))
		} else {
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			b.WriteString(strconv.FormatFloat(f*24, 'f', -1, 64))
		}
		b.WriteString("h")
	}
	return time.ParseDuration(b.String())
}

func kvDur(kv KV, key string, def time.Duration) time.Duration {
	v, ok := kv[strings.ToUpper(key)]
	if !ok {
		return def
	}
	s := cleanScalar(v)
	if s == "" {
		return def
	}
	if d, err := parseCfgDuration(s); err == nil {
		return d
	}
	return def
}
func kvStr(kv KV, key, def string) string {
	v, ok := kv[strings.ToUpper(key)]
	if !ok || v == "" {
		return def
	}
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
