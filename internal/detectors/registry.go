package detectors

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/clam"
	"cfm/internal/detconf"
	core "cfm/internal/detectors/core"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	webdet "cfm/internal/webdetector"
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
	regMu           sync.RWMutex
	registry        = map[string]Factory{}
	registryAliases = map[string]registryAlias{}
)

type registryAlias struct {
	canonical string
	factory   Factory
}

func Register(typ string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[typ] = f
}

// RegisterAlias keeps a legacy section type loadable without advertising it as
// a separate detector in the catalog/inventory.
func RegisterAlias(typ, canonical string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registryAliases[typ] = registryAlias{canonical: canonical, factory: f}
}

func getFactory(typ string) (Factory, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	f, ok := registry[typ]
	if !ok {
		alias, aliasOK := registryAliases[typ]
		f, ok = alias.factory, aliasOK
	}
	return f, ok
}

// CanonicalType resolves an accepted detector section type, including aliases.
func CanonicalType(typ string) (string, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	if _, ok := registry[typ]; ok {
		return typ, true
	}
	alias, ok := registryAliases[typ]
	if !ok {
		return typ, false
	}
	return alias.canonical, true
}

// ConfigSectionOptional reports built-in detector types that run without a
// detectors.conf section and therefore must not be reported as config drift.
func ConfigSectionOptional(typ string) bool {
	canonical, ok := CanonicalType(typ)
	return ok && canonical == cfmEndpointsType
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

// parseCfgDuration parses a detectors.conf duration value, extending Go's
// time.ParseDuration with a "d" (days) unit ("7d", "1d12h", "1.5d"). The
// implementation lives in internal/detconf so the API-server save-time
// validation can enforce the IDENTICAL grammar — two parsers that disagree
// turn a valid operator value into a false "invalid block mode" error while
// the runtime happily accepts it.
var parseCfgDuration = detconf.ParseCfgDuration

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
