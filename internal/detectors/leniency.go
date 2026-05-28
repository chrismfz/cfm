// internal/detectors/leniency.go
//
// Leniency overrides for the autoblock sink.
//
// Any detector section can have a companion [section.leniency] subsection
// in detectors.conf.  When an IP matches the criteria (country or ASN),
// the sink uses the softer block policy instead of the section's default.
//
// Example:
//
//   [exim_security.leniency]
//   MATCH_COUNTRY  = "GR,CY"
//   ; MATCH_ASN   = "AS6799,AS6866"
//   BLOCK          = "1h"
//   BLOCK_COOLDOWN = "30m"
//   SEND_TO_API    = NO
//   ; SEND_TO_BLOCKLIST = lenient   ; record centrally for visibility,
//   ;                               ; but never propagate to the farm

package detectors

import (
	"fmt"
	"strings"

	"cfm/internal/enrich"
	"cfm/internal/logging"
)

// leniencyPolicy holds the parsed [section.leniency] overrides.
type leniencyPolicy struct {
	// Match criteria (OR logic: any match triggers leniency)
	Countries []string // uppercased: "GR", "CY", "GREECE", …
	ASNs      []string // "AS6799", "AS6866", … (with "AS" prefix)

	// Overridden block policy (softer)
	Pol blockPolicy

	// Whether to report the block to the central API / global blocklist.
	SendToAPI bool

	// SendToBlocklist optionally redirects where a lenient-matched block is
	// reported, overriding SendToAPI for recording purposes:
	//   "lenient"   → record centrally for visibility only; NOT served to the
	//                 farm (so a known-good origin is not propagated).
	//   "blacklist" → report to the global blocklist (same as SEND_TO_API=YES).
	//   ""          → defer to SendToAPI (legacy behaviour).
	SendToBlocklist string
}

// parseLeniencyPolicy reads the KV map from a [section.leniency] block.
// Returns nil if the block is empty or has no match criteria.
func parseLeniencyPolicy(kv KV) *leniencyPolicy {
	if kv == nil {
		return nil
	}

	lp := &leniencyPolicy{
		SendToAPI: true, // default: report
	}

	// --- Match criteria ---
	if raw := kvStrClean(kv, "MATCH_COUNTRY", ""); raw != "" {
		for _, tok := range strings.FieldsFunc(raw, isSepRune) {
			tok = strings.TrimSpace(strings.ToUpper(tok))
			if tok != "" {
				lp.Countries = append(lp.Countries, tok)
			}
		}
	}

	if raw := kvStrClean(kv, "MATCH_ASN", ""); raw != "" {
		for _, tok := range strings.FieldsFunc(raw, isSepRune) {
			tok = strings.TrimSpace(strings.ToUpper(tok))
			if tok != "" {
				if !strings.HasPrefix(tok, "AS") {
					tok = "AS" + tok
				}
				lp.ASNs = append(lp.ASNs, tok)
			}
		}
	}

	// No match criteria → leniency disabled
	if len(lp.Countries) == 0 && len(lp.ASNs) == 0 {
		return nil
	}

	// --- Override block policy ---
	lp.Pol = parseBlockPolicy(kv)

	// --- SEND_TO_API (default: YES) ---
	lp.SendToAPI = kvBool(kv, "SEND_TO_API", true)

	// --- SEND_TO_BLOCKLIST (optional list-type override) ---
	switch strings.ToLower(kvStrClean(kv, "SEND_TO_BLOCKLIST", "")) {
	case "lenient":
		lp.SendToBlocklist = "lenient"
	case "blacklist":
		lp.SendToBlocklist = "blacklist"
	default:
		lp.SendToBlocklist = "" // defer to SEND_TO_API
	}

	return lp
}

func isSepRune(r rune) bool {
	return r == ',' || r == ' ' || r == '\t' || r == ';'
}

// matchesIP checks whether the given IP falls under leniency rules.
// Uses the enricher to resolve country and ASN (OR logic).
// Returns (matched, reason) for logging.
func (lp *leniencyPolicy) matchesIP(ipStr string, enr *enrich.Enricher) (bool, string) {
	if lp == nil || enr == nil || ipStr == "" {
		return false, ""
	}

	r := enr.Lookup(ipStr)

	// Country match — supports both ISO codes ("GR") and full names ("Greece")
	if len(lp.Countries) > 0 && r.Country != "" {
		countryUpper := strings.ToUpper(r.Country)
		for _, c := range lp.Countries {
			// Direct match: config="GREECE" matches enricher="Greece"
			if c == countryUpper {
				return true, "country=" + c
			}
			// ISO→name: config="GR" matches enricher="Greece"
			if iso, ok := countryNameToISO[countryUpper]; ok && iso == c {
				return true, "country=" + c
			}
			// Name→ISO: config="GREECE" matches enricher="GR" (if enricher returns ISO)
			if iso, ok := countryNameToISO[c]; ok && iso == countryUpper {
				return true, "country=" + c
			}
		}
	}

	// ASN match
	if len(lp.ASNs) > 0 && r.ASN > 0 {
		asnStr := fmt.Sprintf("AS%d", r.ASN)
		for _, a := range lp.ASNs {
			if a == asnStr {
				return true, "asn=" + asnStr
			}
		}
	}

	return false, ""
}

// countryNameToISO maps enricher full names → ISO-2 codes.
var countryNameToISO = map[string]string{
	"GREECE":               "GR",
	"CYPRUS":               "CY",
	"TURKEY":               "TR",
	"BULGARIA":             "BG",
	"ALBANIA":              "AL",
	"NORTH MACEDONIA":      "MK",
	"SERBIA":               "RS",
	"ROMANIA":              "RO",
	"GERMANY":              "DE",
	"FRANCE":               "FR",
	"ITALY":                "IT",
	"SPAIN":                "ES",
	"PORTUGAL":             "PT",
	"UNITED KINGDOM":       "GB",
	"NETHERLANDS":          "NL",
	"BELGIUM":              "BE",
	"AUSTRIA":              "AT",
	"SWITZERLAND":          "CH",
	"POLAND":               "PL",
	"CZECH REPUBLIC":       "CZ",
	"CZECHIA":              "CZ",
	"HUNGARY":              "HU",
	"CROATIA":              "HR",
	"SLOVENIA":             "SI",
	"SLOVAKIA":             "SK",
	"UKRAINE":              "UA",
	"UNITED STATES":        "US",
	"CANADA":               "CA",
	"AUSTRALIA":            "AU",
	"JAPAN":                "JP",
	"CHINA":                "CN",
	"INDIA":                "IN",
	"BRAZIL":               "BR",
	"RUSSIA":               "RU",
	"RUSSIAN FEDERATION":   "RU",
	"SOUTH KOREA":          "KR",
	"REPUBLIC OF KOREA":    "KR",
	"SWEDEN":               "SE",
	"NORWAY":               "NO",
	"DENMARK":              "DK",
	"FINLAND":              "FI",
	"IRELAND":              "IE",
	"ISRAEL":               "IL",
	"SINGAPORE":            "SG",
	"HONG KONG":            "HK",
	"TAIWAN":               "TW",
	"MEXICO":               "MX",
	"ARGENTINA":            "AR",
	"SOUTH AFRICA":         "ZA",
	"NEW ZEALAND":          "NZ",
	"UNITED ARAB EMIRATES": "AE",
}

// logLeniencyMatch logs when leniency is applied.
func logLeniencyMatch(section, ipStr, reason string, lp *leniencyPolicy) {
	mode := lp.Pol.Mode
	if mode == "ttl" {
		mode = lp.Pol.TTL.String()
	}
	dest := lp.SendToBlocklist
	if dest == "" {
		dest = "default"
	}
	logging.Logf("[leniency][%s] ip=%s matched (%s) → block=%s cooldown=%s send_to_api=%t send_to_blocklist=%s",
		section, ipStr, reason, mode, lp.Pol.Cooldown, lp.SendToAPI, dest)
}
