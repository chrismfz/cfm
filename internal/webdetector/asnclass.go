package webdetector

import "strings"

// asnclass.go — datacenter/hosting ASN classification for the abuse-shadow
// signals (docs/webdetector-refactor.md §4). Pure/no-I/O so it is unit-tested
// in isolation and cheap to call on the per-IP hot path.
//
// IMPORTANT: "datacenter" is NOT "malicious". Verified search bots (Googlebot,
// Bingbot), LLM crawlers (GPTBot, ClaudeBot), SEO crawlers (AhrefsBot), uptime
// monitors, and legitimate ecommerce import/export integrations all originate
// from cloud/hosting ASNs — several from the SAME ASN as the provider's cloud
// (Googlebot on AS15169, Bingbot on AS8075). This classifier ONLY answers "does
// this IP originate from hosting infrastructure rather than a consumer ISP?".
// The good-bot FCrDNS exemption, allowlists, and log-only burn-in are what make
// the signal safe to act on — never the ASN flag alone.
//
// HARD INVARIANT (docs/webdetector-refactor.md §4a): this is ADDITIVE-ONLY. A
// "" result means "no cloud-scraper-origin hint" — it must NEVER be read as
// "trusted", "normal", "safe", or "exempt". Origin is not innocence: the fleet's
// real abuse is RESIDENTIAL (SQLi from consumer ISPs — Vodafone/OTE/Nova/
// Starlink), already caught by the WAF regardless of ASN. A consumer-ISP IP must
// keep exactly the WAF + rate/behaviour scrutiny it always had. This classifier
// may only ADD suspicion to a scraping-shaped request; it may never subtract
// from or short-circuit any other detector.

// knownCloudASNs maps a hosting/cloud provider's ASN to a short, stable tag.
// Exact ASN match is authoritative (org-name keywords are only a fallback).
// Deliberately NON-exhaustive: seeded from the fleet's own most-blocked ASNs
// and the majors; grow it from observed abuse-shadow data, not from memory.
var knownCloudASNs = map[uint]string{
	16509:  "amazon-aws",
	14618:  "amazon-aws",
	15169:  "google", // NOTE: also Googlebot's origin — good-bot exemption must run first
	396982: "google-cloud",
	8075:   "microsoft", // NOTE: also Bingbot's origin
	8068:   "microsoft",
	14061:  "digitalocean",
	24940:  "hetzner",
	213230: "hetzner",
	16276:  "ovh",
	45102:  "alibaba",
	37963:  "alibaba",
	132203: "tencent",
	63949:  "linode-akamai",
	20473:  "vultr-choopa",
	51167:  "contabo",
	9009:   "m247",
	212238: "datacamp",
	60068:  "datacamp",
	23470:  "reliablesite",
	60781:  "leaseweb",
	199524: "gcore",
	14340:  "salesforce",
}

// cloudOrgKeywords is the fallback: a lowercased substring match on the ASN's
// organization name. Kept to STRONG, provider-identifying tokens — ambiguous
// generic words ("server", "cloud", "net", "solutions") are intentionally
// excluded because they also appear in consumer-ISP org names and would inflate
// false positives. The curated ASN map above is the primary signal.
var cloudOrgKeywords = []string{
	"amazon", "aws", "digitalocean", "hetzner",
	"ovh", "linode", "akamai", "vultr", "contabo", "alibaba",
	"tencent", "leaseweb", "choopa", "datacamp", "gcore", "scaleway",
	"upcloud", "kamatera", "hostwinds", "colocrossing", "quadranet",
	"hosting", "datacenter", "data center", "colocation",
}

// DatacenterClass returns a short provider tag when the ASN looks like
// hosting/cloud infrastructure, or "" otherwise. Exact ASN match wins; the
// org-name keyword scan is the fallback for the long tail not in the curated
// map. It says nothing about intent — see the file header.
func DatacenterClass(asn uint, asnName string) string {
	if tag, ok := knownCloudASNs[asn]; ok {
		return tag
	}
	name := strings.ToLower(asnName)
	for _, kw := range cloudOrgKeywords {
		if strings.Contains(name, kw) {
			// Canonicalize to a space-free tag: the abuse-shadow log line is
			// space-delimited (provider=%s), so a keyword like "data center"
			// must never be emitted verbatim or it splits the field and the
			// parser drops the tail. "data center" -> "datacenter".
			return strings.ReplaceAll(kw, " ", "")
		}
	}
	return ""
}

// IsDatacenter is the boolean convenience wrapper.
func IsDatacenter(asn uint, asnName string) bool {
	return DatacenterClass(asn, asnName) != ""
}
