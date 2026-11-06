package alerts

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var hostname = func() string { h, _ := os.Hostname(); return h }()

// normalize fills the derived columns (category, ASN number, vhost, time) and
// bounds every free-text field, so one oversized sample can't bloat the store.
func normalize(r Record) Record {
	if r.TsUnix == 0 {
		r.TsUnix = time.Now().Unix()
	}
	if r.Host == "" {
		r.Host = hostname
	}
	r.Kind = clip(strings.TrimSpace(r.Kind), 128)
	if r.Category == "" {
		r.Category = CategoryOf(r.Kind)
	}
	r.Severity = NormalizeSeverity(r.Severity)
	r.IP = clip(strings.TrimSpace(r.IP), 64)
	r.Country = clip(strings.TrimSpace(r.Country), 128)
	r.CountryISO = strings.ToUpper(clip(strings.TrimSpace(r.CountryISO), 2))
	r.ASN = clip(strings.TrimSpace(r.ASN), 256)
	if r.ASNNum == 0 {
		r.ASNNum = ParseASN(r.ASN)
	}
	r.PTR = clip(strings.TrimSpace(r.PTR), 255)
	r.Reason = clip(strings.TrimSpace(r.Reason), maxFieldBytes)
	r.Section = clip(strings.TrimSpace(r.Section), 64)
	if r.Mode == "" {
		r.Mode = strings.TrimSpace(r.Extra["mode"])
	}
	if r.Mode == "" {
		// The detector sink names it block_mode (ttl, permanent, dryrun).
		r.Mode = strings.TrimSpace(r.Extra["block_mode"])
	}
	r.Mode = clip(r.Mode, 32)
	if r.Vhost == "" {
		r.Vhost = vhostOf(r.Extra, r.Samples)
	}
	r.Vhost = strings.ToLower(clip(r.Vhost, 255))
	if len(r.Samples) > maxSamples {
		r.Samples = r.Samples[:maxSamples]
	}
	if len(r.Samples) > 0 {
		out := make([]string, 0, len(r.Samples))
		for _, s := range r.Samples {
			out = append(out, clip(s, maxSampleBytes))
		}
		r.Samples = out
	}
	if len(r.Extra) > 0 {
		ex := make(map[string]string, len(r.Extra))
		for k, v := range r.Extra {
			ex[clip(k, 64)] = clip(v, maxFieldBytes)
		}
		r.Extra = ex
	}
	return r
}

// CategoryOf groups a kind into the family an operator filters by — the part
// before the "/" ("WAF/SQLI" → WAF, "MYSQL/CONN_LIMIT" → MYSQL), or for the
// older unslashed kinds the part before the first "_" ("outbound_abuse" →
// OUTBOUND, "lsm_detect" → LSM). Upper-cased.
func CategoryOf(kind string) string {
	k := strings.TrimSpace(kind)
	if k == "" {
		return "OTHER"
	}
	if i := strings.IndexByte(k, '/'); i > 0 {
		k = k[:i]
	} else if i := strings.IndexAny(k, "_: "); i > 0 {
		k = k[:i]
	}
	return strings.ToUpper(k)
}

// NormalizeSeverity folds the spellings detectors use into info / warning /
// critical ("warn" → warning, "notice" → info). Unknown values pass through.
func NormalizeSeverity(s string) string {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "warn", "warning":
		return "warning"
	case "notice", "info":
		return "info"
	case "crit", "critical":
		return "critical"
	default:
		return v
	}
}

// SeverityRank orders severities for a min_severity filter.
func SeverityRank(s string) int {
	switch NormalizeSeverity(s) {
	case "info":
		return 1
	case "warning":
		return 2
	case "critical":
		return 3
	}
	return 0
}

var asnRe = regexp.MustCompile(`(?i)^\s*(?:AS)?(\d+)\b`)

// ParseASN reads the number out of "AS14061 DigitalOcean, LLC", "AS14061" or
// "14061"; 0 when there is none.
func ParseASN(s string) int64 {
	m := asnRe.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

var (
	// [waf] reason=... host=evelins-home.gr uri=...
	sampleHostRe = regexp.MustCompile(`(?:^|\s)host=([A-Za-z0-9.-]+\.[A-Za-z]{2,})`)
	// ModSecurity: [hostname "ar.mindwiseapps.com"]
	sampleModsecHostRe = regexp.MustCompile(`\[hostname "([A-Za-z0-9.-]+\.[A-Za-z]{2,})"\]`)
)

// vhostOf finds the website an event is about: the detector's own "vhost" or
// "host" extra when it names a domain (MySQL's "host" is a client host such as
// localhost, so a bare name or an address doesn't count), else the first
// sample line that carries one.
func vhostOf(extra map[string]string, samples []string) string {
	for _, k := range []string{"vhost", "host"} {
		if v := strings.TrimSpace(extra[k]); isDomain(v) {
			return v
		}
	}
	for _, s := range samples {
		if m := sampleHostRe.FindStringSubmatch(s); m != nil {
			return m[1]
		}
		if m := sampleModsecHostRe.FindStringSubmatch(s); m != nil {
			return m[1]
		}
	}
	return ""
}

func isDomain(v string) bool {
	if v == "" || !strings.Contains(v, ".") || strings.ContainsAny(v, " /:") {
		return false
	}
	return net.ParseIP(v) == nil
}

// clip cuts s to at most n bytes without splitting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
