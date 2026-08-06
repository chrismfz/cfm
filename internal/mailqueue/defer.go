package mailqueue

import (
	"regexp"
	"sort"
	"strings"
)

// Deferral/freeze reasons come from the exim mainlog. Each retained line names a
// specific recipient/domain/host/IP; we normalize those variable bits away so
// the SAME underlying cause aggregates (e.g. hundreds of "retry time not reached
// for any host for 'X'" collapse into one "retry time not reached").

var (
	// exim `==` deferral: "... defer (CODE): <reason>"
	reDeferReason = regexp.MustCompile(`defer \([^)]*\):\s*(.*)$`)
	reQuoted      = regexp.MustCompile(`'[^']*'`)
	reAngleAddr   = regexp.MustCompile(`<[^>]*>`)
	reEmail       = regexp.MustCompile(`[\w.+%=-]+@[\w.-]+`)
	reIP          = regexp.MustCompile(`\[?\b\d{1,3}(?:\.\d{1,3}){3}\b\]?`)
	reWS          = regexp.MustCompile(`\s+`)
	reURL         = regexp.MustCompile(`https?://\S+`)
	// A per-session id + provider trailer, e.g. "…NoSuchUser ffacd0b85a97d-47ff…si… - gsmtp".
	// Strip it so short bounces carrying a session id aggregate instead of
	// splitting one reason per delivery attempt. The pre-dash token must be
	// session-id-shaped (contains an internal '.' or '-') so a normal reason
	// ending in "… <word> - <word>" is NOT eaten.
	reSessionTail = regexp.MustCompile(`\s+[0-9a-z]+[.-][0-9a-z.-]*\s+-\s+\w+\s*$`)
)

const maxReasonLen = 140

// ParseEximDeferReasons scans exim mainlog lines for deferral (`==`), failure
// (`**`) and freeze (`Frozen`) events, normalizes each reason, and returns the
// top reasons by frequency. Pure — the caller supplies a bounded log tail.
func ParseEximDeferReasons(lines []string, top int) []DeferReason {
	hits := make([]reasonHit, 0, len(lines))
	for _, line := range lines {
		cat, raw := eximLineReason(line)
		if raw == "" {
			continue
		}
		key := normalizeDeferReason(raw)
		if key == "" {
			continue
		}
		hits = append(hits, reasonHit{category: cat, key: key, sample: raw})
	}
	return aggregateReasons(hits, top)
}

// reasonHit is one classified+normalized reason occurrence fed to
// aggregateReasons. sample is the RAW reason (trimmed on aggregation).
type reasonHit struct {
	category string // deferred | failed | frozen
	key      string // normalized reason (the aggregation key)
	sample   string // representative raw reason
}

// aggregateReasons buckets reasonHits by (category, normalized key), counts
// them, keeps one representative sample per bucket, and returns the top-N by
// frequency. Shared by the exim (mainlog) and postfix (inline) providers so the
// two can never drift.
func aggregateReasons(hits []reasonHit, top int) []DeferReason {
	if top <= 0 {
		top = DefaultTop
	}
	type agg struct {
		count    int
		category string
		sample   string
	}
	m := map[string]*agg{}
	for _, h := range hits {
		if h.key == "" {
			continue
		}
		mk := h.category + "\x00" + h.key
		a := m[mk]
		if a == nil {
			a = &agg{category: h.category, sample: trimSample(h.sample)}
			m[mk] = a
		}
		a.count++
	}
	out := make([]DeferReason, 0, len(m))
	for mk, a := range m {
		reason := mk[strings.IndexByte(mk, 0)+1:]
		out = append(out, DeferReason{Reason: reason, Category: a.category, Count: a.count, Sample: a.sample})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	if len(out) > top {
		out = out[:top]
	}
	return out
}

// eximLineReason classifies a mainlog line and extracts its raw reason text.
func eximLineReason(line string) (category, raw string) {
	switch {
	case strings.Contains(line, " == "):
		if mm := reDeferReason.FindStringSubmatch(line); mm != nil {
			return "deferred", mm[1]
		}
		if i := strings.Index(line, "defer"); i >= 0 {
			return "deferred", strings.TrimSpace(line[i:])
		}
		return "deferred", ""
	case strings.Contains(line, " ** "):
		// failure: the reason follows the first " : " after the routing tokens.
		if i := strings.Index(line, " : "); i >= 0 {
			return "failed", line[i+3:]
		}
		return "failed", ""
	case strings.Contains(line, "Frozen"):
		if i := strings.Index(line, "Frozen"); i >= 0 {
			return "frozen", line[i:]
		}
		return "frozen", ""
	}
	return "", ""
}

// normalizeDeferReason strips the variable bits (quoted domains, addresses, IPs,
// exim's literal "\n" line-joins) so the same cause aggregates, and collapses
// the ubiquitous transient "retry time not reached …" into a single bucket.
func normalizeDeferReason(s string) string {
	s = strings.ReplaceAll(s, `\n`, " ")
	s = reURL.ReplaceAllString(s, "")
	s = reQuoted.ReplaceAllString(s, "")
	s = reAngleAddr.ReplaceAllString(s, "")
	s = reEmail.ReplaceAllString(s, "")
	s = reIP.ReplaceAllString(s, "")
	s = reWS.ReplaceAllString(s, " ")
	s = reSessionTail.ReplaceAllString(s, "") // drop a trailing "<sessionid> - <provider>"
	s = strings.TrimSpace(strings.Trim(s, ":"))
	s = strings.TrimSpace(s)

	if strings.HasPrefix(strings.ToLower(s), "retry time not reached") {
		return "retry time not reached"
	}
	if len([]rune(s)) > maxReasonLen {
		s = string([]rune(s)[:maxReasonLen]) + "…"
	}
	return s
}

func trimSample(s string) string {
	s = strings.ReplaceAll(s, `\n`, " ")
	s = reWS.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	if len([]rune(s)) > 200 {
		s = string([]rune(s)[:200]) + "…"
	}
	return s
}
