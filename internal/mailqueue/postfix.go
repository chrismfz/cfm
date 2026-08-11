package mailqueue

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Postfix `postqueue -p` (a.k.a. `mailq`) listing. Format:
//
//	-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
//	9758362208D   15353 Wed Aug  5 10:00:33  support@myip.gr
//	     (connect to host.example[1.2.3.4]:25: Connection timed out)
//	                                         info@dest.gr
//
//	-- 14 Kbytes in 1 Request.
//
// Per message: a HEADER line (queue id, size in bytes, arrival time with NO
// year, sender), an optional inline `(reason)` line (the deferral cause —
// postfix carries it in the listing, so no maillog tail is needed), and one or
// more indented recipient lines. A trailing `*`/`!` on the queue id marks the
// active/hold queue; `!` (hold) is treated as frozen. Empty queue prints
// `Mail queue is empty`.

var (
	// host[ip]:port token, e.g. "mx.example.com[2606:4700::1]:25" or
	// "relay[1.2.3.4]". Stripped so the SAME cause aggregates across hosts.
	reHostIP = regexp.MustCompile(`\S*\[[0-9a-fA-F:.]+\](?::\d+)?`)

	weekdays = map[string]bool{"Mon": true, "Tue": true, "Wed": true, "Thu": true, "Fri": true, "Sat": true, "Sun": true}
	months   = map[string]bool{"Jan": true, "Feb": true, "Mar": true, "Apr": true, "May": true, "Jun": true, "Jul": true, "Aug": true, "Sep": true, "Oct": true, "Nov": true, "Dec": true}
)

// BuildPostfixReport parses `postqueue -p` output into an aggregated Report.
// now is passed in (not read from the clock) so age is computable and tests are
// deterministic — postfix prints arrival time without a year. total is the
// authoritative count from the detector (postqueue count); it wins over the
// parsed count so Report.Total matches the health snapshot even past the parse
// cap. top bounds the returned domain lists, oldest-N sample and reason list.
func BuildPostfixReport(out string, now time.Time, total, top int) Report {
	if top <= 0 {
		top = DefaultTop
	}
	msgs, truncated := parsePostqueue(out, now)

	r := Report{
		MTA:        "postfix",
		MeasuredAt: now,
		Parsed:     len(msgs),
		Truncated:  truncated,
		AgeBuckets: map[string]int{"<10m": 0, "10m-1h": 0, "1h-6h": 0, "6h-1d": 0, ">1d": 0},
	}
	senderDom := map[string]int{}
	recipDom := map[string]int{}
	frozen := 0
	hits := make([]reasonHit, 0, len(msgs))
	for _, m := range msgs {
		if m.Frozen {
			frozen++
		}
		if !m.Frozen && m.AgeSec >= 3600 {
			r.Deferred++
		}
		bucketAge(r.AgeBuckets, m.AgeSec)
		if d := domainOf(m.Sender); d != "" {
			senderDom[d]++
		}
		for _, d := range m.rcptDomains {
			recipDom[d]++
		}
		if m.reason != "" {
			cat := "deferred"
			if m.Frozen {
				cat = "frozen"
			}
			if key := normalizePostfixReason(m.reason); key != "" {
				hits = append(hits, reasonHit{category: cat, key: key, sample: m.reason})
			}
		}
	}
	r.Total = len(msgs)
	if total > 0 {
		r.Total = total
	}
	r.Frozen = frozen
	r.TopSenderDomains = topDomains(senderDom, top)
	r.TopSenders = topSenders(msgs, top)
	r.TopRecipientDomains = topDomains(recipDom, top)
	r.Oldest = oldestN(msgs, top)
	r.DeferReasons = aggregateReasons(hits, top)
	return r
}

// parsePostqueue parses a `postqueue -p` listing into per-message entries.
func parsePostqueue(out string, now time.Time) (msgs []QueuedMsg, truncated bool) {
	var cur *QueuedMsg
	flush := func() {
		if cur != nil {
			msgs = append(msgs, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "-Queue ID-"): // column header row
			continue
		case strings.HasPrefix(trimmed, "--"): // footer "-- N Kbytes in M Requests."
			continue
		case trimmed == "Mail queue is empty":
			continue
		}
		if m, ok := parsePostfixHeader(line, now); ok {
			if len(msgs) >= maxParseMsgs {
				truncated = true
				break
			}
			flush()
			cur = &m
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(trimmed, "(") { // inline defer/bounce reason
			cur.reason = strings.TrimSuffix(strings.TrimPrefix(trimmed, "("), ")")
			continue
		}
		if strings.Contains(trimmed, "@") { // recipient
			cur.Recipients++
			if d := domainOf(strings.Trim(trimmed, "<>")); d != "" {
				addDomainCapped(cur, d)
			}
		}
	}
	flush()
	return msgs, truncated
}

// parsePostfixHeader parses a message header line. Returns ok=false for any
// non-header line so parsePostqueue can route reason/recipient lines.
func parsePostfixHeader(line string, now time.Time) (QueuedMsg, bool) {
	f := strings.Fields(line)
	if len(f) < 6 { // id size Wdy Mon DD HH:MM:SS [sender]
		return QueuedMsg{}, false
	}
	id, frozen := f[0], false
	switch id[len(id)-1] {
	case '*': // active queue
		id = id[:len(id)-1]
	case '!': // hold queue → treat as frozen
		id = id[:len(id)-1]
		frozen = true
	}
	if !isQueueID(id) {
		return QueuedMsg{}, false
	}
	size, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return QueuedMsg{}, false
	}
	if !weekdays[f[2]] || !months[f[3]] {
		return QueuedMsg{}, false
	}
	// Rejoin the date fields with single spaces so the space-padded day
	// ("Aug  5") parses cleanly against a non-padded layout.
	age, ok := parsePostfixArrival(strings.Join(f[2:6], " "), now)
	if !ok {
		return QueuedMsg{}, false
	}
	sender := ""
	if len(f) >= 7 {
		sender = f[6]
	}
	return QueuedMsg{ID: id, SizeBytes: size, AgeSec: age, Sender: sender, Frozen: frozen}, true
}

// parsePostfixArrival turns "Wed Aug 5 10:00:33" (no year) into an age in
// seconds relative to now, assuming the current year and rolling back a year if
// that would place arrival in the future (a late-December queue read in early
// January).
func parsePostfixArrival(s string, now time.Time) (int64, bool) {
	t, err := time.ParseInLocation("Mon Jan 2 15:04:05", s, now.Location())
	if err != nil {
		return 0, false
	}
	t = t.AddDate(now.Year(), 0, 0) // parsed year is 0000 → set to now's year
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	age := int64(now.Sub(t).Seconds())
	if age < 0 {
		age = 0
	}
	return age, true
}

// isQueueID reports whether s looks like a postfix queue id (alphanumeric; the
// modern long form is base-52, the legacy form hex).
func isQueueID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// normalizePostfixReason strips the variable bits (host[ip]:port endpoints,
// addresses, IPs, quoted names, URLs) from an inline postqueue reason so the
// same underlying cause aggregates (e.g. every "connect to HOST: Connection
// timed out" collapses to one).
func normalizePostfixReason(s string) string {
	s = reURL.ReplaceAllString(s, "")
	s = reHostIP.ReplaceAllString(s, "") // host[ip]:port — before reIP/reEmail
	s = reAngleAddr.ReplaceAllString(s, "")
	s = reEmail.ReplaceAllString(s, "")
	s = reIP.ReplaceAllString(s, "")
	s = reQuoted.ReplaceAllString(s, "")
	s = reWS.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, " :", ":") // tidy " :" left where a token was removed
	s = reWS.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	if len([]rune(s)) > maxReasonLen {
		s = string([]rune(s)[:maxReasonLen]) + "…"
	}
	return s
}
