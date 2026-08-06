// Package mailqueue summarizes the exim mail queue on demand (the `exim -bp`
// view, structured): how many messages are queued/frozen, how old they are, and
// which sender / recipient domains dominate. It backs the read-only MCP tool
// mail_queue_summary / GET /api/v1/system/mail-queue.
//
// The health snapshot already carries the raw queued/frozen COUNTS (from the
// exim_queues detector via internal/mailq); this adds the breakdown an operator
// needs to answer "why is the queue backing up?" — age distribution + the top
// sender/recipient domains + the oldest messages — without shelling out
// per-message. One `exim -bp` (+ `exim -bpc` for the authoritative count),
// bounded by a message cap and a context timeout; read-only, no reason logs.
package mailqueue

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	scanTimeout   = 15 * time.Second
	maxParseMsgs  = 20000 // hard cap on messages parsed from `exim -bp`
	defaultTopDom = 10
)

// QueuedMsg is one parsed `exim -bp` entry (kept internal; the API returns
// aggregates + a bounded oldest-N sample, not the whole queue).
type QueuedMsg struct {
	AgeSec      int64    `json:"age_sec"`
	SizeBytes   int64    `json:"size_bytes"`
	ID          string   `json:"id"`
	Sender      string   `json:"sender"`
	Frozen      bool     `json:"frozen"`
	Recipients  int      `json:"recipients"`
	rcptDomains []string // deduped, capped; aggregated then dropped from JSON
}

// maxRcptDomainsPerMsg bounds how many distinct recipient domains we retain per
// message (fan-out mail can list thousands) — enough for the aggregate.
const maxRcptDomainsPerMsg = 8

// Summary is the aggregated queue view.
type Summary struct {
	MTA                 string         `json:"mta"`
	Total               int            `json:"total"`  // authoritative count (exim -bpc); falls back to parsed
	Parsed              int            `json:"parsed"` // messages actually parsed from -bp (<= maxParseMsgs)
	Frozen              int            `json:"frozen"`
	Deferred            int            `json:"deferred"`    // non-frozen, older than 1h (stuck but retrying)
	Truncated           bool           `json:"truncated"`   // queue larger than the parse cap
	AgeBuckets          map[string]int `json:"age_buckets"` // <10m,10m-1h,1h-6h,6h-1d,>1d
	TopSenderDomains    []DomCount     `json:"top_sender_domains"`
	TopRecipientDomains []DomCount     `json:"top_recipient_domains"`
	Oldest              []QueuedMsg    `json:"oldest"` // bounded sample, oldest first
}

// DomCount is a domain with its message count.
type DomCount struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// SummarizeQueue runs `exim -bp`/`-bpc`, parses and aggregates. top bounds how
// many domains and oldest-messages to return.
func SummarizeQueue(ctx context.Context, top int) (Summary, error) {
	if top <= 0 {
		top = defaultTopDom
	}
	if _, err := eximPath(); err != nil {
		return Summary{}, fmt.Errorf("exim not found (postfix not yet supported): %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	out, err := runExim(cctx, "-bp")
	if err != nil {
		return Summary{}, fmt.Errorf("exim -bp: %w", err)
	}
	msgs, truncated := parseBP(out)

	s := Summary{
		MTA:        "exim",
		Parsed:     len(msgs),
		Truncated:  truncated,
		AgeBuckets: map[string]int{"<10m": 0, "10m-1h": 0, "1h-6h": 0, "6h-1d": 0, ">1d": 0},
	}
	senderDom := map[string]int{}
	recipDom := map[string]int{}
	for _, m := range msgs {
		if m.Frozen {
			s.Frozen++
		} else if m.AgeSec >= 3600 {
			s.Deferred++
		}
		bucketAge(s.AgeBuckets, m.AgeSec)
		if d := domainOf(m.Sender); d != "" {
			senderDom[d]++
		}
		for _, d := range m.rcptDomains {
			recipDom[d]++
		}
	}
	s.Total = len(msgs)
	if n, err := parseCount(runEximCount(cctx)); err == nil {
		s.Total = n
	}

	s.TopSenderDomains = topDomains(senderDom, top)
	s.TopRecipientDomains = topDomains(recipDom, top)
	s.Oldest = oldestN(msgs, top)
	return s, nil
}

// parseBP parses `exim -bp` output into messages. Format per message:
//
//	<age> <size> <id> <sender@dom>
//	          recipient@dom          (indented; one or more)
//	*** frozen ***                   (only for frozen messages)
//
// A line under a login shell can be preceded by profile noise; a message row is
// recognized by the "<age> <size> <id> <...>" shape, so noise is ignored. The
// parse stops at maxParseMsgs (truncated=true) to bound work on a huge queue.
func parseBP(out string) (msgs []QueuedMsg, truncated bool) {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var cur *QueuedMsg
	flush := func() {
		if cur != nil {
			msgs = append(msgs, *cur)
			cur = nil
		}
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "*** frozen ***") {
			if cur != nil {
				cur.Frozen = true
			}
			continue
		}
		if m, ok := parseHeaderLine(line); ok {
			if len(msgs) >= maxParseMsgs {
				truncated = true
				break
			}
			flush()
			cur = &m
			continue
		}
		// indented recipient line
		if cur != nil && strings.TrimSpace(line) != "" && strings.Contains(line, "@") {
			cur.Recipients++
			if d := domainOf(strings.Trim(strings.TrimSpace(line), "<>")); d != "" {
				addDomainCapped(cur, d)
			}
		}
	}
	flush()
	return msgs, truncated
}

// parseHeaderLine matches the "<age> <size> <id> <sender>" first line of a queue
// entry. Returns ok=false for anything else (recipients, blank, profile noise).
func parseHeaderLine(line string) (QueuedMsg, bool) {
	f := strings.Fields(line)
	if len(f) < 4 {
		return QueuedMsg{}, false
	}
	age, ok := parseAge(f[0])
	if !ok {
		return QueuedMsg{}, false
	}
	size, ok := parseSize(f[1])
	if !ok {
		return QueuedMsg{}, false
	}
	// f[2] = message id; sender is the first <...> token on the line.
	sender := ""
	if i := strings.IndexByte(line, '<'); i >= 0 {
		if j := strings.IndexByte(line[i:], '>'); j >= 0 {
			sender = line[i+1 : i+j]
		}
	}
	return QueuedMsg{AgeSec: age, SizeBytes: size, ID: f[2], Sender: sender}, true
}

// parseAge converts an exim age token ("45s","25m","2h","3d") to seconds.
func parseAge(s string) (int64, bool) {
	if len(s) < 2 {
		return 0, false
	}
	unit := s[len(s)-1]
	num, err := strconv.ParseFloat(s[:len(s)-1], 64)
	if err != nil {
		return 0, false
	}
	switch unit {
	case 's':
		return int64(num), true
	case 'm':
		return int64(num * 60), true
	case 'h':
		return int64(num * 3600), true
	case 'd':
		return int64(num * 86400), true
	case 'w':
		return int64(num * 604800), true
	}
	return 0, false
}

// parseSize converts an exim size token ("541","2.9K","1.5M","1G") to bytes.
func parseSize(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	mult := float64(1)
	switch s[len(s)-1] {
	case 'K', 'k':
		mult, s = 1024, s[:len(s)-1]
	case 'M', 'm':
		mult, s = 1024*1024, s[:len(s)-1]
	case 'G', 'g':
		mult, s = 1024*1024*1024, s[:len(s)-1]
	}
	num, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return int64(num * mult), true
}

func bucketAge(buckets map[string]int, age int64) {
	switch {
	case age < 600:
		buckets["<10m"]++
	case age < 3600:
		buckets["10m-1h"]++
	case age < 6*3600:
		buckets["1h-6h"]++
	case age < 86400:
		buckets["6h-1d"]++
	default:
		buckets[">1d"]++
	}
}

// addDomainCapped adds a distinct recipient domain to the message, bounded.
func addDomainCapped(m *QueuedMsg, d string) {
	if len(m.rcptDomains) >= maxRcptDomainsPerMsg {
		return
	}
	for _, e := range m.rcptDomains {
		if e == d {
			return
		}
	}
	m.rcptDomains = append(m.rcptDomains, d)
}

func domainOf(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(addr[at+1:])
}

func topDomains(m map[string]int, top int) []DomCount {
	out := make([]DomCount, 0, len(m))
	for d, c := range m {
		out = append(out, DomCount{Domain: d, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain < out[j].Domain
	})
	if len(out) > top {
		out = out[:top]
	}
	return out
}

func oldestN(msgs []QueuedMsg, n int) []QueuedMsg {
	cp := make([]QueuedMsg, len(msgs))
	copy(cp, msgs)
	sort.Slice(cp, func(i, j int) bool { return cp[i].AgeSec > cp[j].AgeSec })
	if len(cp) > n {
		cp = cp[:n]
	}
	return cp
}

func parseCount(out string, err error) (int, error) {
	if err != nil {
		return 0, err
	}
	n, found := 0, false
	for _, line := range strings.Split(out, "\n") {
		if v, e := strconv.Atoi(strings.TrimSpace(line)); e == nil {
			n, found = v, true
		}
	}
	if !found {
		return 0, fmt.Errorf("no numeric line")
	}
	return n, nil
}

func runExim(ctx context.Context, args ...string) (string, error) {
	// Login shell like the exim_queues detector, so PATH/profile resolve exim.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-lc", "exim "+strings.Join(args, " "))
	out, err := cmd.Output()
	return string(out), err
}

func runEximCount(ctx context.Context) (string, error) { return runExim(ctx, "-bpc") }

func eximPath() (string, error) {
	if p, err := exec.LookPath("exim"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/sbin/exim", "/usr/sbin/exim4", "/usr/exim/bin/exim"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p, nil
		}
	}
	return "", fmt.Errorf("exim binary not found")
}
