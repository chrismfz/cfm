package mailmeter

import (
	"regexp"
	"strings"
)

// Outcome classifies a remote outbound delivery attempt.
type Outcome int

const (
	OutcomeNone Outcome = iota
	Delivered           // accepted by the remote MX (exim =>/->, postfix status=sent)
	Deferred            // temporary failure, will retry (exim ==, postfix status=deferred)
	Bounced             // permanent failure (exim **, postfix status=bounced)
)

func (o Outcome) String() string {
	switch o {
	case Delivered:
		return "delivered"
	case Deferred:
		return "deferred"
	case Bounced:
		return "bounced"
	default:
		return "none"
	}
}

// Delivery is one parsed REMOTE outbound delivery attempt — the unit of the
// deliverability view ("which provider is accepting / deferring / bouncing our
// mail, and why"). Local deliveries into a mailbox (dovecot LMTP / virtual /
// pipe) are inbound and are NOT reported here.
type Delivery struct {
	Outcome  Outcome `json:"outcome"`
	Provider string  `json:"provider"`         // google | microsoft | yahoo | apple | <registrable domain> | "" (unknown)
	Code     string  `json:"code,omitempty"`   // leading SMTP status, e.g. "250","421","550"
	Reason   string  `json:"reason,omitempty"` // normalized short reason family
}

// ---- Exim ----
//
// Real exim mainlog delivery lines (captured in the field):
//
//	<id> => user@remote R=dkim_lookuphost T=dkim_remote_smtp H=mx.example [1.2.3.4] … C="250 …"   (delivered, remote)
//	<id> => box <box@dom> R=localuser T=dovecot_delivery C="250 …"                                 (delivered, LOCAL — skip)
//	<id> => name |/path/pipe … T=…_pipe                                                            (LOCAL pipe — skip)
//	<id> ** user@gmail.com R=… T=dkim_remote_smtp H=alt1.gmail-smtp-in.l.google.com [ip] … : SMTP error … 550-5.7.1 …  (bounce)
//	<id> == user@dom R=… T=dkim_remote_smtp defer (-54): retry time not reached for any host for 'dom'                  (defer, no host)
//	<id> == user (orig) <user@dom> R=… T=dkim_remote_forwarded_smtp defer (-46) H=mx [ip]: SMTP error … 421-4.7.28 …    (defer, remote)
var (
	reEximDeliv = regexp.MustCompile(`\s(=>|->|\*\*|==)\s`)
	reEximT     = regexp.MustCompile(`\sT=(\S+)`)
	reEximHost  = regexp.MustCompile(`\sH=(\S+)`)
	reEximC     = regexp.MustCompile(`\sC="([^"]*)"`) // completion response on a delivered line
)

// ParseEximDelivery extracts a remote delivery outcome from one exim mainlog
// line, or ok=false when the line is not a remote delivery attempt (arrival,
// local delivery, or anything else). Delivered is reported only for genuinely
// remote deliveries (a remote_smtp transport), so local mailbox deliveries don't
// inflate the "sent to a provider" counts.
func ParseEximDelivery(line string) (Delivery, bool) {
	line = strings.TrimRight(line, "\r\n")
	m := reEximDeliv.FindStringSubmatch(line)
	if m == nil {
		return Delivery{}, false
	}
	transport := ""
	if t := reEximT.FindStringSubmatch(line); t != nil {
		transport = strings.ToLower(t[1])
	}
	host := ""
	if h := reEximHost.FindStringSubmatch(line); h != nil {
		host = strings.Trim(h[1], "()")
	}
	remote := strings.Contains(transport, "remote_smtp") || host != ""

	var d Delivery
	delivered := false
	switch m[1] {
	case "=>", "->":
		if !remote {
			return Delivery{}, false // local mailbox / pipe delivery — inbound, not counted
		}
		d.Outcome = Delivered
		delivered = true
	case "**":
		d.Outcome = Bounced
	case "==":
		d.Outcome = Deferred
	}
	if host != "" {
		d.Provider = classifyProvider(host)
	}
	reason := eximDeliveryReason(line, delivered)
	d.Code = leadingSMTPCode(reason)
	d.Reason = normalizeDeliveryReason(reason)
	return d, true
}

// eximDeliveryReason returns the response text a reason can be classified from.
// A delivered line carries it in the completion field C="…"; a failure/defer
// line carries it after the first ": " that follows the H=/T=/defer(...)
// preamble (the exim log format is `<preamble>: <remote response>`).
func eximDeliveryReason(line string, delivered bool) string {
	if delivered {
		if m := reEximC.FindStringSubmatch(line); m != nil {
			return strings.TrimSpace(m[1])
		}
		return ""
	}
	if i := strings.Index(line, ": "); i >= 0 {
		return strings.TrimSpace(line[i+2:])
	}
	return ""
}

// ---- Postfix ----
//
// Real postfix maillog delivery lines (NGM corpus):
//
//	postfix/smtp[..]: QID: to=<u@rem>, relay=mx[1.2.3.4]:25, …, dsn=2.0.0, status=sent (250 …)
//	postfix/smtp[..]: QID: to=<u@gmail>, relay=gmail-smtp-in.l.google.com[ip]:25, …, dsn=5.2.1, status=bounced (host … said: 550 …)
//	postfix/smtp[..]: QID: to=<u@rem>, relay=mx[ip]:25, …, dsn=4.x, status=deferred (… 451 …)
var (
	rePfxSmtp   = regexp.MustCompile(`^\w{3}\s+\d+\s+[0-9:]+\s+\S+\s+postfix/smtp\[\d+\]:\s`)
	rePfxRelay  = regexp.MustCompile(`\brelay=([^,\s]+)`)
	rePfxStatus = regexp.MustCompile(`\bstatus=(sent|bounced|deferred)\b`)
)

// ParsePostfixDelivery extracts a remote delivery outcome from a postfix/smtp
// maillog line, or ok=false otherwise. postfix/lmtp (local delivery) is
// intentionally not matched.
func ParsePostfixDelivery(line string) (Delivery, bool) {
	line = strings.TrimRight(line, "\r\n")
	if !rePfxSmtp.MatchString(line) {
		return Delivery{}, false
	}
	sm := rePfxStatus.FindStringSubmatch(line)
	if sm == nil {
		return Delivery{}, false
	}
	var d Delivery
	switch sm[1] {
	case "sent":
		d.Outcome = Delivered
	case "bounced":
		d.Outcome = Bounced
	case "deferred":
		d.Outcome = Deferred
	}
	if rel := rePfxRelay.FindStringSubmatch(line); rel != nil {
		d.Provider = classifyProvider(relayHost(rel[1]))
	}
	reason := postfixDeliveryReason(line)
	d.Code = leadingSMTPCode(reason)
	d.Reason = normalizeDeliveryReason(reason)
	return d, true
}

// relayHost strips the "[ip]:port" suffix from a postfix relay= value, leaving
// the hostname (or the bracketed IP when there is no name).
func relayHost(relay string) string {
	if i := strings.IndexByte(relay, '['); i > 0 {
		return relay[:i]
	}
	return relay
}

// postfixDeliveryReason returns the text inside the trailing "status=… (…)"
// parenthetical (the remote server's response), or "".
func postfixDeliveryReason(line string) string {
	i := strings.Index(line, "status=")
	if i < 0 {
		return ""
	}
	open := strings.IndexByte(line[i:], '(')
	if open < 0 {
		return ""
	}
	rest := line[i+open+1:]
	if close := strings.LastIndexByte(rest, ')'); close >= 0 {
		rest = rest[:close]
	}
	return strings.TrimSpace(rest)
}

// ---- shared classification ----

// classifyProvider maps a remote MX hostname to a coarse provider bucket so the
// deliverability view groups by mail operator rather than by individual MX. An
// unrecognised host collapses to its registrable domain (last two labels), which
// keeps the cardinality bounded without a public-suffix list.
func classifyProvider(host string) string {
	host = strings.ToLower(strings.Trim(strings.TrimSuffix(host, "."), "[]"))
	if host == "" {
		return ""
	}
	switch {
	case strings.Contains(host, "google.com") || strings.Contains(host, "googlemail.com") || strings.Contains(host, "gmail.com"):
		return "google"
	case strings.Contains(host, "outlook.com") || strings.Contains(host, "hotmail.com") ||
		strings.Contains(host, "office365.com") || strings.Contains(host, "protection.outlook.com"):
		return "microsoft"
	case strings.Contains(host, "yahoodns.net") || strings.Contains(host, "yahoo.com") || strings.Contains(host, "yahoo.net"):
		return "yahoo"
	case strings.Contains(host, "icloud.com") || strings.Contains(host, "apple.com") || strings.Contains(host, "me.com"):
		return "apple"
	}
	return registrableDomain(host)
}

// registrableDomain returns the last two dot-labels of host (best-effort, no
// public-suffix list — good enough for grouping delivery targets).
func registrableDomain(host string) string {
	if strings.HasPrefix(host, "[") || net_ParseIPish(host) {
		return host // a bare IP literal — keep as-is
	}
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// net_ParseIPish reports whether host looks like a bare IPv4/IPv6 literal (so we
// don't chop it as if it were a hostname). Kept dependency-free.
func net_ParseIPish(host string) bool {
	if strings.Contains(host, ":") {
		return true // IPv6
	}
	dots := strings.Count(host, ".")
	if dots != 3 {
		return false
	}
	for _, p := range strings.Split(host, ".") {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

var reLeadingCode = regexp.MustCompile(`\b([245]\d\d)\b`)

// leadingSMTPCode returns the first 3-digit SMTP status code in reason, or "".
func leadingSMTPCode(reason string) string {
	if m := reLeadingCode.FindStringSubmatch(reason); m != nil {
		return m[1]
	}
	return ""
}

// normalizeDeliveryReason collapses a remote server's response (or an exim defer
// note) into a small, stable family so the deliverability view aggregates the
// same cause instead of showing thousands of per-message variants. Order matters:
// the more specific enhanced-status / phrase checks come before the generic ones.
func normalizeDeliveryReason(reason string) string {
	if reason == "" {
		return ""
	}
	l := strings.ToLower(reason)
	switch {
	case strings.Contains(l, "4.7.27") || (strings.Contains(l, "spf") && strings.Contains(l, "not pass")):
		return "spf-not-passed"
	case strings.Contains(l, "dkim") && (strings.Contains(l, "fail") || strings.Contains(l, "not pass")):
		return "dkim-failed"
	case strings.Contains(l, "dmarc"):
		return "dmarc-policy"
	case strings.Contains(l, "4.7.28") || (strings.Contains(l, "unsolicited") && strings.Contains(l, "rate")):
		return "unsolicited-rate-limited"
	case strings.Contains(l, "unsolicited") || strings.Contains(l, "this message is likely"):
		return "unsolicited-blocked"
	case strings.Contains(l, "rate limit") || strings.Contains(l, "ratelimit") || strings.Contains(l, "too many"):
		return "rate-limited"
	case strings.Contains(l, "retry time not reached") || strings.Contains(l, "retry time not yet reached"):
		return "retry-backoff"
	case strings.Contains(l, "connection refused"):
		return "connection-refused"
	case strings.Contains(l, "timed out") || strings.Contains(l, "timeout"):
		return "connection-timeout"
	case strings.Contains(l, "5.1.1") || strings.Contains(l, "does not exist") ||
		strings.Contains(l, "user unknown") || strings.Contains(l, "no such user") || strings.Contains(l, "recipient address rejected"):
		return "no-such-user"
	case strings.Contains(l, "5.2.2") || strings.Contains(l, "over quota") ||
		strings.Contains(l, "quota exceeded") || strings.Contains(l, "mailbox is full") || strings.Contains(l, "mailbox full"):
		return "over-quota"
	case strings.Contains(l, "relay access denied") || strings.Contains(l, "relaying denied"):
		return "relay-denied"
	case strings.Contains(l, "greylist") || strings.Contains(l, "greylisted") || strings.Contains(l, "try again later"):
		return "greylisted"
	case strings.Contains(l, "blocked") || strings.Contains(l, "blacklist") || strings.Contains(l, "blocklist") ||
		strings.Contains(l, "spamhaus") || strings.Contains(l, "reputation"):
		return "blocked-reputation"
	case strings.Contains(l, "sender verify") || strings.Contains(l, "could not complete sender verify"):
		return "sender-verify-failed"
	case strings.HasPrefix(l, "250") || strings.Contains(l, "ok:") || strings.Contains(l, "2.0.0"):
		return "ok"
	}
	// Fall back to the leading code so at least the class is visible.
	if c := leadingSMTPCode(reason); c != "" {
		return c
	}
	return "other"
}
