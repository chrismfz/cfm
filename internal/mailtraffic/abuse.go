package mailtraffic

// abuse.go — turns the Mail Monitor's counters into durable node faults that
// cfm-web routes to the team channel (docs/mail-abuse.md):
//
//   - mail_script_spike: a unix user's LOCAL submissions (sendmail from a PHP
//     app or cron, `U=user P=local`) far above that user's own history — a
//     hacked site or an abused contact form. On titan (Oct 2026) a Joomla
//     form sent ~1 000 messages a day for days, ~43 an hour: never enough for
//     exim_relays' fixed 110-per-15-minutes threshold, obvious against the
//     user's own ~1 a day.
//   - mail_outbound_spike: an authenticated mailbox sending far above its own
//     history (the anomaly whats_wrong already showed, now an alert).
//   - mail_hijack: one mailbox SUCCESSFULLY authenticating from many IPs or
//     countries within an hour (SMTP AUTH, or IMAP/POP3 through dovecot) — a
//     stolen password being used.
//   - mail_bounce_spike: a sender whose mail bounces in bulk — a hacked
//     account or form writing to harvested / made-up addresses (abuse_signals.go).
//   - mail_queue_hog: one sender holding most of a large queue.
//   - mail_rbl_listed: one of the node's public IPs on a DNS blocklist.
//
// Each finding is published once when it appears (again if its severity
// rises), and resolved with mail_recovered under the same key once it is over.
// A spike closes only when the volume is back near what it was BEFORE the
// alert opened: a sender's baseline is its own trailing week, so a long
// incident slowly becomes its own baseline and would otherwise "recover"
// while still spamming.
//
// Visibility only: nothing here blocks, holds or changes mail.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"mime"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/enrich"
	"cfm/internal/logging"
	"cfm/internal/mailmeter"
)

// Finding types — detection_history event types, so a change here is a wire
// change for cfm-web's ingest.
const (
	TypeScriptSpike   = "mail_script_spike"
	TypeOutboundSpike = "mail_outbound_spike"
	TypeHijack        = "mail_hijack"
	TypeBounceSpike   = "mail_bounce_spike"
	TypeQueueHog      = "mail_queue_hog"
	TypeRBLListed     = "mail_rbl_listed"
	TypeRecovered     = "mail_recovered"
)

const (
	abuseEvalEvery = 5 * time.Minute
	// a hijack: one mailbox logged in from this many countries, or from this
	// many sources of which hijackMinAbroad are outside its main country,
	// within hijackWindow. Sources alone are not enough: a phone's IPv6
	// privacy addresses or a home + VPN are many sources, one or two places.
	hijackWindow       = time.Hour
	hijackMinCountries = 3
	hijackMinIPs       = 10
	hijackMinAbroad    = 5
	// a spike is critical when it is both this many times its usual rate and
	// at least this many messages in the recent window (or a sender with no
	// history sending at least anomalyNewSenderFloor).
	abuseCritRatio = 10.0
	abuseCritFloor = 50
	// a spike closes once the recent volume is under this factor of the
	// expected volume recorded when it opened (or under the spike floor).
	abuseCloseFactor = 1.5
	// context kept per user / mailbox (bounded: a flood must not grow memory).
	contextWindow   = anomalyRecentHours * time.Hour
	maxSamples      = 2000
	maxTrackedIPs   = 256
	maxTrackedUsers = 5000
)

// systemLocalUsers submit mail that is the host's own (cron output, cPanel
// notices), not a tenant's; a spike there is not a hacked site.
var systemLocalUsers = map[string]bool{"root": true, "mailnull": true, "cpanel": true, "cpanelphpmyadmin": true, "cpanelroundcube": true, "exim": true}

// FaultSink receives a finding as a node fault (detection_history). It reports
// whether it was delivered; an undelivered finding is retried next check.
type FaultSink func(typ, severity, key, message string, when time.Time) bool

var (
	sinkMu sync.RWMutex
	sink   FaultSink

	abuseOn atomic.Bool

	// localDomainFiles list the domains this host serves (cPanel, then
	// DirectAdmin): an envelope sender outside them is noted, since a
	// contact form sending "from" someone's gmail address is forging it.
	localDomainFiles = []string{"/etc/localdomains", "/etc/virtualdomains", "/etc/virtual/domains"}

	// geoOf resolves an IP to its ISO country ("" when unknown) and ASN (0
	// when unknown). A var so tests stub it; the default opens the node's
	// GeoIP databases lazily.
	geoOf = defaultGeoOf
)

func init() { abuseOn.Store(true) }

// SetFaultSink registers the consumer of mail-abuse findings (the webdetector
// history store). nil detaches; findings then stay armed and are retried.
func SetFaultSink(fn FaultSink) {
	sinkMu.Lock()
	sink = fn
	sinkMu.Unlock()
}

// SetAbuseAlert turns the findings on or off (cfm.conf MAIL_ABUSE_ALERT).
func SetAbuseAlert(on bool) { abuseOn.Store(on) }

func publish(typ, sev, key, msg string, when time.Time) bool {
	sinkMu.RLock()
	fn := sink
	sinkMu.RUnlock()
	if fn == nil {
		return false
	}
	defer func() { _ = recover() }()
	return fn(typ, sev, key, msg, when)
}

var (
	geoOnce sync.Once
	geoEnr  *enrich.Enricher
)

func defaultGeoOf(ip string) (string, uint) {
	geoOnce.Do(func() { geoEnr, _ = enrich.New("/etc/cfm", "/var/lib/cfm/maxmind") })
	if geoEnr == nil {
		return "", 0
	}
	r := geoEnr.LookupGeoFast(ip)
	return r.CountryISO, r.ASN
}

// fetcherASNs are the big mail providers whose servers log in to a mailbox on
// its owner's behalf: Gmail fetching over POP3 or sending "as" the address,
// Outlook.com, Yahoo, iCloud. Their many addresses count as one source and
// their country as none, or every such mailbox would look hijacked. A hijacker
// renting a VM in the same network is missed — they rarely do; residential
// proxies and VPS networks are what show up.
var fetcherASNs = map[uint]bool{15169: true, 8075: true, 36647: true, 26101: true, 34010: true, 714: true, 6185: true}

// authSource normalises a login's source address: "" for an address that is not
// a remote client (loopback, private: webmail, a local relay), the network for
// a provider fetching mail, the /64 for IPv6 (one device rotates privacy
// addresses inside it), else the address itself; and the country.
func authSource(ip string) (src, country string) {
	pip := net.ParseIP(ip)
	if pip == nil || pip.IsLoopback() || pip.IsPrivate() || pip.IsLinkLocalUnicast() || pip.IsUnspecified() {
		return "", ""
	}
	cc, asn := geoOf(ip)
	if fetcherASNs[asn] {
		return fmt.Sprintf("AS%d", asn), ""
	}
	if v4 := pip.To4(); v4 != nil {
		return v4.String(), cc // ::ffff:1.2.3.4 is 1.2.3.4
	}
	return pip.Mask(net.CIDRMask(64, 128)).String() + "/64", cc
}

// ---- per-line context (what the counters don't keep) ----

// sample is one recent message of a sender, kept for the alert's context: a
// subject and the recipients tell a newsletter from a hijacked contact form.
type sample struct {
	at      time.Time
	cwd     string // local submissions: the script's directory
	from    string // envelope sender
	subject string
	rcpts   []string
}

type tracker struct {
	mu         sync.Mutex
	line       int
	pendingCwd string
	pendingAt  int
	samples    map[string][]sample            // "local:<user>" / "auth:<mailbox>" → recent messages
	authIPs    map[string]map[string]authSeen // mailbox → source IP → last successful login
	owners     map[string]owner               // exim message id / postfix QID → the sender key it was submitted by
	outcomes   map[string][]outcome           // sender key → recent remote delivery outcomes

	last      []AbuseView // the latest check's findings, for whats_wrong / mail_traffic
	lastCheck time.Time
	started   time.Time // what is in memory covers only the time since
}

// authSeen is a mailbox's last login from one source, and over what.
type authSeen struct {
	at  time.Time
	via string // smtp | imap | pop3
}

func newTracker() *tracker {
	return &tracker{
		samples:  map[string][]sample{},
		authIPs:  map[string]map[string]authSeen{},
		owners:   map[string]owner{},
		outcomes: map[string][]outcome{},
		started:  time.Now(),
	}
}

var (
	// `<date> <time> [pid] cwd=/home/u/public_html 4 args: /usr/sbin/sendmail -t -i -f…`
	reCwdLine = regexp.MustCompile(`\scwd=(\S+)\s+\d+\s+args:`)
	reLogTime = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)`)
	reFrom    = regexp.MustCompile(`\s<=\s(\S+)`)
	reHostIP  = regexp.MustCompile(`\bH=[^\[]*\[([0-9a-fA-F:.]+)\]`)
	// T="subject" (exim log_selector +subject; `\"` escapes a quote)
	reSubject = regexp.MustCompile(`\sT="((?:[^"\\]|\\.)*)"`)
	// Postfix submission: `QID: client=host[ip], sasl_method=PLAIN, sasl_username=user`
	rePostfixAuth = regexp.MustCompile(`(?:\]: ([0-9A-Za-z]+): )?client=[^\[]*\[([0-9a-fA-F:.]+)\].*\bsasl_username=([^\s,]+)`)
	// a postfix line's queue id: `postfix/smtp[123]: 4AB12CD: to=<…>, …`
	rePostfixQID = regexp.MustCompile(`postfix/[^\s\[]+\[\d+\]: ([0-9A-Za-z]+): `)
	// Dovecot: `imap-login: Login: user=<a@b>, method=PLAIN, rip=1.2.3.4, lip=…`
	// (2.4 logs "Logged in").
	reDovecotLogin = regexp.MustCompile(`\b(imap|pop3)-login: (?:Login|Logged in): user=<([^>]+)>.*?\brip=([0-9a-fA-F:.]+)`)
	// an exim mainlog line's message id and flag: `<date> <time> [pid] <id> <flag> `
	reEximID = regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)?(?: [-+]\d{4})? (?:\[\d+\] )?([0-9A-Za-z]{6}-[0-9A-Za-z]{6,11}-[0-9A-Za-z]{2,4}) (<=|=>|->|\*\*|==) `)
)

func logTime(line string, now time.Time) time.Time {
	if m := reLogTime.FindStringSubmatch(line); m != nil {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local); err == nil {
			return t
		}
	}
	return now
}

var (
	subjectDecoder = new(mime.WordDecoder)
	reEncodedLeft  = regexp.MustCompile(`=\?\S*`)
)

// decodeSubject turns exim's logged subject (often RFC 2047 encoded words, and
// cut short by exim) into readable text. An encoded word exim cut in half is
// dropped rather than shown as base64.
func decodeSubject(raw string) string {
	raw = strings.ReplaceAll(raw, `\"`, `"`)
	if d, err := subjectDecoder.DecodeHeader(raw); err == nil {
		raw = d
	}
	// whatever is still an encoded word did not decode (exim cut it short)
	raw = reEncodedLeft.ReplaceAllString(raw, "")
	raw = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, raw)
	raw = strings.Join(strings.Fields(raw), " ")
	if r := []rune(raw); len(r) > 80 {
		raw = string(r[:79]) + "…"
	}
	return raw
}

// observeExim takes one exim mainlog line.
func (t *tracker) observeExim(line string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.line++
	if m := reCwdLine.FindStringSubmatch(line); m != nil {
		t.pendingCwd, t.pendingAt = m[1], t.line
		return
	}
	id := reEximID.FindStringSubmatch(line)
	if id != nil && id[2] != "<=" {
		if d, ok := mailmeter.ParseEximDelivery(line); ok && !localTransport(line) {
			t.addOutcome(id[1], d, logTime(line, now))
		}
		return
	}
	if !strings.Contains(line, " <= ") {
		return
	}
	s := sample{at: logTime(line, now)}
	if f := reFrom.FindStringSubmatch(line); f != nil {
		s.from = strings.ToLower(f[1])
	}
	if m := reSubject.FindStringSubmatch(line); m != nil {
		s.subject = decodeSubject(m[1])
	}
	if i := strings.LastIndex(line, " for "); i >= 0 {
		for _, r := range strings.Fields(line[i+5:]) {
			if strings.Contains(r, "@") {
				s.rcpts = append(s.rcpts, strings.ToLower(r))
			}
		}
	}
	if m := reEximLocalUser.FindStringSubmatch(line); m != nil {
		if t.line-t.pendingAt <= 4 { // the cwd line is logged just before its arrival line
			s.cwd = t.pendingCwd
		}
		t.addSample("local:"+m[1], s)
		if id != nil {
			t.addOwner(id[1], "local:"+m[1], s.at)
		}
		return
	}
	if m := reEximAuthed.FindStringSubmatch(line); m != nil {
		user := strings.ToLower(m[1])
		t.addSample("auth:"+user, s)
		if id != nil {
			t.addOwner(id[1], "auth:"+user, s.at)
		}
		if ip := reHostIP.FindStringSubmatch(line); ip != nil {
			t.addAuth(user, ip[1], "smtp", s.at)
		}
	}
}

// observeMaillog takes one syslog maillog line: Postfix submissions and
// deliveries, and Dovecot logins (on any host, exim's included).
func (t *tracker) observeMaillog(line string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if m := reDovecotLogin.FindStringSubmatch(line); m != nil {
		t.addAuth(strings.ToLower(m[2]), m[3], m[1], now)
		return
	}
	if m := rePostfixAuth.FindStringSubmatch(line); m != nil {
		user := strings.ToLower(m[3])
		t.addAuth(user, m[2], "smtp", now)
		if m[1] != "" {
			t.addOwner(m[1], "auth:"+user, now)
		}
		return
	}
	if q := rePostfixQID.FindStringSubmatch(line); q != nil {
		if d, ok := mailmeter.ParsePostfixDelivery(line); ok {
			t.addOutcome(q[1], d, now)
		} else if strings.HasSuffix(strings.TrimSpace(line), ": removed") {
			delete(t.owners, q[1]) // postfix reuses queue ids
		}
	}
}

var reEximTransport = regexp.MustCompile(`\sT=(\S+)`)

// localTransport reports a delivery line through a local transport (a mailbox,
// a pipe): local deliveries are not counted as delivered, so their failures
// (a full or deleted local mailbox) must not count as bounces either. A line
// with no transport at all ("retry timeout exceeded") is a remote give-up.
func localTransport(line string) bool {
	m := reEximTransport.FindStringSubmatch(line)
	return m != nil && !strings.Contains(strings.ToLower(m[1]), "smtp")
}

var (
	reEximLocalUser = regexp.MustCompile(`\bU=([^\s]+)\s+P=local\b`)
	reEximAuthed    = regexp.MustCompile(`\bP=esmtps?a\b.*\bA=[^:\s]+:([^\s]+)`)
)

func (t *tracker) addSample(key string, s sample) {
	if _, ok := t.samples[key]; !ok && len(t.samples) >= maxTrackedUsers {
		return
	}
	ss := append(t.samples[key], s)
	if len(ss) > maxSamples {
		ss = ss[len(ss)-maxSamples:]
	}
	t.samples[key] = ss
}

func (t *tracker) addAuth(user, ip, via string, at time.Time) {
	ips := t.authIPs[user]
	if ips == nil {
		if len(t.authIPs) >= maxTrackedUsers {
			return
		}
		ips = map[string]authSeen{}
		t.authIPs[user] = ips
	}
	if _, ok := ips[ip]; !ok && len(ips) >= maxTrackedIPs {
		return
	}
	ips[ip] = authSeen{at: at, via: via}
}

// prune drops context older than the windows it is read over.
func (t *tracker) prune(now time.Time) {
	for k, ss := range t.samples {
		i := 0
		for i < len(ss) && now.Sub(ss[i].at) > contextWindow {
			i++
		}
		if i == len(ss) {
			delete(t.samples, k)
		} else {
			t.samples[k] = ss[i:]
		}
	}
	for u, ips := range t.authIPs {
		for ip, a := range ips {
			if now.Sub(a.at) > hijackWindow {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(t.authIPs, u)
		}
	}
	t.pruneOutcomes(now)
}

// Context is what a sender's recent messages looked like — enough to tell a
// newsletter from a hacked contact form without opening a log.
type Context struct {
	Messages    int      `json:"messages"` // in the sample (the last 2 h, capped)
	Cwd         string   `json:"cwd,omitempty"`
	From        string   `json:"from,omitempty"`
	ForeignFrom bool     `json:"foreign_from,omitempty"` // the envelope sender's domain is not on this host
	OtherFrom   bool     `json:"other_from,omitempty"`   // a mailbox sending as an address that is not itself
	Subjects    []string `json:"subjects,omitempty"`     // the most common, up to 3
	Recipients  int      `json:"recipients"`             // distinct
	RcptDomains []string `json:"rcpt_domains,omitempty"` // "gmail.com×812", top 5
	// CopiedTo is set when one address gets (nearly) every message while the
	// rest go to a new address each time: a contact form's "send a copy to
	// the sender" abused to spam, the owner in copy.
	CopiedTo string `json:"copied_to,omitempty"`
}

func (t *tracker) context(key, self string) Context {
	ss := t.samples[key]
	c := Context{Messages: len(ss)}
	if len(ss) == 0 {
		return c
	}
	cwds, froms, subjects, rcpts, doms := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	others := 0
	for _, s := range ss {
		if s.cwd != "" {
			cwds[s.cwd]++
		}
		if s.from != "" {
			froms[s.from]++
		}
		if s.subject != "" {
			subjects[s.subject]++
		}
		for _, r := range s.rcpts {
			if rcpts[r] == 0 {
				if i := strings.LastIndex(r, "@"); i >= 0 {
					doms[r[i+1:]]++
				}
			}
			rcpts[r]++
		}
		others += len(s.rcpts)
	}
	c.Cwd, c.From, c.Recipients = topKey(cwds), topKey(froms), len(rcpts)
	if c.From != "" {
		c.ForeignFrom = foreignSender(c.From)
		c.OtherFrom = self != "" && strings.Contains(self, "@") && c.From != self
	}
	for _, kv := range topN(subjects, 3) {
		c.Subjects = append(c.Subjects, kv.k)
	}
	for _, kv := range topN(doms, 5) {
		c.RcptDomains = append(c.RcptDomains, fmt.Sprintf("%s×%d", kv.k, kv.n))
	}
	if top := topN(rcpts, 1); len(top) == 1 && len(ss) >= 5 &&
		float64(top[0].n) >= 0.8*float64(len(ss)) && float64(len(rcpts)-1) >= 0.8*float64(others-top[0].n) {
		c.CopiedTo = top[0].k
	}
	return c
}

type kv struct {
	k string
	n int
}

func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topKey(m map[string]int) string {
	if t := topN(m, 1); len(t) == 1 {
		return t[0].k
	}
	return ""
}

// describe appends a context's telling parts to an alert message, most
// telling first (the message is cut at the column limit).
func (c Context) describe(msg string) string {
	if c.Cwd != "" {
		msg += " · from " + c.Cwd
	}
	if c.From != "" {
		switch {
		case c.ForeignFrom:
			msg += " · as " + c.From + " (not a domain here)"
		case c.OtherFrom:
			msg += " · as " + c.From + " (not itself)"
		}
	}
	if c.CopiedTo != "" {
		msg += fmt.Sprintf(" · contact-form pattern: %s + a new address each", c.CopiedTo)
	} else if c.Recipients > 0 {
		msg += fmt.Sprintf(" · %d different recipients", c.Recipients)
	}
	if len(c.Subjects) > 0 {
		msg += " · «" + c.Subjects[0] + "»"
	}
	return msg
}

// ---- evaluation ----

type abuseFinding struct {
	Type, Severity, Key, Message string
	Expected                     float64 // the spike's expected volume when it opened
}

// AbuseView is one current finding with its full context, for whats_wrong
// and the mail_traffic view.
type AbuseView struct {
	Type      string   `json:"type"`
	Severity  string   `json:"severity"`
	Key       string   `json:"key"`
	Message   string   `json:"message"`
	Subject   string   `json:"subject"` // the user / mailbox
	Recent    int64    `json:"recent,omitempty"`
	Context   *Context `json:"context,omitempty"`
	IPs       int      `json:"ips,omitempty"`
	Countries []string `json:"countries,omitempty"`
}

// evaluate returns this check's findings, plus each spike key's recent volume
// (for closing spikes against their opening baseline). ok=false when the store
// could not be read: nothing should change on such a check.
func (t *tracker) evaluate(st *Store, now time.Time) (fs []abuseFinding, recent map[string]int64, ok bool) {
	fs, recent, _, ok = t.evaluateWith(st, now, nil, nil)
	return fs, recent, ok
}

// evaluateWith is evaluate knowing which keys are open (so a finding can stay
// open on a lower threshold than it took to open) and the latest RBL results.
// held lists open keys this check could not judge (no fresh queue reading, a
// blocklist that did not answer): they are neither re-published nor resolved.
func (t *tracker) evaluateWith(st *Store, now time.Time, open map[string]bool, rbl *rblChecker) (fs []abuseFinding, recent map[string]int64, held map[string]bool, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(now)
	recent = map[string]int64{}
	held = map[string]bool{}

	out, outRecent, err := st.anomalyScan(now, nil, "outbound")
	if err != nil {
		return nil, nil, nil, false
	}
	loc, locRecent, err := st.anomalyScan(now, nil, "local_sub")
	if err != nil {
		return nil, nil, nil, false
	}
	for a, n := range outRecent {
		recent["mail:out:"+a] = n
	}
	for a, n := range locRecent {
		recent["mail:script:"+a] = n
	}

	var views []AbuseView
	for _, a := range loc {
		if systemLocalUsers[a.Addr] {
			continue
		}
		c := t.context("local:"+a.Addr, "")
		msg := clip(c.describe(fmt.Sprintf("%s: %d messages sent by scripts in %dh (%s)", a.Addr, a.Recent, anomalyRecentHours, usual(a))))
		f := abuseFinding{Type: TypeScriptSpike, Severity: spikeSeverity(a), Key: "mail:script:" + a.Addr, Message: msg, Expected: expectedOf(a)}
		fs = append(fs, f)
		views = append(views, AbuseView{Type: f.Type, Severity: f.Severity, Key: f.Key, Message: msg, Subject: a.Addr, Recent: a.Recent, Context: &c})
	}
	hijacked := map[string]bool{}
	for user, ips := range t.authIPs {
		countries, sources, via := map[string]bool{}, map[string]string{}, map[string]bool{}
		for ip, a := range ips {
			src, cc := authSource(ip)
			if src == "" {
				continue
			}
			sources[src] = cc
			via[a.via] = true
			if cc != "" {
				countries[cc] = true
			}
		}
		perCountry := map[string]int{}
		for _, cc := range sources {
			if cc != "" {
				perCountry[cc]++
			}
		}
		abroad := 0
		if top := topN(perCountry, 1); len(top) == 1 {
			for _, cc := range sources {
				if cc != "" && cc != top[0].k {
					abroad++
				}
			}
		}
		if len(countries) < hijackMinCountries && (len(sources) < hijackMinIPs || abroad < hijackMinAbroad) {
			continue
		}
		hijacked[user] = true
		cs := sortedKeys(countries)
		msg := clip(fmt.Sprintf("%s: logged in (%s) from %d IPs in %d countries (%s) within an hour — likely a stolen password",
			user, strings.Join(sortedKeys(via), "/"), len(sources), len(countries), strings.Join(cs, ", ")))
		f := abuseFinding{Type: TypeHijack, Severity: "critical", Key: "mail:hijack:" + user, Message: msg}
		fs = append(fs, f)
		c := t.context("auth:"+user, user)
		views = append(views, AbuseView{Type: f.Type, Severity: f.Severity, Key: f.Key, Message: msg, Subject: user, IPs: len(sources), Countries: cs, Context: &c})
	}
	if now.Sub(t.started) < hijackWindow {
		// after a restart the logins in memory cover less than the window: an
		// open hijack is neither confirmed nor resolved yet
		for k := range open {
			if strings.HasPrefix(k, "mail:hijack:") && !hijacked[strings.TrimPrefix(k, "mail:hijack:")] {
				held[k] = true
			}
		}
	}
	for _, a := range out {
		c := t.context("auth:"+a.Addr, a.Addr)
		head := fmt.Sprintf("%s: %d authenticated messages in %dh (%s)", a.Addr, a.Recent, anomalyRecentHours, usual(a))
		if ips := t.authIPs[a.Addr]; len(ips) > 1 && !hijacked[a.Addr] {
			head += fmt.Sprintf(" · from %d IPs", len(ips))
		}
		msg := clip(c.describe(head))
		f := abuseFinding{Type: TypeOutboundSpike, Severity: spikeSeverity(a), Key: "mail:out:" + a.Addr, Message: msg, Expected: expectedOf(a)}
		fs = append(fs, f)
		views = append(views, AbuseView{Type: f.Type, Severity: f.Severity, Key: f.Key, Message: msg, Subject: a.Addr, Recent: a.Recent, IPs: len(t.authIPs[a.Addr]), Context: &c})
	}
	for _, more := range [][]AbuseView{t.bounceFindings(now, open, held), queueFindings(now, open, held), rblFindings(rbl, open, held)} {
		for _, v := range more {
			fs = append(fs, abuseFinding{Type: v.Type, Severity: v.Severity, Key: v.Key, Message: v.Message})
			views = append(views, v)
		}
	}
	t.last, t.lastCheck = views, now
	return fs, recent, held, true
}

// CurrentAbuse returns the latest mail-abuse check's findings with their
// context and when it ran; nil and a zero time before the first check, when the
// collector is not running, or when the check is off.
func CurrentAbuse() ([]AbuseView, time.Time) {
	sharedMu.RLock()
	c := coll
	sharedMu.RUnlock()
	if c == nil || !abuseOn.Load() {
		return nil, time.Time{}
	}
	c.ab.mu.Lock()
	defer c.ab.mu.Unlock()
	return append([]AbuseView(nil), c.ab.last...), c.ab.lastCheck
}

func usual(a Anomaly) string {
	if a.Kind == "new-sender" {
		return "it rarely sends mail"
	}
	return fmt.Sprintf("%.0f× its usual %.1f/h", a.Ratio, a.BaselinePerHour)
}

func expectedOf(a Anomaly) float64 { return a.BaselinePerHour * anomalyRecentHours }

func spikeSeverity(a Anomaly) string {
	if a.Recent >= abuseCritFloor && (a.Kind == "new-sender" || a.Ratio >= abuseCritRatio) {
		return "critical"
	}
	return "warning"
}

// clip keeps a message inside cfm-web's 255-character event column.
func clip(s string) string {
	if r := []rune(s); len(r) > 240 {
		return string(r[:239]) + "…"
	}
	return s
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	localDomMu   sync.Mutex
	localDoms    map[string]bool
	localDomRead time.Time
)

// foreignSender reports whether an envelope sender's domain is not one this
// host serves. Unknown (no domain list at all) is never foreign.
func foreignSender(from string) bool {
	i := strings.LastIndex(from, "@")
	if i < 0 {
		return false
	}
	dom := strings.TrimSuffix(from[i+1:], ">")
	localDomMu.Lock()
	defer localDomMu.Unlock()
	if localDoms == nil || time.Since(localDomRead) > 10*time.Minute {
		localDoms, localDomRead = readLocalDomains(), time.Now()
	}
	if len(localDoms) == 0 {
		return false
	}
	return !localDoms[dom]
}

func readLocalDomains() map[string]bool {
	m := map[string]bool{}
	for _, p := range localDomainFiles {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			if i := strings.IndexByte(l, ':'); i >= 0 { // virtualdomains: "dom: user"
				l = strings.TrimSpace(l[:i])
			}
			m[strings.ToLower(l)] = true
		}
		_ = f.Close()
	}
	return m
}

// ---- edge-triggered publishing ----

type openFinding struct {
	Type     string  `json:"type"`
	Severity string  `json:"severity"`
	Message  string  `json:"message"`
	Expected float64 `json:"expected"`
}

type publisher struct {
	mu     sync.Mutex
	path   string // "" = not persisted
	loaded bool
	open   map[string]openFinding
}

func (p *publisher) load() {
	if p.loaded {
		return
	}
	p.loaded = true
	p.open = map[string]openFinding{}
	if p.path == "" {
		return
	}
	if raw, err := os.ReadFile(p.path); err == nil {
		if json.Unmarshal(raw, &p.open) != nil {
			p.open = map[string]openFinding{}
		}
	}
}

func (p *publisher) save() {
	if p.path == "" {
		return
	}
	raw, err := json.Marshal(p.open)
	if err != nil {
		return
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		logging.Logf("[mailtraffic] abuse state not saved: %v", err)
		return
	}
	if err := os.Rename(tmp, p.path); err != nil {
		logging.Logf("[mailtraffic] abuse state not saved: %v", err)
	}
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 2
	case "warning":
		return 1
	}
	return 0
}

// openKeys lists the findings currently open.
func (p *publisher) openKeys() map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load()
	out := make(map[string]bool, len(p.open))
	for k := range p.open {
		out[k] = true
	}
	return out
}

// apply publishes what is new or worse, and resolves what is over.
func (p *publisher) apply(fs []abuseFinding, recent map[string]int64, now time.Time) {
	p.applyHeld(fs, recent, nil, now)
}

// applyHeld is apply that leaves the held keys (not judged this check) as
// they are.
func (p *publisher) applyHeld(fs []abuseFinding, recent map[string]int64, held map[string]bool, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.load()
	current := map[string]bool{}
	for _, f := range fs {
		current[f.Key] = true
		prev, seen := p.open[f.Key]
		if seen && sevRank(f.Severity) <= sevRank(prev.Severity) {
			continue // still open, no worse: nothing new to say
		}
		if !publish(f.Type, f.Severity, f.Key, f.Message, now) {
			continue // no sink yet: retried next check
		}
		exp := f.Expected
		if seen {
			exp = prev.Expected // keep the baseline from before the incident
		}
		p.open[f.Key] = openFinding{Type: f.Type, Severity: f.Severity, Message: f.Message, Expected: exp}
	}
	for key, o := range p.open {
		if current[key] || held[key] {
			continue
		}
		n := recent[key]
		spike := o.Type == TypeScriptSpike || o.Type == TypeOutboundSpike
		if spike && n >= anomalySpikeFloor && float64(n) > math.Max(o.Expected*abuseCloseFactor, 0) {
			continue // the ratio fell (the incident became its own baseline) but the volume did not
		}
		var msg string
		switch o.Type {
		case TypeHijack:
			msg = "no more logins from many places — still change the password (was: " + o.Message + ")"
		case TypeBounceSpike:
			msg = "bounces back to normal (was: " + o.Message + ")"
		case TypeQueueHog:
			msg = "no longer filling the queue (was: " + o.Message + ")"
		case TypeRBLListed:
			msg = "no longer listed (was: " + o.Message + ")"
		default:
			msg = fmt.Sprintf("back to normal, %d in %dh (was: %s)", n, anomalyRecentHours, o.Message)
		}
		msg = clip(msg)
		if publish(TypeRecovered, "info", key, msg, now) {
			delete(p.open, key)
		}
	}
	p.save()
}
