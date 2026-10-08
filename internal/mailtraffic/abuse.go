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
//     countries within an hour — a stolen password being used.
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
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/enrich"
	"cfm/internal/logging"
)

// Finding types — detection_history event types, so a change here is a wire
// change for cfm-web's ingest.
const (
	TypeScriptSpike   = "mail_script_spike"
	TypeOutboundSpike = "mail_outbound_spike"
	TypeHijack        = "mail_hijack"
	TypeRecovered     = "mail_recovered"
)

const (
	abuseEvalEvery = 5 * time.Minute
	// a hijack: one mailbox authenticated from this many countries, or this
	// many distinct IPs, within hijackWindow.
	hijackWindow       = time.Hour
	hijackMinCountries = 3
	hijackMinIPs       = 10
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

	// countryOf resolves an IP to its ISO country ("" when unknown). A var so
	// tests stub it; the default opens the node's GeoIP databases lazily.
	countryOf = defaultCountryOf
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

func defaultCountryOf(ip string) string {
	geoOnce.Do(func() { geoEnr, _ = enrich.New("/etc/cfm", "/var/lib/cfm/maxmind") })
	if geoEnr == nil {
		return ""
	}
	return geoEnr.LookupGeoFast(ip).CountryISO
}

// ---- per-line context (what the counters don't keep) ----

type localSample struct {
	at    time.Time
	cwd   string
	from  string
	rcpts []string
}

type tracker struct {
	mu         sync.Mutex
	line       int
	pendingCwd string
	pendingAt  int
	local      map[string][]localSample        // unix user → recent local submissions
	authIPs    map[string]map[string]time.Time // mailbox → source IP → last successful auth
}

func newTracker() *tracker {
	return &tracker{local: map[string][]localSample{}, authIPs: map[string]map[string]time.Time{}}
}

var (
	// `<date> <time> [pid] cwd=/home/u/public_html 4 args: /usr/sbin/sendmail -t -i -f…`
	reCwdLine = regexp.MustCompile(`\scwd=(\S+)\s+\d+\s+args:`)
	reLogTime = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)`)
	reFrom    = regexp.MustCompile(`\s<=\s(\S+)`)
	reHostIP  = regexp.MustCompile(`\bH=[^\[]*\[([0-9a-fA-F:.]+)\]`)
	// Postfix submission: `client=host[ip], sasl_method=PLAIN, sasl_username=user`
	rePostfixAuth = regexp.MustCompile(`client=[^\[]*\[([0-9a-fA-F:.]+)\].*\bsasl_username=([^\s,]+)`)
)

func logTime(line string, now time.Time) time.Time {
	if m := reLogTime.FindStringSubmatch(line); m != nil {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local); err == nil {
			return t
		}
	}
	return now
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
	if !strings.Contains(line, " <= ") {
		return
	}
	at := logTime(line, now)
	if m := reEximLocalUser.FindStringSubmatch(line); m != nil {
		s := localSample{at: at}
		if t.line-t.pendingAt <= 4 { // the cwd line is logged just before its arrival line
			s.cwd = t.pendingCwd
		}
		if f := reFrom.FindStringSubmatch(line); f != nil {
			s.from = strings.ToLower(f[1])
		}
		if i := strings.LastIndex(line, " for "); i >= 0 {
			for _, r := range strings.Fields(line[i+5:]) {
				if strings.Contains(r, "@") {
					s.rcpts = append(s.rcpts, strings.ToLower(r))
				}
			}
		}
		t.addLocal(m[1], s)
		return
	}
	if m := reEximAuthed.FindStringSubmatch(line); m != nil {
		if ip := reHostIP.FindStringSubmatch(line); ip != nil {
			t.addAuth(strings.ToLower(m[1]), ip[1], at)
		}
	}
}

// observeMaillog takes one syslog maillog line (Postfix submissions).
func (t *tracker) observeMaillog(line string, now time.Time) {
	m := rePostfixAuth.FindStringSubmatch(line)
	if m == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.addAuth(strings.ToLower(m[2]), m[1], now)
}

var (
	reEximLocalUser = regexp.MustCompile(`\bU=([^\s]+)\s+P=local\b`)
	reEximAuthed    = regexp.MustCompile(`\bP=esmtps?a\b.*\bA=[^:\s]+:([^\s]+)`)
)

func (t *tracker) addLocal(user string, s localSample) {
	if _, ok := t.local[user]; !ok && len(t.local) >= maxTrackedUsers {
		return
	}
	ss := append(t.local[user], s)
	if len(ss) > maxSamples {
		ss = ss[len(ss)-maxSamples:]
	}
	t.local[user] = ss
}

func (t *tracker) addAuth(user, ip string, at time.Time) {
	ips := t.authIPs[user]
	if ips == nil {
		if len(t.authIPs) >= maxTrackedUsers {
			return
		}
		ips = map[string]time.Time{}
		t.authIPs[user] = ips
	}
	if _, ok := ips[ip]; !ok && len(ips) >= maxTrackedIPs {
		return
	}
	ips[ip] = at
}

// prune drops context older than the windows it is read over.
func (t *tracker) prune(now time.Time) {
	for u, ss := range t.local {
		i := 0
		for i < len(ss) && now.Sub(ss[i].at) > contextWindow {
			i++
		}
		if i == len(ss) {
			delete(t.local, u)
		} else {
			t.local[u] = ss[i:]
		}
	}
	for u, ips := range t.authIPs {
		for ip, at := range ips {
			if now.Sub(at) > hijackWindow {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(t.authIPs, u)
		}
	}
}

// localContext summarises a user's recent local submissions for a message.
func (t *tracker) localContext(user string) (cwd, from string, rcpts int) {
	cwds, froms := map[string]int{}, map[string]int{}
	seen := map[string]bool{}
	for _, s := range t.local[user] {
		if s.cwd != "" {
			cwds[s.cwd]++
		}
		if s.from != "" {
			froms[s.from]++
		}
		for _, r := range s.rcpts {
			seen[r] = true
		}
	}
	return topKey(cwds), topKey(froms), len(seen)
}

func topKey(m map[string]int) string {
	best, n := "", 0
	for k, v := range m {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

// ---- evaluation ----

type abuseFinding struct {
	Type, Severity, Key, Message string
	Expected                     float64 // the spike's expected volume when it opened
}

// evaluate returns this check's findings, plus each spike key's recent volume
// (for closing spikes against their opening baseline). ok=false when the store
// could not be read: nothing should change on such a check.
func (t *tracker) evaluate(st *Store, now time.Time) (fs []abuseFinding, recent map[string]int64, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune(now)
	recent = map[string]int64{}

	out, outRecent, err := st.anomalyScan(now, nil, "outbound")
	if err != nil {
		return nil, nil, false
	}
	loc, locRecent, err := st.anomalyScan(now, nil, "local_sub")
	if err != nil {
		return nil, nil, false
	}
	for a, n := range outRecent {
		recent["mail:out:"+a] = n
	}
	for a, n := range locRecent {
		recent["mail:script:"+a] = n
	}

	for _, a := range loc {
		if systemLocalUsers[a.Addr] {
			continue
		}
		cwd, from, rcpts := t.localContext(a.Addr)
		msg := fmt.Sprintf("%s: %d messages sent by scripts in %dh (%s)", a.Addr, a.Recent, anomalyRecentHours, usual(a))
		if cwd != "" {
			msg += " · from " + cwd
		}
		if from != "" {
			msg += " · as " + from
			if foreignSender(from) {
				msg += " (not a domain on this server)"
			}
		}
		if rcpts > 0 {
			msg += fmt.Sprintf(" · %d different recipients", rcpts)
		}
		fs = append(fs, abuseFinding{Type: TypeScriptSpike, Severity: spikeSeverity(a), Key: "mail:script:" + a.Addr, Message: clip(msg), Expected: expectedOf(a)})
	}
	hijacked := map[string]bool{}
	for user, ips := range t.authIPs {
		countries := map[string]bool{}
		for ip := range ips {
			if c := countryOf(ip); c != "" {
				countries[c] = true
			}
		}
		if len(countries) < hijackMinCountries && len(ips) < hijackMinIPs {
			continue
		}
		hijacked[user] = true
		fs = append(fs, abuseFinding{Type: TypeHijack, Severity: "critical", Key: "mail:hijack:" + user,
			Message: clip(fmt.Sprintf("%s: authenticated from %d IPs in %d countries (%s) within an hour — likely a stolen password",
				user, len(ips), len(countries), strings.Join(sortedKeys(countries), ", ")))})
	}
	for _, a := range out {
		msg := fmt.Sprintf("%s: %d authenticated messages in %dh (%s)", a.Addr, a.Recent, anomalyRecentHours, usual(a))
		if ips := t.authIPs[a.Addr]; len(ips) > 1 && !hijacked[a.Addr] {
			msg += fmt.Sprintf(" · from %d IPs", len(ips))
		}
		fs = append(fs, abuseFinding{Type: TypeOutboundSpike, Severity: spikeSeverity(a), Key: "mail:out:" + a.Addr, Message: clip(msg), Expected: expectedOf(a)})
	}
	return fs, recent, true
}

func usual(a Anomaly) string {
	if a.Kind == "new-sender" {
		return "it rarely sends mail"
	}
	return fmt.Sprintf("usually %.1f/h, %.0f× that", a.BaselinePerHour, a.Ratio)
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

// apply publishes what is new or worse, and resolves what is over.
func (p *publisher) apply(fs []abuseFinding, recent map[string]int64, now time.Time) {
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
		if current[key] {
			continue
		}
		n := recent[key]
		if o.Type != TypeHijack && n >= anomalySpikeFloor && float64(n) > math.Max(o.Expected*abuseCloseFactor, 0) {
			continue // the ratio fell (the incident became its own baseline) but the volume did not
		}
		msg := clip("back to normal (was: " + o.Message + ")")
		if o.Type != TypeHijack {
			msg = clip(fmt.Sprintf("back to normal, %d in %dh (was: %s)", n, anomalyRecentHours, o.Message))
		}
		if publish(TypeRecovered, "info", key, msg, now) {
			delete(p.open, key)
		}
	}
	p.save()
}
