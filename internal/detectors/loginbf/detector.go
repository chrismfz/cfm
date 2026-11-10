// Package loginbf is the login_bruteforce detector: it turns the login
// ledger's failed logins (webdetector.SubscribeLoginEvents) into an nft
// ban through the shared section sink, which owns the block policy, the
// leniency tier (GR/CY), the edge ban, the central API report and the mail.
//
// Two rules, per client, over one sliding WINDOW (1 h by default):
//
//   - SITE_FAILS: that many failed logins on ONE site (a registrable domain:
//     www., staging. and the bare name are one site); a lostpassword /
//     register form shown again counts a third (Event.Form);
//   - SITES: failed logins on that many DIFFERENT sites, any number on each.
//     A proxy pool spreads a spray as one or two tries per site per address,
//     which no per-site count ever sees (virgo, 1-6 Nov 2026: 1 363
//     site-hours of 10+ addresses with fewer than 5 failures each).
//
// A client is an IPv4 address or an IPv6 /64 (one subscriber, who can
// rotate addresses inside it); the ban is on the /64's address with the
// most failures in the window, not on whichever failed last: in an office
// /64 a colleague's one typo must not take the ban for another's spray. When
// several addresses failed, the worst one needs 2 failures, and on the
// one-site rule more than half of SITE_FAILS on that site, or the alert only
// logs (ipv6_ambiguous); a second such alert within WINDOW (an attacker
// alternating two addresses) bans it.
//
// A success takes back up to RetractMax of the client's latest failures on
// that site in the last RetractWindow, and a failure counts only once it is
// Grace old, so the success arrives first: a 2FA plugin that sends no cookie on the password step (Two
// Factor 0.8+) shows its second-factor form as a failure, and the success
// after it is the same login. A typo then a success is not brute force
// either. Only a real success (the site's logged-in cookie) does it.
//
// Never banned:
//   - a failure on a site where the client is its owner (the ledger's
//     record: it failed there and already succeeded at least as often), a
//     site's own tool;
//   - a private, loopback, link-local or CGNAT address;
//   - an address of a trusted proxy (trusted_proxies.conf, Cloudflare): the
//     edge sees one only when the proxy named itself (a Worker's
//     subrequest), and it stands for every visitor arriving that way;
//   - an address of ALLOW_ASNS: a reverse proxy CFM does not trust to name
//     the client (Sucuri, Imperva, Fastly, ...) reads as one client for all
//     its visitors, and a 3 day ban reported to the fleet would take every
//     site behind it down. Cloudflare is not listed by ASN: its ASN is also
//     WARP's egress, which an attacker can use (the shipped leniency gives
//     AS13335 the 10 minute local tier instead: a WARP address is shared). (Workers come in from the
//     trusted ranges above and are exempt: a known gap.)
//   - an address with no geo record (no database yet, ENRICH = 0): the
//     GR/CY leniency cannot be decided, so the alert is a dry run.
//
// docs/DETECTORS.md "login_bruteforce" and docs/webdetector-signals-v2.md.
package loginbf

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/edgeban"
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

// Kind is the alert kind (and the nft comment's first part).
const Kind = core.AlertKind("WEB/LOGIN_BRUTEFORCE")

type Config struct {
	Every     time.Duration
	Window    time.Duration
	SiteFails int // failures on one site within Window (a Form one counts a third); 0 turns the rule off
	Sites     int // distinct failed sites within Window; 0 turns the rule off
	DryRun    bool

	AllowIPs  []string
	AllowNets []string
	AllowASNs []string // "AS30148" or "30148"

	// MaxClients bounds the tracked clients; the ones idle longest go
	// first when it is reached. 0 means DefaultMaxClients.
	MaxClients int
}

const (
	DefaultMaxClients = 100000
	maxEventsPerIP    = 128 // a client past this many failures in a window has long tripped a rule
	maxQueue          = 200000
	sampleLines       = 10
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Event is one failed login, or a success (OK).
type Event struct {
	When  time.Time
	IP    string
	Host  string
	Site  string
	Tag   string
	OK    bool
	Owner bool
	// Form: a lostpassword / register form shown again, or a login hidden
	// behind that query (webdetector.LoginEvent.Form): a third of a failure on
	// the one-site rule.
	Form bool
}

// RetractWindow is how far back a success takes back failures, and
// RetractMax how many: the 2FA password step, and a mistyped code or two.
const (
	RetractWindow = 15 * time.Minute
	RetractMax    = 3
)

// Grace is how long a failure waits before it counts toward a rule, so the
// success that takes it back (a 2FA code typed a minute later, five client
// sites opened in parallel tabs) arrives first. Brute force loses nothing
// to it.
const Grace = 2 * time.Minute

type fail struct {
	at   int64
	ip   string
	site string
	host string
	tag  string
	form bool
}

type client struct {
	fails []fail // within the window
	last  int64
	// firedAt is the newest failure an alert already covered: only later
	// failures count toward the next one. A banned client sends none; a
	// lenient one (a 10 minute ban) that keeps failing is banned again.
	firedAt int64
	// quietUntil: under DRY_RUN a client is never banned, so it keeps
	// failing; one would-be ban per client per WINDOW, or the burn-in's
	// counts (and mail) would be many times what armed mode does.
	quietUntil int64
	// ambigAt: the last alert held as ipv6_ambiguous because the /64's worst
	// address had at least 2 failures but not more than half of SITE_FAILS.
	// A second one within WINDOW bans that address.
	ambigAt int64
}

type geoLookup interface {
	LookupGeoFast(ip string) enrich.Result
}

type Detector struct {
	cfg  Config
	name string

	allowIPs  map[netip.Addr]struct{}
	allowNets []netip.Prefix
	allowASNs map[uint]struct{}

	qmu     sync.Mutex
	queue   []Event
	dropped int

	pending []Event // failures inside Grace, under mu

	mu      sync.Mutex
	clients map[string]*client
	newest  int64 // the newest failure seen: the clock the window prunes on

	gmu sync.RWMutex
	geo geoLookup

	unmu  sync.Mutex
	unsub []func()

	now func() time.Time
}

func New(cfg Config) *Detector {
	if cfg.Every <= 0 {
		cfg.Every = 10 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Hour
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = DefaultMaxClients
	}
	d := &Detector{
		cfg:       cfg,
		allowIPs:  map[netip.Addr]struct{}{},
		allowASNs: map[uint]struct{}{},
		clients:   map[string]*client{},
		now:       time.Now,
	}
	for _, s := range cfg.AllowIPs {
		if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			d.allowIPs[a.Unmap()] = struct{}{}
		}
	}
	for _, s := range cfg.AllowNets {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			d.allowNets = append(d.allowNets, p.Masked())
		}
	}
	var asns []string
	for _, s := range cfg.AllowASNs {
		asns = append(asns, strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		})...)
	}
	for _, s := range asns {
		s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS")
		if n, err := strconv.ParseUint(s, 10, 32); err == nil && n > 0 {
			d.allowASNs[uint(n)] = struct{}{}
		}
	}
	return d
}

func (d *Detector) SetName(name string) { d.name = name }
func (d *Detector) Name() string {
	if d.name != "" {
		return d.name
	}
	return "login_bruteforce"
}
func (d *Detector) Every() time.Duration { return d.cfg.Every }

// DryRun reports whether every alert is a dry run (DRY_RUN).
func (d *Detector) DryRun() bool { return d.cfg.DryRun }

// SetEnricher is called by the manager with the node's geo database.
func (d *Detector) SetEnricher(e *enrich.Enricher) {
	if e == nil {
		return
	}
	d.setGeo(e)
}

func (d *Detector) setGeo(g geoLookup) {
	d.gmu.Lock()
	d.geo = g
	d.gmu.Unlock()
}

func (d *Detector) AddUnsubscribe(fn func()) {
	if fn == nil {
		return
	}
	d.unmu.Lock()
	d.unsub = append(d.unsub, fn)
	d.unmu.Unlock()
}

// Shutdown drops the event subscription (a config reload builds a new
// detector; the old one must stop receiving).
func (d *Detector) Shutdown() error {
	d.unmu.Lock()
	unsub := d.unsub
	d.unsub = nil
	d.unmu.Unlock()
	for _, fn := range unsub {
		fn()
	}
	return nil
}

// Enqueue takes one failed login. It runs on the ingest path: it only
// appends, bounded, and the work happens in RunOnce.
func (d *Detector) Enqueue(ev Event) {
	if ev.Owner && !ev.OK {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ev.IP))
	if err != nil {
		return
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || cgnat.Contains(addr) || d.allowed(addr) ||
		edgeban.IsTrustedProxy(addr.AsSlice()) {
		return
	}
	if ev.When.IsZero() {
		ev.When = d.now()
	}
	// Canonical form (the ban key), and copies: the strings can be slices
	// of the edge's log line.
	ev.IP = addr.String()
	ev.Host, ev.Site, ev.Tag = strings.Clone(ev.Host), strings.Clone(ev.Site), strings.Clone(ev.Tag)
	d.qmu.Lock()
	if len(d.queue) >= maxQueue {
		d.dropped++
	} else {
		d.queue = append(d.queue, ev)
	}
	d.qmu.Unlock()
}

func (d *Detector) allowed(a netip.Addr) bool {
	if _, ok := d.allowIPs[a]; ok {
		return true
	}
	for _, p := range d.allowNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// clientKey is the address, or its /64 for IPv6.
func clientKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is4() {
		return ip
	}
	p, _ := a.Prefix(64)
	return p.String()
}

func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	d.qmu.Lock()
	batch := d.queue
	d.queue = nil
	dropped := d.dropped
	d.dropped = 0
	d.qmu.Unlock()
	if dropped > 0 {
		logging.Logf("[detectors] %s: queue full, %d failed logins dropped", d.Name(), dropped)
	}

	win := int64(d.cfg.Window / time.Second)
	if win <= 0 {
		win = 1
	}
	var alerts []core.Alert
	d.mu.Lock()
	for _, ev := range batch {
		if at := ev.When.Unix(); at > d.newest {
			d.newest = at
		}
		if ev.OK {
			// Pending failures first (the usual case: the 2FA step), then
			// counted ones.
			n := d.retractPendingLocked(ev, RetractMax)
			d.retractLocked(clientKey(ev.IP), ev, ev.When.Unix(), RetractMax-n)
			continue
		}
		d.pending = append(d.pending, ev)
	}
	// A failure counts once it is Grace old, by the newest line or the wall
	// (no line for a while), or at once when the pending set is too large.
	clock := d.newest
	if w := d.now().Unix(); w > clock {
		clock = w
	}
	cutoff := clock - int64(Grace/time.Second)
	kept := d.pending[:0]
	for i, ev := range d.pending {
		if ev.When.Unix() <= cutoff || len(d.pending)-i > maxQueue {
			if a, ok := d.addLocked(ev, win); ok {
				alerts = append(alerts, a)
			}
			continue
		}
		kept = append(kept, ev)
	}
	d.pending = kept
	d.pruneLocked(win)
	d.mu.Unlock()

	for _, a := range alerts {
		d.gate(&a)
		if a.Extra == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- a:
		}
	}
	return nil
}

// gate applies the geo-based exemptions: it drops an ALLOW_ASNS address
// (Extra set to nil) and turns an alert whose address has no geo record
// into a dry run.
func (d *Detector) gate(a *core.Alert) {
	d.gmu.RLock()
	g := d.geo
	d.gmu.RUnlock()
	var r enrich.Result
	if g != nil {
		r = g.LookupGeoFast(a.Extra["ip"])
	}
	if _, ok := d.allowASNs[r.ASN]; ok && r.ASN != 0 {
		logging.LogfDETECTOR("[detectors] %s: %s not banned: AS%d (%s) is in ALLOW_ASNS", d.Name(), a.Extra["ip"], r.ASN, r.ASNName)
		a.Extra = nil
		return
	}
	if r.CountryISO == "" && r.Country == "" {
		// The GR/CY leniency is decided on the country: without one, a
		// Greek customer would get the full ban and a fleet report.
		a.Extra["enforcement"] = "dryrun"
		a.Extra["geo"] = "unknown"
	}
}

func (d *Detector) addLocked(ev Event, win int64) (core.Alert, bool) {
	at := ev.When.Unix()
	if at > d.newest {
		d.newest = at
	}
	key := clientKey(ev.IP)
	c := d.clients[key]
	if c == nil {
		if len(d.clients) >= d.cfg.MaxClients {
			d.evictLocked()
		}
		c = &client{}
		d.clients[key] = c
	}
	if at > c.last {
		c.last = at
	}
	// The window ends at the client's newest failure. Lines can arrive out
	// of order (the edge ships them in batches), so every one is checked.
	cut := c.last - win
	kept := c.fails[:0]
	for _, f := range c.fails {
		if f.at > cut {
			kept = append(kept, f)
		}
	}
	c.fails = kept
	if at <= cut {
		return core.Alert{}, false // older than the window: too late to count
	}
	c.fails = append(c.fails, fail{at: at, ip: ev.IP, site: ev.Site, host: ev.Host, tag: ev.Tag, form: ev.Form})
	if len(c.fails) > maxEventsPerIP {
		sort.Slice(c.fails, func(i, j int) bool { return c.fails[i].at < c.fails[j].at })
		c.fails = append(c.fails[:0], c.fails[len(c.fails)-maxEventsPerIP:]...)
	}

	// onSite3 is three times the failures on this site: a Form failure
	// counts 1, a login 3. On gacbp.com (2026-11-08) a Greek customer failed
	// twice, then asked for a reset four times with the wrong address: 6
	// "failures", 3.3 now, under SITE_FAILS = 4.
	onSite3, onSite, onSiteForm := 0, 0, 0
	siteW := map[string]int{} // weight per site, a login 3, a form 1
	for _, f := range c.fails {
		if f.at <= c.firedAt {
			continue
		}
		siteW[f.site] += failWeight(f)
		if f.site == ev.Site {
			onSite++
			onSite3 += failWeight(f)
			if f.form {
				onSiteForm++
			}
		}
	}
	// A site counts toward SITES with one failed login, or three forms: a
	// customer asking three of their sites for a reset is no spray.
	sites := map[string]int{}
	for s, w := range siteW {
		if w >= 3 {
			sites[s] = w
		}
	}
	rule := ""
	switch {
	case d.cfg.SiteFails > 0 && onSite3 >= 3*d.cfg.SiteFails:
		rule = "site"
	case d.cfg.Sites > 0 && len(sites) >= d.cfg.Sites:
		rule = "sites"
	}
	if rule == "" {
		return core.Alert{}, false
	}
	if d.cfg.DryRun && at < c.quietUntil {
		c.firedAt = c.last
		return core.Alert{}, false
	}
	if d.cfg.DryRun {
		c.quietUntil = at + win
	}
	a := d.alert(ev, key, c, rule, onSite, sites)
	if onSiteForm > 0 && rule == "site" {
		// Say how many were reset / register forms (a third each): what an
		// unblock request needs to see.
		a.Extra["site_form_fails"] = strconv.Itoa(onSiteForm)
		a.Extra["reason"] = fmt.Sprintf("%d failed %s logins and %d failed lostpassword / register forms (a third each) on %s in %s",
			onSite-onSiteForm, ev.Tag, onSiteForm, ev.Site, d.cfg.Window)
	}
	// On the one-site rule the /64's addresses are weighed on that site only.
	scope := ""
	if rule == "site" {
		scope = ev.Site
	}
	if ip, worst, addrs := worstAddr(c.fails, c.firedAt, scope); ip != "" {
		a.Key, a.Extra["ip"] = ip, ip
		// Several addresses of one /64 and the worst one alone did not get
		// near the rule: nothing says which is the attacker (a VPS provider's
		// shared /64, a rotating client, two colleagues in an office /64 who
		// mistyped twice each at SITE_FAILS = 4). Logged, never banned. The
		// worst address needs more than half of SITE_FAILS on the rule's
		// site, and 2 failures either way, weighed as the rule weighs them
		// (worst is in thirds: a login 3, a form 1).
		need := 2
		if rule == "site" && d.cfg.SiteFails/2+1 > need {
			need = d.cfg.SiteFails/2 + 1
		}
		switch {
		case addrs > 1 && worst < 2*3:
			a.Extra["enforcement"] = "dryrun"
			a.Extra["ipv6_ambiguous"] = "1"
		case addrs > 1 && worst < need*3:
			// Colleagues do not do it twice in one window; an attacker
			// alternating two addresses of its /64 does, every round.
			if c.ambigAt > 0 && at-c.ambigAt < win {
				a.Extra["ipv6_ambiguous_repeat"] = "1"
			} else {
				a.Extra["enforcement"] = "dryrun"
				a.Extra["ipv6_ambiguous"] = "1"
				c.ambigAt = at
			}
		}
	}
	c.firedAt = c.last
	return a, true
}

func (d *Detector) alert(ev Event, key string, c *client, rule string, onSite int, sites map[string]int) core.Alert {
	names := make([]string, 0, len(sites))
	for s := range sites {
		names = append(names, s)
	}
	sort.Strings(names)
	list := names
	if len(list) > 10 {
		list = list[:10]
	}
	reason := fmt.Sprintf("%d failed %s logins on %s in %s", onSite, ev.Tag, ev.Site, d.cfg.Window)
	if rule == "sites" {
		reason = fmt.Sprintf("failed logins on %d sites in %s", len(sites), d.cfg.Window)
	}
	fails := append([]fail(nil), c.fails...)
	sort.Slice(fails, func(i, j int) bool { return fails[i].at < fails[j].at })
	if len(fails) > sampleLines {
		fails = fails[len(fails)-sampleLines:]
	}
	var samples []string
	for _, f := range fails {
		what := "login"
		if f.form {
			what = "form (lostpassword / register)"
		}
		samples = append(samples, fmt.Sprintf("%s %s failed %s %s host=%s",
			time.Unix(f.at, 0).UTC().Format(time.RFC3339), f.ip, f.tag, what, f.host))
	}
	a := core.Alert{
		When:    ev.When,
		Kind:    Kind,
		Key:     ev.IP,
		Count:   len(c.fails),
		Samples: samples,
		Extra: map[string]string{
			"ip":           ev.IP,
			"client":       key,
			"reason":       reason,
			"rule":         rule,
			"host":         ev.Host,
			"site":         ev.Site,
			"tag":          ev.Tag,
			"site_fails":   strconv.Itoa(onSite),
			"sites_failed": strconv.Itoa(len(sites)),
			"sites":        strings.Join(list, ","),
			"window":       d.cfg.Window.String(),
		},
	}
	if d.cfg.DryRun {
		a.Extra["enforcement"] = "dryrun"
	}
	return a
}

// retractPendingLocked drops up to max of the latest pending failures on
// ev's site from the address that succeeded, within RetractWindow before
// the success, and says how many it dropped.
func (d *Detector) retractPendingLocked(ev Event, max int) int {
	at := ev.When.Unix()
	from := at - int64(RetractWindow/time.Second)
	n := 0
	for i := len(d.pending) - 1; i >= 0 && n < max; i-- {
		p := d.pending[i]
		if p.Site == ev.Site && p.IP == ev.IP && p.When.Unix() >= from && p.When.Unix() <= at {
			d.pending = append(d.pending[:i], d.pending[i+1:]...)
			n++
		}
	}
	return n
}

// retractLocked drops up to max of the client's latest counted failures on
// ev's site from the address that succeeded, within RetractWindow before the
// success.
func (d *Detector) retractLocked(key string, ev Event, at int64, max int) {
	c := d.clients[key]
	if c == nil {
		return
	}
	from := at - int64(RetractWindow/time.Second)
	for n := 0; n < max; n++ {
		best := -1
		for i, f := range c.fails {
			if f.site == ev.Site && f.ip == ev.IP && f.at >= from && f.at <= at && f.at > c.firedAt &&
				(best < 0 || f.at >= c.fails[best].at) {
				best = i
			}
		}
		if best < 0 {
			return
		}
		c.fails = append(c.fails[:best], c.fails[best+1:]...)
	}
}

// worstAddr is the address with the most failures after firedAt, weighed in
// thirds (failWeight; the newest one's on a tie), that weight, and how many
// addresses failed. For IPv4 it is
// the only one.
func worstAddr(fails []fail, after int64, site string) (string, int, int) {
	n := map[string]int{}
	last := map[string]int64{}
	for _, f := range fails {
		if f.at <= after || (site != "" && f.site != site) {
			continue
		}
		n[f.ip] += failWeight(f)
		if f.at > last[f.ip] {
			last[f.ip] = f.at
		}
	}
	best := ""
	for ip, k := range n {
		if best == "" || k > n[best] || (k == n[best] && (last[ip] > last[best] || (last[ip] == last[best] && ip < best))) {
			best = ip
		}
	}
	return best, n[best], len(n)
}

// failWeight is a failure in thirds: a login 3, a lostpassword / register
// form shown again 1 (Event.Form). The rules, the /64 guard and the choice of
// the /64's address all weigh with it.
func failWeight(f fail) int {
	if f.form {
		return 1
	}
	return 3
}

// pruneLocked drops the clients whose last failure left the window. The
// clock is the newest failure seen, not the wall: a backlog read after a
// restart is counted against its own time.
func (d *Detector) pruneLocked(win int64) {
	for k, c := range d.clients {
		if d.newest-c.last > win {
			delete(d.clients, k)
		}
	}
}

// evictLocked frees a tenth of the table, the clients idle longest first.
func (d *Detector) evictLocked() {
	type kv struct {
		key  string
		last int64
	}
	all := make([]kv, 0, len(d.clients))
	for k, c := range d.clients {
		all = append(all, kv{k, c.last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last < all[j].last })
	n := len(all) / 10
	if n < 1 {
		n = 1
	}
	for _, e := range all[:n] {
		delete(d.clients, e.key)
	}
}
