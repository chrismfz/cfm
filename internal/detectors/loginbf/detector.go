// Package loginbf is the login_bruteforce detector: it turns the login
// ledger's failed logins (webdetector.SubscribeLoginFailEvents) into an nft
// ban through the shared section sink, which owns the block policy, the
// leniency tier (GR/CY), the edge ban, the central API report and the mail.
//
// Two rules, per client, over one sliding WINDOW (1 h by default):
//
//   - SITE_FAILS: that many failed logins on ONE site (a registrable domain:
//     www., staging. and the bare name are one site);
//   - SITES: failed logins on that many DIFFERENT sites, any number on each.
//     A proxy pool spreads a spray as one or two tries per site per address,
//     which no per-site count ever sees (virgo, 1-6 Nov 2026: 1 363
//     site-hours of 10+ addresses with fewer than 5 failures each).
//
// A client is an IPv4 address or an IPv6 /64 (one subscriber, who can
// rotate addresses inside it); the ban is on the address that failed.
//
// Never banned:
//   - a failure on a site where the client is its owner (the ledger's
//     record: it failed there and already succeeded at least as often), a
//     site's own tool;
//   - a private, loopback, link-local or CGNAT address;
//   - an address of ALLOW_ASNS: a reverse proxy CFM does not trust to name
//     the client (Sucuri, Imperva, Fastly, ...) reads as one client for all
//     its visitors, and a 90 day ban reported to the fleet would take every
//     site behind it down;
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
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

// Kind is the alert kind (and the nft comment's first part).
const Kind = core.AlertKind("WEB/LOGIN_BRUTEFORCE")

type Config struct {
	Every     time.Duration
	Window    time.Duration
	SiteFails int // failures on one site within Window; 0 turns the rule off
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

// Event is one failed login.
type Event struct {
	When  time.Time
	IP    string
	Host  string
	Site  string
	Tag   string
	Owner bool
}

type fail struct {
	at   int64
	ip   string
	site string
	host string
	tag  string
}

type client struct {
	fails []fail // within the window
	last  int64
	// firedAt is the newest failure an alert already covered: only later
	// failures count toward the next one. A banned client sends none; a
	// lenient one (a 10 minute ban) that keeps failing is banned again.
	firedAt int64
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
	for _, s := range cfg.AllowASNs {
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
	if ev.Owner {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ev.IP))
	if err != nil {
		return
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || cgnat.Contains(addr) || d.allowed(addr) {
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
		if a, ok := d.addLocked(ev, win); ok {
			alerts = append(alerts, a)
		}
	}
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
	c.fails = append(c.fails, fail{at: at, ip: ev.IP, site: ev.Site, host: ev.Host, tag: ev.Tag})
	if len(c.fails) > maxEventsPerIP {
		sort.Slice(c.fails, func(i, j int) bool { return c.fails[i].at < c.fails[j].at })
		c.fails = append(c.fails[:0], c.fails[len(c.fails)-maxEventsPerIP:]...)
	}

	onSite := 0
	sites := map[string]int{}
	for _, f := range c.fails {
		if f.at <= c.firedAt {
			continue
		}
		sites[f.site]++
		if f.site == ev.Site {
			onSite++
		}
	}
	rule := ""
	switch {
	case d.cfg.SiteFails > 0 && onSite >= d.cfg.SiteFails:
		rule = "site"
	case d.cfg.Sites > 0 && len(sites) >= d.cfg.Sites:
		rule = "sites"
	}
	if rule == "" {
		return core.Alert{}, false
	}
	a := d.alert(ev, key, c, rule, onSite, sites)
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
		samples = append(samples, fmt.Sprintf("%s %s failed %s login on %s",
			time.Unix(f.at, 0).UTC().Format(time.RFC3339), f.ip, f.tag, f.host))
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
