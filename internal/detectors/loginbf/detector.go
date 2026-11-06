// Package loginbf is the login_bruteforce detector: it turns the login
// ledger's failed logins (webdetector.SubscribeLoginFailEvents) into an nft
// ban through the shared section sink, which owns the block policy, the
// leniency tier (GR/CY), the edge ban, the central API report and the mail.
//
// Two rules, per client address, over one sliding WINDOW (1 h by default):
//
//   - SITE_FAILS: that many failed logins on ONE site (a registrable domain:
//     www., staging. and the bare name are one site);
//   - SITES: failed logins on that many DIFFERENT sites, any number on each.
//     A proxy pool spreads a spray as one or two tries per site per address,
//     which no per-site count ever sees (virgo, 1-6 Nov 2026: 1 363
//     site-hours of 10+ addresses with fewer than 5 failures each).
//
// A failure on a site where the client is its owner (the ledger's record: it
// already succeeded there at least as often as it failed) counts toward
// neither rule: a site's own tool logs in all day and sometimes fails.
//
// docs/DETECTORS.md "login_bruteforce" and docs/webdetector-signals-v2.md.
package loginbf

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
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

	// MaxClients bounds the tracked addresses; the ones idle longest go
	// first when it is reached. 0 means DefaultMaxClients.
	MaxClients int
}

const (
	DefaultMaxClients = 100000
	maxEventsPerIP    = 128 // a client past this many failures in a window has long tripped a rule
	maxQueue          = 200000
	sampleLines       = 10
)

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
	site string
	host string
	tag  string
}

type client struct {
	fails []fail // oldest first, within the window
	last  int64
	// firedAt is the newest failure an alert already covered: only later
	// failures count toward the next one. A banned client sends none; a
	// lenient one (a 10 minute ban) that keeps failing is banned again.
	firedAt int64
}

type Detector struct {
	cfg  Config
	name string

	allowIPs  map[string]struct{}
	allowNets []*net.IPNet

	qmu     sync.Mutex
	queue   []Event
	dropped int

	mu      sync.Mutex
	clients map[string]*client

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
		cfg:      cfg,
		allowIPs: map[string]struct{}{},
		clients:  map[string]*client{},
		now:      time.Now,
	}
	for _, ip := range cfg.AllowIPs {
		if ip = strings.TrimSpace(ip); ip != "" {
			d.allowIPs[ip] = struct{}{}
		}
	}
	for _, cidr := range cfg.AllowNets {
		if cidr = strings.TrimSpace(cidr); cidr == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			d.allowNets = append(d.allowNets, n)
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
	if ev.IP == "" || ev.Owner {
		return
	}
	if d.allowed(ev.IP) {
		return
	}
	if ev.When.IsZero() {
		ev.When = d.now()
	}
	// The strings can be slices of the edge's log line; keep copies only.
	ev.IP, ev.Host, ev.Site, ev.Tag = strings.Clone(ev.IP), strings.Clone(ev.Host), strings.Clone(ev.Site), strings.Clone(ev.Tag)
	d.qmu.Lock()
	if len(d.queue) >= maxQueue {
		d.dropped++
	} else {
		d.queue = append(d.queue, ev)
	}
	d.qmu.Unlock()
}

func (d *Detector) allowed(ipStr string) bool {
	if _, ok := d.allowIPs[ipStr]; ok {
		return true
	}
	if len(d.allowNets) == 0 {
		return false
	}
	if ip := net.ParseIP(ipStr); ip != nil {
		for _, n := range d.allowNets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	d.qmu.Lock()
	batch := d.queue
	d.queue = nil
	d.dropped = 0
	d.qmu.Unlock()

	win := int64(d.cfg.Window / time.Second)
	if win <= 0 {
		win = 1
	}
	now := d.now()
	var alerts []core.Alert
	d.mu.Lock()
	for _, ev := range batch {
		if a, ok := d.addLocked(ev, win); ok {
			alerts = append(alerts, a)
		}
	}
	d.pruneLocked(now.Unix(), win)
	d.mu.Unlock()

	for _, a := range alerts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- a:
		}
	}
	return nil
}

func (d *Detector) addLocked(ev Event, win int64) (core.Alert, bool) {
	at := ev.When.Unix()
	c := d.clients[ev.IP]
	if c == nil {
		if len(d.clients) >= d.cfg.MaxClients {
			d.evictLocked()
		}
		c = &client{}
		d.clients[ev.IP] = c
	}
	if at > c.last {
		c.last = at
	}
	// The window ends at the newest failure seen: a batch that arrives late
	// (the edge ships lines in batches) still counts against its own time.
	c.fails = append(c.fails, fail{at: at, site: ev.Site, host: ev.Host, tag: ev.Tag})
	cut := c.last - win
	i := 0
	for i < len(c.fails) && c.fails[i].at <= cut {
		i++
	}
	if i > 0 {
		c.fails = append(c.fails[:0], c.fails[i:]...)
	}
	if len(c.fails) > maxEventsPerIP {
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
	a := d.alert(ev, c, rule, onSite, sites)
	c.firedAt = c.last
	return a, true
}

func (d *Detector) alert(ev Event, c *client, rule string, onSite int, sites map[string]int) core.Alert {
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
	var samples []string
	start := len(c.fails) - sampleLines
	if start < 0 {
		start = 0
	}
	for _, f := range c.fails[start:] {
		samples = append(samples, fmt.Sprintf("%s failed %s login on %s",
			time.Unix(f.at, 0).UTC().Format(time.RFC3339), f.tag, f.host))
	}
	a := core.Alert{
		When:    ev.When,
		Kind:    Kind,
		Key:     ev.IP,
		Count:   len(c.fails),
		Samples: samples,
		Extra: map[string]string{
			"ip":           ev.IP,
			"reason":       reason,
			"rule":         rule,
			"host":         ev.Host,
			"site":         ev.Site,
			"tag":          ev.Tag,
			"site_fails":   fmt.Sprint(onSite),
			"sites_failed": fmt.Sprint(len(sites)),
			"sites":        strings.Join(list, ","),
			"window":       d.cfg.Window.String(),
		},
	}
	if d.cfg.DryRun {
		a.Extra["enforcement"] = "dryrun"
	}
	return a
}

// pruneLocked drops the clients whose last failure left the window.
func (d *Detector) pruneLocked(now, win int64) {
	for ip, c := range d.clients {
		if now-c.last > win {
			delete(d.clients, ip)
		}
	}
}

// evictLocked frees a tenth of the table, the clients idle longest first.
func (d *Detector) evictLocked() {
	type kv struct {
		ip   string
		last int64
	}
	all := make([]kv, 0, len(d.clients))
	for ip, c := range d.clients {
		all = append(all, kv{ip, c.last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last < all[j].last })
	n := len(all) / 10
	if n < 1 {
		n = 1
	}
	for _, e := range all[:n] {
		delete(d.clients, e.ip)
	}
}
