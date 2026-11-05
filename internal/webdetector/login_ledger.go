package webdetector

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"
)

// The login ledger: phase 1 of docs/webdetector-signals-v2.md (§3), SHADOW
// only. It counts the failed logins the edge's login column reports (the
// daemon's outcome, authOutcome: WordPress is the one CMS with a rule so far)
// and writes three kinds of history row. Nothing is blocked, challenged or
// alerted; the rows are for a fleet read (detection_history) that sets the
// thresholds and the action (a sink ban or an edge deny) of phase 2.
//
//   login_spray          one client: >= loginSprayDayFails failed logins on
//                        >= loginSpraySites sites in its 24 h window, or >=
//                        loginBurstHour in an hour, or >= loginHeavyDay in a
//                        day (L1). The slow cross-site sprayer rule 501 never
//                        sees (8 POSTs in 20 s). single_site marks the last
//                        two shapes when only one site saw them (an owner's
//                        app with a stale password looks the same).
//   login_spray_net      one network: >= loginNetFlagged of its clients
//                        flagged by L1 in 24 h, or >= loginNetDayFails
//                        failures from >= loginNetIPs of its clients (L2):
//                        the proxy pools that send a try or two per address.
//   login_dirty_success  a successful login from a client flagged by L1 or
//                        L2 in the last 24 h, or after >= loginOwnFails of
//                        its own failures on that site (L4). Row on the
//                        site's host.
//
// A "client" is an IPv4 address or an IPv6 /64 (one host holds a whole /64,
// so per-address counting let one machine spread its tries); a "network" is
// an IPv4 /24 or an IPv6 /48. A "site" is a registrable domain (example.gr,
// www.example.gr and staging.example.gr are one site, one owner).
//
// Not counted: a client on the bypass list (crawlers, QUIC.cloud) or
// rec.Bypass, which would add every visitor of a CDN-fronted site to the
// CDN node's count. A proxy CFM does not know (Sucuri, a tenant's own) still
// reads as one client: a residual for the fleet read.
//
// Bounded: loginMaxIPs clients and loginMaxNets networks (idle ones evicted
// first, flagged ones last), 8 sites per client, 16 clients per network, and
// a row budget per row type (loginRowsPerMin, the rest counted into the next
// row's `suppressed`), because rows are synchronous inserts into a history
// store whose row cap is shared with every other detector. The ledger is in
// memory: a restart or a config reload (a new Engine) empties it. Tenant
// privacy: a spray row names no site (counts only). Kill switch:
// [webdetector] LOGIN_SIGNALS.

const (
	loginSprayDayFails = 10
	loginSpraySites    = 3
	loginBurstHour     = 20
	loginHeavyDay      = 50
	loginNetFlagged    = 5
	loginNetDayFails   = 30
	loginNetIPs        = 5
	loginOwnFails      = 10
	loginFlagTTL       = int64(24 * 3600)
	loginRowEvery      = int64(6 * 3600) // one spray row per key per 6 h
	loginOKRows        = 4               // dirty-success rows per client per hour
	loginRowsPerMin    = 30              // per row type
	loginRowsBurst     = 60
	loginFutureSkew    = int64(300) // a line stamped further ahead uses the wall clock

	loginMaxIPs     = 100000
	loginMaxNets    = 20000
	loginMaxSites   = 8
	loginMaxNetIPs  = 16
	loginEvictBatch = 1000
)

var loginSignalsOn atomic.Bool

func init() { loginSignalsOn.Store(true) }

// ConfigureLoginSignals applies [webdetector] LOGIN_SIGNALS (every reload).
func ConfigureLoginSignals(on bool) { loginSignalsOn.Store(on) }

// loginWin is a fixed 24 h window plus a sliding one-hour estimate. A line
// older than the current hour (the edge's batches can arrive out of order)
// counts into the current hour: the window never moves back.
type loginWin struct {
	dayStart  int64
	day       uint32
	hourStart int64
	hour      uint32
	prevHour  uint32
}

func (w *loginWin) roll(now int64) {
	if w.dayStart == 0 || now-w.dayStart >= 86400 {
		w.dayStart, w.day = now, 0
	}
	h := now - now%3600
	switch {
	case h <= w.hourStart:
	case h == w.hourStart+3600:
		w.prevHour, w.hour, w.hourStart = w.hour, 0, h
	default:
		w.prevHour, w.hour, w.hourStart = 0, 0, h
	}
}

func (w *loginWin) add(now int64) {
	w.roll(now)
	w.day++
	w.hour++
}

// hourEst is the failures of the last hour: the current hour plus the share
// of the previous one the sliding window still covers.
func (w *loginWin) hourEst(now int64) float64 {
	frac := float64(now-w.hourStart) / 3600
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	return float64(w.hour) + float64(w.prevHour)*(1-frac)
}

type loginSite struct {
	h uint64
	n uint16
}

type loginOK struct {
	h  uint64
	at int64
}

type loginIP struct {
	win     loginWin
	sites   [loginMaxSites]loginSite // reset with the day window
	nsites  uint8
	full    bool // a ninth site was seen
	last    int64
	flagged int64 // flagged by L1 until
	rowAt   int64 // last login_spray row
	oks     [loginOKRows]loginOK
}

func (s *loginIP) site(h uint64) *loginSite {
	for i := 0; i < int(s.nsites); i++ {
		if s.sites[i].h == h {
			return &s.sites[i]
		}
	}
	return nil
}

type loginNet struct {
	win     loginWin
	ips     [loginMaxNetIPs]uint64 // distinct failing clients, day window
	nips    uint8
	flagged [loginMaxNetIPs]uint64 // its clients flagged by L1, day window
	nflag   uint8
	last    int64
	until   int64 // flagged by L2 until
	rowAt   int64
}

func addHash(arr []uint64, n *uint8, h uint64) {
	for i := 0; i < int(*n); i++ {
		if arr[i] == h {
			return
		}
	}
	if int(*n) < len(arr) {
		arr[*n] = h
		*n++
	}
}

type loginBucket struct {
	tokens     float64
	last       int64
	suppressed int
}

type loginLedger struct {
	mu      sync.Mutex
	ips     map[string]*loginIP
	nets    map[string]*loginNet
	budget  map[string]*loginBucket
	emit    func(HistoryEvent)
	wall    func() int64
	maxIPs  int
	maxNets int
}

func newLoginLedger(emit func(HistoryEvent)) *loginLedger {
	return &loginLedger{
		ips: make(map[string]*loginIP), nets: make(map[string]*loginNet), budget: make(map[string]*loginBucket),
		emit: emit, wall: func() int64 { return time.Now().Unix() }, maxIPs: loginMaxIPs, maxNets: loginMaxNets,
	}
}

// loginKeys is the client (an IPv4 address, an IPv6 /64) and the network
// (an IPv4 /24, an IPv6 /48) a failure is counted on.
func loginKeys(ip string) (client, network string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return strings.Clone(ip), strings.Clone(ip)
	}
	a = a.Unmap()
	if a.Is4() {
		n, _ := a.Prefix(24)
		return a.String(), n.String()
	}
	c, _ := a.Prefix(64)
	n, _ := a.Prefix(48)
	return c.String(), n.String()
}

// siteCount renders a site count, "8+" once the per-client cap was passed.
func siteCount(n int, capped bool) string {
	if capped {
		return fmt.Sprintf("%d+", n)
	}
	return fmt.Sprintf("%d", n)
}

// loginSiteKey is the registrable domain of a host: one owner's www.,
// staging. and bare names are one site.
func loginSiteKey(host string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// observe takes one login line with its outcome. Only "fail" and "ok" count.
func (l *loginLedger) observe(rec LogRec, host, tag, outcome string) {
	if l == nil || !loginSignalsOn.Load() || (outcome != "fail" && outcome != "ok") || rec.IP == "" {
		return
	}
	wall := l.wall()
	now := int64(rec.TS)
	if now <= 0 || now > wall+loginFutureSkew {
		now = wall // a skewed edge clock must not move a window ahead
	}
	client, network := loginKeys(rec.IP)
	site := authHash(loginSiteKey(host))
	var rows []HistoryEvent
	l.mu.Lock()
	if outcome == "fail" {
		rows = l.failLocked(rec.IP, client, network, site, tag, now)
	} else {
		rows = l.okLocked(rec.IP, client, network, host, site, tag, now)
	}
	rows = l.budgetLocked(rows, wall)
	l.mu.Unlock()
	for _, r := range rows {
		if l.emit != nil {
			l.emit(r)
		}
	}
}

// budgetLocked lets at most loginRowsPerMin rows of a type through per
// minute (bursts of loginRowsBurst); the rest are counted into the next
// row's `suppressed`.
func (l *loginLedger) budgetLocked(rows []HistoryEvent, wall int64) []HistoryEvent {
	out := rows[:0]
	for _, r := range rows {
		b := l.budget[r.Type]
		if b == nil {
			b = &loginBucket{tokens: loginRowsBurst, last: wall}
			l.budget[r.Type] = b
		}
		b.tokens += float64(wall-b.last) * loginRowsPerMin / 60
		if b.tokens > loginRowsBurst {
			b.tokens = loginRowsBurst
		}
		b.last = wall
		if b.tokens < 1 {
			b.suppressed++
			continue
		}
		b.tokens--
		if b.suppressed > 0 {
			r.Payload["suppressed"] = b.suppressed
			b.suppressed = 0
		}
		out = append(out, r)
	}
	return out
}

func (l *loginLedger) ipLocked(client string, now int64) *loginIP {
	s := l.ips[client]
	if s == nil {
		if len(l.ips) >= l.maxIPs {
			evictLogin(l.ips, now, func(s *loginIP) (int64, bool) { return s.last, s.flagged > now })
		}
		s = &loginIP{}
		l.ips[client] = s
	}
	return s
}

func (l *loginLedger) netLocked(network string, now int64) *loginNet {
	s := l.nets[network]
	if s == nil {
		if len(l.nets) >= l.maxNets {
			evictLogin(l.nets, now, func(s *loginNet) (int64, bool) { return s.last, s.until > now })
		}
		s = &loginNet{}
		l.nets[network] = s
	}
	return s
}

// evictLogin frees a batch: entries idle for a day first, then unflagged
// ones, and flagged ones only when nothing else is left, so a flood of new
// addresses cannot wipe the clients a later success must be checked against.
func evictLogin[T any](m map[string]T, now int64, state func(T) (last int64, flagged bool)) {
	n := 0
	for k, v := range m {
		if last, _ := state(v); now-last >= 86400 {
			delete(m, k)
			n++
		}
	}
	for k, v := range m {
		if n >= loginEvictBatch {
			return
		}
		if _, flagged := state(v); !flagged {
			delete(m, k)
			n++
		}
	}
	for k := range m {
		if n >= loginEvictBatch {
			return
		}
		delete(m, k)
		n++
	}
}

func (l *loginLedger) failLocked(ip, client, network string, site uint64, tag string, now int64) []HistoryEvent {
	var rows []HistoryEvent
	s := l.ipLocked(client, now)
	prevDay := s.win.dayStart
	s.win.add(now)
	if s.win.dayStart != prevDay {
		s.nsites, s.full = 0, false
	}
	if st := s.site(site); st != nil {
		if st.n < 0xffff {
			st.n++
		}
	} else if int(s.nsites) < loginMaxSites {
		s.sites[s.nsites] = loginSite{h: site, n: 1}
		s.nsites++
	} else {
		s.full = true
	}
	if now > s.last {
		s.last = now
	}

	ns := l.netLocked(network, now)
	prevNetDay := ns.win.dayStart
	ns.win.add(now)
	if ns.win.dayStart != prevNetDay {
		ns.nips, ns.nflag = 0, 0
	}
	ch := authHash(client)
	addHash(ns.ips[:], &ns.nips, ch)
	if now > ns.last {
		ns.last = now
	}

	// L1: one client.
	sites, hourEst := int(s.nsites), s.win.hourEst(now)
	if (s.win.day >= loginSprayDayFails && sites >= loginSpraySites) || hourEst >= loginBurstHour || s.win.day >= loginHeavyDay {
		s.flagged = now + loginFlagTTL
		addHash(ns.flagged[:], &ns.nflag, ch)
		if now-s.rowAt >= loginRowEvery {
			s.rowAt = now
			rows = append(rows, HistoryEvent{
				TsUnix: now, Type: "login_spray", IP: strings.Clone(ip), Mode: "shadow", Score: float64(s.win.day),
				Reason: fmt.Sprintf("login spray (shadow): %d failed %s logins on %s sites in 24h, %.0f in the last hour", s.win.day, tag, siteCount(sites, s.full), hourEst),
				Payload: map[string]interface{}{
					"tag": tag, "client": client, "fails_24h": s.win.day, "fails_1h": int(hourEst + 0.5),
					"sites": sites, "sites_capped": s.full, "single_site": sites == 1,
					"net": network, "would": "ban",
				},
			})
		}
	}

	// L2: its network.
	if int(ns.nflag) >= loginNetFlagged || (ns.win.day >= loginNetDayFails && int(ns.nips) >= loginNetIPs) {
		ns.until = now + loginFlagTTL
		if now-ns.rowAt >= loginRowEvery {
			ns.rowAt = now
			rows = append(rows, HistoryEvent{
				TsUnix: now, Type: "login_spray_net", Mode: "shadow", Score: float64(ns.win.day),
				Reason: fmt.Sprintf("login spray from %s (shadow): %d failed %s logins from %d clients in 24h, %d of them flagged", network, ns.win.day, tag, ns.nips, ns.nflag),
				Payload: map[string]interface{}{
					"tag": tag, "net": network, "fails_24h": ns.win.day, "clients": int(ns.nips),
					"clients_capped": int(ns.nips) == loginMaxNetIPs, "clients_flagged": int(ns.nflag), "would": "ban",
				},
			})
		}
	}
	return rows
}

func (l *loginLedger) okLocked(ip, client, network, host string, site uint64, tag string, now int64) []HistoryEvent {
	s := l.ips[client]
	ns := l.nets[network]
	var own uint16
	sites := 0
	if s != nil && now-s.win.dayStart < 86400 {
		if st := s.site(site); st != nil {
			own = st.n
		}
		sites = int(s.nsites)
	}
	by := ""
	switch {
	case s != nil && s.flagged > now:
		by = "ip"
	case ns != nil && ns.until > now:
		by = "net"
	case own >= loginOwnFails:
		by = "own_fails"
	}
	if by == "" {
		return nil
	}
	if s == nil {
		s = l.ipLocked(client, now)
		s.last = now
	}
	// At most one row per (client, site) per hour, and loginOKRows per client.
	slot := -1
	for i, o := range s.oks {
		if o.at != 0 && now-o.at < 3600 {
			if o.h == site {
				return nil
			}
			continue
		}
		if slot < 0 {
			slot = i
		}
	}
	if slot < 0 {
		return nil
	}
	s.oks[slot] = loginOK{h: site, at: now}
	return []HistoryEvent{{
		TsUnix: now, Type: "login_dirty_success", Host: strings.Clone(host), IP: strings.Clone(ip), Mode: "shadow", Score: float64(own),
		Reason: fmt.Sprintf("successful %s login (shadow) from a client flagged by %s: %d failures on this site, %d sites failed in 24h", tag, by, own, sites),
		Payload: map[string]interface{}{
			"tag": tag, "flagged_by": by, "own_fails_24h": own, "sites_failed_24h": sites,
			"client": client, "net": network, "would": "alert",
		},
	}}
}
