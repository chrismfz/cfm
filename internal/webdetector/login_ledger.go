package webdetector

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The login ledger: phase 1 of docs/webdetector-signals-v2.md (§3), SHADOW
// only. It counts the failed logins the edge's login column reports (the
// daemon's outcome, authOutcome: WordPress is the one CMS with a rule so far)
// and writes three kinds of history row. Nothing is blocked, challenged or
// alerted; the rows are for a fleet read (detection_history) that sets the
// thresholds and the action (a sink ban or an edge deny) of phase 2.
//
//   login_spray          one IP: >= loginSprayDayFails failed logins on >=
//                        loginSpraySites sites in its 24 h window, or >=
//                        loginBurstHour in an hour, or >= loginHeavyDay in a
//                        day (L1). The slow cross-site sprayer rule 501 never
//                        sees (8 POSTs in 20 s).
//   login_spray_net      one /24 (or IPv6 /64): >= loginNetFlagged of its IPs
//                        flagged by L1 in 24 h, or >= loginNetDayFails
//                        failures from >= loginNetIPs of its IPs (L2): the
//                        proxy pools that send one or two tries per address.
//   login_dirty_success  a successful login from an IP flagged by L1 or L2 in
//                        the last 24 h, or after >= loginOwnFails of its own
//                        failures on that site (L4). Row on the site's host.
//
// Tenant privacy: a spray row names no site (counts only), so a scoped
// caller (who reads its own host's rows) never sees another tenant's name.
// The ledger is in memory: a restart or a config reload (a new Engine)
// empties it. Kill switch: [webdetector] LOGIN_SIGNALS.

const (
	loginSprayDayFails = 10
	loginSpraySites    = 3
	loginBurstHour     = 20
	loginHeavyDay      = 50
	loginNetFlagged    = 5
	loginNetDayFails   = 30
	loginNetIPs        = 5
	loginOwnFails      = 10
	loginFlagTTL       = 24 * time.Hour
	loginRowEvery      = 6 * time.Hour // one spray row per key per 6 h
	loginOKRowEvery    = time.Hour     // one dirty-success row per (ip, host) per hour

	loginMaxIPs     = 100000
	loginMaxNets    = 20000
	loginMaxHosts   = 32 // per IP, in its day window
	loginMaxNetIPs  = 64 // distinct IPs kept per net, in its day window
	loginEvictBatch = 1000
)

var loginSignalsOn atomic.Bool

func init() { loginSignalsOn.Store(true) }

// ConfigureLoginSignals applies [webdetector] LOGIN_SIGNALS (every reload).
func ConfigureLoginSignals(on bool) { loginSignalsOn.Store(on) }

// loginWin is a fixed 24 h window plus a sliding one-hour estimate.
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
	case w.hourStart == h:
	case w.hourStart == h-3600:
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
	if frac > 1 {
		frac = 1
	}
	return float64(w.hour) + float64(w.prevHour)*(1-frac)
}

type loginIP struct {
	win     loginWin
	hosts   map[uint64]uint16 // host hash → failures, reset with the day window
	last    int64
	flagged int64 // flagged by L1 until
	rowAt   int64 // last login_spray row
	okRowAt int64 // last login_dirty_success row
	okHost  uint64
}

type loginNet struct {
	win     loginWin
	ips     map[uint64]struct{} // distinct failing IPs in the day window
	flagged map[uint64]struct{} // its IPs flagged by L1 in the day window
	last    int64
	until   int64 // flagged by L2 until
	rowAt   int64
}

type loginLedger struct {
	mu   sync.Mutex
	ips  map[string]*loginIP
	nets map[string]*loginNet
	emit func(HistoryEvent)
}

func newLoginLedger(emit func(HistoryEvent)) *loginLedger {
	return &loginLedger{ips: make(map[string]*loginIP), nets: make(map[string]*loginNet), emit: emit}
}

// observe takes one login line with its outcome. Only "fail" and "ok" count.
func (l *loginLedger) observe(rec LogRec, host, tag, outcome string) {
	if l == nil || !loginSignalsOn.Load() || (outcome != "fail" && outcome != "ok") || rec.IP == "" {
		return
	}
	now := int64(rec.TS)
	if now <= 0 {
		now = time.Now().Unix()
	}
	var rows []HistoryEvent
	l.mu.Lock()
	if outcome == "fail" {
		rows = l.failLocked(rec.IP, host, tag, now)
	} else {
		rows = l.okLocked(rec.IP, host, tag, now)
	}
	l.mu.Unlock()
	for _, r := range rows {
		if l.emit != nil {
			l.emit(r)
		}
	}
}

func (l *loginLedger) ipLocked(ip string, now int64) *loginIP {
	s := l.ips[ip]
	if s == nil {
		if len(l.ips) >= loginMaxIPs {
			evictLogin(l.ips, now, func(s *loginIP) int64 { return s.last })
		}
		s = &loginIP{}
		l.ips[strings.Clone(ip)] = s // a key cut from the socket line would pin it
	}
	return s
}

func (l *loginLedger) netLocked(n string, now int64) *loginNet {
	s := l.nets[n]
	if s == nil {
		if len(l.nets) >= loginMaxNets {
			evictLogin(l.nets, now, func(s *loginNet) int64 { return s.last })
		}
		s = &loginNet{}
		l.nets[n] = s
	}
	return s
}

// evictLogin drops entries idle for a day, or failing that a batch of
// arbitrary ones (map order), so a full map costs one pass per batch.
func evictLogin[T any](m map[string]T, now int64, last func(T) int64) {
	n := 0
	for k, v := range m {
		if now-last(v) >= 86400 {
			delete(m, k)
			n++
		}
	}
	for k := range m {
		if n >= loginEvictBatch {
			break
		}
		delete(m, k)
		n++
	}
}

func (l *loginLedger) failLocked(ip, host, tag string, now int64) []HistoryEvent {
	var rows []HistoryEvent
	s := l.ipLocked(ip, now)
	prevDay := s.win.dayStart
	s.win.add(now)
	if s.win.dayStart != prevDay || s.hosts == nil {
		s.hosts = make(map[uint64]uint16)
	}
	hh := authHash(host)
	if c, ok := s.hosts[hh]; ok || len(s.hosts) < loginMaxHosts {
		if c < 0xffff {
			s.hosts[hh] = c + 1
		}
	}
	s.last = now

	netKey := authNet(ip)
	ns := l.netLocked(netKey, now)
	prevNetDay := ns.win.dayStart
	ns.win.add(now)
	if ns.win.dayStart != prevNetDay || ns.ips == nil {
		ns.ips, ns.flagged = make(map[uint64]struct{}), make(map[uint64]struct{})
	}
	ih := authHash(ip)
	if len(ns.ips) < loginMaxNetIPs {
		ns.ips[ih] = struct{}{}
	}
	ns.last = now

	// L1: one IP.
	sites, hourEst := len(s.hosts), s.win.hourEst(now)
	if (s.win.day >= loginSprayDayFails && sites >= loginSpraySites) || hourEst >= loginBurstHour || s.win.day >= loginHeavyDay {
		s.flagged = now + int64(loginFlagTTL/time.Second)
		if len(ns.flagged) < loginMaxNetIPs {
			ns.flagged[ih] = struct{}{}
		}
		if now-s.rowAt >= int64(loginRowEvery/time.Second) {
			s.rowAt = now
			rows = append(rows, HistoryEvent{
				TsUnix: now, Type: "login_spray", IP: strings.Clone(ip), Mode: "shadow", Score: float64(s.win.day),
				Reason: fmt.Sprintf("login spray (shadow): %d failed %s logins on %d sites in 24h, %.0f in the last hour", s.win.day, tag, sites, hourEst),
				Payload: map[string]interface{}{
					"tag": tag, "fails_24h": s.win.day, "fails_1h": int(hourEst + 0.5), "sites": sites,
					"net": netKey, "would": "ban",
				},
			})
		}
	}

	// L2: its network.
	if len(ns.flagged) >= loginNetFlagged || (ns.win.day >= loginNetDayFails && len(ns.ips) >= loginNetIPs) {
		ns.until = now + int64(loginFlagTTL/time.Second)
		if now-ns.rowAt >= int64(loginRowEvery/time.Second) {
			ns.rowAt = now
			rows = append(rows, HistoryEvent{
				TsUnix: now, Type: "login_spray_net", Mode: "shadow", Score: float64(ns.win.day),
				Reason: fmt.Sprintf("login spray from %s (shadow): %d failed %s logins from %d IPs in 24h, %d of them flagged", netKey, ns.win.day, tag, len(ns.ips), len(ns.flagged)),
				Payload: map[string]interface{}{
					"tag": tag, "net": netKey, "fails_24h": ns.win.day, "ips": len(ns.ips),
					"ips_flagged": len(ns.flagged), "would": "ban",
				},
			})
		}
	}
	return rows
}

func (l *loginLedger) okLocked(ip, host, tag string, now int64) []HistoryEvent {
	s := l.ips[ip]
	ns := l.nets[authNet(ip)]
	hh := authHash(host)
	var own uint16
	sites := 0
	if s != nil && now-s.win.dayStart < 86400 {
		own = s.hosts[hh]
		sites = len(s.hosts)
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
		s = l.ipLocked(ip, now)
		s.last = now
	}
	if s.okHost == hh && now-s.okRowAt < int64(loginOKRowEvery/time.Second) {
		return nil
	}
	s.okHost, s.okRowAt = hh, now
	return []HistoryEvent{{
		TsUnix: now, Type: "login_dirty_success", Host: strings.Clone(host), IP: strings.Clone(ip), Mode: "shadow", Score: float64(own),
		Reason: fmt.Sprintf("successful %s login (shadow) from an IP flagged by %s: %d failures on this site, %d sites failed in 24h", tag, by, own, sites),
		Payload: map[string]interface{}{
			"tag": tag, "flagged_by": by, "own_fails_24h": own, "sites_failed_24h": sites, "net": authNet(ip), "would": "alert",
		},
	}}
}
