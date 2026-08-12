// Package dbwebcorr correlates per-account MySQL pressure (the DB side) with
// per-vhost web request volume (the web side) to surface the "few web hits,
// high DB pressure" tenants — a hosting account whose databases are working
// hard while its sites take almost no front-end traffic. That quadrant is the
// interesting one: a heavy cron, a runaway import, an abusive backend script,
// or a compromised account grinding the DB without a matching visitor load
// (contrast the boring "lots of traffic → lots of DB" case).
//
// This package is a PURE leaf: it takes already-collected data (DB-user
// pressure rows, vhost activity rows, and a host→owner-account map) plus
// thresholds, and returns account-level correlation rows. It performs NO I/O —
// the caller fetches the governor + webdetector snapshots and builds the
// host→owner map (from /etc/userdomains etc.) and passes them in. Keeping the
// join here makes the scoring unit-testable and reusable by both an HTTP
// endpoint and an MCP tool.
package dbwebcorr

import (
	"sort"
	"strings"
)

// DBUser is one MySQL user's pressure over the governor's last poll window.
// CPUSec is real CPU seconds when available (perf_schema / MariaDB CPU_TIME);
// BusySec is the CloudLinux/MariaDB wall-clock proxy used when CPUSec is 0.
type DBUser struct {
	User       string
	CPUSec     float64
	BusySec    float64
	QueryCount int64
	Conns      int
	Active     int
}

// Vhost is one virtual host's request rate over the web engine's short window.
type Vhost struct {
	Host string
	RPS  float64
}

// Params tunes the correlation. Zero values fall back to sensible defaults via
// withDefaults, so a caller can pass Params{} and get a usable ranking.
type Params struct {
	// WindowSec is the web engine's short window in seconds; web hits over the
	// window are approximated as RPS * WindowSec. Default 60.
	WindowSec int
	// MinPressure is the effective-pressure floor (CPU seconds) below which an
	// account is never flagged — filters out idle tenants. Default 0.05.
	MinPressure float64
	// MaxHitsForFlag is the "few hits" ceiling (approx requests over the window)
	// at or below which an account with pressure ≥ MinPressure is flagged.
	// Default 5.
	MaxHitsForFlag float64
	// TopN caps the returned rows (0 = all). Applied after sorting.
	TopN int
	// ExcludeAccounts are account names to drop entirely (system/shared DB
	// users like root, mysql, eximstats, roundcube — not real tenants). Matched
	// case-insensitively against the derived account name.
	ExcludeAccounts []string
}

func (p Params) withDefaults() Params {
	if p.WindowSec <= 0 {
		p.WindowSec = 60
	}
	if p.MinPressure <= 0 {
		p.MinPressure = 0.05
	}
	if p.MaxHitsForFlag <= 0 {
		p.MaxHitsForFlag = 5
	}
	return p
}

// Account is the correlated per-account row. Pressure is the effective DB cost
// used for ranking (max of CPUSec and BusySec, so a CloudLinux box where
// CPUSec==0 still ranks by the busy-time proxy). WebHits is the approximate
// request count over the window (WebRPS * WindowSec).
type Account struct {
	Account    string   `json:"account"`
	CPUSec     float64  `json:"cpu_sec"`
	BusySec    float64  `json:"busy_sec"`
	Pressure   float64  `json:"pressure"`
	QueryCount int64    `json:"query_count"`
	Conns      int      `json:"conns"`
	Active     int      `json:"active"`
	WebRPS     float64  `json:"web_rps"`
	WebHits    float64  `json:"web_hits"`
	DBUsers    []string `json:"db_users"`
	Vhosts     []string `json:"vhosts"`
	// PressurePerHit is Pressure / (WebHits + 1) — the ranking key. High means
	// a lot of DB cost per web request, i.e. the "few hits, high pressure" tell.
	PressurePerHit float64 `json:"pressure_per_hit"`
	// FewHitsHighPressure is the headline flag: Pressure ≥ MinPressure AND
	// WebHits ≤ MaxHitsForFlag.
	FewHitsHighPressure bool `json:"few_hits_high_pressure"`
}

// AccountOf derives the hosting-account name from a MySQL user name. cPanel and
// DirectAdmin both name per-account DB users "<account>_<suffix>", so the
// account is the prefix before the first underscore. A user with no underscore
// (e.g. "root") is returned as-is.
func AccountOf(dbUser string) string {
	dbUser = strings.TrimSpace(dbUser)
	if i := strings.IndexByte(dbUser, '_'); i > 0 {
		return dbUser[:i]
	}
	return dbUser
}

// Correlate joins DB pressure and web activity per hosting account and returns
// the rows sorted most-interesting-first: flagged (few-hits/high-pressure)
// accounts first, then by PressurePerHit descending, then Pressure descending,
// then account name. hostOwner maps a vhost name to its owning account; vhosts
// with no mapping contribute to no account's web total (they can't be
// attributed) and are silently skipped.
func Correlate(db []DBUser, web []Vhost, hostOwner map[string]string, params Params) []Account {
	p := params.withDefaults()

	excluded := make(map[string]struct{}, len(p.ExcludeAccounts))
	for _, a := range p.ExcludeAccounts {
		excluded[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}

	// accountKey normalizes the join key so the DB side (account derived from the
	// MySQL user) and the web side (owner from the host→owner map) always agree.
	// Without this, a mixed-case MySQL user (AccountOf("Chris_wp")="Chris") would
	// key a different account than the lowercase userdomains owner ("chris"),
	// splitting one tenant into two rows and FALSELY flagging the DB half as
	// few-hits/high-pressure. Matches the (already lowercased) exclusion keys.
	accountKey := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

	acc := make(map[string]*Account)
	get := func(name string) *Account {
		if a, ok := acc[name]; ok {
			return a
		}
		a := &Account{Account: name}
		acc[name] = a
		return a
	}

	// DB side: fold each user into its account.
	for _, u := range db {
		name := accountKey(AccountOf(u.User))
		if name == "" {
			continue
		}
		if _, skip := excluded[name]; skip {
			continue
		}
		a := get(name)
		a.CPUSec += u.CPUSec
		a.BusySec += u.BusySec
		a.QueryCount += u.QueryCount
		a.Conns += u.Conns
		a.Active += u.Active
		a.DBUsers = append(a.DBUsers, u.User)
	}

	// Web side: fold each vhost into its owner account (skip unmapped hosts).
	for _, v := range web {
		owner := accountKey(hostOwner[v.Host])
		if owner == "" {
			continue
		}
		if _, skip := excluded[owner]; skip {
			continue
		}
		a := get(owner)
		a.WebRPS += v.RPS
		a.Vhosts = append(a.Vhosts, v.Host)
	}

	out := make([]Account, 0, len(acc))
	for _, a := range acc {
		a.Pressure = a.CPUSec
		if a.BusySec > a.Pressure {
			a.Pressure = a.BusySec
		}
		a.WebHits = a.WebRPS * float64(p.WindowSec)
		a.PressurePerHit = a.Pressure / (a.WebHits + 1)
		a.FewHitsHighPressure = a.Pressure >= p.MinPressure && a.WebHits <= p.MaxHitsForFlag
		sort.Strings(a.DBUsers)
		sort.Strings(a.Vhosts)
		out = append(out, *a)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].FewHitsHighPressure != out[j].FewHitsHighPressure {
			return out[i].FewHitsHighPressure // flagged first
		}
		if out[i].PressurePerHit != out[j].PressurePerHit {
			return out[i].PressurePerHit > out[j].PressurePerHit
		}
		if out[i].Pressure != out[j].Pressure {
			return out[i].Pressure > out[j].Pressure
		}
		return out[i].Account < out[j].Account
	})

	if p.TopN > 0 && len(out) > p.TopN {
		out = out[:p.TopN]
	}
	return out
}
