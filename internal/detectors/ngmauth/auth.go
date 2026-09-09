// Package ngmauth detects abusive NGM control-panel login attempts by tailing
// NGM's panel auth log (/var/log/ngm/auth.log). NGM writes that file expressly
// for an external fail2ban-family detector (see NGM internal/web/authfilelog.go),
// in a stable single-line key=value format:
//
//	2026-08-05T17:30:00Z event=FAIL user="bob" ip=1.2.3.4 role=admin reason=bad_password
//
// The file is a COMBINED auth+audit log, so this detector keys on an allowlist
// of abuse events and ignores audit verbs (SUCCESS/LOGOUT/MFA_SUCCESS/DAV_*/
// CONTAINER_*/...). It is the panel-login analogue of the cpanel/login detector
// and reuses the same core window primitives + file-tailer resume. The detector
// only emits core.Alert; blocking/leniency/notify/IP-decoration are the section
// sink's job (autoblock_sink.go). Design: docs/ngm-auth-detector.md.
package ngmauth

import (
	"context"
	"io"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
)

// abuseEvents is the allowlist of auth.log events that count as abuse signal.
// Everything else in the log (SUCCESS, LOGOUT, MFA_REQUIRED/SUCCESS/ENABLE/
// DISABLE, DAV_*, CONTAINER_*, ...) is audit/lifecycle noise and is ignored, so
// a new audit verb added on the NGM side can never turn into a false ban.
//
//   - FAIL         interactive login failure (bad_password/lockout/suspended/…)
//   - RATELIMIT    NGM's own per-IP login throttle already fired — i.e. NGM has
//     itself judged this source abusive (high-confidence)
//   - MFA_FAILURE  credential-stuffing that cleared the password step
//   - TOKEN_FAIL   API-token authentication failure (bad token value; role=token)
//
// TOKEN_IP_REJECT (a valid token presented from a not-yet-allowlisted source IP)
// is deliberately NOT counted: NGM already refused the request on its own CIDR
// gate, and a legitimate token retried from a new office/CI egress would
// otherwise get that IP banned fleet-wide — a self-inflicted outage from a
// benign misconfiguration.
var abuseEvents = map[string]bool{
	"FAIL":        true,
	"RATELIMIT":   true,
	"MFA_FAILURE": true,
	"TOKEN_FAIL":  true,
}

type AuthConfig struct {
	// source selection
	Mode    string // "file" only (auth.log is a file; opened per-write, rotate-safe)
	LogPath string // default: /var/log/ngm/auth.log

	// cadence
	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	// thresholds (0 disables a bucket; ADMIN/TOKEN fall back to AuthFailPerIP)
	AuthFailPerIP   int // per source IP (interactive login)
	AuthFailPerUser int // per targeted username
	AdminFailPerIP  int // stricter, for role=admin (mirrors cpanel ROOT_IP)
	TokenFailPerIP  int // API-token brute (TOKEN_FAIL)
}

type pend struct {
	kindKey string // "AUTHFAIL|ip" | "AUTHFAIL|user" | "ADMIN|ip" | "TOKEN|ip"
	key     string // ip or username
}

type Auth struct {
	cfg AuthConfig

	// identity + source
	name string
	src  core.LineSource

	// state wiring (offset/inode resume)
	state    *core.State
	stateKey string

	// window state
	pending map[string]pend
	samples *core.SampleRing
	gate    *core.AlertGate
	counts  *core.SlidingCounter
}

func New(cfg AuthConfig) *Auth {
	if cfg.Mode == "" {
		cfg.Mode = "file"
	}
	if cfg.LogPath == "" {
		cfg.LogPath = "/var/log/ngm/auth.log"
	}
	if cfg.Every <= 0 {
		cfg.Every = 2 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Minute
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 20 * time.Minute
	}
	if cfg.SampleLimit <= 0 {
		cfg.SampleLimit = 10
	}

	a := &Auth{cfg: cfg}
	a.pending = make(map[string]pend)
	a.samples = core.NewSampleRing(cfg.SampleLimit)
	a.gate = core.NewAlertGate(cfg.Cooldown)
	a.counts = core.NewSlidingCounter(cfg.Window, 0) // cap=0 → unbounded per-key
	return a
}

// -------- PeriodicDetector --------

func (a *Auth) Name() string {
	if a.name != "" {
		return a.name
	}
	return "ngm_auth"
}

func (a *Auth) Every() time.Duration {
	if a.cfg.Every > 0 {
		return a.cfg.Every
	}
	return 2 * time.Second
}

// -------- PositionAware --------

func (a *Auth) ApplyPosition(p core.Position) {
	if ft, ok := a.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
}

func (a *Auth) Position() core.Position {
	if a.src == nil {
		return core.Position{}
	}
	off, ino, ts := a.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

// -------- wiring (from factory) --------

func (a *Auth) SetState(st *core.State, key string) { a.state = st; a.stateKey = key }
func (a *Auth) SetName(n string)                    { a.name = n }
func (a *Auth) SetSource(src core.LineSource)       { a.src = src }

// Shutdown propagates final cleanup to the source (core.Shutdowner).
func (a *Auth) Shutdown() error {
	if a.src != nil {
		return a.src.Shutdown()
	}
	return nil
}

// -------- run loop --------

func (a *Auth) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	if a.pending == nil {
		a.pending = make(map[string]pend)
	} else {
		for k := range a.pending {
			delete(a.pending, k)
		}
	}
	if a.src == nil {
		return nil
	}

	// Resume file position BEFORE opening.
	if a.state != nil && a.stateKey != "" {
		if p, ok := a.state.Get(a.stateKey); ok {
			a.ApplyPosition(p)
		}
	}

	if err := a.src.Open(); err != nil {
		// Missing file (non-NGM host) or transient error: no-op this tick.
		return nil
	}
	defer a.src.Close()

	now := time.Now()
	for {
		line, err := a.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		a.processLine(now, line)
	}

	a.flush(now, out)

	// Save file position AFTER reading.
	if a.state != nil && a.stateKey != "" {
		a.state.Put(a.stateKey, a.Position())
	}
	return nil
}

// -------- parsing & aggregation --------

func (a *Auth) processLine(now time.Time, line string) {
	f := kvLine(line)
	if f == nil {
		return
	}
	ev := strings.ToUpper(f["event"])
	if !abuseEvents[ev] {
		return
	}
	ip := strings.TrimSpace(f["ip"])
	user := strings.ToLower(strings.TrimSpace(f["user"]))
	role := strings.ToLower(strings.TrimSpace(f["role"]))

	// API-token brute is its own bucket (role=token; carries no meaningful user).
	if ev == "TOKEN_FAIL" {
		if ip != "" && ip != "-" {
			a.bump(now, "TOKEN|ip", ip, line)
		}
		return
	}

	// Interactive login abuse (FAIL / RATELIMIT / MFA_FAILURE).
	if ip != "" && ip != "-" {
		// Every failure counts toward the general per-IP threshold, so a spray
		// mixing admin + user logins from one IP cannot hide by splitting buckets.
		a.bump(now, "AUTHFAIL|ip", ip, line)
		// role=admin ALSO feeds the stricter admin bucket (fires earlier).
		if role == "admin" && a.cfg.AdminFailPerIP > 0 {
			a.bump(now, "ADMIN|ip", ip, line)
		}
	}
	if user != "" && user != "-" {
		a.bump(now, "AUTHFAIL|user", user, line)
	}
}

// kvLine parses one auth.log line into its key=value fields. The line begins
// with an RFC3339 timestamp (a bare token with no '=', which is skipped) then
// space-separated key=value pairs whose values are quoted only when they contain
// spaces/quotes (NGM's authLogValue). reason= in particular can carry spaces
// inside quotes, so scan quote-aware rather than splitting on whitespace. NGM
// sanitises control chars and embedded quotes out on the write side (line-forgery
// guard), and the fields this detector keys on (event/ip/user/role) never
// legitimately contain quotes or spaces, so a mangled reason cannot mis-bucket.
func kvLine(line string) map[string]string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	m := make(map[string]string, 6)
	i, n := 0, len(line)
	for i < n {
		for i < n && line[i] == ' ' {
			i++
		}
		if i >= n {
			break
		}
		start := i
		for i < n && line[i] != '=' && line[i] != ' ' {
			i++
		}
		if i >= n || line[i] != '=' {
			// Bare token (e.g. the leading timestamp) — no key=value here.
			continue
		}
		key := line[start:i]
		i++ // consume '='
		var val string
		if i < n && line[i] == '"' {
			i++ // opening quote
			vs := i
			for i < n && line[i] != '"' {
				i++
			}
			val = line[vs:i]
			if i < n {
				i++ // closing quote
			}
		} else {
			vs := i
			for i < n && line[i] != ' ' {
				i++
			}
			val = line[vs:i]
		}
		if key != "" {
			m[key] = val
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func (a *Auth) bump(now time.Time, kindKey, key, line string) {
	sk := kindKey + ":" + key
	a.samples.Add(sk, line)
	_ = a.counts.Add(sk, now)
	if _, ok := a.pending[sk]; !ok {
		a.pending[sk] = pend{kindKey: kindKey, key: key}
	}
}

// -------- flush --------

func (a *Auth) flush(now time.Time, out chan<- core.Alert) {
	for _, p := range a.pending {
		limit, kindStr, _ := a.thresholdAndKey(p.kindKey, p.key)
		if limit <= 0 {
			continue
		}
		sk := p.kindKey + ":" + p.key
		n := a.counts.Count(sk, now)
		if n < limit {
			continue
		}
		if !a.gate.Allow(sk, now, n, limit) {
			continue
		}

		samples := a.samples.GetAndClear(sk)

		extra := map[string]string{
			"window":   a.cfg.Window.String(),
			"cooldown": a.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(limit),
			"mode":     a.cfg.Mode,
			"log":      a.cfg.LogPath,
		}
		if strings.Contains(p.kindKey, "|ip") {
			// IP-keyed: the section sink reads Extra["ip"] as authoritative and
			// overwrites Key with its own (cached, timeout-bounded) PTR/ASN
			// decoration, so the detector does NOT do reverse-DNS on the hot path.
			extra["ip"] = p.key
		}
		if strings.Contains(p.kindKey, "|user") {
			// Per-account signal (one username, possibly many source IPs).
			// Declaring the host scope stops the sink from banning an arbitrary
			// sample IP — and from silently dropping the alert when that IP is
			// self/loopback/ignored: a distributed per-account attack is a notify,
			// not a single-IP ban. A single-source attack is already covered by
			// the AUTHFAIL|ip bucket.
			extra["user"] = p.key
			extra[core.ExtraIPScope] = core.IPScopeHost
		}

		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind(kindStr),
			Key:     p.key, // sink overwrites this with its decorated IP for |ip alerts
			Count:   n,
			Samples: samples,
			Extra:   extra,
		}
	}
}

func (a *Auth) thresholdAndKey(kindKey, rawKey string) (limit int, alertKind, baseKey string) {
	switch kindKey {
	case "AUTHFAIL|ip":
		return a.cfg.AuthFailPerIP, "NGM/AUTHFAIL", rawKey
	case "AUTHFAIL|user":
		return a.cfg.AuthFailPerUser, "NGM/AUTHFAIL", rawKey
	case "ADMIN|ip":
		lim := a.cfg.AdminFailPerIP
		if lim <= 0 {
			lim = a.cfg.AuthFailPerIP
		}
		return lim, "NGM/ADMIN", rawKey
	case "TOKEN|ip":
		lim := a.cfg.TokenFailPerIP
		if lim <= 0 {
			lim = a.cfg.AuthFailPerIP
		}
		return lim, "NGM/TOKEN", rawKey
	default:
		return 0, "", rawKey
	}
}
