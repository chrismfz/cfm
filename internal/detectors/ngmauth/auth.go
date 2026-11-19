// Package ngmauth detects abusive NGM control-panel login attempts by tailing
// NGM's panel auth log (/var/log/ngm/auth.log). NGM writes that file expressly
// for an external fail2ban-family detector (see NGM internal/web/authfilelog.go),
// in a stable single-line key=value format: ip= first, user and reason always
// quoted (ngm authfilelog.go writeAuthFileLine):
//
//	2026-08-05T17:30:00Z ip=1.2.3.4 event=FAIL role=admin user="bob" reason="bad_password"
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

// abuseEvents is the allowlist of auth.log events that count as abuse signal,
// and the bucket each feeds. It is an ALLOWLIST, not "anything not SUCCESS":
// the log is a combined auth+audit stream, so audit/lifecycle verbs (SUCCESS,
// LOGOUT, MFA_REQUIRED/SUCCESS/ENABLE/DISABLE, DAV_DISCOVERY/DAV_HOST/
// DAV_IMPORT_FAIL, CONTAINER_*, PWRESET_REQUEST/SENT/SUCCESS,
// SERVICE_ENABLE_DENIED, …) are ignored and a new audit verb can never become a
// false ban. Only genuine credential/brute events:
//
//   - FAIL                     interactive login failure (bad_password/lockout/…)
//   - RATELIMIT                NGM's own per-IP login throttle already fired —
//     i.e. NGM has itself judged this source abusive (high-confidence)
//   - MFA_FAILURE              credential-stuffing that cleared the password step
//   - DAV_FAIL                 WebDAV/CalDAV/CardDAV mailbox auth failure
//   - PWRESET_FAILURE          failed password-reset verification (token brute)
//   - RECOVERY_VERIFY_FAILURE  failed recovery-code verification (code brute)
//   - PASSWORD_CHANGE_FAIL, MFA_DISABLE_FAIL, RECOVERY_SET_FAIL
//     a logged-in session failing the step-up re-auth (ngm stepUp /
//     mailboxStepUp, `<EVENT>_FAIL`): a hijacked session guessing the
//     password. NGM bounds them itself (the panel's on the login form's
//     failed-attempt counter and lockout, the mailbox's on its own step-up
//     budget). Their account_disabled / account_suspended reasons are state
//     refusals, not guesses, and are not counted (stepUpStateReasons).
//   - TOKEN_FAIL               API-token auth failure (bad token value; role=token)
//
// DAV_FAIL / PWRESET_FAILURE / RECOVERY_VERIFY_FAILURE are role=mailbox credential
// failures and flow through the interactive path (per-IP + per-user), the same as
// FAIL — NOT the audit DAV_*/PWRESET_* verbs above.
//
// Deliberately NOT counted:
//   - TOKEN_IP_REJECT (a valid token presented from a not-yet-allowlisted
//     source IP): NGM already refused the request on its own CIDR gate, and a
//     legitimate token retried from a new office/CI egress would otherwise get
//     that IP banned fleet-wide — a self-inflicted outage from a benign
//     misconfiguration.
//   - API_ACCOUNT_DENIED: a VALID API token asking for an account it does not
//     own. An authorization refusal, not a credential guess; a misconfigured
//     integration would loop on it.
//   - DYNDNS_DENY (reason badauth): NGM logs a suspended account's VALID
//     token as badauth too, and the router keeps its schedule. ddclient
//     updates each hostname on its own, so one suspended customer with three
//     hostnames polling every minute makes 30 a window, past AUTHFAIL_IP, and
//     would get its home IP banned fleet-wide. The tokens are random, so
//     guessing one is not a practical attack. Count it only once NGM tells a
//     wrong token from a suspended one.
//
// Keep this allowlist in sync with NGM's authLog() call sites (ngm
// internal/web/authfilelog.go + its callers). testdata/ngm_auth_events.txt
// classifies the events NGM's call sites name; TestNGMEventFixture pins it to this map,
// and with NGM_SRC set to an ngm checkout it also fails on an NGM event the
// fixture does not list. A new NGM credential-failure verb is otherwise
// silently undetected.
var abuseEvents = map[string]eventBucket{
	"FAIL":                    bucketInteractive,
	"RATELIMIT":               bucketInteractive,
	"MFA_FAILURE":             bucketInteractive,
	"DAV_FAIL":                bucketInteractive,
	"PWRESET_FAILURE":         bucketInteractive,
	"RECOVERY_VERIFY_FAILURE": bucketInteractive,
	"PASSWORD_CHANGE_FAIL":    bucketInteractive,
	"MFA_DISABLE_FAIL":        bucketInteractive,
	"RECOVERY_SET_FAIL":       bucketInteractive,
	"TOKEN_FAIL":              bucketToken,
}

// eventBucket is where a counted event goes.
type eventBucket int

const (
	bucketInteractive eventBucket = iota + 1 // per IP, per user, privileged per IP
	bucketToken                              // TOKEN|ip
)

// stepUpEvents are the step-up `<EVENT>_FAIL` verbs; stepUpStateReasons are
// their reasons that refuse on account state, not on a wrong credential.
var (
	stepUpEvents = map[string]bool{
		"PASSWORD_CHANGE_FAIL": true,
		"MFA_DISABLE_FAIL":     true,
		"RECOVERY_SET_FAIL":    true,
	}
	stepUpStateReasons = map[string]bool{
		"account_disabled":  true,
		"account_suspended": true,
	}
)

type AuthConfig struct {
	// source selection
	Mode    string // "file" only (auth.log is a file; opened per-write, rotate-safe)
	LogPath string // default: /var/log/ngm/auth.log

	// cadence
	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	// thresholds (0 disables a bucket; TOKEN falls back to AuthFailPerIP)
	AuthFailPerIP   int // per source IP (interactive login)
	AuthFailPerUser int // per targeted username
	AdminFailPerIP  int // stricter, for role=admin or reseller (mirrors cpanel ROOT_IP)
	TokenFailPerIP  int // API-token brute (TOKEN_FAIL); 0 = AuthFailPerIP
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
		cfg.SampleLimit = 16 // matches the shipped [ngm_auth] reference config
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
	bucket := abuseEvents[ev]
	if bucket == 0 {
		return
	}
	if stepUpEvents[ev] && stepUpStateReasons[strings.ToLower(strings.TrimSpace(f["reason"]))] {
		return
	}
	ip := strings.TrimSpace(f["ip"])
	user := strings.ToLower(strings.TrimSpace(f["user"]))
	role := strings.ToLower(strings.TrimSpace(f["role"]))

	if bucket == bucketToken {
		// API-token brute is its own bucket (role=token; carries no meaningful user).
		if ip != "" && ip != "-" {
			a.bump(now, "TOKEN|ip", ip, line)
		}
		return
	}

	// Interactive / credential-verification abuse: FAIL, RATELIMIT,
	// MFA_FAILURE, DAV_FAIL, PWRESET_FAILURE, RECOVERY_VERIFY_FAILURE and the
	// step-up *_FAIL verbs.
	if ip != "" && ip != "-" {
		// Every failure counts toward the general per-IP threshold, so a spray
		// mixing privileged + user logins from one IP cannot hide by splitting
		// buckets.
		a.bump(now, "AUTHFAIL|ip", ip, line)
		// Privileged roles (admin AND reseller — a reseller administers many
		// customer accounts, so it is as high-value as admin) ALSO feed the
		// stricter bucket, which fires earlier. A sustained single-IP privileged
		// brute therefore trips NGM/ADMIN and NGM/AUTHFAIL (per-IP) and, past
		// AUTHFAIL_USER, a host-scoped per-user notify — accepted noise: the extra
		// nft ban is a no-op and multi-bucket coverage is worth the notifications.
		if (role == "admin" || role == "reseller") && a.cfg.AdminFailPerIP > 0 {
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
	// An IPv6 client counts as its /64; pending keeps the address with the most hits (core.TopAddr).
	sk := kindKey + ":" + core.ClientKey(kindKey, key)
	a.samples.Add(sk, line)
	_ = a.counts.Add(sk, now)
	a.pending[sk] = pend{kindKey: kindKey, key: core.TopAddr("ngmauth", sk, key, now)}
}

// -------- flush --------

func (a *Auth) flush(now time.Time, out chan<- core.Alert) {
	for sk, p := range a.pending { // sk: the key bump counted on
		limit, kindStr := a.threshold(p.kindKey)
		if limit <= 0 {
			continue
		}
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
			core.TagClient(extra, p.key)
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

func (a *Auth) threshold(kindKey string) (limit int, alertKind string) {
	switch kindKey {
	case "AUTHFAIL|ip":
		return a.cfg.AuthFailPerIP, "NGM/AUTHFAIL"
	case "AUTHFAIL|user":
		return a.cfg.AuthFailPerUser, "NGM/AUTHFAIL"
	case "ADMIN|ip":
		// No fallback: ADMIN_IP = 0 turns the bucket off (processLine never
		// bumps it), it does not borrow AUTHFAIL_IP.
		return a.cfg.AdminFailPerIP, "NGM/ADMIN"
	case "TOKEN|ip":
		lim := a.cfg.TokenFailPerIP
		if lim <= 0 {
			lim = a.cfg.AuthFailPerIP
		}
		return lim, "NGM/TOKEN"
	default:
		return 0, ""
	}
}
