package dovecot

import (
	"context"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

type Config struct {
	// source
	Mode            string // "file" | "journal" | "docker"
	LogPath         string
	JournalUnit     string
	DockerContainer string
	DockerArgs      []string
	// cadence
	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	// thresholds
	AuthFailPerIP   int
	AuthFailPerUser int

	// Logins refused as user_disabled (see processLine). Counted apart from
	// the password failures, per IP, in their own window, and banned for at
	// most UserDisabledBlockTTL whatever the section's BLOCK.
	UserDisabledPerIP    int           // 0 disables the bucket
	UserDisabledWindow   time.Duration // default 24h
	UserDisabledBlockTTL time.Duration // default 24h
	UserDisabledNotify   bool          // mail per ban; off by default (hundreds a day)

	// enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string
}

type pend struct {
	kindKey string // "AUTHFAIL|ip" | "AUTHFAIL|user"
	key     string // ip or username
}

type Auth struct {
	cfg  Config
	name string
	src  core.LineSource

	// state wiring (offset/inode for file, ts for journal)
	state    *core.State
	stateKey string

	pending   map[string]pend
	samples   *core.SampleRing
	gate      *core.AlertGate
	counts    *core.SlidingCounter
	disCounts *core.SlidingCounter // user_disabled, its own window

	// regexes
	reQuick    *regexp.Regexp
	reDisabled *regexp.Regexp
	reRip      *regexp.Regexp
	reUser     *regexp.Regexp

	enr *enrich.Enricher
}

func NewAuth(cfg Config) *Auth {

	// sensible defaults (Mode επιλέγεται κυρίως στο register)
	if cfg.Mode == "" {
		cfg.Mode = "file"
	}
	if cfg.LogPath == "" && cfg.Mode == "file" {
		cfg.LogPath = "/var/log/maillog"
	}
	if cfg.Every <= 0 {
		cfg.Every = 2 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = 15 * time.Minute
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 20 * time.Minute
	}
	if cfg.SampleLimit <= 0 {
		cfg.SampleLimit = 10
	}
	if cfg.UserDisabledWindow <= 0 {
		cfg.UserDisabledWindow = 24 * time.Hour
	}
	if cfg.UserDisabledBlockTTL <= 0 {
		cfg.UserDisabledBlockTTL = 24 * time.Hour
	}
	if !cfg.UseEnrich && !cfg.UsePTR {
		cfg.UsePTR = true
	}
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
	}

	a := &Auth{cfg: cfg}
	a.pending = make(map[string]pend)
	// core window primitives
	a.samples = core.NewSampleRing(cfg.SampleLimit)
	a.gate = core.NewAlertGate(cfg.Cooldown)
	a.counts = core.NewSlidingCounter(cfg.Window, 0)
	// Capped per key: the threshold is a handful, and a phone retrying a
	// suspended mailbox all day must not keep every timestamp for 24 hours.
	disCap := 64
	if 2*cfg.UserDisabledPerIP > disCap {
		disCap = 2 * cfg.UserDisabledPerIP
	}
	a.disCounts = core.NewSlidingCounter(cfg.UserDisabledWindow, disCap)
	// Lines we care about (keep this fast pre-filter).
	// The `dovecot` tag is PID-tolerant (`dovecot[1234]:`), because BOTH sources
	// we read are syslog-framed WITH the pid: /var/log/maillog (rsyslog) and
	// `journalctl -o short-unix` both emit `dovecot[<pid>]:`. The old anchor
	// required a bare `dovecot:` and so matched NOTHING on a normal host — the
	// detector was silently inert. This single `[pid]`-tolerant anchor revives it
	// for EVERY dovecot login service in one go, since they share the format:
	//   - imap-login / pop3-login  (auth failed, N attempts) (auth_failed)
	//   - managesieve-login (Sieve, :4190) — same line shape, now covered
	//   - submission-login (:587)
	//   - auth-worker(...) / passwd-file(...): Password mismatch
	//   - any "authentication failure" or "aborted login"
	// The pure-scan noise (Login aborted with `no_auth_attempts` — connection
	// closed / too many invalid commands, never an actual password try) does NOT
	// contain any of these markers, so it stays filtered out.
	a.reQuick = regexp.MustCompile(`dovecot(\[[0-9]+\])?:.*(auth failed|authentication failure|aborted login|password mismatch)`)
	// A login dovecot refused as user_disabled before any password check:
	//   imap-login: Login aborted: Connection closed (user disabled, 1 attempts
	//   in 2 secs) (user_disabled): user=<info@x.gr>, method=PLAIN, rip=…
	// On a cPanel node with Imunify360 it is pam_imunify locking an address on
	// Imunify's global RBL ("[IM360_RBL] The IP … has been locked", in
	// /var/log/messages): on earth all 969 addresses with such lines over three
	// days (2 363 lines) were RBL locks. None of the markers above is in it, so
	// these sources never failed a password here, were never banned and never
	// reached the fleet list. Elsewhere it is also a suspended mailbox, whose
	// owner's phone retries; hence a separate bucket with its own threshold and
	// a capped ban.
	a.reDisabled = regexp.MustCompile(`dovecot(\[[0-9]+\])?:.*\((user_disabled\)|user disabled[,)])`)
	a.reRip = regexp.MustCompile(`\brip=([0-9a-f:.]+)(?:[,\s]|$)`)
	// NB: no trailing \b after `>`. A real line is `user=<addr>,` and there is no
	// word boundary between `>` and `,`, so a `>\b` anchor matched NOTHING — the
	// per-user bucket never populated and AuthFailPerUser was inert. `>` already
	// delimits the capture; the trailing anchor was both wrong and unnecessary.
	a.reUser = regexp.MustCompile(`\buser=<([^>]+)>`)

	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			a.enr = e
			logging.Logf("[detectors] dovecot/auth enrichment enabled (dirs=%v)", cfg.EnrichDirs)
		} else {
			logging.Logf("[detectors] dovecot/auth enrichment unavailable; PTR only")
		}
	}
	return a
}

// wiring (manager/factory will set these)
func (a *Auth) SetName(n string)              { a.name = n }
func (a *Auth) SetSource(src core.LineSource) { a.src = src }

func (a *Auth) Name() string {
	if a.name != "" {
		return a.name
	}
	return "dovecot/auth"
}
func (a *Auth) Every() time.Duration {
	if a.cfg.Every > 0 {
		return a.cfg.Every
	}
	return 2 * time.Second
}

// PositionAware (optional) — keep parity with ssh detector
func (a *Auth) ApplyPosition(p core.Position) {
	if ft, ok := a.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
	if jt, ok := a.src.(*core.JournalTailer); ok {
		jt.ApplyResume(0, 0, p.TS)
	}
	if dt, ok := a.src.(*core.DockerTailer); ok {
		dt.ApplyResume(0, 0, p.TS)
	}

}
func (a *Auth) Position() core.Position {
	if a.src == nil {
		return core.Position{}
	}
	off, ino, ts := a.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

// State wiring
func (a *Auth) SetState(st *core.State, key string) { a.state = st; a.stateKey = key }

// ---------- run loop ----------
func (a *Auth) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// reset pending map
	for k := range a.pending {
		delete(a.pending, k)
	}

	if a.src == nil {
		// source is wired by the factory; if nil, nothing to do
		return nil
	}

	// Resume file/journal position BEFORE opening
	if a.state != nil && a.stateKey != "" {
		if p, ok := a.state.Get(a.stateKey); ok {
			a.ApplyPosition(p)
		}
	}

	if err := a.src.Open(); err != nil {
		return nil
	}
	defer a.src.Close()
	// Always save position on exit (even on ctx cancel or errors)
	if a.state != nil && a.stateKey != "" {
		defer func() { a.state.Put(a.stateKey, a.Position()) }()
	}

	now := time.Now()
	lines := 0

	for {
		line, err := a.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		lines++
		a.processLine(now, line)
	}

	a.flush(now, out)

	if lines > 0 && (a.cfg.SampleLimit > 0) && (a.cfg.Cooldown > 0) {
		// lightweight trace; keep or drop as you like
	}
	return nil
}

func (a *Auth) processLine(now time.Time, line string) {
	ll := strings.ToLower(line)
	// The verdict (the reason and its code) is the server's text BEFORE
	// `user=<`; the username after it is whatever the client tried, and may
	// itself read "(user_disabled)", "no auth attempts in 0 secs" or
	// "rip=1.2.3.4,". So the reason is matched in the head only: a password
	// failure whose username says "(user_disabled)" must stay a password
	// failure, or a brute force would trade the permanent ban for a capped one.
	head := ll
	hasUser := false
	if i := strings.Index(ll, "user=<"); i >= 0 {
		head, hasUser = ll[:i], true
	}
	// Only a login service's line (`… (code): user=<…>`) states a verdict in
	// server text. The auth-worker / passwd-file / pam lines put the username
	// BEFORE the marker (`passwd-file(USER,IP,<s>): Password mismatch`), so
	// their head is client text too, and they never say user_disabled.
	if hasUser && a.reDisabled.MatchString(head) {
		// Never a password failure: its own bucket only, per IP (the mailbox
		// is the victim, not the attacker).
		if a.cfg.UserDisabledPerIP > 0 {
			if ip := a.lineIP(ll, head, hasUser); ip != "" {
				a.bump(now, kindDisabledIP, ip, line)
			}
		}
		return
	}
	if !a.reQuick.MatchString(head) {
		return
	}

	// Ignore pure noise:
	// e.g. "Aborted login by logging out (no auth attempts in 0 secs)"
	if strings.Contains(head, "no auth attempts in 0 secs") {
		return
	}

	// ip
	if ip := a.lineIP(ll, head, hasUser); ip != "" {
		a.bump(now, "AUTHFAIL|ip", ip, line)
	}

	// user
	if m := a.reUser.FindStringSubmatch(ll); m != nil {
		for i := 1; i < len(m); i++ {
			if m[i] != "" {
				// already lowercased from ll
				a.bump(now, "AUTHFAIL|user", m[i], line)
				break
			}
		}
	}

}

const kindDisabledIP = "DISABLED|ip"

var (
	// `…(USER,IP)` or `…(USER,IP,<session>)`, as auth-worker writes it.
	reAuthTuple = regexp.MustCompile(`,([0-9a-f:.]+)(?:,<[^<>]*>)?\)`)
	reRhost     = regexp.MustCompile(`\brhost=([0-9a-f:.]+)(?:[\s;,]|$)`)
)

// lineIP is the source address of a dovecot line, canonical (IPv4 as dotted
// quad); "" when there is none. Never from the username, which the client
// chooses ("rip=203.0.113.50,a@b.gr" would otherwise name a third party's
// address to ban and report to the whole fleet):
//   - a login service's line (hasUser): the LAST rip= (dovecot writes it after
//     user=<…>), else the first IP before user=<;
//   - an auth-worker / passwd-file / pam line: the IP of the LAST
//     `(USER,IP[,<session>])` tuple (the server text after it is only the
//     message), else rhost= when there is exactly one; else none.
func (a *Auth) lineIP(ll, head string, hasUser bool) string {
	ipStr := ""
	if hasUser {
		if ms := a.reRip.FindAllStringSubmatch(ll, -1); len(ms) > 0 {
			ipStr = ms[len(ms)-1][1]
		} else {
			ipStr = firstIPInLine(head)
		}
	} else if ms := reAuthTuple.FindAllStringSubmatch(ll, -1); len(ms) > 0 {
		ipStr = ms[len(ms)-1][1]
	} else if ms := reRhost.FindAllStringSubmatch(ll, -1); len(ms) == 1 {
		ipStr = ms[0][1]
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// counter is the window a bucket counts in.
func (a *Auth) counter(kindKey string) *core.SlidingCounter {
	if kindKey == kindDisabledIP {
		return a.disCounts
	}
	return a.counts
}

func (a *Auth) bump(now time.Time, kindKey, key, line string) {
	sk := kindKey + ":" + key
	if _, ok := a.pending[sk]; !ok {
		a.pending[sk] = pend{kindKey: kindKey, key: key}
	}
	_ = a.counter(kindKey).Add(sk, now)
	a.samples.Add(sk, line)
}

// ---------- flush ----------
func (a *Auth) flush(now time.Time, out chan<- core.Alert) {

	for sk, p := range a.pending {
		limit, kindStr, baseKey := a.thresholdAndKey(p.kindKey, p.key)
		if limit <= 0 {
			continue
		}
		n := a.counter(p.kindKey).Count(sk, now)
		if n < limit {
			continue
		}
		if !a.gate.Allow(sk, now, n, limit) {
			continue
		}

		displayKey := a.enrichDisplay(p.kindKey, baseKey, p.key)

		samples := a.samples.GetAndClear(sk)
		window := a.cfg.Window
		if p.kindKey == kindDisabledIP {
			window = a.cfg.UserDisabledWindow
		}
		extra := map[string]string{
			"window":   window.String(),
			"cooldown": a.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(limit),
			"mode":     a.cfg.Mode,
		}
		if strings.Contains(p.kindKey, "|ip") {
			extra["ip"] = p.key
			if p.kindKey == kindDisabledIP {
				// Someone else's verdict (Imunify's RBL) or a suspended
				// mailbox: a capped ban, not the section's permanent one.
				extra[core.ExtraMaxBlockTTL] = a.cfg.UserDisabledBlockTTL.String()
				extra["reason"] = "user_disabled"
				if !a.cfg.UserDisabledNotify {
					extra[core.ExtraNotify] = core.NotifyNo
				}
			}
		} else {
			// A per-USER finding (one mailbox sprayed) is HOST-scoped: the samples
			// can span many source IPs, so the sink must NOT ban an arbitrary one —
			// it notifies instead. Same stance as the ngm_auth user bucket
			// (autoblock_sink honours Extra["ip_scope"]="host").
			extra[core.ExtraIPScope] = core.IPScopeHost
		}

		switch strings.ToLower(a.cfg.Mode) {
		case "file":
			extra["log"] = a.cfg.LogPath
		case "docker":
			extra["container"] = a.cfg.DockerContainer
		default:
			extra["unit"] = a.cfg.JournalUnit
		}

		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind(kindStr), // "DOVECOT/AUTHFAIL"
			Key:     displayKey,
			Count:   n,
			Samples: samples,
			Extra:   extra,
		}
	}
}

func (a *Auth) thresholdAndKey(kindKey, rawKey string) (limit int, alertKind, baseKey string) {
	switch kindKey {
	case "AUTHFAIL|ip":
		return a.cfg.AuthFailPerIP, "DOVECOT/AUTHFAIL", rawKey
	case "AUTHFAIL|user":
		return a.cfg.AuthFailPerUser, "DOVECOT/AUTHFAIL", rawKey
	case kindDisabledIP:
		return a.cfg.UserDisabledPerIP, "DOVECOT/USER_DISABLED", rawKey
	default:
		return 0, "", rawKey
	}
}

// ---------- helper: first valid IP in line (IPv4 or IPv6) ----------
func firstIPInLine(s string) string {
	// split tokens on non-IP chars
	f := func(r rune) bool {
		if r == '.' || r == ':' {
			return false
		}
		if (r >= '0' && r <= '9') || (r|32 >= 'a' && r|32 <= 'f') {
			return false
		}
		return true
	}

	toks := strings.FieldsFunc(s, f)
	for _, tok := range toks {
		if ip := net.ParseIP(tok); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
			return ip.String()
		}
	}
	return ""
}

// ---------- enrichment (only for IP keys) ----------
func (a *Auth) enrichDisplay(kindKey, baseKey, rawKey string) string {
	if !strings.Contains(kindKey, "|ip") {
		return baseKey
	}
	if !a.cfg.UseEnrich && !a.cfg.UsePTR {
		return baseKey
	}

	ip := rawKey
	var ptr, country, asname string
	var asn int

	if a.enr != nil && a.cfg.UseEnrich {
		res := a.enr.Lookup(ip)
		if res.PTR != "" {
			ptr = strings.TrimSuffix(res.PTR, ".")
		}
		if res.Country != "" {
			country = res.Country
		}
		if res.ASN > 0 {
			asn = int(res.ASN)
		}
		if res.ASNName != "" {
			asname = res.ASNName
		}
	}
	if a.cfg.UsePTR && ptr == "" {
		if names, _ := net.LookupAddr(ip); len(names) > 0 {
			ptr = strings.TrimSuffix(names[0], ".")
		}
	}

	parts := []string{ip}
	if ptr != "" {
		parts = append(parts, ptr)
	}
	if asn > 0 || country != "" || asname != "" {
		tag := strings.TrimSpace(strings.Join([]string{
			func() string {
				if asn > 0 {
					return strconv.Itoa(asn)
				}
				return ""
			}(),
			asname,
			country,
		}, " "))
		if tag != "" {
			parts = append(parts, "["+tag+"]")
		}
	}
	return strings.Join(parts, " ")
}
