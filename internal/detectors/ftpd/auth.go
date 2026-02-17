package ftpd

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
	Mode        string // auto|file|journal
	LogPath     string // path|auto|""
	JournalUnit string // unit|auto

	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	AuthFailPerIP   int
	AuthFailPerUser int

	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string
}

type pend struct {
	kindKey string // "AUTHFAIL|ip" | "AUTHFAIL|user"
	key     string // ip or user
}

type Auth struct {
	cfg  Config
	name string
	src  core.LineSource
	// state wiring (offset/inode for file, ts for journal)
	state    *core.State
	stateKey string

	pending map[string]pend

	samples *core.SampleRing
	gate    *core.AlertGate
	counts  *core.SlidingCounter

	// fast prefilters (kept minimal; we mainly use strings.Contains gates now)
	reQuick *regexp.Regexp


	// extractors (shared across daemons)
	rePamHost  *regexp.Regexp // pam_unix(...): ... rhost=IP user=USER
	reVsFail   *regexp.Regexp // FAIL LOGIN: Client "IP"
	reBracketH *regexp.Regexp // (host[IP])  proftpd style
	rePureAt   *regexp.Regexp // (user@IP)   pure-ftpd style
	reUserKV   *regexp.Regexp // user=<USER> or user=USER
	reUserVs   *regexp.Regexp // \[USER\] in vsftpd prefix
	reVsUserPrefix *regexp.Regexp // precompiled extractor for vsftpd "[USER] FAIL LOGIN:"

	enr *enrich.Enricher

	// daemon hint (vsftpd|proftpd|pure-ftpd|"")
	daemon string

}

func NewAuth(cfg Config) *Auth {
	// sensible defaults (align with other detectors)
	if cfg.Every <= 0 { cfg.Every = 2 * time.Second }
	if cfg.Window <= 0 { cfg.Window = 15 * time.Minute }
	if cfg.Cooldown <= 0 { cfg.Cooldown = 20 * time.Minute }
	if cfg.SampleLimit <= 0 { cfg.SampleLimit = 10 }
	if !cfg.UseEnrich && !cfg.UsePTR { cfg.UsePTR = true }
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
	}

	a := &Auth{cfg: cfg}
	a.pending = make(map[string]pend)
	// core window primitives
	a.samples = core.NewSampleRing(cfg.SampleLimit)
	a.gate    = core.NewAlertGate(cfg.Cooldown)
	a.counts  = core.NewSlidingCounter(cfg.Window, 0)

	// (1) QUICK FILTER: make it cheaper (no (?i), no wide backtracking).
	// We now lowercase the line and use strings.Contains first; keep a narrow regex as a fallback.
	a.reQuick = regexp.MustCompile(`\b(vsftpd|pure-?ftpd|proftpd|ftp-login)\b.*\b(fail|failed|violation|authentication failure|maximum login)\b`)



// IP class that matches v4, v6, and v4-mapped (::ffff:1.2.3.4)
const ipClass = `[0-9a-f:.]+`

// common extractors (used on the LOWERCASED line s := strings.ToLower(line))
a.rePamHost  = regexp.MustCompile(`\brhost=(` + ipClass + `)(?:[,\s]|$)`)
a.reVsFail   = regexp.MustCompile(`fail login:\s+client\s+"(` + ipClass + `)"`)
a.reBracketH = regexp.MustCompile(`\([^\[]*\[(` + ipClass + `)\]\)`)
a.rePureAt   = regexp.MustCompile(`\([^@]+@(` + ipClass + `)\)`)

// user extractors (lowercased tokens to match the lowercased line)
a.reUserKV       = regexp.MustCompile(`\buser=<([^>]+)>|\buser=([^\s,]+)`)
a.reUserVs       = regexp.MustCompile(`\[[^\]]+\]\s+fail login:`)
// Go's regexp doesn't support named groups; use a normal capture group:
a.reVsUserPrefix = regexp.MustCompile(`\[([^\]]+)\]\s+fail login:`)


	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			a.enr = e
			logging.Logf("[detectors] ftpd/auth enrichment enabled (dirs=%v)", cfg.EnrichDirs)
		}
	}
	return a
}

func (a *Auth) SetName(n string)             { a.name = n }
func (a *Auth) SetSource(src core.LineSource) { a.src = src }
func (a *Auth) SetDaemon(d string)           { a.daemon = strings.ToLower(d) }

func (a *Auth) Name() string {
	if a.name != "" { return a.name }
	return "ftpd/auth"
}
func (a *Auth) Every() time.Duration {
	if a.cfg.Every > 0 { return a.cfg.Every }
	return 2 * time.Second
}

// Position persistence (same style as ssh)
func (a *Auth) ApplyPosition(p core.Position) {
	if ft, ok := a.src.(*core.FileTailer); ok { ft.ApplyResume(p.Inode, p.Offset) }
	if jt, ok := a.src.(*core.JournalTailer); ok { jt.ApplyResume(0, 0, p.TS) }
}
func (a *Auth) Position() core.Position {
	if a.src == nil { return core.Position{} }
	off, ino, ts := a.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}


// State wiring
func (a *Auth) SetState(st *core.State, key string) { a.state = st; a.stateKey = key }


func (a *Auth) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// reset batch
	for k := range a.pending {
		delete(a.pending, k)
	}

	if a.src == nil {
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
		defer func() {
			a.state.Put(a.stateKey, a.Position())
		}()
	}

	now := time.Now()

	// CAP WORK PER TICK: prevent backlog-driven CPU stairs.
	const maxLines = 2000
	start := time.Now()
	deadline := start.Add(800 * time.Millisecond)
	processed := 0

	for {
		select {
		case <-ctx.Done():
			a.flush(now, out)
			return nil
		default:
		}

		line, err := a.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		a.consume(now, line)
		processed++

		if processed >= maxLines || time.Now().After(deadline) {
			break
		}
	}

	a.flush(now, out)
	return nil
}



func (a *Auth) consume(now time.Time, line string) {
	// (2) CHEAP CONTAINS GATES + DAEMON HINT (no Unicode SimpleFold)
	ll := strings.ToLower(line)

	// Ignore file-transfer activity lines that can contain "failed" in filenames
	// (e.g. WooCommerce "*-failed-order.php" uploads) and would otherwise trip AUTHFAIL.
	// We only want authentication failures here.
	if strings.Contains(ll, " uploaded") ||
		strings.Contains(ll, " downloaded") ||
		strings.Contains(ll, " renamed") ||
		strings.Contains(ll, " deleted") ||
		strings.Contains(ll, " chmod") ||
		strings.Contains(ll, " chown") ||
		strings.Contains(ll, " mkdir") ||
		strings.Contains(ll, " rmdir") {
		return
	}

	// require an ftp daemon token
	if !(strings.Contains(ll, "ftpd") || strings.Contains(ll, "ftp-login")) {
		return
	}
	// require a failure-ish verb
	if !(strings.Contains(ll, "fail") ||
		strings.Contains(ll, "authentication failure") ||
		strings.Contains(ll, "maximum login") ||
		strings.Contains(ll, "violation")) {
		return
	}
	// if we know the daemon, require it to appear in the line
	switch a.daemon {
	case "vsftpd":
		if !strings.Contains(ll, "vsftpd") { return }
	case "proftpd":
		if !strings.Contains(ll, "proftpd") { return }
	case "pure-ftpd", "pureftpd":
		if !(strings.Contains(ll, "pure-ftpd") || strings.Contains(ll, "pureftpd")) { return }
	}
	// optional extra guard using the narrowed regex (kept for safety)
	if !a.reQuick.MatchString(ll) { return }
	// Prefer extractors based on daemon hint to minimize regex tries

var ip string
if a.daemon == "vsftpd" {
	ip = firstIP(ll, a.reVsFail, a.rePamHost, a.rePureAt, a.reBracketH)
} else if a.daemon == "proftpd" {
	ip = firstIP(ll, a.reBracketH, a.rePamHost, a.rePureAt, a.reVsFail)
} else if a.daemon == "pure-ftpd" || a.daemon == "pureftpd" {
	ip = firstIP(ll, a.rePureAt, a.rePamHost, a.reBracketH, a.reVsFail)
} else {
	// unknown daemon → try all
	ip = firstIP(ll, a.rePamHost, a.reVsFail, a.rePureAt, a.reBracketH)
}


	if ip != "" {
		a.bump(now, "AUTHFAIL|ip", ip, line)
	}


user := pickUser(a.reUserKV, ll)
if user == "" && a.reUserVs.MatchString(ll) {
	if m := a.reVsUserPrefix.FindStringSubmatch(ll); m != nil {
		user = m[1]
	}
}



	if user != "" {
		user = strings.ToLower(user)
		a.bump(now, "AUTHFAIL|user", user, line)
	}
}

func first(matches ...[]string) string {
	for _, m := range matches {
		if len(m) > 1 && m[1] != "" { return m[1] }
	}
	return ""
}
func pickUser(rx *regexp.Regexp, s string) string {
	if m := rx.FindStringSubmatch(s); m != nil {
		for i := 1; i < len(m); i++ {
			if m[i] != "" { return m[i] }
		}
	}
	return ""
}


// normalizeIP returns canonical "1.2.3.4" for IPv4 and compressed form for IPv6.
// It also collapses IPv4-mapped IPv6 (::ffff:1.2.3.4) down to plain IPv4.
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// firstIP tries each regex against the LOWERCASED line and returns
// the first valid, normalized IP it finds (v4 / v6 / v4-mapped).
func firstIP(lowercased string, regs ...*regexp.Regexp) string {
	for _, rx := range regs {
		if m := rx.FindStringSubmatch(lowercased); len(m) > 1 && m[1] != "" {
			if ip := normalizeIP(m[1]); ip != "" {
				return ip
			}
		}
	}
	return ""
}



func (a *Auth) bump(now time.Time, kindKey, key, line string) {
sk := kindKey + ":" + key
	if _, ok := a.pending[sk]; !ok {
		a.pending[sk] = pend{kindKey: kindKey, key: key}
	}
	_ = a.counts.Add(sk, now)
	a.samples.Add(sk, line)
}

func (a *Auth) flush(now time.Time, out chan<- core.Alert) {
	for sk, p := range a.pending {
		limit, kindStr, isIP, base := a.thresholdAndKey(p.kindKey, p.key)

		if limit <= 0 { continue }
		n := a.counts.Count(sk, now)
		if n < limit { continue }
		if !a.gate.Allow(sk, now, n, limit) { continue }

		displayKey := base
		if isIP {
			displayKey = a.decorate(base)
		}

samples := a.samples.GetAndClear(sk)

		extra := map[string]string{
			"window":   a.cfg.Window.String(),
			"cooldown": a.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(limit),
		}
		if isIP {
			extra["ip"] = base
		}

		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind(kindStr), // "FTP/AUTHFAIL"
			Key:     displayKey,              // ip(...) or user
			Count:   n,
			Samples: samples,
			Extra:   extra,
		}
	}
}

func (a *Auth) thresholdAndKey(kindKey, rawKey string) (limit int, alertKind string, isIP bool, base string) {
	switch kindKey {
	case "AUTHFAIL|ip":
		return a.cfg.AuthFailPerIP, "FTP/AUTHFAIL", true, rawKey
	case "AUTHFAIL|user":
		return a.cfg.AuthFailPerUser, "FTP/AUTHFAIL", false, rawKey
	default:
		return 0, "", false, rawKey
	}
}





func (a *Auth) decorate(ip string) string {
	if !a.cfg.UseEnrich && !a.cfg.UsePTR {
		return ip
	}
	var ptr string
	var asn int
	var asname, country string

	if a.enr != nil && a.cfg.UseEnrich {
		res := a.enr.Lookup(ip)
		ptr = strings.TrimSuffix(res.PTR, ".")
		asn = int(res.ASN)
		asname = res.ASNName
		country = res.Country
	}
	if a.cfg.UsePTR && ptr == "" {
		if names, _ := net.LookupAddr(ip); len(names) > 0 {
			ptr = strings.TrimSuffix(names[0], ".")
		}
	}
	parts := []string{ip}
	if ptr != "" { parts = append(parts, "("+ptr+")") }
	tag := strings.TrimSpace(strings.Join([]string{
		func() string { if asn > 0 { return strconv.Itoa(asn) } ; return "" }(),
		asname,
		country,
	}, " "))
	if tag != "" { parts = append(parts, "["+tag+"]") }
	return strings.Join(parts, " ")
}
