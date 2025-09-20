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
	n       int
}

type Auth struct {
	cfg  Config
	name string
	src  core.LineSource

	pending map[string]pend
	samples map[string][]string
	lastHit map[string]time.Time

	// fast prefilters
	reQuick *regexp.Regexp

	// extractors (shared across daemons)
	rePamHost  *regexp.Regexp // pam_unix(...): ... rhost=IP user=USER
	reVsFail   *regexp.Regexp // FAIL LOGIN: Client "IP"
	reBracketH *regexp.Regexp // (host[IP])  proftpd style
	rePureAt   *regexp.Regexp // (user@IP)   pure-ftpd style
	reUserKV   *regexp.Regexp // user=<USER> or user=USER
	reUserVs   *regexp.Regexp // \[USER\] in vsftpd prefix

	enr *enrich.Enricher
}

func NewAuth(cfg Config) *Auth {
	a := &Auth{cfg: cfg}
	a.pending = make(map[string]pend)
	a.samples = make(map[string][]string)
	a.lastHit = make(map[string]time.Time)

	// quick filter if line looks ftp-ish & failed
	a.reQuick = regexp.MustCompile(`(?i)(vsftpd|pure-?ftpd|proftpd|ftp-login).*?(fail|failed|violation|authentication failure|maximum login)`)

	// common extractors
	a.rePamHost  = regexp.MustCompile(`\brhost=(\d{1,3}(?:\.\d{1,3}){3})\b`)
	a.reVsFail   = regexp.MustCompile(`FAIL LOGIN: Client "(\d{1,3}(?:\.\d{1,3}){3})"`)
	a.reBracketH = regexp.MustCompile(`\([^\[]*\[(\d{1,3}(?:\.\d{1,3}){3})\]\)`)
	a.rePureAt   = regexp.MustCompile(`\([^@]+@(\d{1,3}(?:\.\d{1,3}){3})\)`)
	a.reUserKV   = regexp.MustCompile(`\buser=<([^>]+)>|\buser=([^\s,]+)`)
	a.reUserVs   = regexp.MustCompile(`\[[^\]]+\]\s+FAIL LOGIN:`) // vsftpd: pid [USER] FAIL LOGIN:

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

func (a *Auth) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// reset batch
	for k := range a.pending { delete(a.pending, k) }

	if a.src == nil {
		return nil
	}
	if err := a.src.Open(); err != nil {
		return nil
	}
	defer a.src.Close()

	now := time.Now()
	for {
		select {
		case <-ctx.Done():
			a.flush(now, out)
			return nil
		default:
		}
		line, err := a.src.ReadNext(ctx)
		if err == io.EOF { break }
		if err != nil { break }
		a.consume(now, line)
	}
	a.flush(now, out)
	return nil
}

func (a *Auth) consume(now time.Time, line string) {
	if !a.reQuick.MatchString(line) {
		return
	}
	ip := first(
		a.rePamHost.FindStringSubmatch(line),
		a.reVsFail.FindStringSubmatch(line),
		a.rePureAt.FindStringSubmatch(line),
		a.reBracketH.FindStringSubmatch(line),
	)
	if ip != "" {
		a.bump(now, "AUTHFAIL|ip", ip, line)
	}
	user := pickUser(a.reUserKV, line)
	if user == "" && a.reUserVs.MatchString(line) {
		// optional: try to pull the [USER] token from vsftpd prefix
		if m := regexp.MustCompile(`\[(?P<u>[^\]]+)\]\s+FAIL LOGIN:`).FindStringSubmatch(line); m != nil {
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

func (a *Auth) bump(now time.Time, kindKey, key, line string) {
	sk := kindKey + ":" + key
	p := a.pending[sk]
	p.kindKey, p.key, p.n = kindKey, key, p.n+1
	a.pending[sk] = p

	a.samples[sk] = append(a.samples[sk], line)
	if a.cfg.SampleLimit > 0 && len(a.samples[sk]) > a.cfg.SampleLimit {
		a.samples[sk] = a.samples[sk][len(a.samples[sk])-a.cfg.SampleLimit:]
	}
}

func (a *Auth) flush(now time.Time, out chan<- core.Alert) {
	for sk, p := range a.pending {
		limit, kindStr, isIP, base := a.thresholdAndKey(p.kindKey, p.key)
		if limit <= 0 || p.n < limit { continue }
		if !a.cool(sk, now) { continue }

		displayKey := base
		if isIP {
			displayKey = a.decorate(base)
		}
		samples := a.samples[sk]
		if a.cfg.SampleLimit > 0 && len(samples) > a.cfg.SampleLimit {
			samples = samples[:a.cfg.SampleLimit]
		}

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
			Count:   p.n,
			Samples: samples,
			Extra:   extra,
		}
		a.samples[sk] = nil
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




func (a *Auth) cool(sk string, now time.Time) bool {
	cd := a.cfg.Cooldown
	if cd <= 0 { cd = 10 * time.Minute }
	if last, ok := a.lastHit[sk]; ok && now.Sub(last) < cd {
		return false
	}
	a.lastHit[sk] = now
	return true
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
