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
	Mode        string // "file" | "journal"
	LogPath     string
	JournalUnit string

	// cadence
	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	// thresholds
	AuthFailPerIP   int
	AuthFailPerUser int

	// enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string
}

type pend struct {
	kindKey string // "AUTHFAIL|ip" | "AUTHFAIL|user"
	key     string // ip or username
	n       int
}

type Auth struct {
	cfg  Config
	name string
	src  core.LineSource

	pending map[string]pend
	samples map[string][]string
	lastHit map[string]time.Time

	// regexes
	reQuick *regexp.Regexp
	reRip   *regexp.Regexp
	reUser  *regexp.Regexp

	enr *enrich.Enricher
}

func NewAuth(cfg Config) *Auth {
	a := &Auth{cfg: cfg}
	a.pending = make(map[string]pend)
	a.samples = make(map[string][]string)
	a.lastHit = make(map[string]time.Time)

	// Lines we care about (keep this fast pre-filter)
	a.reQuick = regexp.MustCompile(`dovecot:\s+(imap|pop3)-login:.*(auth failed|Aborted login|Authentication failure)`)
	a.reRip   = regexp.MustCompile(`\brip=(\d{1,3}(?:\.\d{1,3}){3})\b`)
	a.reUser  = regexp.MustCompile(`\buser=<([^>]+)>\b`)

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
func (a *Auth) SetName(n string)             { a.name = n }
func (a *Auth) SetSource(src core.LineSource) { a.src = src }

func (a *Auth) Name() string {
	if a.name != "" { return a.name }
	return "dovecot/auth"
}
func (a *Auth) Every() time.Duration {
	if a.cfg.Every > 0 { return a.cfg.Every }
	return 2 * time.Second
}

// PositionAware (optional) — keep parity with ssh detector
func (a *Auth) ApplyPosition(p core.Position) {
	if ft, ok := a.src.(*core.FileTailer); ok { ft.ApplyResume(p.Inode, p.Offset) }
	if jt, ok := a.src.(*core.JournalTailer); ok { jt.ApplyResume(0, 0, p.TS) }
}
func (a *Auth) Position() core.Position {
	if a.src == nil { return core.Position{} }
	off, ino, ts := a.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

// ---------- run loop ----------
func (a *Auth) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// reset pending map
	for k := range a.pending { delete(a.pending, k) }

	if a.src == nil {
		// source is wired by the factory; if nil, nothing to do
		return nil
	}
	if err := a.src.Open(); err != nil {
		return nil
	}
	defer a.src.Close()

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
	if !a.reQuick.MatchString(line) {
		return
	}
	// ip
	if m := a.reRip.FindStringSubmatch(line); m != nil && m[1] != "" {
		a.bump(now, "AUTHFAIL|ip", m[1], line)
	}
	// user
	if m := a.reUser.FindStringSubmatch(line); m != nil && m[1] != "" {
		u := strings.ToLower(m[1])
		a.bump(now, "AUTHFAIL|user", u, line)
	}
}

func (a *Auth) bump(now time.Time, kindKey, key, line string) {
	sk := kindKey + ":" + key
	p, ok := a.pending[sk]
	if !ok {
		p = pend{kindKey: kindKey, key: key}
	}
	p.n++
	a.pending[sk] = p

	// keep samples per key
	a.samples[sk] = append(a.samples[sk], line)
	if a.cfg.SampleLimit > 0 && len(a.samples[sk]) > a.cfg.SampleLimit {
		a.samples[sk] = a.samples[sk][len(a.samples[sk])-a.cfg.SampleLimit:]
	}
}

// ---------- flush ----------
func (a *Auth) flush(now time.Time, out chan<- core.Alert) {
	for sk, p := range a.pending {
		limit, kindStr, baseKey := a.thresholdAndKey(p.kindKey, p.key)
		if limit <= 0 || p.n < limit {
			continue
		}
		if !a.cool(sk, now) {
			continue
		}

		displayKey := a.enrichDisplay(p.kindKey, baseKey, p.key)
		samples := a.samples[sk]
		if a.cfg.SampleLimit > 0 && len(samples) > a.cfg.SampleLimit {
			samples = samples[:a.cfg.SampleLimit]
		}

		extra := map[string]string{
			"window":   a.cfg.Window.String(),
			"cooldown": a.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(limit),
			"mode":     a.cfg.Mode,
		}
		// help the sink pick an IP when alert is per-user
		if strings.Contains(p.kindKey, "|ip") {
			extra["ip"] = p.key
		}
		if a.cfg.Mode == "file" {
			extra["log"] = a.cfg.LogPath
		} else {
			extra["unit"] = a.cfg.JournalUnit
		}

		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind(kindStr), // "DOVECOT/AUTHFAIL"
			Key:     displayKey,
			Count:   p.n,
			Samples: samples,
			Extra:   extra,
		}
		// drop samples for next round
		a.samples[sk] = nil
	}
}

func (a *Auth) thresholdAndKey(kindKey, rawKey string) (limit int, alertKind, baseKey string) {
	switch kindKey {
	case "AUTHFAIL|ip":
		return a.cfg.AuthFailPerIP, "DOVECOT/AUTHFAIL", rawKey
	case "AUTHFAIL|user":
		return a.cfg.AuthFailPerUser, "DOVECOT/AUTHFAIL", rawKey
	default:
		return 0, "", rawKey
	}
}

func (a *Auth) cool(sk string, now time.Time) bool {
	cd := a.cfg.Cooldown
	if cd <= 0 {
		cd = 10 * time.Minute
	}
	if last, ok := a.lastHit[sk]; ok && now.Sub(last) < cd {
		return false
	}
	a.lastHit[sk] = now
	return true
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
			func() string { if asn > 0 { return strconv.Itoa(asn) } ; return "" }(),
			asname,
			country,
		}, " "))
		if tag != "" {
			parts = append(parts, "["+tag+"]")
		}
	}
	return strings.Join(parts, " ")
}
