package cpanel

import (
	"context"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/enrich"
	"cfm/internal/logging"
)

type LoginConfig struct {
	// source selection
	Mode    string        // "file" only for now (login_log isn't in journal)
	LogPath string        // default: /usr/local/cpanel/logs/login_log

	// cadence
	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	// thresholds
	AuthFailPerIP   int
	AuthFailPerUser int
	RootFailPerIP   int // optional: stricter for WHM root attempts

	// enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string
}

type pend struct {
	kindKey string // e.g. "AUTHFAIL|ip", "AUTHFAIL|user", "ROOT|ip"
	key     string // ip or username
}

type Login struct {
	cfg LoginConfig

	// identity + source
	name string
	src  core.LineSource

	// state
	pending map[string]pend
	samples *core.SampleRing
	gate    *core.AlertGate
	counts  *core.SlidingCounter
	// regexes (multiple formats in login_log)
	// 1) Bracketed cpaneld/whostmgrd/webmaild:
	// [YYYY-MM-DD hh:mm:ss +TZ] info [svc] IP - user "..." FAILED LOGIN svc: <reason...>
	reBracket *regexp.Regexp

	// 2) cpdavd plain format:
	// IP - user [DD/MM/YYYY:hh:mm:ss -0000] "VERB" FAILED LOGIN cpdavd: Authentication failed for user: user
	reDavd *regexp.Regexp

	// 3) Some variants: "invalid user name specified", "invalid cpanel user X (has_cpuser_file failed)", etc.
	// Covered via generic FAILED LOGIN capture above, but we keep a fallback for robustness:
	reGeneric *regexp.Regexp

	// enrichment
	enr *enrich.Enricher
}

func NewLogin(cfg LoginConfig) *Login {
	// sensible defaults
	if cfg.Mode == "" { cfg.Mode = "file" }
	if cfg.LogPath == "" { cfg.LogPath = "/usr/local/cpanel/logs/login_log" }
	if cfg.Every <= 0 { cfg.Every = 2 * time.Second }
	if cfg.Window <= 0 { cfg.Window = 15 * time.Minute }
	if cfg.Cooldown <= 0 { cfg.Cooldown = 20 * time.Minute }
	if cfg.SampleLimit <= 0 { cfg.SampleLimit = 10 }
	if !cfg.UseEnrich && !cfg.UsePTR { cfg.UsePTR = true }
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/usr/share/GeoIP", "/usr/local/share/GeoIP", "./configs"}
	}

	l := &Login{cfg: cfg}
	l.pending = make(map[string]pend)
	// core window primitives
	l.samples = core.NewSampleRing(cfg.SampleLimit)
	l.gate    = core.NewAlertGate(cfg.Cooldown)
	l.counts  = core.NewSlidingCounter(cfg.Window, 0) // cap=0 → unbounded per-key

	// IPv4/IPv6 tolerant ip token (not hyper-strict on v6)
	ipTok := `(?P<ip>[0-9a-fA-F:\.]+)`
	userTok := `(?P<user>[^"\s]+)`
	svcTok := `(?P<svc>[a-zA-Z0-9_]+)`

	// Examples handled:
	// [2025-09-10 13:14:33 +0300] info [whostmgrd] 156.228.113.227 - root "GET ... " FAILED LOGIN whostmgrd: user password incorrect
	// [2025-09-10 16:13:59 +0300] info [cpaneld] 34.26.85.25 - 2083 "POST ... " FAILED LOGIN cpaneld: invalid user name specified
	// [2025-09-09 22:24:30 +0300] info [webmaild] 154.255.80.148 - info@... "GET ... " FAILED LOGIN webmaild: user password incorrect
	l.reBracket = regexp.MustCompile(
		`^\[\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[+\-]\d{4}\]\s+info\s+\[` + svcTok + `\]\s+` + ipTok + `\s+-\s+` + userTok + `\s+".*?"\s+FAILED LOGIN\s+` + svcTok + `:`,
	)

	// cpdavd format samples:
	// 127.0.0.1 - user [09/10/2025:07:46:04 -0000] "PROPFIND" FAILED LOGIN cpdavd: Authentication failed for user: user
	l.reDavd = regexp.MustCompile(
		`^` + ipTok + `\s+-\s+` + userTok + `\s+\[[^\]]+\]\s+"[A-Z]+"(?:\s+[^"]*)?\s+FAILED LOGIN\s+cpdavd:`,
	)

	// Fallback: just find FAILED LOGIN and try to pick ip/user cheaply
	l.reGeneric = regexp.MustCompile(`(?i)FAILED LOGIN`)

	// enrichment
	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			l.enr = e
			logging.Logf("[detectors] cpanel/login enrichment enabled (dirs=%v)", cfg.EnrichDirs)
		} else {
			logging.Logf("[detectors] cpanel/login enrichment unavailable; PTR only")
		}
	}

	return l
}

// -------- PeriodicDetector --------

func (l *Login) Name() string         { if l.name != "" { return l.name } ; return "cpanel/login" }
func (l *Login) Every() time.Duration { if l.cfg.Every > 0 { return l.cfg.Every } ; return 2 * time.Second }

// -------- PositionAware --------

func (l *Login) ApplyPosition(p core.Position) {
	if ft, ok := l.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
}

func (l *Login) Position() core.Position {
	if l.src == nil {
		return core.Position{}
	}
	off, ino, ts := l.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

// wiring from factory
func (l *Login) SetName(n string)             { l.name = n }
func (l *Login) SetSource(src core.LineSource) { l.src = src }

// -------- run loop --------

func (l *Login) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// reset per-run aggregation
	if l.pending == nil {
		l.pending = make(map[string]pend)
	} else {
		for k := range l.pending {
			delete(l.pending, k)
		}
	}

	if l.src == nil {
		return nil
	}
	if err := l.src.Open(); err != nil {
		return nil
	}
	defer l.src.Close()

	now := time.Now()
	lines := 0

	for {
		line, err := l.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		lines++
		l.processLine(now, line)
	}

	l.flush(now, out)

	if os.Getenv("CFM_DEBUG") == "2" && lines > 0 {
		logging.Logf("[detectors] cpanel/login scanned %d new lines", lines)
	}
	return nil
}

// -------- parsing & aggregation --------

func (l *Login) processLine(now time.Time, line string) {
	s := line

	// 1) Bracketed (cpaneld/whostmgrd/webmaild)
	if m := l.reBracket.FindStringSubmatch(s); m != nil {
		ip := sub(m, l.reBracket, "ip")
		user := sub(m, l.reBracket, "user")
		svc := sub(m, l.reBracket, "svc")
		if ip != "" {
			if svc == "whostmgrd" && strings.EqualFold(user, "root") && l.cfg.RootFailPerIP > 0 {
				l.bump(now, "ROOT|ip", ip, line)
			} else {
				l.bump(now, "AUTHFAIL|ip", ip, line)
			}
		}
		if user != "" {
			l.bump(now, "AUTHFAIL|user", strings.ToLower(user), line)
		}
		return
	}

	// 2) cpdavd (WebDAV/WebDisk)
	if m := l.reDavd.FindStringSubmatch(s); m != nil {
		ip := sub(m, l.reDavd, "ip")
		user := sub(m, l.reDavd, "user")
		if ip != "" {
			l.bump(now, "AUTHFAIL|ip", ip, line)
		}
		if user != "" {
			l.bump(now, "AUTHFAIL|user", strings.ToLower(user), line)
		}
		return
	}

	// 3) Fallback: FAILED LOGIN seen; try a cheap IP + user snatch
	if l.reGeneric.MatchString(s) {
		if ip := cheapIP(s); ip != "" {
			l.bump(now, "AUTHFAIL|ip", ip, line)
		}
		if u := cheapUserGuess(s); u != "" {
			l.bump(now, "AUTHFAIL|user", strings.ToLower(u), line)
		}
	}
}

func (l *Login) bump(now time.Time, kindKey, key, line string) {
	sk := kindKey + ":" + key
	l.samples.Add(sk, line)
	_ = l.counts.Add(sk, now)
	if _, ok := l.pending[sk]; !ok {
		l.pending[sk] = pend{kindKey: kindKey, key: key}
	}
}

// -------- flush --------

func (l *Login) flush(now time.Time, out chan<- core.Alert) {

	for _, p := range l.pending {
		limit, kindStr, baseKey := l.thresholdAndKey(p.kindKey, p.key)
		if limit <= 0 {
			continue
		}
		sk := p.kindKey + ":" + p.key
		n := l.counts.Count(sk, now)
		if n < limit { continue }
		if !l.gate.Allow(sk, now, n, limit) { continue }


		displayKey := l.enrichDisplay(p.kindKey, baseKey, p.key)

		samples := l.samples.GetAndClear(sk)

		extra := map[string]string{
			"window":   l.cfg.Window.String(),
			"cooldown": l.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(limit),
			"mode":     l.cfg.Mode,
			"log":      l.cfg.LogPath,
		}

		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind(kindStr),
			Key:     displayKey,
			Count:   n,
			Samples: samples,
			Extra:   extra,
		}

	}
}

func (l *Login) thresholdAndKey(kindKey, rawKey string) (limit int, alertKind, baseKey string) {
	switch kindKey {
	case "AUTHFAIL|ip":
		return l.cfg.AuthFailPerIP, "CPANEL/AUTHFAIL", rawKey
	case "AUTHFAIL|user":
		return l.cfg.AuthFailPerUser, "CPANEL/AUTHFAIL", rawKey
	case "ROOT|ip":
		lim := l.cfg.RootFailPerIP
		if lim <= 0 { lim = l.cfg.AuthFailPerIP }
		return lim, "CPANEL/ROOT", rawKey
	default:
		return 0, "", rawKey
	}
}

// cooldown handled by core.AlertGate

// -------- enrichment (same approach as SSH) --------

func (l *Login) enrichDisplay(kindKey, baseKey, rawKey string) string {
	if !strings.Contains(kindKey, "|ip") {
		return baseKey
	}
	if !l.cfg.UseEnrich && !l.cfg.UsePTR {
		return baseKey
	}
	ip := rawKey

	var ptr, country, asname string
	var asn int

	if l.enr != nil && l.cfg.UseEnrich {
		res := l.enr.Lookup(ip)
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
	if l.cfg.UsePTR && ptr == "" {
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

// -------- helpers --------

func sub(m []string, re *regexp.Regexp, name string) string {
	idx := re.SubexpIndex(name)
	if idx >= 0 && idx < len(m) {
		return m[idx]
	}
	return ""
}

var cheapIPRe = regexp.MustCompile(`\b([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]{2,})\b`)

func cheapIP(s string) string {
	m := cheapIPRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

// try to fish a user token after ' - ' or before quotes if present
var cheapUserRe = regexp.MustCompile(`-\s+([^\s"\[]+)`)
func cheapUserGuess(s string) string {
	if m := cheapUserRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}
