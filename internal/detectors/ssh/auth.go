package ssh

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

type AuthConfig struct {
	// source selection
	Mode        string        // "file" | "journal"
	LogPath     string        // used when Mode=file
	JournalUnit string        // used when Mode=journal

	// cadence
	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	// thresholds
	AuthFailPerIP   int
	AuthFailPerUser int
	DDOSPerIP       int

	// enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string

}

type pend struct {
	kindKey string // e.g. "AUTHFAIL|ip", "AUTHFAIL|user", "DDOS|ip"
	key     string // ip or username
	n       int
}

type Auth struct {
	cfg AuthConfig

	// identity + source
	name string
	src  core.LineSource

	// state

        pending    map[string]pend
        samples    *core.SampleRing
        gate       *core.AlertGate
        counts     *core.SlidingCounter
	lastHit map[string]time.Time        // (legacy) still here so cool() compiles

	// regexes
	reAuthFail    *regexp.Regexp
	reInvalidUser *regexp.Regexp
	reTooManyAuth *regexp.Regexp
	reDDOSBucket  *regexp.Regexp
	rePamAuthFail *regexp.Regexp

	// enrichment (same pattern as exim detectors)
	enr *enrich.Enricher
}

// -------- constructor --------

func NewAuth(cfg AuthConfig) *Auth {
	a := &Auth{cfg: cfg}
	a.samples = core.NewSampleRing(cfg.SampleLimit)
	a.gate    = core.NewAlertGate(cfg.Cooldown)
	a.counts  = core.NewSlidingCounter(cfg.Window, 0) // cap optional

	// useful base patterns (extend later as needed)
	a.reAuthFail = regexp.MustCompile(`(?i)failed (?:password|publickey|keyboard-interactive) for (?:invalid user )?(?P<user>[^\s]+).* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})`)
	a.reInvalidUser = regexp.MustCompile(`(?i)(?:illegal|invalid) user (?P<user>[^\s]+).* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})`)
	a.reTooManyAuth = regexp.MustCompile(`(?i)too many authentication failures(?: for (?P<user>[^\s]+))?`)
	a.reDDOSBucket = regexp.MustCompile(`(?i)(?:Did not receive identification string from|kex_exchange_identification|Bad protocol version identification|banner exchange|ssh_dispatch_run_fatal|Connection (?:closed|reset) by peer|Timeout before authentication).*?(?:from )?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})`)
	a.rePamAuthFail = regexp.MustCompile(`(?i)pam.*authentication failure.*rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:.*user=(?P<user>[^\s]+))?`)

	// enricher like exim: build once, use per lookup
	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			a.enr = e
			logging.Logf("[detectors] ssh/auth enrichment enabled (dirs=%v)", cfg.EnrichDirs)
		} else {
			logging.Logf("[detectors] ssh/auth enrichment unavailable; PTR only")
		}
	}

	return a
}

// -------- PeriodicDetector --------

func (a *Auth) Name() string         { if a.name != "" { return a.name } ; return "ssh/auth" }
func (a *Auth) Every() time.Duration { if a.cfg.Every > 0 { return a.cfg.Every } ; return 2 * time.Second }

// -------- PositionAware --------

func (a *Auth) ApplyPosition(p core.Position) {
	if ft, ok := a.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
	if jt, ok := a.src.(*core.JournalTailer); ok {
		// journald uses timestamp only
		jt.ApplyResume(0, 0, p.TS)
	}
}

func (a *Auth) Position() core.Position {
	if a.src == nil {
		return core.Position{}
	}
	off, ino, ts := a.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

// wiring from factory
func (a *Auth) SetName(n string)             { a.name = n }
func (a *Auth) SetSource(src core.LineSource) { a.src = src }

// -------- run loop --------

func (a *Auth) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// reset per-run aggregation
	if a.pending == nil {
		a.pending = make(map[string]pend)
	} else {
		for k := range a.pending {
			delete(a.pending, k)
		}
	}

	// open once per tick
	if a.src == nil {
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

	if os.Getenv("CFM_DEBUG") == "2" && lines > 0 {
		logging.Logf("[detectors] ssh/auth scanned %d new lines", lines)
	}
	return nil
}

// -------- parsing & aggregation --------

func (a *Auth) processLine(now time.Time, line string) {
	l := line

	// 1) failed password/publickey/keyboard-interactive
	if m := a.reAuthFail.FindStringSubmatch(l); m != nil {
		u := sub(m, a.reAuthFail, "user")
		ip := sub(m, a.reAuthFail, "ip")
		if ip != "" {
			a.bump(now, "AUTHFAIL|ip", ip, line)
		}
		if u != "" {
			a.bump(now, "AUTHFAIL|user", strings.ToLower(u), line)
		}
		return
	}

	// 2) illegal/invalid user
	if m := a.reInvalidUser.FindStringSubmatch(l); m != nil {
		u := sub(m, a.reInvalidUser, "user")
		ip := sub(m, a.reInvalidUser, "ip")
		if ip != "" {
			a.bump(now, "AUTHFAIL|ip", ip, line)
		}
		if u != "" {
			a.bump(now, "AUTHFAIL|user", strings.ToLower(u), line)
		}
		return
	}

	// 3) PAM auth failures (rhost=, optional user=)
	if m := a.rePamAuthFail.FindStringSubmatch(l); m != nil {
		ip := sub(m, a.rePamAuthFail, "ip")
		u := sub(m, a.rePamAuthFail, "user")
		if ip != "" {
			a.bump(now, "AUTHFAIL|ip", ip, line)
		}
		if u != "" {
			a.bump(now, "AUTHFAIL|user", strings.ToLower(u), line)
		}
		return
	}

	// 4) Too many authentication failures
	if m := a.reTooManyAuth.FindStringSubmatch(l); m != nil {
		if u := sub(m, a.reTooManyAuth, "user"); u != "" {
			a.bump(now, "AUTHFAIL|user", strings.ToLower(u), line)
		}
		// cheap ip fallback
		if ip := cheapIP(l); ip != "" {
			a.bump(now, "AUTHFAIL|ip", ip, line)
		}
		return
	}

	// 5) DDoS-ish protocol/banners/resets/timeouts
	if m := a.reDDOSBucket.FindStringSubmatch(l); m != nil {
		ip := sub(m, a.reDDOSBucket, "ip")
		if ip == "" {
			ip = cheapIP(l)
		}
		if ip != "" {
			a.bump(now, "DDOS|ip", ip, line)
		}
		return
	}

	// else ignore
}



func (a *Auth) bump(now time.Time, kindKey, key, line string) {
    sk := kindKey + ":" + key

    // samples (ring)
    a.samples.Add(sk, line)

    // mark as touched this tick (no per-tick increment anymore)
    p := a.pending[sk]
    p.kindKey, p.key = kindKey, key
    a.pending[sk] = p

    // real counting happens in the sliding window
    _ = a.counts.Add(sk, now)
}




// -------- flush --------

func (a *Auth) flush(now time.Time, out chan<- core.Alert) {
    for _, p := range a.pending {
        limit, kindStr, baseKey := a.thresholdAndKey(p.kindKey, p.key)

        sk := p.kindKey + ":" + p.key
        n := a.counts.Count(sk, now)
        if !a.gate.Allow(sk, now, n, limit) {
            continue
        }

        displayKey := a.enrichDisplay(p.kindKey, baseKey, p.key)

        samples := a.samples.GetAndClear(sk)

        extra := map[string]string{
            "window":   a.cfg.Window.String(),
            "cooldown": a.cfg.Cooldown.String(),
            "limit":    strconv.Itoa(limit),
            "mode":     a.cfg.Mode,
        }
        if a.cfg.Mode == "file" {
            extra["log"] = a.cfg.LogPath
        } else {
            extra["unit"] = a.cfg.JournalUnit
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


func (a *Auth) thresholdAndKey(kindKey, rawKey string) (limit int, alertKind, baseKey string) {
	switch kindKey {
	case "AUTHFAIL|ip":
		return a.cfg.AuthFailPerIP, "SSH/AUTHFAIL", rawKey
	case "AUTHFAIL|user":
		return a.cfg.AuthFailPerUser, "SSH/AUTHFAIL", rawKey
	case "DDOS|ip":
		return a.cfg.DDOSPerIP, "SSH/DDOS", rawKey
	default:
		return 0, "", rawKey
	}
}

func (a *Auth) cool(sk string, now time.Time) bool {
	cd := a.cfg.Cooldown
	if cd <= 0 {
		cd = 10 * time.Minute
	}
	if last, ok := a.lastHit[sk]; ok {
		if now.Sub(last) < cd {
			return false
		}
	}
	a.lastHit[sk] = now
	return true
}

// -------- enrichment (same approach as exim) --------

func (a *Auth) enrichDisplay(kindKey, baseKey, rawKey string) string {
	// Only IP keys are enriched
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

// -------- helpers --------

func sub(m []string, re *regexp.Regexp, name string) string {
	idx := re.SubexpIndex(name)
	if idx >= 0 && idx < len(m) {
		return m[idx]
	}
	return ""
}

var cheapIPRe = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

func cheapIP(s string) string {
	m := cheapIPRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}
