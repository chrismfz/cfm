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
        Mode           string // "file" | "journal" | "docker"
        LogPath        string
        JournalUnit    string
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

	pending map[string]pend
	samples *core.SampleRing
	gate    *core.AlertGate
	counts  *core.SlidingCounter

	// regexes
	reQuick *regexp.Regexp
	reRip   *regexp.Regexp
	reUser  *regexp.Regexp

	enr *enrich.Enricher
}

func NewAuth(cfg Config) *Auth {

	// sensible defaults (Mode επιλέγεται κυρίως στο register)
	if cfg.Mode == "" { cfg.Mode = "file" }
	if cfg.LogPath == "" && cfg.Mode == "file" { cfg.LogPath = "/var/log/maillog" }
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
	// Lines we care about (keep this fast pre-filter)
        // Expanded to also catch:
        //   - auth-worker(...): Password mismatch
        //   - passwd-file(...): Password mismatch
        //   - imap-login: ... (auth failed, N attempts)
        //   - any "authentication failure" or "aborted login"
        a.reQuick = regexp.MustCompile(`dovecot:.*(auth failed|authentication failure|aborted login|password mismatch)`)
	a.reRip = regexp.MustCompile(`\brip=([0-9a-f:.]+)(?:[,\s]|$)`)
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
	if a.src == nil { return core.Position{} }
	off, ino, ts := a.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

// State wiring
func (a *Auth) SetState(st *core.State, key string) { a.state = st; a.stateKey = key }



// ---------- run loop ----------
func (a *Auth) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// reset pending map
	for k := range a.pending { delete(a.pending, k) }

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
    if !a.reQuick.MatchString(ll) { return }



    // Ignore pure noise:
    // e.g. "Aborted login by logging out (no auth attempts in 0 secs)"
    if strings.Contains(ll, "no auth attempts in 0 secs") {
        return
    }



	// ip
    ipStr := ""
    if m := a.reRip.FindStringSubmatch(ll); m != nil && m[1] != "" {
        ipStr = m[1]
    } else {
        ipStr = firstIPInLine(ll)
    }
    if ipStr != "" {
        if ip := net.ParseIP(ipStr); ip != nil {
            if v4 := ip.To4(); v4 != nil {
                a.bump(now, "AUTHFAIL|ip", v4.String(), line)
            } else {
                a.bump(now, "AUTHFAIL|ip", ip.String(), line)
            }
        }
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


func (a *Auth) bump(now time.Time, kindKey, key, line string) {
	sk := kindKey + ":" + key
	if _, ok := a.pending[sk]; !ok {
		a.pending[sk] = pend{kindKey: kindKey, key: key}
	}
	_ = a.counts.Add(sk, now)
	a.samples.Add(sk, line)
}

// ---------- flush ----------
func (a *Auth) flush(now time.Time, out chan<- core.Alert) {

	for sk, p := range a.pending {
		limit, kindStr, baseKey := a.thresholdAndKey(p.kindKey, p.key)
		if limit <= 0 { continue }
		n := a.counts.Count(sk, now)
		if n < limit { continue }
		if !a.gate.Allow(sk, now, n, limit) { continue }

		displayKey := a.enrichDisplay(p.kindKey, baseKey, p.key)

		samples := a.samples.GetAndClear(sk)
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
