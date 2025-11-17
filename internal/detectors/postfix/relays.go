package postfix

import (
    "context"
    "fmt"
    "io"
    "net"
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "time"

    core "cfm/internal/detectors/core"
    "cfm/internal/enrich"
    "cfm/internal/logging"
)

// ---- Config ----

type RelaysConfig struct {

	LogPath        string        // αν κενό, δοκιμάζουμε autoDetectPostfixLog()
	JournalUnit    string        // journald unit (optional)
	JournalMatch   string        // extra matches (optional)
	DockerContainer string       // docker logs mode (container name)
	DockerArgs      []string     // extra args to docker logs
	Every           time.Duration // default: 5s
	Window          time.Duration // default: 15m
	SampleLimit     int           // default: 10
	Cooldown        time.Duration // default: 10m

    // Thresholds (>= triggers)
    LocalUserMax   int // local submissions (postfix/pickup uid=...)
    AuthUserMax    int // authenticated user (sasl_username=user)
    AuthIPMax      int // authenticated IP (client=[ip], sasl_username=…)
    AuthUserIPMax  int // combined key ip/user
    UnauthIPMax    int // unauthenticated client ip (client=[ip] χωρίς sasl_username)

    // enrichment flags
    UseEnrich  bool
    UsePTR     bool
    EnrichDirs []string
}

// ---- Alert kinds ----

const (
    KindLocalRelay core.AlertKind = "LOCALRELAY"
    KindAuthRelay  core.AlertKind = "AUTHRELAY"
    KindRelay      core.AlertKind = "RELAY"
)

// ---- Detector ----

type Relays struct {
    cfg RelaysConfig

    samples *core.SampleRing
    gate    *core.AlertGate
    counts  *core.SlidingCounter

    path     string
    readyLog bool
    enr      *enrich.Enricher

    pending map[string]pend

    name string
    src  core.LineSource

}

type pend struct {
    kindKey string
    key     string
}

// Constructor
func NewRelays(cfg RelaysConfig) *Relays {
    if cfg.Every <= 0 {
        cfg.Every = 5 * time.Second
    }
    if cfg.Window <= 0 {
        cfg.Window = 15 * time.Minute
    }
    if cfg.SampleLimit <= 0 {
        cfg.SampleLimit = 10
    }
    if cfg.Cooldown <= 0 {
        cfg.Cooldown = 10 * time.Minute
    }

    if !cfg.UseEnrich && !cfg.UsePTR {
        cfg.UsePTR = true
    }
    if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
        cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
    }

    d := &Relays{cfg: cfg}
    d.samples = core.NewSampleRing(cfg.SampleLimit)
    d.gate = core.NewAlertGate(cfg.Cooldown)
    d.counts = core.NewSlidingCounter(cfg.Window, 0)

    if cfg.UseEnrich {
        if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
            d.enr = e
            logging.Logf("[detectors] postfix/relays enrichment enabled (dirs=%v)", cfg.EnrichDirs)
        } else {
            logging.Logf("[detectors] postfix/relays enrichment unavailable; falling back to PTR only")
        }
    }

    return d
}

func (d *Relays) Every() time.Duration { return d.cfg.Every }

// --- PositionAware / naming ---

func (d *Relays) Name() string {
    if d.name != "" {
        return d.name
    }
    return "postfix/relays"
}

func (d *Relays) SetName(n string) { d.name = n }

func (d *Relays) ApplyPosition(p core.Position) {
	if d.src == nil {
		return
	}
	switch t := d.src.(type) {
	case *core.FileTailer:
		t.ApplyResume(p.Inode, p.Offset)
	case *core.JournalTailer:
		t.ApplyResume(p.Inode, p.Offset, p.TS)
	case *core.DockerTailer:
		t.ApplyResume(p.Inode, p.Offset, p.TS)
	default:
		// unknown LineSource – τίποτα
	}


}

func (d *Relays) Position() core.Position {
    if d.src == nil {
        return core.Position{}
    }
    off, ino, ts := d.src.Position()
    return core.Position{Offset: off, Inode: ino, TS: ts}
}

// ---- RunOnce ----

func (d *Relays) RunOnce(ctx context.Context, out chan<- core.Alert) error {
    d.pending = make(map[string]pend)


	// 1) Select / init log source (μία φορά)
	if d.src == nil {
		switch {
		case d.cfg.JournalUnit != "" || d.cfg.JournalMatch != "":
			jt := core.NewJournalTailer(d.cfg.JournalUnit)
			if d.cfg.JournalMatch != "" {
				jt.Matches = strings.Fields(d.cfg.JournalMatch)
			}
			d.src = jt
			if d.path == "" {
				d.path = "journal:" + strings.TrimSpace(d.cfg.JournalUnit+" "+d.cfg.JournalMatch)
			}
			if !d.readyLog {
				logging.Logf("[detectors] postfix/relays using journald: %s", d.path)
				d.readyLog = true
			}

		case d.cfg.DockerContainer != "":
			d.src = core.NewDockerTailer(d.cfg.DockerContainer, d.cfg.DockerArgs...)
			if d.path == "" {
				d.path = "docker:" + d.cfg.DockerContainer
			}
			if !d.readyLog {
				logging.Logf("[detectors] postfix/relays using docker logs for container %s", d.cfg.DockerContainer)
				d.readyLog = true
			}

		default:
			// file mode (όπως πριν)
			if d.path == "" {
				if d.cfg.LogPath != "" {
					d.path = d.cfg.LogPath
				} else {
					d.path = autoDetectPostfixLog()
				}
				if d.path == "" {
					if !d.readyLog {
						logging.Logf("[detectors] postfix/relays: no log path found (set LOG_PATH)")
						d.readyLog = true
					}
					return nil
				}
			}
			if !d.readyLog {
				logging.Logf("[detectors] postfix/relays using log: %s", d.path)
				d.readyLog = true
			}
			d.src = core.NewFileTailer(d.path)
		}
	}


    if err := d.src.Open(); err != nil {
        // missing / rotated; θα ξαναδοκιμάσουμε στο επόμενο tick
        return nil
    }
    defer d.src.Close()

    now := time.Now()
    lines := 0

    for {
        line, err := d.src.ReadNext(ctx)
        if err == io.EOF {
            break
        }
        if err != nil {
            break
        }
        lines++
        d.processLine(now, line)
    }

    // 3) flush aggregated
    nowSend := time.Now()
    for _, p := range d.pending {
        thr, kind, baseKey := d.thresholdAndKey(p.kindKey, p.key)
        if thr <= 0 {
            continue
        }
        sk := p.kindKey + ":" + p.key
        n := d.counts.Count(sk, nowSend)
        if !d.gate.Allow(sk, nowSend, n, thr) {
            continue
        }

        displayKey := d.enrichDisplay(p.kindKey, baseKey, p.key)
        samples := d.samples.GetAndClear(sk)

        extra := map[string]string{
            "log":      d.path,
            "window":   d.cfg.Window.String(),
            "cooldown": d.cfg.Cooldown.String(),
            "limit":    fmt.Sprintf("%d", thr),
        }

        out <- core.Alert{
            When:    nowSend,
            Kind:    kind,
            Key:     displayKey,
            Count:   n,
            Samples: samples,
            Extra:   extra,
        }
    }

    if os.Getenv("CFM_DEBUG") == "2" && lines > 0 {
        logging.Logf("[detectors] postfix/relays scanned %d new lines", lines)
    }
    return nil
}

// ---- Parsing ----
//
// Στόχος: μετρώντας "γεννήσεις" μηνυμάτων από:
//
// 1) Local submissions:
//    postfix/pickup[PID]: QUEUEID: uid=1000 from=<...>
//
// 2) Auth submissions:
//    postfix/submission/smtpd[PID]: QUEUEID: client=host[1.2.3.4], sasl_method=..., sasl_username=user@site
//
// 3) Unauth SMTP/ESMTP:
//    postfix/smtpd[PID]: QUEUEID: client=host[1.2.3.4] proto=ESMTP ...
//

var (
    rePickupLocal = regexp.MustCompile(`postfix/pickup\[\d+\]: [0-9A-F]+: uid=(\d+)`)
    reClientLine  = regexp.MustCompile(`postfix/(?:submission/)?smtpd\[\d+\]: [0-9A-F]+: client=[^[]*\[([0-9a-fA-F\.:]+)\]`)
    reSASLUser    = regexp.MustCompile(`sasl_username=([^ ,>]+)`)
)

func (d *Relays) processLine(now time.Time, line string) {
    s := line

    // 1) Local relay via pickup (uid=N)
    if m := rePickupLocal.FindStringSubmatch(s); m != nil {
        uid := m[1]
        if uid != "" {
            d.bump(now, string(KindLocalRelay), uid, line)
        }
        return
    }

    // 2) Lines with client=[ip] from smtpd/submission
    if !strings.Contains(s, "postfix/") || !strings.Contains(s, "client=") {
        return
    }

    var ip, user string

    if m := reClientLine.FindStringSubmatch(s); m != nil {
        ip = m[1]
    }

    if m := reSASLUser.FindStringSubmatch(s); m != nil {
        user = m[1]
    }

    // Nothing interesting
    if ip == "" && user == "" {
        return
    }

    // AUTH relay (user+ip)
    if user != "" {
        d.bump(now, string(KindAuthRelay)+"|user", strings.ToLower(user), line)
    }
    if ip != "" {
        if user != "" {
            d.bump(now, string(KindAuthRelay)+"|userip", ip+"/"+strings.ToLower(user), line)
        } else {
            // UNAUTH relay (ip only)
            d.bump(now, string(KindRelay)+"|ip", ip, line)
        }
        if user != "" {
            d.bump(now, string(KindAuthRelay)+"|ip", ip, line)
        }
    }
}

// bump: προσθέτει sample + αυξάνει counter στο sliding window
func (d *Relays) bump(now time.Time, kindKey, key, line string) {
    sk := kindKey + ":" + key
    d.samples.Add(sk, line)
    _ = d.counts.Add(sk, now)
    if d.pending == nil {
        d.pending = make(map[string]pend)
    }
    d.pending[sk] = pend{kindKey: kindKey, key: key}
}

// thresholds / base alertKey
func (d *Relays) thresholdAndKey(kindKey, key string) (int, core.AlertKind, string) {
    switch kindKey {
    case string(KindLocalRelay):
        return d.cfg.LocalUserMax, KindLocalRelay, "Local uid " + key
    case string(KindAuthRelay) + "|user":
        return d.cfg.AuthUserMax, KindAuthRelay, "user " + key
    case string(KindAuthRelay) + "|ip":
        return d.cfg.AuthIPMax, KindAuthRelay, "ip " + key
    case string(KindAuthRelay) + "|userip":
        return d.cfg.AuthUserIPMax, KindAuthRelay, "ip/user " + key
    case string(KindRelay) + "|ip":
        return d.cfg.UnauthIPMax, KindRelay, "ip " + key
    }
    return 0, "", key
}

// εμπλουτισμός displayKey (Geo/ASN/PTR) όπου υπάρχει IP
func (d *Relays) enrichDisplay(kindKey, alertKey, rawKey string) string {
    displayKey := alertKey
    if !(strings.HasPrefix(kindKey, string(KindRelay)) || strings.Contains(kindKey, "|ip")) {
        return displayKey
    }
    if !(d.cfg.UseEnrich || d.cfg.UsePTR) {
        return displayKey
    }

    // extract IP από rawKey ("1.2.3.4" ή "1.2.3.4/user")
    ip := rawKey
    if i := strings.IndexByte(ip, '/'); i > 0 {
        ip = ip[:i]
    }
    if ip == "" {
        return displayKey
    }
    if meta := d.lookupMeta(ip); meta != "" {
        if strings.HasPrefix(displayKey, "ip/user ") {
            rest := displayKey[len("ip/user "):]
            if i := strings.IndexByte(rest, '/'); i > 0 {
                return "ip/user " + ip + " (" + meta + ")/" + rest[i+1:]
            }
            return displayKey
        }
        if strings.HasPrefix(displayKey, "ip ") {
            return "ip " + ip + " (" + meta + ")"
        }
        return displayKey + " (" + meta + ")"
    }
    return displayKey
}

// enrichment helper (ίδιο στυλ με exim/relays)
func (d *Relays) lookupMeta(ip string) string {
    if ip == "" {
        return ""
    }

    var country, city, ptr, asname string
    var asn uint

    if d.enr != nil {
        r := d.enr.Lookup(ip)
        if r.Country != "" {
            country = r.Country
        }
        if r.City != "" {
            city = r.City
        }
        if r.PTR != "" {
            ptr = strings.TrimSuffix(r.PTR, ".")
        }
        if r.ASN > 0 {
            asn = r.ASN
            asname = r.ASNName
        }
    }

    if d.cfg.UsePTR && ptr == "" {
        names, _ := net.LookupAddr(ip)
        if len(names) > 0 {
            ptr = strings.TrimSuffix(names[0], ".")
        }
    }

    geo := ""
    if country != "" || city != "" {
        if country == "" {
            country = "-"
        }
        if city == "" {
            city = "-"
        }
        geo = country + "/" + city
    }

    as := ""
    if asn > 0 && asname != "" {
        as = fmt.Sprintf("[AS%d %s", asn, asname)
    } else if asn > 0 {
        as = fmt.Sprintf("[AS%d", asn)
    }
    if ptr != "" {
        if as != "" {
            as += "; PTR " + ptr + "]"
        } else {
            as = "[PTR " + ptr + "]"
        }
    } else if as != "" {
        as += "]"
    }

    if geo != "" && as != "" {
        return geo + "/" + as
    }
    if geo != "" {
        return geo
    }
    return as
}

// απλό autodetect για Postfix log (μπορείς να το κάνεις πιο έξυπνο αργότερα)
func autoDetectPostfixLog() string {
    paths := []string{"/var/log/mail.log", "/var/log/maillog"}
    for _, p := range paths {
        if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
            return p
        }
    }
    // fallback: ψάξε λίγο στο /var/log
    var found string
    _ = filepath.Walk("/var/log", func(path string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() {
            return nil
        }
        base := filepath.Base(path)
        if base == "mail.log" || base == "maillog" {
            found = path
            return filepath.SkipDir
        }
        return nil
    })
    return found
}
