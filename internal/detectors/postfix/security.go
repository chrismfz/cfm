package postfix

import (
    "context"
    "fmt"
    "io"
    "regexp"
    "strconv"
    "strings"
    "sync"
    "time"

    core "cfm/internal/detectors/core"
    "cfm/internal/enrich"
    "cfm/internal/logging"
)

// Config for postfix_security (similar to exim.SecConfig)
type SecConfig struct {
    LogPath       string        // file tail mode
    JournalUnit   string        // journald unit (e.g. postfix@-.service)
    JournalMatch  string        // optional extra match, e.g. "_SYSTEMD_UNIT=postfix@-.service"
    Every         time.Duration
    Window        time.Duration
    SampleLimit   int
    Cooldown      time.Duration
    UseEnrich     bool
    UsePTR        bool
    EnrichDirs    []string
    Thresholds    map[string]int
}

// internal rule descriptor
type secRule struct {
    Name string
    Desc string
    Re   *regexp.Regexp
}

type pend struct {
    kindKey string
    key     string
}

// small per-user IP history (like exim)
type recentIPs struct {
    order []string
    set   map[string]struct{}
}

func (r *recentIPs) Add(ip string, capN int) {
    if ip == "" {
        return
    }
    if r.set == nil {
        r.set = make(map[string]struct{})
    }
    if _, ok := r.set[ip]; ok {
        return
    }
    r.order = append(r.order, ip)
    r.set[ip] = struct{}{}
    if capN > 0 && len(r.order) > capN {
        old := r.order[0]
        r.order = r.order[1:]
        delete(r.set, old)
    }
}

func (r *recentIPs) CSV() (string, int) {
    return strings.Join(r.order, ","), len(r.order)
}

type PostfixSecurity struct {
    cfg SecConfig

    mu       sync.Mutex
    name     string
    path     string   // for file-mode; used only for Extra["log"]
    src      core.LineSource
    state    *core.State
    readyLog bool

    samples *core.SampleRing
    gate    *core.AlertGate
    counts  *core.SlidingCounter

    pending map[string]pend
    rules   []secRule
    enr     *enrich.Enricher

    userIPs map[string]*recentIPs

    reBracketIP *regexp.Regexp // [1.2.3.4]
    reRBLAddr   *regexp.Regexp // addr 1.2.3.4 listed by domain
    reSaslUser  *regexp.Regexp // sasl_username=...
}

// ---- constructor -----------------------------------------------------------

func NewSecurity(cfg SecConfig) *PostfixSecurity {
    if cfg.Every <= 0 {
        cfg.Every = 2 * time.Second
    }
    if cfg.Window <= 0 {
        cfg.Window = 15 * time.Minute
    }
    if cfg.SampleLimit <= 0 {
        cfg.SampleLimit = 10
    }
    if cfg.Cooldown <= 0 {
        cfg.Cooldown = 20 * time.Minute
    }
    if cfg.Thresholds == nil {
        cfg.Thresholds = make(map[string]int)
    }
    if !cfg.UseEnrich && !cfg.UsePTR {
        cfg.UsePTR = true
    }
    if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
        cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
    }

    // some sane defaults (override via config)
    defaults := map[string]int{
        "AUTHFAIL":       10, // generic fallback
        "AUTHFAIL_IP":    8,
        "AUTHFAIL_USER":  6,
        "RELAY_DENIED":   4,
        "USER_UNKNOWN":   8,
        "RCPT_REJECT":    10,
        "RBL_HIT":        3,
        "NONSMTP_CMD":    4,
        "PIPELINING":     4,
        "TLS_ERR":        4,
    }
    for k, v := range defaults {
        if _, ok := cfg.Thresholds[k]; !ok {
            cfg.Thresholds[k] = v
        }
    }

    d := &PostfixSecurity{
        cfg:        cfg,
        reBracketIP: regexp.MustCompile(`\[(\d{1,3}(?:\.\d{1,3}){3})\]`),
        reRBLAddr:   regexp.MustCompile(`addr\s+(\d{1,3}(?:\.\d{1,3}){3})\s+listed by domain`),
        reSaslUser:  regexp.MustCompile(`sasl_username=([^\s,]+)`),
        userIPs:     make(map[string]*recentIPs),
    }

    d.samples = core.NewSampleRing(cfg.SampleLimit)
    d.gate = core.NewAlertGate(cfg.Cooldown)
    d.counts = core.NewSlidingCounter(cfg.Window, 0)

    if cfg.UseEnrich {
        if e, err := enrich.New(cfg.EnrichDirs...); err == nil {
            d.enr = e
        } else {
            logging.Logf("[detectors] postfix/security: enrich init failed: %v", err)
        }
    }

    return d
}

// ---- core.PeriodicDetector minimal hooks ----------------------------------

func (d *PostfixSecurity) Name() string { return d.name }
func (d *PostfixSecurity) SetName(n string) { d.name = n }

func (d *PostfixSecurity) SetState(st *core.State) { d.state = st }
func (d *PostfixSecurity) Every() time.Duration    { return d.cfg.Every }

// RunOnce will be wired to FileTailer / JournalTailer in next step.
// For now, assume d.src is already set by the factory.
func (d *PostfixSecurity) RunOnce(ctx context.Context, out chan<- core.Alert) error {
    if d.src == nil {
        return nil
    }
    now := time.Now()
    for {
        line, err := d.src.ReadNext(ctx)
        if err == io.EOF {
            break
        }
        if err != nil {
            break
        }
        d.processLine(now, line)
    }
    d.flush(now, out)
    if d.state != nil {
        d.state.Set(d.Name(), d.Position())
    }
    return nil
}

func (d *PostfixSecurity) ApplyPosition(p core.Position) {
    if d.src != nil {
        d.src.ApplyResume(p.Inode, p.Offset)
    }
}

func (d *PostfixSecurity) Position() core.Position {
    if d.src == nil {
        return core.Position{}
    }
    off, ino, ts := d.src.Position()
    return core.Position{Offset: off, Inode: ino, TS: ts}
}

// ---- line processing -------------------------------------------------------

func (d *PostfixSecurity) processLine(now time.Time, line string) {
    s := strings.ToLower(line)

    // Fast prefilter – must look like postfix/dnsblog/smtpd/etc.
    if !strings.Contains(s, "postfix/") && !strings.Contains(s, "dnsblog[") {
        return
    }

    // extract remote IP: bracketed form first
    ip := ""
    if ms := d.reBracketIP.FindAllStringSubmatch(line, -1); len(ms) > 0 {
        ip = ms[len(ms)-1][1]
    }

    for _, r := range d.rules {
        m := r.Re.FindStringSubmatch(line)
        if m == nil {
            continue
        }

        switch r.Name {
        case "AUTHFAIL":
            // SASL auth failed; we want per-IP and per-user
            if ip == "" {
                // no IP? still try to parse user, but skip IP-specific keys
                u := d.extractUser(line)
                if u != "" {
                    d.bump(now, "AUTHFAIL|user", u, line)
                }
                continue
            }
            u := d.extractUser(line)
            if u != "" {
                d.bump(now, "AUTHFAIL|ip", ip, line)
                d.bump(now, "AUTHFAIL|user", u, line)
                d.bump(now, "AUTHFAIL|userip", u+"@"+ip, line)
                d.addUserIP(u, ip)
            } else {
                d.bump(now, "AUTHFAIL|ip", ip, line)
            }

        case "RBL_HIT":
            // IP is not in brackets; extract from regex submatch
            hitIP := ip
            if len(m) >= 2 && m[1] != "" {
                hitIP = m[1]
            }
            if hitIP != "" {
                d.bump(now, "RBL_HIT", hitIP, line)
            }

        default:
            // generic IP-based rule
            if ip == "" {
                continue
            }
            d.bump(now, r.Name, ip, line)
        }
    }
}

func (d *PostfixSecurity) extractUser(line string) string {
    if m := d.reSaslUser.FindStringSubmatch(line); m != nil && m[1] != "" {
        return strings.ToLower(m[1])
    }
    return ""
}

func (d *PostfixSecurity) addUserIP(user, ip string) {
    if user == "" || ip == "" {
        return
    }
    d.mu.Lock()
    rp := d.userIPs[user]
    if rp == nil {
        rp = &recentIPs{}
        d.userIPs[user] = rp
    }
    d.mu.Unlock()
    rp.Add(ip, 20) // keep last ~20 distinct IPs per user
}

// ---- bump & flush (like EximSecurity) -------------------------------------

func (d *PostfixSecurity) bump(now time.Time, tag, key, line string) {
    sk := tag + ":" + key
    d.samples.Add(sk, line)
    _ = d.counts.Add(sk, now)
    if d.pending == nil {
        d.pending = make(map[string]pend)
    }
    d.pending[sk] = pend{kindKey: tag, key: key}
}

func (d *PostfixSecurity) flush(now time.Time, out chan<- core.Alert) {
    for sk, p := range d.pending {
        thr, kind, isIP, base := d.thresholdAndKey(p.kindKey, p.key)
        if thr <= 0 {
            continue
        }

        n := d.counts.Count(sk, now)
        if !d.gate.Allow(sk, now, n, thr) {
            continue
        }

        displayKey := base
        if isIP {
            displayKey = "ip " + base
            if d.cfg.UseEnrich || d.cfg.UsePTR {
                if meta := d.lookupMeta(base); meta != "" {
                    displayKey += " (" + meta + ")"
                }
            }
        }

        samples := d.samples.GetAndClear(sk)

        extra := map[string]string{
            "log":      d.path,
            "window":   d.cfg.Window.String(),
            "cooldown": d.cfg.Cooldown.String(),
            "limit":    strconv.Itoa(thr),
            "rule":     p.kindKey,
        }
        if isIP {
            extra["ip"] = base
        } else if rp := d.userIPs[base]; rp != nil {
            csv, cnt := rp.CSV()
            if cnt > 0 {
                extra["ips"], extra["unique_ips"] = csv, strconv.Itoa(cnt)
            }
        }

        out <- core.Alert{
            When:    now,
            Kind:    core.AlertKind(kind),
            Key:     displayKey,
            Count:   n,
            Samples: samples,
            Extra:   extra,
        }
    }
    d.pending = nil
}

func (d *PostfixSecurity) thresholdAndKey(kindKey, rawKey string) (thr int, alertKind string, isIP bool, base string) {
    // AUTHFAIL per-IP/per-user
    if strings.HasPrefix(kindKey, "AUTHFAIL|") {
        alertKind = "SECURITY/AUTHFAIL"
        base = rawKey
        if strings.HasSuffix(kindKey, "|ip") {
            thr = d.cfg.Thresholds["AUTHFAIL_IP"]
            if thr == 0 {
                thr = d.cfg.Thresholds["AUTHFAIL"]
            }
            return thr, alertKind, true, base
        }
        if strings.HasSuffix(kindKey, "|user") {
            thr = d.cfg.Thresholds["AUTHFAIL_USER"]
            if thr == 0 {
                thr = d.cfg.Thresholds["AUTHFAIL"]
            }
            return thr, alertKind, false, base
        }
        if strings.HasSuffix(kindKey, "|userip") {
            thr = d.cfg.Thresholds["AUTHFAIL"]
            return thr, alertKind, false, base
        }
    }

    // everything else is simple IP-based
    thr = d.cfg.Thresholds[kindKey]
    alertKind = "SECURITY/" + kindKey
    base = rawKey
    return thr, alertKind, true, base
}

func (d *PostfixSecurity) lookupMeta(ip string) string {
    if ip == "" {
        return ""
    }
    if d.enr != nil {
        if meta, err := d.enr.Lookup(ip); err == nil && meta != "" {
            return meta
        }
    }
    return ""
}
