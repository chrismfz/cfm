package exim

import (
//	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"net"
	"path/filepath"
	"io"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
	"cfm/internal/enrich"
)



type SecConfig struct {
	LogPath     string
	RejectPath  string
	Every       time.Duration
	Window      time.Duration
	SampleLimit int
	Cooldown    time.Duration

	RulesPath  string         // π.χ. /etc/cfm/exim_security.rules (προαιρετικό)
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string

	// thresholds per tag (αν δεν οριστούν στους κανόνες)
	Thresholds map[string]int

	// ignore CIDRs (optional, TODO)
	IgnoreCIDRs []string
}

type secRule struct {
	Name string // π.χ. AUTHFAIL
	Desc string
	Re   *regexp.Regexp // compiled
}

type EximSecurity struct {
	cfg SecConfig

	mu       sync.Mutex
	path     string
	rpaths   []string            // zero, one, or two: rejectlog / exim_rejectlog

	inode    uint64
	off      int64
	readyLog bool

	pending  map[string]pend
	rules    []secRule
	enr      *enrich.Enricher
	reHostIP *regexp.Regexp
	reSetID  *regexp.Regexp   // (set_id=foo)
	reUserAng*regexp.Regexp   // user=<foo>

	name string          // unique instance name (section)

    src   *core.FileTailer       // mainlog
    rsrcs []*core.FileTailer     // reject logs

	// per-user recent distinct IPs (small, capped)
	state *core.State
	userIPs map[string]*recentIPs
	reSrvPort *regexp.Regexp  // I=<server_ip>:<port> (for 465/587 inference)
	samples *core.SampleRing
	gate    *core.AlertGate
	counts  *core.SlidingCounter

}


// small deduped, ordered list
type recentIPs struct {
    order []string
    set   map[string]struct{}
}
func (r *recentIPs) Add(ip string, capN int) {
    if ip == "" { return }
    if r.set == nil { r.set = make(map[string]struct{}) }
    if _, ok := r.set[ip]; ok { return }
    r.order = append(r.order, ip)
    r.set[ip] = struct{}{}
    if capN > 0 && len(r.order) > capN {
        old := r.order[0]
        r.order = r.order[1:]
        delete(r.set, old)
    }
}

func (r *recentIPs) CSV() (csv string, n int) {
    return strings.Join(r.order, ","), len(r.order)
}


func NewSecurity(cfg SecConfig) *EximSecurity {
	if cfg.Every <= 0 { cfg.Every = 2 * time.Second }
	if cfg.Window <= 0 { cfg.Window = 15 * time.Minute }
	if cfg.SampleLimit <= 0 { cfg.SampleLimit = 10 }
	if cfg.Cooldown <= 0 { cfg.Cooldown = 20 * time.Minute }
	if !cfg.UseEnrich && !cfg.UsePTR { cfg.UsePTR = true }
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
	}

defaults := map[string]int{
			"AUTHFAIL":            10,
			"SENDER_VERIFY_FAIL":  10,
			"RCPT_REJECT":         10,
			"SYNC_ERR":             8,
			"PROTO_ERR":            8,
			"NO_MAIL":             10,
			"DROP_ACL":             6,
			"RCPT_AUTH_REQUIRED":      6,
			"NONMAIL_CMD":             4,
			"NO_HELO":                 6,
			"BAD_HELO_IMPERSONATION":  6,
			"HELO_SYNTAX":             6,
			"PIPELINING":              6,
			"SESSION_ALL_FAILED":     10, // "Detected session with all messages failed"
			"SLOW_FAIL_BLOCK":        10, // "Increment slow_fail_block Ratelimit"
		}


    if cfg.Thresholds == nil {
        cfg.Thresholds = defaults
    } else {
        // merge: keep existing keys, fill the rest from defaults
        for k, v := range defaults {
            if _, ok := cfg.Thresholds[k]; !ok {
                cfg.Thresholds[k] = v
            }
        }
    }


    d := &EximSecurity{
        cfg:      cfg,
        reHostIP: regexp.MustCompile(`\[((?:\d{1,3}(?:\.\d{1,3}){3})|[0-9a-fA-F:]+)\]`), // IPv4 ή IPv6 σε αγκύλες
        userIPs:  make(map[string]*recentIPs),
    }

    // init core window primitives
    d.samples = core.NewSampleRing(cfg.SampleLimit)
    d.gate    = core.NewAlertGate(cfg.Cooldown)
    d.counts  = core.NewSlidingCounter(cfg.Window, 0) // optional cap=0
    d.reSrvPort = regexp.MustCompile(`\bI=\S+:(\d{2,5})\b`)

    d.reSetID   = regexp.MustCompile(`\bset_id=([^) \t]+)`)
    d.reUserAng = regexp.MustCompile(`\buser=<([^>]+)>`)


	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			d.enr = e
			logging.Logf("[detectors] exim/security enrichment enabled (dirs=%v)", cfg.EnrichDirs)
		} else {
			logging.Logf("[detectors] exim/security enrichment unavailable; PTR only")
		}
	}
	d.loadRules()
	return d
}

func (d *EximSecurity) Name() string {
	if d.name != "" { return d.name }
	return "exim/security"
}

// SetState allows the register to inject a shared state handle.
func (d *EximSecurity) SetState(st *core.State) { d.state = st }


func (d *EximSecurity) Every() time.Duration { return d.cfg.Every }
//if you want to shave a bit more CPU, add a coarse strings.Contains(s, "rejected rcpt") / "authenticator failed" guard per rule before the regex .MatchString(s)
// φόρτωσε κανόνες από rules file ή βάλε defaults
func (d *EximSecurity) loadRules() {
	var raws = []struct{
		name, desc, re string
	}{

	{"AUTHFAIL", "SMTP AUTH failed", `(?:authenticator failed .* \[[^\]]+\].* 535 incorrect authentication data|smtp authentication failed\b|authentic(?:ate|ation) failed\b|plaintext authentication failure\b)`},
	{"SENDER_VERIFY_FAIL", "sender verify fail", `sender verify fail\b`},
	{"RCPT_REJECT", "RCPT rejected", `rejected rcpt\s+(?:<[^>]+>|[^: ]+)\s*:\s*(?:relay not permitted|rejected relay attempt|sender verify failed|unknown user|unrouteable address)`},
	{"SYNC_ERR", "protocol sync error", `smtp protocol synchronization error .* rejected .*`},
	{"PROTO_ERR", "AUTH used when not advertised", `smtp protocol error in ".*" .*auth command used when not advertised`},
	{"NO_MAIL", "no MAIL in SMTP connection", `no mail in smtp connection .*`},
	{"DROP_ACL", "closed by DROP in ACL", `smtp connection .* closed by drop in acl`},
	{"RCPT_AUTH_REQUIRED", "RCPT rejected: auth required on submission", `rejected rcpt\b.*:\s*(?:smtp )?auth (?:is )?required(?: for (?:message )?submission)?(?: on port \d+)?|rejected rcpt\b.*:\s*authentication required|rcpt .* rejected: authentication required`},
	{"NONMAIL_CMD", "Too many nonmail commands", `smtp call from \[[^\]]+\] dropped: too many nonmail commands`},
	{"NO_HELO", "No HELO/EHLO given", `rejected (?:mail|rcpt) .*: no helo/ehlo given`},
	{"BAD_HELO_IMPERSONATION", "Bad HELO impersonation", `bad helo - host impersonating domain name`},
	{"HELO_SYNTAX", "HELO/EHLO syntax error", `rejected (?:ehlo|helo)\b.*\b(?:syntax error|invalid|bad)\b`},
	{"PIPELINING", "Command pipelining / sync", `(?:pipelining not supported|command pipelining).*rejected|did not wait for response`},
	{"SESSION_ALL_FAILED", "Session all messages failed", `\bwarning:\s*"detected session with all messages failed"`},
	{"SLOW_FAIL_BLOCK", "Slow fail block ratelimit", `\bwarning:\s*"increment slow_fail_block ratelimit\b`},


	}
	// TODO: αν υπάρχει d.cfg.RulesPath → διάβασέ το (macros, κ.λπ.). Για αρχή βάλε τα defaults.
	d.rules = make([]secRule, 0, len(raws))
	for _, r := range raws {
		re := regexp.MustCompile(r.re)
		d.rules = append(d.rules, secRule{Name: r.name, Desc: r.desc, Re: re})
	}
	logging.Logf("[detectors] exim/security loaded %d rules", len(d.rules))
}

func (d *EximSecurity) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	// (1) ensure log path
	if d.path == "" {
		if d.cfg.LogPath != "" { d.path = d.cfg.LogPath } else { d.path = autoDetectEximLog() }
		if d.path == "" {
			if !d.readyLog {
				logging.Logf("[detectors] exim/security: no log path found (set LOG_PATH)")
				d.readyLog = true
			}
			return nil
		}

    // Decide reject logs:
    if d.rpaths == nil {
        d.rpaths = d.pickRejectLogs(d.path, d.cfg.RejectPath)
    }
    if !d.readyLog {
        logging.Logf("[detectors] exim/security using main log: %s", d.path)
        if len(d.rpaths) == 0 {
            logging.Logf("[detectors] exim/security no reject log found (looked for rejectlog/exim_rejectlog next to main or at REJECT_LOG_PATH)")
        } else {
            for _, p := range d.rpaths {
                logging.Logf("[detectors] exim/security using reject log: %s", p)
            }
        }
        d.readyLog = true
    }

	}

	// reset per-run aggregation
	d.pending = make(map[string]pend)


	// Prepare tailer and resume from state (after path is known)
	if d.src == nil {
		d.src = core.NewFileTailer(d.path)
	}

    if d.rsrcs == nil && len(d.rpaths) > 0 {
        for _, rp := range d.rpaths {
            d.rsrcs = append(d.rsrcs, core.NewFileTailer(rp))
        }
    }
	var stateKey string
	rStateKeys := make([]string, len(d.rsrcs))

	if d.state != nil && d.path != "" {
		stateKey = core.FileStateKey(d.Name(), d.path)
		if p, ok := d.state.Get(stateKey); ok {
			d.ApplyPosition(p)
		}
	}

    if d.state != nil && len(d.rsrcs) > 0 {
        for i, t := range d.rsrcs {
            if t == nil { continue }
            k := core.FileStateKey(d.Name(), d.rpaths[i])
            rStateKeys[i] = k
            if p, ok := d.state.Get(k); ok {
                t.ApplyResume(p.Inode, p.Offset)
            }
        }
    }


	if err := d.src.Open(); err != nil {
		// quiet: missing/rotating log; next tick will retry
		return nil
	}
	defer d.src.Close()
    // Open reject tailers (best-effort)
    for _, t := range d.rsrcs { if t != nil { _ = t.Open(); defer t.Close() } }

	// Always persist position on exit
	if stateKey != "" {
		defer func() {
			d.state.Put(stateKey, d.Position())
		}()
	}
    // Persist reject positions
    if len(rStateKeys) > 0 {
        defer func() {
            for i, t := range d.rsrcs {
                if t == nil || rStateKeys[i] == "" { continue }
                off, ino, ts := t.Position()
                d.state.Put(rStateKeys[i], core.Position{Offset: off, Inode: ino, TS: ts})
            }
        }()
    }

now := time.Now()
// drain mainlog
for {
	line, err := d.src.ReadNext(ctx)
	if err == io.EOF {
		break // caught up
	}
	if err != nil {
		break // transient read issue; retry next tick
	}
	d.processLine(now, line)
}
    // drain reject logs
    for _, t := range d.rsrcs {
        if t == nil { continue }
        for {
            line, err := t.ReadNext(ctx)
            if err == io.EOF { break }
            if err != nil    { break }
            d.processLine(now, line)
        }
    }

// flush aggregated alerts
d.flush(now, out)
return nil

}



func (d *EximSecurity) processLine(now time.Time, line string) {
    s := strings.ToLower(line)

    // quick skip: must have brackets (socket ip is always bracketed)
    if !strings.Contains(s, "[") || !strings.Contains(s, "]") { return }

    ip := lastBracketIP(line) // <-- only trust bracketed token, validated

// DEBUG: show what we picked for every matching line
    if logging.DebugEnabled() {
        if ip != "" {
            logging.LogfDETECTOR("[exim/security][debug] picked_ip=%q line=%s", ip, line)
        } else {
            logging.LogfDETECTOR("[exim/security][debug] no_ip line=%s", line)
        }
    }
//debug end

    if ip == "" { return }

    // ... keep the rest the same ...
    for _, r := range d.rules {
        if r.Re.MatchString(s) {

            if r.Name == "AUTHFAIL" {

                if logging.DebugEnabled() {
                    logging.LogfDETECTOR("[exim/security][debug] bump AUTHFAIL ip=%q", ip)
                }

                d.bump(now, "AUTHFAIL|ip", ip, line) // now always the real socket IP
                if u := d.extractUser(s); u != "" {
                    d.bump(now, "AUTHFAIL|user", u, line)
                    d.addUserIP(u, ip)
                }
            } else {
                d.bump(now, r.Name, ip, line)
            }
        }
    }
}





func (d *EximSecurity) extractUser(line string) string {
    if m := d.reSetID.FindStringSubmatch(line); m != nil && m[1] != "" {
        return strings.ToLower(m[1])
    }
    if m := d.reUserAng.FindStringSubmatch(line); m != nil && m[1] != "" {
        return strings.ToLower(m[1])
    }
    return ""
}

func (d *EximSecurity) addUserIP(user, ip string) {
    if user == "" || ip == "" { return }
    d.mu.Lock()
    rp := d.userIPs[user]
    if rp == nil {
        rp = &recentIPs{}
        d.userIPs[user] = rp
    }
    d.mu.Unlock()
    rp.Add(ip, 20) // keep last ~20 distinct IPs per user
}


func (d *EximSecurity) bump(now time.Time, tag, key, line string) {
    sk := tag + ":" + key
    d.samples.Add(sk, line)
    _ = d.counts.Add(sk, now) // real counting in sliding window

    if d.pending == nil { d.pending = make(map[string]pend) }
    d.pending[sk] = pend{kindKey: tag, key: key} // no per-tick n here
}





func (d *EximSecurity) flush(now time.Time, out chan<- core.Alert) {
    for sk, p := range d.pending {
        thr, kind, isIP, base := d.thresholdAndKey(p.kindKey, p.key)
        if thr <= 0 { continue }

        n := d.counts.Count(sk, now)
        if !d.gate.Allow(sk, now, n, thr) { continue }

        // display + enrichment exactly as before
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
        // Derive submission transport info (best-effort) from first sample
        enc := ""
        port := ""
        if len(samples) > 0 {
            s0 := strings.ToLower(samples[0])
            if strings.Contains(s0, "ssl on the wire") { enc = "smtps" } else if strings.Contains(s0, "tls") { enc = "tls" }
            if m := d.reSrvPort.FindStringSubmatch(samples[0]); m != nil { port = m[1] }
        }


// DEBUG: single line that mirrors what will be emitted as an alert
        if logging.DebugEnabled() {
            if len(samples) > 0 {
                logging.LogfDETECTOR("[exim/security][debug] flush kind=%s key=%s isIP=%t base=%s count=%d thr=%d samples=%d enc=%s port=%s first=%q",
                    kind, displayKey, isIP, base, n, thr, len(samples), enc, port, samples[0])
            } else {
                logging.LogfDETECTOR("[exim/security][debug] flush kind=%s key=%s isIP=%t base=%s count=%d thr=%d samples=%d enc=%s port=%s",
                    kind, displayKey, isIP, base, n, thr, len(samples), enc, port)
            }
        }
//DEBUG END

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
            csv, n := rp.CSV()
            if n > 0 { extra["ips"], extra["unique_ips"] = csv, strconv.Itoa(n) }
        }

        if enc != "" { extra["enc"] = enc }   // smtps or tls
        if port != "" { extra["port"] = port } // often 465 or 587
        out <- core.Alert{
            When: now, Kind: core.AlertKind(kind),
            Key: displayKey, Count: n, Samples: samples, Extra: extra,
        }
    }
}






func (d *EximSecurity) thresholdAndKey(kindKey, rawKey string) (thr int, alertKind string, isIP bool, base string) {
    // AUTHFAIL per-IP/per-user
    if strings.HasPrefix(kindKey, "AUTHFAIL|") {
        alertKind = "SECURITY/AUTHFAIL"
        base = rawKey
        if strings.HasSuffix(kindKey, "|ip") {
            thr = d.cfg.Thresholds["AUTHFAIL_IP"]
            if thr == 0 { thr = d.cfg.Thresholds["AUTHFAIL"] }
            return thr, alertKind, true, base
        }
        if strings.HasSuffix(kindKey, "|user") {
            thr = d.cfg.Thresholds["AUTHFAIL_USER"]
            if thr == 0 { thr = d.cfg.Thresholds["AUTHFAIL"] }
            return thr, alertKind, false, base
        }
        thr = d.cfg.Thresholds["AUTHFAIL"]
        return thr, alertKind, false, base
    }
    // other tags unchanged
    thr = d.cfg.Thresholds[kindKey]
    alertKind = "SECURITY/" + kindKey
    base = rawKey // ip
    return thr, alertKind, true, base
}





// --- helpers που ήδη έχεις στο relays.go, ανακύκλωσε/εξήγαγε κοινά αν θέλεις ---

func (d *EximSecurity) lookupMeta(ip string) string {
	var country, city, ptr, asname string
	var asn uint
	if d.enr != nil {
		r := d.enr.Lookup(ip)
		if r.Country != "" { country = r.Country }
		if r.City != "" { city = r.City }
		if r.PTR != "" { ptr = strings.TrimSuffix(r.PTR, ".") }
		if r.ASN > 0 { asn = r.ASN; asname = r.ASNName }
	}
	if d.cfg.UsePTR && ptr == "" {
		names, _ := net.LookupAddr(ip)
		if len(names) > 0 { ptr = strings.TrimSuffix(names[0], ".") }
	}
	geo := ""
	if country != "" || city != "" {
		if country == "" { country = "-" }
		if city == "" { city = "-" }
		geo = country + "/" + city
	}
	as := ""
	if asn > 0 && asname != "" { as = fmt.Sprintf("[AS%d %s", asn, asname) } else if asn > 0 { as = fmt.Sprintf("[AS%d", asn) }
	if ptr != "" { if as != "" { as += "; PTR " + ptr + "]" } else { as = "[PTR " + ptr + "]" } } else if as != "" { as += "]" }
	if geo != "" && as != "" { return geo + "/" + as }
	if geo != "" { return geo }
	return as
}



// helper: return canonical IPv4 or IPv6 from the last/right-most [ ... ] token on the line,
// preferring a global/public address if multiple bracketed IPs exist.
func lastBracketIP(line string) string {
	type span struct{ lo, hi int }

	// collect all [ ... ] spans
	var spans []span
	for i := 0; i < len(line); i++ {
		if line[i] != '[' {
			continue
		}
		j := strings.IndexByte(line[i:], ']')
		if j <= 1 {
			continue
		}
		spans = append(spans, span{lo: i + 1, hi: i + j})
		i += j
	}
	if len(spans) == 0 {
		return ""
	}

	// parseCanonical returns (parsed net.IP, canonical string) and handles IPv6-mapped v4.
	parseCanonical := func(s string) (net.IP, string) {
		s = strings.TrimSpace(s)

		// Try to pull a trailing IPv4 from IPv6-mapped literals like ::ffff:1.2.3.4
		if strings.Count(s, ":") >= 2 {
			if k := strings.LastIndexByte(s, ':'); k >= 0 && k+1 < len(s) {
				if v4 := net.ParseIP(s[k+1:]); v4 != nil {
					if q := v4.To4(); q != nil {
						return q, q.String()
					}
				}
			}
		}

		ip := net.ParseIP(s)
		if ip == nil {
			return nil, ""
		}
		if v4 := ip.To4(); v4 != nil {
			return v4, v4.String()
		}
		return ip, ip.String()
	}

	isGlobal := func(ip net.IP) bool {
		if ip == nil {
			return false
		}
		if v4 := ip.To4(); v4 != nil {
			// RFC1918
			if v4[0] == 10 {
				return false
			}
			if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
				return false
			}
			if v4[0] == 192 && v4[1] == 168 {
				return false
			}
			// link-local 169.254/16
			if v4[0] == 169 && v4[1] == 254 {
				return false
			}
			// loopback 127/8
			if v4[0] == 127 {
				return false
			}
			return true
		}
		// IPv6: loopback ::1, ULA fc00::/7, link-local fe80::/10
		if ip.IsLoopback() {
			return false
		}
		if ip[0]&0xfe == 0xfc { // fc00::/7
			return false
		}
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 { // fe80::/10
			return false
		}
		return true
	}

	// Pass 1: right → left, return first global/public IP
	for i := len(spans) - 1; i >= 0; i-- {
		cand := line[spans[i].lo:spans[i].hi]
		ip, canon := parseCanonical(cand)
		if canon != "" && isGlobal(ip) {
			return canon
		}
	}

	// Pass 2: right → left, return first valid IP (even if private)
	for i := len(spans) - 1; i >= 0; i-- {
		cand := line[spans[i].lo:spans[i].hi]
		_, canon := parseCanonical(cand)
		if canon != "" {
			return canon
		}
	}

	return ""
}




//new position
func (d *EximSecurity) ApplyPosition(p core.Position) {
    if d.src != nil {
        d.src.ApplyResume(p.Inode, p.Offset)
    }
}

func (d *EximSecurity) Position() core.Position {
    if d.src == nil {
        return core.Position{}
    }
    off, ino, ts := d.src.Position()
    return core.Position{Offset: off, Inode: ino, TS: ts}
}

// Setter used by the factory
func (d *EximSecurity) SetName(n string) { d.name = n }

// ---- helpers ---------------------------------------------------------------
func (d *EximSecurity) pickRejectLogs(mainPath, override string) []string {
    // If explicit, use that (and only that) if it exists.
    if s := strings.TrimSpace(override); s != "" {
        if fileExists(s) { return []string{s} }
        return nil
    }
    // Otherwise, try siblings next to mainPath: rejectlog, exim_rejectlog (cPanel)
    dir := filepath.Dir(mainPath)
    c1 := filepath.Join(dir, "rejectlog")
    c2 := filepath.Join(dir, "exim_rejectlog")
    out := make([]string, 0, 2)
    if fileExists(c1) { out = append(out, c1) }
    if fileExists(c2) { out = append(out, c2) }
    return out
}
func fileExists(p string) bool {
    if p == "" { return false }
    fi, err := os.Stat(p)
    return err == nil && !fi.IsDir()
}
