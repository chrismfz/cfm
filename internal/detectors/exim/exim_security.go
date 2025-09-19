package exim

import (
//	"bufio"
	"context"
	"fmt"
//	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"net"
//	"syscall"
	"io"

	core "cfm/internal/detectors/core"
	"cfm/internal/logging"
	"cfm/internal/enrich"
)

type SecConfig struct {
	LogPath     string
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
	inode    uint64
	off      int64
	readyLog bool

	counts   *windowCounter
	samples  map[string][]string           // key=tag:ip
	pending  map[string]pend               // στο τέλος του RunOnce στέλνουμε alerts
	rules    []secRule
	enr      *enrich.Enricher
	reHostIP *regexp.Regexp
	lastFire map[string]time.Time

	name string          // unique instance name (section)
	src  *core.FileTailer
}

func NewSecurity(cfg SecConfig) *EximSecurity {
	if cfg.Every <= 0 { cfg.Every = 2 * time.Second }
	if cfg.Window <= 0 { cfg.Window = 15 * time.Minute }
	if cfg.SampleLimit <= 0 { cfg.SampleLimit = 10 }
	if cfg.Cooldown <= 0 { cfg.Cooldown = 20 * time.Minute }
	if !cfg.UseEnrich && !cfg.UsePTR { cfg.UsePTR = true }
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/usr/share/GeoIP", "/usr/local/share/GeoIP", "./configs"}
	}
	if cfg.Thresholds == nil {
		cfg.Thresholds = map[string]int{
			"AUTHFAIL":            15,
			"SENDER_VERIFY_FAIL":  20,
			"RCPT_REJECT":         30,
			"SYNC_ERR":             8,
			"PROTO_ERR":            8,
			"NO_MAIL":             12,
			"DROP_ACL":             6,
		}
	}
	d := &EximSecurity{
		cfg:     cfg,
		counts:  newWindowCounter(cfg.Window),
		samples: make(map[string][]string),
		reHostIP: regexp.MustCompile(`\[(\d{1,3}(?:\.\d{1,3}){3})\]`), // IP σε αγκύλες
		lastFire: make(map[string]time.Time),
	}
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


func (d *EximSecurity) Every() time.Duration { return d.cfg.Every }

// φόρτωσε κανόνες από rules file ή βάλε defaults
func (d *EximSecurity) loadRules() {
	var raws = []struct{
		name, desc, re string
	}{
		{"AUTHFAIL", "Incorrect authentication data", `authenticator failed .* \[[^\]]+\].* 535 Incorrect authentication data`},
		{"SENDER_VERIFY_FAIL", "sender verify fail",  `sender verify fail\b`},
		{"RCPT_REJECT", "RCPT rejected",              `rejected RCPT [^@]+@\S+: (?:relay not permitted|Sender verify failed|Unknown user|Unrouteable address)`},
		{"SYNC_ERR", "protocol sync error",           `SMTP protocol synchronization error .* rejected .*`},
		{"PROTO_ERR", "AUTH used when not advertised",`SMTP protocol error in ".*" .*AUTH command used when not advertised`},
		{"NO_MAIL", "no MAIL in SMTP connection",     `no MAIL in SMTP connection .*`},
		{"DROP_ACL", "closed by DROP in ACL",         `SMTP connection .* closed by DROP in ACL`},
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
		if !d.readyLog {
			logging.Logf("[detectors] exim/security using log: %s", d.path)
			d.readyLog = true
		}
	}

// reset per-run aggregation
d.pending = make(map[string]pend)

// Use FileTailer (starts at "now" unless ApplyPosition() injected a resume)
if d.src == nil {
	d.src = core.NewFileTailer(d.path)
}
if err := d.src.Open(); err != nil {
	// quiet: missing/rotating log; next tick will retry
	return nil
}
defer d.src.Close()

now := time.Now()
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

// flush aggregated alerts
d.flush(now, out)
return nil

}

func (d *EximSecurity) processLine(now time.Time, line string) {
	// γρήγορο skip: κοιτάμε αν έχει IP σε αγκύλες
	if !strings.Contains(line, "[") || !strings.Contains(line, "]") {
		return
	}
	ip := ""
	if m := d.reHostIP.FindStringSubmatch(line); m != nil {
		ip = m[1]
	}
	if ip == "" {
		return
	}
	// πέρασε από όλους τους κανόνες
	for _, r := range d.rules {
		if r.Re.MatchString(line) {
			d.bump(now, r.Name, ip, line)
		}
	}
}

func (d *EximSecurity) bump(now time.Time, tag, ip, line string) {
	n := d.counts.Add(tag+":"+ip, now)

	d.mu.Lock()
	sk := tag + ":" + ip
	if _, ok := d.samples[sk]; !ok {
		d.samples[sk] = make([]string, 0, d.cfg.SampleLimit)
	}
	if len(d.samples[sk]) < d.cfg.SampleLimit {
		d.samples[sk] = append(d.samples[sk], line)
	}
	d.mu.Unlock()

	if d.pending == nil {
		d.pending = make(map[string]pend)
	}
	d.pending[sk] = pend{kindKey: tag, key: ip, n: n}
}

func (d *EximSecurity) flush(now time.Time, out chan<- core.Alert) {
	for sk, p := range d.pending {
		thr := d.cfg.Thresholds[p.kindKey]
		if thr <= 0 || p.n < thr {
			continue
		}
		// cooldown per key
		if !d.cool(sk, now) {
			continue
		}

		// enrich display key (ip -> geo/asn/ptr)
		displayKey := "ip " + p.key
		if d.cfg.UseEnrich || d.cfg.UsePTR {
			if meta := d.lookupMeta(p.key); meta != "" {
				displayKey = displayKey + " (" + meta + ")"
			}
		}

		// samples (+ decoded subject αν θέλεις: ανακύκλωσε decodeSubjectFromLine από relays.go)
		samples := d.samples[sk]
		if len(samples) > d.cfg.SampleLimit {
			samples = samples[:d.cfg.SampleLimit]
		}

		extra := map[string]string{
			"log":      d.path,
			"window":   d.cfg.Window.String(),
			"cooldown": d.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(thr),
			"rule":     p.kindKey,
		}
		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind("SECURITY/" + p.kindKey),
			Key:     displayKey,
			Count:   p.n, // <- Σύνολο μέσα στο window σε αυτό το run
			Samples: samples,
			Extra:   extra,
		}

		// reset samples για αυτό το key
		d.samples[sk] = nil
	}
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




func (d *EximSecurity) cool(key string, now time.Time) bool {
    if d.cfg.Cooldown <= 0 {
        return true
    }
    if last, ok := d.lastFire[key]; ok {
        if now.Sub(last) < d.cfg.Cooldown {
            return false
        }
    }
    d.lastFire[key] = now
    return true
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
