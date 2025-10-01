package modsec

import (
	"context"
	"encoding/json"
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
	// Source
	Mode    string // auto|file
	LogPath string // path|auto

	// Cadence
	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	// Thresholds
	ModsecPerIP int

	// Enrichment
	UseEnrich  bool
	UsePTR     bool
	EnrichDirs []string
}

type pend struct {
	key string // ip
}

type meta struct {
	ip       string
	ruleID   string
	msg      string
	logdata  string
	host     string
	uri      string
	uniqueID string
}

type Detector struct {
	cfg  Config
	name string
	src  core.LineSource

	pending map[string]pend

	samples *core.SampleRing
	gate    *core.AlertGate
	counts  *core.SlidingCounter

	metas   map[string]meta

	// text extractors (Apache error_log style)
	reQuick   *regexp.Regexp
	reClient  *regexp.Regexp
	reID      *regexp.Regexp
	reMsg     *regexp.Regexp
	reLogData *regexp.Regexp
	reHost    *regexp.Regexp
	reURI     *regexp.Regexp
	reUID     *regexp.Regexp

	// JSON (ModSecurity v3, SecAuditLogFormat JSON) accumulator
	inJSON  bool
	jsDepth int
	jsBuf   strings.Builder

	enr *enrich.Enricher
}

func New(cfg Config) *Detector {

	// sensible defaults
	if cfg.Every <= 0 { cfg.Every = 2 * time.Second }
	if cfg.Window <= 0 { cfg.Window = 15 * time.Minute }
	if cfg.Cooldown <= 0 { cfg.Cooldown = 20 * time.Minute }
	if cfg.SampleLimit <= 0 { cfg.SampleLimit = 10 }
	if !cfg.UseEnrich && !cfg.UsePTR { cfg.UsePTR = true }
	if cfg.UseEnrich && len(cfg.EnrichDirs) == 0 {
		cfg.EnrichDirs = []string{"/etc/cfm", "/var/lib/cfm/maxmind"}
	}

	d := &Detector{cfg: cfg}
	d.pending = make(map[string]pend)
	d.metas   = make(map[string]meta)
	// core window primitives
	d.samples = core.NewSampleRing(cfg.SampleLimit)
	d.gate    = core.NewAlertGate(cfg.Cooldown)
	d.counts  = core.NewSlidingCounter(cfg.Window, 0) // cap=0 → unbounded keys

	// Only handle hard blocks (403)
	d.reQuick = regexp.MustCompile(`ModSecurity:\s+Access denied with code 403`)
	// [client 47.128.123.119] or IPv6
	d.reClient = regexp.MustCompile(`\bclient\s+([0-9a-fA-F:\.]+)\b`)
	d.reID = regexp.MustCompile(`\[id\s+"(\d+)"\]`)
	d.reMsg = regexp.MustCompile(`\[msg\s+"([^"]+)"\]`)
	d.reLogData = regexp.MustCompile(`\[logdata\s+"([^"]+)"\]`)
	d.reHost = regexp.MustCompile(`\[hostname\s+"([^"]+)"\]`)
	d.reURI = regexp.MustCompile(`\[uri\s+"([^"]+)"\]`)
	d.reUID = regexp.MustCompile(`\[unique_id\s+"([^"]+)"\]`)

	if cfg.UseEnrich {
		if e, _ := enrich.New(cfg.EnrichDirs...); e != nil {
			d.enr = e
			logging.Logf("[detectors] modsec enrichment enabled (dirs=%v)", cfg.EnrichDirs)
		}
	}
	return d
}

func (d *Detector) SetName(n string)             { d.name = n }
func (d *Detector) SetSource(src core.LineSource) { d.src = src }
func (d *Detector) Name() string {
	if d.name != "" {
		return d.name
	}
	return "modsec"
}
func (d *Detector) Every() time.Duration {
	if d.cfg.Every > 0 {
		return d.cfg.Every
	}
	return 2 * time.Second
}

func (d *Detector) ApplyPosition(p core.Position) {
	if ft, ok := d.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
}
func (d *Detector) Position() core.Position {
	if d.src == nil {
		return core.Position{}
	}
	off, ino, ts := d.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	for k := range d.pending {
		delete(d.pending, k)
	}
	if d.src == nil {
		return nil
	}
	if err := d.src.Open(); err != nil {
		return nil
	}
	defer d.src.Close()

	now := time.Now()
	for {
		line, err := d.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		d.consume(now, line)
	}
	// flush any unterminated JSON record safely (ignore)
	d.flush(now, out)
	return nil
}

func (d *Detector) consume(now time.Time, line string) {
	trim := strings.TrimSpace(line)
	// JSON accumulation (pretty-printed audit log)
	if d.inJSON || (strings.HasPrefix(trim, "{") && (strings.Contains(line, `"transaction"`) || strings.Contains(line, `"audit_data"`))) {
		d.ingestJSON(now, line)
		return
	}
	// Compact one-line JSON
	if strings.HasPrefix(trim, `{"transaction"`) || strings.HasPrefix(trim, `{"audit_data"`) {
		if d.tryJSON(now, trim) {
			return
		}
		// fallthrough to text if JSON parse failed
	}

	// Classic text mode
	if !d.reQuick.MatchString(line) {
		return
	}
	m := meta{}
	if mm := d.reClient.FindStringSubmatch(line); mm != nil {
		ip := mm[1]
		// strip :port for IPv4
		if i := strings.IndexByte(ip, ':'); i != -1 && strings.Count(ip, ":") == 1 && strings.Count(ip, ".") == 3 {
			ip = ip[:i]
		}
		m.ip = ip
	}
	if mm := d.reID.FindStringSubmatch(line); mm != nil {
		m.ruleID = mm[1]
	}
	if mm := d.reMsg.FindStringSubmatch(line); mm != nil {
		m.msg = mm[1]
	}
	if mm := d.reLogData.FindStringSubmatch(line); mm != nil {
		m.logdata = mm[1]
	}
	if mm := d.reHost.FindStringSubmatch(line); mm != nil {
		m.host = mm[1]
	}
	if mm := d.reURI.FindStringSubmatch(line); mm != nil {
		m.uri = mm[1]
	}
	if mm := d.reUID.FindStringSubmatch(line); mm != nil {
		m.uniqueID = mm[1]
	}

	if m.ip == "" {
		return
	}
	d.bump(now, m.ip, line)
	d.metas["ip:"+m.ip] = m
}

func (d *Detector) ingestJSON(now time.Time, line string) {
	// naive brace depth counter (good enough for ModSec JSON)
	open := strings.Count(line, "{")
	close := strings.Count(line, "}")
	if !d.inJSON {
		d.inJSON = true
		d.jsDepth = 0
		d.jsBuf.Reset()
	}
	d.jsBuf.WriteString(line)
	d.jsBuf.WriteByte('\n')
	d.jsDepth += open - close
	if d.jsDepth <= 0 {
		d.inJSON = false
		raw := strings.TrimSpace(d.jsBuf.String())
		_ = d.tryJSON(now, raw) // ignore parse errors
		d.jsBuf.Reset()
	}
}

func (d *Detector) tryJSON(now time.Time, raw string) bool {
	type rule struct {
		ID          string `json:"id"`
		Rev         string `json:"rev"`
		Severity    string `json:"severity"`
		Msg         string `json:"msg"`
		MatchedData string `json:"matched_data"`
		LogData     string `json:"log_data"`
	}
	var j struct {
		Transaction struct {
			ClientIP  string `json:"client_ip"`
			HostName  string `json:"host_name"`
			RequestURI string `json:"request_uri"`
			UniqueID  string `json:"unique_id"`
			TimeStamp string `json:"time_stamp"`
		} `json:"transaction"`
		AuditData struct {
			Action   string `json:"action"`
			HTTPCode int    `json:"http_code"`
			Rules    []rule `json:"rules"`
		} `json:"audit_data"`
	}
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		return false
	}
	// Only consider hard blocks
	if !(j.AuditData.HTTPCode == 403 || strings.Contains(strings.ToLower(j.AuditData.Action), "access denied")) {
		return true // parsed but not a 403 → treat as handled
	}
	m := meta{
		ip:       strings.TrimSpace(j.Transaction.ClientIP),
		host:     strings.TrimSpace(j.Transaction.HostName),
		uri:      strings.TrimSpace(j.Transaction.RequestURI),
		uniqueID: strings.TrimSpace(j.Transaction.UniqueID),
	}
	if len(j.AuditData.Rules) > 0 {
		m.ruleID = strings.TrimSpace(j.AuditData.Rules[0].ID)
		m.msg = strings.TrimSpace(j.AuditData.Rules[0].Msg)
		if m.msg == "" {
			m.msg = strings.TrimSpace(j.AuditData.Rules[0].MatchedData)
		}
		m.logdata = strings.TrimSpace(j.AuditData.Rules[0].LogData)
	}
	if m.ip == "" {
		return true
	}
	d.bump(now, m.ip, raw)
	d.metas["ip:"+m.ip] = m
	return true
}

func (d *Detector) bump(now time.Time, ip, sample string) {

	sk := "ip:" + ip
	d.samples.Add(sk, sample)
	_ = d.counts.Add(sk, now)
	if _, ok := d.pending[ip]; !ok {
		d.pending[ip] = pend{key: ip}
	}


}



func (d *Detector) flush(now time.Time, out chan<- core.Alert) {
	thr := d.cfg.ModsecPerIP
	if thr <= 0 {
		thr = 20
	}

	for ip := range d.pending {
		sk := "ip:" + ip
		n := d.counts.Count(sk, now)
		if n < thr { continue }
		if !d.gate.Allow(sk, now, n, thr) { continue }

		displayKey := d.decorate(ip)

		samples := d.samples.GetAndClear(sk)

		extra := map[string]string{
			"window":   d.cfg.Window.String(),
			"cooldown": d.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(thr),
			"ip":       ip,
		}
		if m, ok := d.metas["ip:"+ip]; ok {
			if m.ruleID != "" {
				extra["rule_id"] = m.ruleID
			}
			if m.msg != "" {
				extra["msg"] = m.msg
			}
			if m.logdata != "" {
				extra["logdata"] = m.logdata
			}
			if m.host != "" {
				extra["host"] = m.host
			}
			if m.uri != "" {
				extra["uri"] = m.uri
			}
			if m.uniqueID != "" {
				extra["unique_id"] = m.uniqueID
			}
		}
		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind("MODSEC/403"),
			Key:     displayKey,
			Count:   n,
			Samples: samples,
			Extra:   extra,
		}
	}
}




func (d *Detector) decorate(ip string) string {
	if !d.cfg.UseEnrich && !d.cfg.UsePTR {
		return ip
	}
	var ptr string
	var asn int
	var asname, country string

	if d.enr != nil && d.cfg.UseEnrich {
		res := d.enr.Lookup(ip)
		ptr = strings.TrimSuffix(res.PTR, ".")
		asn = int(res.ASN)
		asname = res.ASNName
		country = res.Country
	}
	if d.cfg.UsePTR && ptr == "" {
		if names, _ := net.LookupAddr(ip); len(names) > 0 {
			ptr = strings.TrimSuffix(names[0], ".")
		}
	}
	parts := []string{ip}
	if ptr != "" {
		parts = append(parts, "("+ptr+")")
	}
	tag := strings.TrimSpace(strings.Join([]string{
		func() string { if asn > 0 { return strconv.Itoa(asn) } else { return "" } }(),
		asname,
		country,
	}, " "))
	if tag != "" {
		parts = append(parts, "["+tag+"]")
	}
	return strings.Join(parts, " ")
}
