package notify

import (
	"encoding/json"
//	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"cfm/internal/enrich"
	"fmt"
)

type config struct {
	Enabled          bool
	DefaultCooldown  time.Duration
	JSONLPath        string
	HostnameOverride string
	GlobalRatePerMin int
	SubjectTmpl      string
	BodyTmpl         string

	DedupeKey string
	DedupeTTL time.Duration

	Detectors map[string]detectorOverride
	Channels  []Channel
}

type detectorOverride struct {
	Notify      bool
	Cooldown    time.Duration
	MinSeverity string
	Channels    []string
}

var (
	cfgMu    sync.RWMutex
	cfg      *config
	queueCh  chan Event
	dedup    *deduper
	hostname string
)


// enrichment (optional)
var enricher *enrich.Enricher

// Allow wiring the same enricher instance used by firewall/backend.
func SetEnricher(e *enrich.Enricher) { enricher = e }



func Init(cfgDir string) error {
	hostname, _ = os.Hostname()

	var fp string
	if cfgDir != "" {
		if fileExists(filepath.Join(cfgDir, "notify.conf")) { fp = filepath.Join(cfgDir, "notify.conf") }
	}
	if fp == "" && fileExists("/etc/cfm/notify.conf") { fp = "/etc/cfm/notify.conf" }

	if fp == "" { // no config -> disabled
		cfgMu.Lock(); cfg = &config{Enabled: false}; cfgMu.Unlock()
		return nil
	}
	ini, err := parseINI(fp); if err != nil { return err }

	c := &config{
		Enabled:         true,
		DefaultCooldown: 5 * time.Minute,
		JSONLPath:       "/var/lib/cfm/notify.log.jsonl",
		SubjectTmpl:     "",
		BodyTmpl:        "",
		DedupeKey:       "{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}",
		DedupeTTL:       5 * time.Minute,
		Detectors:       map[string]detectorOverride{},
	}

	if s := ini.getSection("notifier"); s != nil {
		c.Enabled = parseBool(s["enabled"], true)
		if d, err := time.ParseDuration(zv(s["default_cooldown"], "5m")); err == nil { c.DefaultCooldown = d }
		if p := strings.TrimSpace(s["jsonl_path"]); p != "" { c.JSONLPath = p }
		if hn := strings.TrimSpace(s["hostname_override"]); hn != "" { hostname = hn }
		if subj := strings.TrimSpace(s["subject_template"]); subj != "" { c.SubjectTmpl = subj }
		if body := strings.TrimSpace(s["body_template"]); body != "" { c.BodyTmpl = body }
		if rl := strings.TrimSpace(s["rate_limit_per_min"]); rl != "" {
			if n, _ := strconv.Atoi(rl); n > 0 { c.GlobalRatePerMin = n }
		}
	}
	if s := ini.getSection("dedupe"); s != nil {
		if key := strings.TrimSpace(s["key"]); key != "" { c.DedupeKey = key }
		if d := strings.TrimSpace(s["cooldown"]); d != "" {
			if dur, err := time.ParseDuration(d); err == nil { c.DedupeTTL = dur }
		}
	}

	// channels
	chans := []Channel{}
	for name, sec := range ini.sectionsWithPrefix(`channel "`) {
		_ = name // id is inside quotes
		id := between(name, `channel "`, `"`)
		if id == "" || !parseBool(sec["enabled"], true) { continue }

		switch strings.TrimSpace(sec["type"]) {
		case "sendmail":
			ch := &sendmailChannel{
				name: id,
				path: zv(sec["path"], "/usr/sbin/sendmail"),
				from: sec["from"],
				to:   splitCSV(sec["to"]),
			}
			if ch.from != "" && len(ch.to) > 0 { chans = append(chans, ch) }

		case "smtp":
			ch := &smtpChannel{
				name:     id,
				host:     sec["host"],
				user:     sec["user"],
				pass:     sec["pass"],
				from:     sec["from"],
				to:       splitCSV(sec["to"]),
				starttls: parseBool(sec["starttls"], true),
				insecure: parseBool(sec["insecure_skip_verify"], false),
			}
			if ch.host != "" && ch.from != "" && len(ch.to) > 0 { chans = append(chans, ch) }

		case "slack", "slack_webhook":
			ch := &slackChannel{
				name:      id,
				webhook:   sec["webhook_url"],
				mention:   strings.TrimSpace(sec["mention"]),
				username:  strings.TrimSpace(sec["username"]),
				iconEmoji: strings.TrimSpace(sec["icon_emoji"]),
			}
			if ch.webhook != "" { chans = append(chans, ch) }
		}
	}
	c.Channels = chans

	cfgMu.Lock(); cfg = c; cfgMu.Unlock()

	dedup = newDeduper(c.DedupeTTL)
	queueCh = make(chan Event, 100)
	go worker()
	return nil
}

func Emit(ev Event) error {
	cfgMu.RLock(); c := cfg; cfgMu.RUnlock()
	if c == nil || !c.Enabled { return nil }

	if ev.Host == "" { ev.Host = hostname }
	if ev.When.IsZero() { ev.When = time.Now() }

	// dedupe
	key := c.DedupeKey; if key == "" { key = "{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}" }
	key = renderLiteral(key, ev)
	ttl := c.DedupeTTL; if ttl <= 0 { ttl = c.DefaultCooldown }
	if !dedup.allow(key, ttl) { return nil }

	// render
	subj, _ := renderSubject(c.SubjectTmpl, ev)
	body, _ := render(c.BodyTmpl, ev)

	// send
	var firstErr error
	for _, ch := range c.Channels {
		if err := ch.Send(ev, subj, body); err != nil && firstErr == nil { firstErr = err }
	}
	// audit JSONL
	_ = appendJSONL(c.JSONLPath, map[string]interface{}{
		"time": ev.When.Format(time.RFC3339),
		"host": ev.Host,
		"kind": ev.Kind,
		"srcip": ev.SrcIP,
		"reason": ev.Reason,
		"ttl": ev.TTL.String(),
		"asn": ev.ASN,
		"country": ev.Country,
		"ptr": ev.PTR,
		"count": ev.Count,
		"section": ev.Section,
		"err": errString(firstErr),
	})
	return firstErr
}

func worker() { for ev := range queueCh { _ = Emit(ev) } }

func Enqueue(ev Event) {
        // Best-effort enrichment (PTR/ASN/Country) if missing.
        // Centralizing here means all callers benefit (detectors, autoblock, etc.).
        if (ev.PTR == "" || ev.ASN == "" || ev.Country == "") && ev.SrcIP != "" {
                if enr := enricher; enr != nil {
                        info := enr.Lookup(ev.SrcIP)
                        if ev.PTR == "" && info.PTR != "" {
                                ev.PTR = info.PTR
                        }
                        if ev.ASN == "" && (info.ASNName != "" || info.ASN > 0) {
                                if info.ASN > 0 && info.ASNName != "" {
                                        ev.ASN = fmt.Sprintf("AS%d %s", info.ASN, info.ASNName)
                                } else if info.ASNName != "" {
                                        ev.ASN = info.ASNName
                                } else {
                                        ev.ASN = fmt.Sprintf("AS%d", info.ASN)
                                }
                        }
                        if ev.Country == "" {
                                // Prefer "City, Country" when city is available (matches your autoblock vibe)
                                if info.City != "" && info.Country != "" {
                                        ev.Country = info.City + ", " + info.Country
                                } else if info.Country != "" {
                                        ev.Country = info.Country
                                }
                        }
                }
        }

	select {
	case queueCh <- ev:
	default:
		cfgMu.RLock(); path := ""; if cfg != nil { path = cfg.JSONLPath }; cfgMu.RUnlock()
		_ = appendJSONL(path, map[string]interface{}{"dropped": true, "reason": "queue_full", "event": ev})
	}
}

func appendJSONL(path string, v interface{}) error {
	if path == "" { return nil }
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { return err }
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil { return err }
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(v)
}

func renderLiteral(tmpl string, ev Event) string {
	out := tmpl
	repls := map[string]string{
		"Host": ev.Host, "Kind": ev.Kind, "SrcIP": ev.SrcIP, "Reason": ev.Reason,
	}
	for k, v := range repls { out = strings.ReplaceAll(out, "{{."+k+"}}", v) }
	return out
}

func fileExists(p string) bool { fi, err := os.Stat(p); return err == nil && !fi.IsDir() }

func zv(s, def string) string { s = strings.TrimSpace(s); if s == "" { return def }; return s }

func splitCSV(s string) []string {
	s = strings.TrimSpace(s); if s == "" { return nil }
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts { t := strings.TrimSpace(p); if t != "" { out = append(out, t) } }
	return out
}

func parseBool(s string, def bool) bool {
	s = strings.TrimSpace(strings.ToLower(s)); if s == "" { return def }
	switch s {
	case "1","true","yes","on": return true
	case "0","false","no","off": return false
	default: return def
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a); if i < 0 { return "" }
	i += len(a)
	j := strings.Index(s[i:], b); if j < 0 { return "" }
	return s[i : i+j]
}

func errString(err error) string { if err == nil { return "" }; return err.Error() }
