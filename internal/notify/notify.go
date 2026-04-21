package notify

import (
	"crypto/sha256"
	"encoding/json"
	//	"net"
	"cfm/internal/enrich"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
	cfgMu       sync.RWMutex
	cfg         *config
	queueCh     chan Event
	dedup       *deduper
	hostname    string
	runtimeMeta RuntimeMetadata
)

type RuntimeMetadata struct {
	LoadedAt        time.Time  `json:"loaded_at"`
	ReloadedAt      *time.Time `json:"reloaded_at,omitempty"`
	ConfigPath      string     `json:"config_path"`
	ConfigHash      string     `json:"config_hash,omitempty"`
	LastLoadOK      bool       `json:"last_load_ok"`
	LastLoadError   string     `json:"last_load_error,omitempty"`
	LastLoadedAt    time.Time  `json:"last_loaded_at"`
	LastReloadedAt  *time.Time `json:"last_reloaded_at,omitempty"`
	LastReloadError string     `json:"last_reload_error,omitempty"`
}

// enrichment (optional)
var enricher *enrich.Enricher

// Allow wiring the same enricher instance used by firewall/backend.
func SetEnricher(e *enrich.Enricher) { enricher = e }

func Init(cfgDir string) error {
	hostname, _ = os.Hostname()
	admin, _, err := LoadAdminConfig(cfgDir)
	if err != nil {
		recordLoadResult(cfgDir, false, err, false)
		return err
	}

	c := &config{
		Enabled:         admin.Notifier.Enabled,
		DefaultCooldown: 5 * time.Minute,
		JSONLPath:       "/var/lib/cfm/notify.log.jsonl",
		SubjectTmpl:     strings.TrimSpace(admin.Notifier.SubjectTemplate),
		BodyTmpl:        strings.TrimSpace(admin.Notifier.BodyTemplate),
		DedupeKey:       "{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}",
		DedupeTTL:       5 * time.Minute,
		Detectors:       map[string]detectorOverride{},
	}
	if d, err := time.ParseDuration(zv(admin.Notifier.DefaultCooldown, "5m")); err == nil {
		c.DefaultCooldown = d
	}
	if p := strings.TrimSpace(admin.Notifier.JSONLPath); p != "" {
		c.JSONLPath = p
	}
	if hn := strings.TrimSpace(admin.Notifier.HostnameOverride); hn != "" {
		hostname = hn
	}
	if admin.Notifier.RateLimitPerMin > 0 {
		c.GlobalRatePerMin = admin.Notifier.RateLimitPerMin
	}
	if key := strings.TrimSpace(admin.Dedupe.Key); key != "" {
		c.DedupeKey = key
	}
	if d := strings.TrimSpace(admin.Dedupe.Cooldown); d != "" {
		if dur, err := time.ParseDuration(d); err == nil {
			c.DedupeTTL = dur
		}
	}

	chans := []Channel{}
	for _, sec := range admin.Channels {
		id := strings.TrimSpace(sec.ID)
		if id == "" || !sec.Enabled {
			continue
		}
		switch strings.TrimSpace(sec.Type) {
		case "sendmail":
			from := strings.TrimSpace(sec.From)
			if from == "" {
				if hostname == "" {
					hostname, _ = os.Hostname()
				}
				from = fmt.Sprintf("root@%s", hostname)
			}
			ch := &sendmailChannel{name: id, path: zv(sec.Path, "/usr/sbin/sendmail"), from: from, to: sec.To}
			if len(ch.to) > 0 {
				chans = append(chans, ch)
			}
		case "smtp":
			ch := &smtpChannel{name: id, host: sec.Host, user: sec.User, pass: sec.Pass, from: sec.From, to: sec.To, starttls: sec.StartTLS, insecure: sec.InsecureSkipVerify}
			if ch.host != "" && ch.from != "" && len(ch.to) > 0 {
				chans = append(chans, ch)
			}
		case "slack", "slack_webhook":
			ch := &slackChannel{name: id, webhook: sec.WebhookURL, mention: strings.TrimSpace(sec.Mention), username: strings.TrimSpace(sec.Username), iconEmoji: strings.TrimSpace(sec.IconEmoji)}
			if ch.webhook != "" {
				chans = append(chans, ch)
			}
		}
	}
	c.Channels = chans

	for name, sec := range admin.Detectors {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		ov := detectorOverride{Notify: sec.Notify, MinSeverity: strings.ToLower(strings.TrimSpace(sec.MinSeverity)), Channels: sec.Channels}
		if cd := strings.TrimSpace(sec.Cooldown); cd != "" {
			if dur, err := time.ParseDuration(cd); err == nil {
				ov.Cooldown = dur
			}
		}
		c.Detectors[key] = ov
	}

	cfgMu.Lock()
	cfg = c
	recordLoadResultLocked(cfgDir, true, nil, false)
	cfgMu.Unlock()
	dedup = newDeduper(c.DedupeTTL)
	if queueCh == nil {
		queueCh = make(chan Event, 100)
		go worker()
	}
	return nil
}

func Emit(ev Event) error {
	cfgMu.RLock()
	c := cfg
	cfgMu.RUnlock()
	if c == nil || !c.Enabled {
		return nil
	}

	if ev.Host == "" {
		ev.Host = hostname
	}
	if ev.When.IsZero() {
		ev.When = time.Now()
	}

	// dedupe
	key := c.DedupeKey
	if key == "" {
		key = "{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}"
	}
	key = renderLiteral(key, ev)

	// detector override lookup
	ov, hasOV := matchOverride(c, ev)
	if hasOV && !ov.Notify {
		return nil // detector explicitly disabled
	}
	ttl := c.DedupeTTL
	if ttl <= 0 {
		ttl = c.DefaultCooldown
	}
	if hasOV && ov.Cooldown > 0 {
		ttl = ov.Cooldown
	}

	if !dedup.allow(key, ttl) {
		return nil
	}

	// severity gate (if configured)
	if hasOV && ov.MinSeverity != "" {
		if severityRank(ev.Severity) < severityRank(ov.MinSeverity) {
			return nil
		}
	}

	// render
	subj, _ := renderSubject(c.SubjectTmpl, ev)
	body, _ := render(c.BodyTmpl, ev)

	// send
	var firstErr error
	dest := selectChannels(c, ov, hasOV)
	eventID := notificationEventID()
	for _, ch := range dest {
		attemptedAt := time.Now().UTC()
		attemptStart := time.Now()
		err := ch.Send(ev, subj, body)
		latency := time.Since(attemptStart).Milliseconds()
		if err != nil && firstErr == nil {
			firstErr = err
		}

		// audit JSONL (per-channel attempt row)
		_ = appendJSONL(c.JSONLPath, map[string]interface{}{
			"time":           attemptedAt.Format(time.RFC3339Nano),
			"host":           ev.Host,
			"event_id":       eventID,
			"correlation_id": eventID,
			"kind":           ev.Kind,
			"srcip":          ev.SrcIP,
			"reason":         ev.Reason,
			"ttl":            ev.TTL.String(),
			"asn":            ev.ASN,
			"country":        ev.Country,
			"ptr":            ev.PTR,
			"count":          ev.Count,
			"section":        ev.Section,
			"channel":        channelAuditName(ch),
			"attempted":      true,
			"success":        err == nil,
			"error":          errString(err),
			"err":            errString(err),
			"latency_ms":     latency,
		})
	}

	return firstErr
}

func Reload(cfgDir string) error {
	if err := Init(cfgDir); err != nil {
		cfgMu.Lock()
		recordLoadResultLocked(cfgDir, false, err, true)
		cfgMu.Unlock()
		return err
	}
	cfgMu.Lock()
	recordLoadResultLocked(cfgDir, true, nil, true)
	cfgMu.Unlock()
	return nil
}

func RuntimeStatus() RuntimeMetadata {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return runtimeMeta
}

func worker() {
	for ev := range queueCh {
		_ = Emit(ev)
	}
}

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
		cfgMu.RLock()
		path := ""
		if cfg != nil {
			path = cfg.JSONLPath
		}
		cfgMu.RUnlock()
		_ = appendJSONL(path, map[string]interface{}{"dropped": true, "reason": "queue_full", "event": ev})
	}
}

func appendJSONL(path string, v interface{}) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(v)
}

func renderLiteral(tmpl string, ev Event) string {
	out := tmpl
	repls := map[string]string{
		"Host": ev.Host, "Kind": ev.Kind, "SrcIP": ev.SrcIP, "Reason": ev.Reason,
	}
	for k, v := range repls {
		out = strings.ReplaceAll(out, "{{."+k+"}}", v)
	}
	return out
}

func fileExists(p string) bool { fi, err := os.Stat(p); return err == nil && !fi.IsDir() }

func zv(s, def string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	// Best-effort guard in case ini.go wasn’t patched yet:
	if i := strings.IndexAny(s, "#;"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func parseBool(s string, def bool) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return def
	}
	switch s {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	i += len(a)
	j := strings.Index(s[i:], b)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func notificationEventID() string {
	return fmt.Sprintf("evt-%x-%x", time.Now().UTC().UnixNano(), rand.Uint64())
}

func recordLoadResult(cfgDir string, ok bool, err error, manual bool) {
	cfgMu.Lock()
	defer cfgMu.Unlock()
	recordLoadResultLocked(cfgDir, ok, err, manual)
}

func recordLoadResultLocked(cfgDir string, ok bool, err error, manual bool) {
	now := time.Now().UTC()
	path, _ := resolveConfigPath(cfgDir)
	meta := runtimeMeta
	if meta.LoadedAt.IsZero() && ok {
		meta.LoadedAt = now
	}
	if ok {
		meta.ConfigPath = path
		meta.ConfigHash = configFileHash(path)
		meta.LastLoadError = ""
		meta.LastReloadError = ""
	} else if err != nil {
		meta.LastLoadError = err.Error()
		if manual {
			meta.LastReloadError = err.Error()
		}
	}
	meta.LastLoadOK = ok
	meta.LastLoadedAt = now
	if manual {
		reloadedAt := now
		meta.ReloadedAt = &reloadedAt
		meta.LastReloadedAt = &reloadedAt
	}
	runtimeMeta = meta
}

func configFileHash(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func channelAuditName(ch Channel) string {
	switch ch.(type) {
	case *sendmailChannel:
		return "sendmail"
	case *smtpChannel:
		return "smtp"
	case *slackChannel:
		return "slack"
	default:
		return strings.TrimSpace(ch.Name())
	}
}

// ---- helpers for detector overrides ----
func matchOverride(c *config, ev Event) (detectorOverride, bool) {
	if c == nil || len(c.Detectors) == 0 {
		return detectorOverride{}, false
	}
	sec := strings.ToLower(strings.TrimSpace(ev.Section))
	kind := strings.ToLower(strings.TrimSpace(ev.Kind))
	root := kind
	if i := strings.Index(kind, "/"); i > 0 {
		root = kind[:i]
	} // e.g., "health" from "HEALTH/PORT_CONN_SPIKE"

	// priority: exact section → exact kind → kind root → "*" default
	if ov, ok := c.Detectors[sec]; ok && sec != "" {
		return ov, true
	}
	if ov, ok := c.Detectors[kind]; ok && kind != "" {
		return ov, true
	}
	if ov, ok := c.Detectors[root]; ok && root != "" {
		return ov, true
	}
	if ov, ok := c.Detectors["*"]; ok {
		return ov, true
	}
	return detectorOverride{}, false
}

func selectChannels(c *config, ov detectorOverride, hasOV bool) []Channel {
	if !hasOV || len(ov.Channels) == 0 {
		return c.Channels
	}
	want := map[string]struct{}{}
	for _, n := range ov.Channels {
		want[strings.ToLower(strings.TrimSpace(n))] = struct{}{}
	}
	out := make([]Channel, 0, len(want))
	for _, ch := range c.Channels {
		if _, ok := want[strings.ToLower(ch.Name())]; ok {
			out = append(out, ch)
		}
	}
	return out
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 2
	case "warn", "warning":
		return 1
	case "info", "":
		return 0
	default:
		return 0
	}
}
