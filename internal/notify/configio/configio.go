package configio

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
)

type Notifier struct {
	Enabled                                      bool
	DefaultCooldown, JSONLPath, HostnameOverride string
	RateLimitPerMin                              int
	SubjectTemplate, BodyTemplate                string
}
type Dedupe struct{ Key, Cooldown string }
type Channel struct {
	ID, Type                                 string
	Enabled                                  bool
	To                                       []string
	From, Path, Host, User, Pass             string
	StartTLS, InsecureSkipVerify             bool
	WebhookURL, Mention, Username, IconEmoji string
}
type DetectorOverride struct {
	Name                  string
	Notify                bool
	Cooldown, MinSeverity string
	Channels              []string
}
type Config struct {
	Notifier  Notifier
	Dedupe    Dedupe
	Channels  []Channel
	Detectors []DetectorOverride
	Doc       *Document
}
type Document struct {
	Preamble []string
	Order    []SectionRef
	Sections map[string]*Section
}
type SectionRef struct{ Kind, Key string }
type Section struct {
	Name   string
	Raw    []string
	Extras []string
}

func defaultConfig() Config {
	return Config{Notifier: Notifier{Enabled: false, DefaultCooldown: "5m", JSONLPath: "/var/lib/cfm/notify.log.jsonl"}, Dedupe: Dedupe{Key: "{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}", Cooldown: "5m"}, Channels: []Channel{}, Detectors: []DetectorOverride{}, Doc: &Document{Sections: map[string]*Section{}}}
}
func ParseFile(path string) (Config, error) {
	// #nosec G304 -- path is controlled by cfm config location resolution.
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	return Parse(f)
}

func Parse(r io.Reader) (Config, error) {
	cfg := defaultConfig()
	doc := &Document{Sections: map[string]*Section{}}
	cfg.Doc = doc
	sc := bufio.NewScanner(r)
	cur := ""
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			if idx := strings.IndexRune(line, ']'); idx > 1 {
				cur = strings.TrimSpace(line[1:idx])
				if _, ok := doc.Sections[cur]; !ok {
					doc.Sections[cur] = &Section{Name: cur}
					k, key := classifySection(cur)
					doc.Order = append(doc.Order, SectionRef{Kind: k, Key: key})
				}
				continue
			}
		}
		if cur == "" {
			doc.Preamble = append(doc.Preamble, raw)
			continue
		}
		doc.Sections[cur].Raw = append(doc.Sections[cur].Raw, raw)
	}
	if err := sc.Err(); err != nil {
		return Config{}, err
	}
	parseKnown(doc, &cfg)
	return cfg, nil
}

func classifySection(name string) (kind, key string) {
	if name == "notifier" {
		return "notifier", "notifier"
	}
	if name == "dedupe" {
		return "dedupe", "dedupe"
	}
	if strings.HasPrefix(name, `channel "`) {
		id := between(name, `channel "`, `"`)
		if id != "" {
			return "channel", id
		}
	}
	if strings.HasPrefix(name, `detector "`) {
		id := strings.ToLower(strings.TrimSpace(between(name, `detector "`, `"`)))
		if id != "" {
			return "detector", id
		}
	}
	return "unknown", name
}

func parseKnown(doc *Document, cfg *Config) {
	if s := doc.Sections["notifier"]; s != nil {
		m, e := parseKV(s.Raw)
		s.Extras = e
		cfg.Notifier.Enabled = parseBool(m["enabled"], true)
		cfg.Notifier.DefaultCooldown = zv(m["default_cooldown"], cfg.Notifier.DefaultCooldown)
		if p := strings.TrimSpace(m["jsonl_path"]); p != "" {
			cfg.Notifier.JSONLPath = p
		}
		cfg.Notifier.HostnameOverride = strings.TrimSpace(m["hostname_override"])
		cfg.Notifier.RateLimitPerMin = atoiPos(m["rate_limit_per_min"])
		cfg.Notifier.SubjectTemplate = strings.TrimSpace(m["subject_template"])
		cfg.Notifier.BodyTemplate = strings.TrimSpace(m["body_template"])
	}
	if s := doc.Sections["dedupe"]; s != nil {
		m, e := parseKV(s.Raw)
		s.Extras = e
		if v := strings.TrimSpace(m["key"]); v != "" {
			cfg.Dedupe.Key = v
		}
		if v := strings.TrimSpace(m["cooldown"]); v != "" {
			cfg.Dedupe.Cooldown = v
		}
	}
	for name, sec := range doc.Sections {
		if strings.HasPrefix(name, `channel "`) {
			id := between(name, `channel "`, `"`)
			if id == "" {
				continue
			}
			m, e := parseKV(sec.Raw)
			sec.Extras = e
			cfg.Channels = append(cfg.Channels, Channel{ID: id, Type: strings.TrimSpace(m["type"]), Enabled: parseBool(m["enabled"], true), To: splitCSV(m["to"]), From: strings.TrimSpace(m["from"]), Path: strings.TrimSpace(m["path"]), Host: strings.TrimSpace(m["host"]), User: strings.TrimSpace(m["user"]), Pass: strings.TrimSpace(m["pass"]), StartTLS: parseBool(m["starttls"], true), InsecureSkipVerify: parseBool(m["insecure_skip_verify"], false), WebhookURL: strings.TrimSpace(m["webhook_url"]), Mention: strings.TrimSpace(m["mention"]), Username: strings.TrimSpace(m["username"]), IconEmoji: strings.TrimSpace(m["icon_emoji"])})
		}
		if strings.HasPrefix(name, `detector "`) {
			id := strings.ToLower(strings.TrimSpace(between(name, `detector "`, `"`)))
			if id == "" {
				continue
			}
			m, e := parseKV(sec.Raw)
			sec.Extras = e
			cfg.Detectors = append(cfg.Detectors, DetectorOverride{Name: id, Notify: parseBool(m["notify"], true), Cooldown: strings.TrimSpace(m["cooldown"]), MinSeverity: strings.ToLower(strings.TrimSpace(m["min_severity"])), Channels: splitCSV(m["channels"])})
		}
	}
	sort.Slice(cfg.Channels, func(i, j int) bool { return cfg.Channels[i].ID < cfg.Channels[j].ID })
	sort.Slice(cfg.Detectors, func(i, j int) bool { return cfg.Detectors[i].Name < cfg.Detectors[j].Name })
}

func SerializeDeterministic(cfg Config) string {
	doc := cfg.Doc
	if doc == nil {
		doc = &Document{Sections: map[string]*Section{}}
	}
	byChan := map[string]Channel{}
	for _, c := range cfg.Channels {
		if id := strings.TrimSpace(c.ID); id != "" {
			byChan[id] = c
		}
	}
	byDet := map[string]DetectorOverride{}
	for _, d := range cfg.Detectors {
		id := strings.ToLower(strings.TrimSpace(d.Name))
		if id != "" {
			d.Name = id
			byDet[id] = d
		}
	}
	var b strings.Builder
	for _, l := range doc.Preamble {
		b.WriteString(l + "\n")
	}
	if len(doc.Preamble) > 0 && strings.TrimSpace(doc.Preamble[len(doc.Preamble)-1]) != "" {
		b.WriteString("\n")
	}
	rendered := map[string]bool{}
	emit := func(kind, key string) {
		switch kind {
		case "notifier":
			b.WriteString("[notifier]\n")
			b.WriteString(fmt.Sprintf("enabled = %t\n", cfg.Notifier.Enabled))
			writeIf(&b, "default_cooldown", cfg.Notifier.DefaultCooldown)
			writeIf(&b, "jsonl_path", cfg.Notifier.JSONLPath)
			writeIf(&b, "hostname_override", cfg.Notifier.HostnameOverride)
			if cfg.Notifier.RateLimitPerMin > 0 {
				b.WriteString(fmt.Sprintf("rate_limit_per_min = %d\n", cfg.Notifier.RateLimitPerMin))
			}
			writeIf(&b, "subject_template", cfg.Notifier.SubjectTemplate)
			writeIf(&b, "body_template", cfg.Notifier.BodyTemplate)
			appendExtras(&b, doc.Sections["notifier"])
			rendered["notifier"] = true
		case "dedupe":
			b.WriteString("[dedupe]\n")
			writeIf(&b, "key", cfg.Dedupe.Key)
			writeIf(&b, "cooldown", cfg.Dedupe.Cooldown)
			appendExtras(&b, doc.Sections["dedupe"])
			rendered["dedupe"] = true
		case "channel":
			ch, ok := byChan[key]
			if !ok {
				return
			}
			renderChannel(&b, ch)
			appendExtras(&b, doc.Sections[fmt.Sprintf("channel %q", key)])
			rendered["channel:"+key] = true
		case "detector":
			d, ok := byDet[key]
			if !ok {
				return
			}
			renderDetector(&b, d)
			appendExtras(&b, doc.Sections[fmt.Sprintf("detector %q", key)])
			rendered["detector:"+key] = true
		}
		b.WriteString("\n")
	}
	for _, ref := range doc.Order {
		if ref.Kind == "unknown" {
			if s := doc.Sections[ref.Key]; s != nil {
				b.WriteString("[" + s.Name + "]\n")
				for _, l := range s.Raw {
					b.WriteString(l + "\n")
				}
				b.WriteString("\n")
			}
			continue
		}
		emit(ref.Kind, ref.Key)
	}
	if !rendered["notifier"] {
		emit("notifier", "notifier")
	}
	if !rendered["dedupe"] {
		emit("dedupe", "dedupe")
	}
	chIDs := make([]string, 0, len(byChan))
	for k := range byChan {
		chIDs = append(chIDs, k)
	}
	sort.Strings(chIDs)
	for _, id := range chIDs {
		if !rendered["channel:"+id] {
			emit("channel", id)
		}
	}
	dIDs := make([]string, 0, len(byDet))
	for k := range byDet {
		dIDs = append(dIDs, k)
	}
	sort.Strings(dIDs)
	for _, id := range dIDs {
		if !rendered["detector:"+id] {
			emit("detector", id)
		}
	}
	return strings.TrimSpace(b.String()) + "\n"
}

func WriteFile(path string, payload []byte) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	// #nosec G304 -- lock path is derived from validated notify.conf path.
	lf, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return "", err
	}
	defer lf.Close()
	fd, err := fileFD(lf)
	if err != nil {
		return "", err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return "", err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN) //nolint:errcheck
	backupPath := ""
	if _, err := os.Stat(path); err == nil {
		stamp := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
		backupPath = fmt.Sprintf("%s.bak-%s", path, stamp)
		if err := copyFile(path, backupPath); err != nil {
			return "", err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return backupPath, nil
}

func fileFD(f *os.File) (int, error) {
	fd := f.Fd()
	if fd > math.MaxInt {
		return 0, fmt.Errorf("file descriptor overflow")
	}
	return int(fd), nil
}
func copyFile(src, dst string) error {
	// #nosec G304 -- source path is computed from existing target config path.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	// #nosec G304 -- destination backup path is derived from target config path.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
func parseKV(lines []string) (map[string]string, []string) {
	m := map[string]string{}
	extras := []string{}
	known := map[string]struct{}{"enabled": {}, "default_cooldown": {}, "jsonl_path": {}, "hostname_override": {}, "rate_limit_per_min": {}, "subject_template": {}, "body_template": {}, "key": {}, "cooldown": {}, "type": {}, "to": {}, "from": {}, "path": {}, "host": {}, "user": {}, "pass": {}, "starttls": {}, "insecure_skip_verify": {}, "webhook_url": {}, "mention": {}, "username": {}, "icon_emoji": {}, "notify": {}, "min_severity": {}, "channels": {}}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			extras = append(extras, raw)
			continue
		}
		i := strings.Index(line, "=")
		if i <= 0 {
			extras = append(extras, raw)
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:i]))
		v := stripInlineComments(strings.TrimSpace(line[i+1:]))
		v = expandEnvRef(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		m[k] = strings.TrimSpace(v)
		if _, ok := known[k]; !ok {
			extras = append(extras, raw)
		}
	}
	return m, extras
}
func appendExtras(b *strings.Builder, s *Section) {
	if s == nil {
		return
	}
	for _, l := range s.Extras {
		b.WriteString(l + "\n")
	}
}
func renderChannel(b *strings.Builder, ch Channel) {
	b.WriteString(fmt.Sprintf("[channel %q]\n", strings.TrimSpace(ch.ID)))
	b.WriteString(fmt.Sprintf("enabled = %t\n", ch.Enabled))
	writeIf(b, "type", ch.Type)
	writeIf(b, "to", strings.Join(ch.To, ","))
	writeIf(b, "from", ch.From)
	writeIf(b, "path", ch.Path)
	writeIf(b, "host", ch.Host)
	writeIf(b, "user", ch.User)
	writeIf(b, "pass", ch.Pass)
	if strings.TrimSpace(ch.Type) == "smtp" {
		b.WriteString(fmt.Sprintf("starttls = %t\n", ch.StartTLS))
		b.WriteString(fmt.Sprintf("insecure_skip_verify = %t\n", ch.InsecureSkipVerify))
	}
	writeIf(b, "webhook_url", ch.WebhookURL)
	writeIf(b, "mention", ch.Mention)
	writeIf(b, "username", ch.Username)
	writeIf(b, "icon_emoji", ch.IconEmoji)
}
func renderDetector(b *strings.Builder, d DetectorOverride) {
	id := strings.ToLower(strings.TrimSpace(d.Name))
	if id == "" {
		return
	}
	b.WriteString(fmt.Sprintf("[detector %q]\n", id))
	b.WriteString(fmt.Sprintf("notify = %t\n", d.Notify))
	writeIf(b, "cooldown", d.Cooldown)
	writeIf(b, "min_severity", strings.ToLower(d.MinSeverity))
	writeIf(b, "channels", strings.Join(d.Channels, ","))
}
func writeIf(b *strings.Builder, key, value string) {
	if v := strings.TrimSpace(value); v != "" {
		b.WriteString(key + " = " + v + "\n")
	}
}
func parseBool(s string, d bool) bool {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "" {
		return d
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
func zv(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return strings.TrimSpace(s)
}
func atoiPos(s string) int {
	s = strings.TrimSpace(s)
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	if n > 0 {
		return n
	}
	return 0
}
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	p := strings.Split(s, ",")
	out := make([]string, 0, len(p))
	for _, x := range p {
		if v := strings.TrimSpace(x); v != "" {
			out = append(out, v)
		}
	}
	return out
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
func stripInlineComments(s string) string {
	in := []rune(s)
	var out []rune
	quote := rune(0)
	for i, r := range in {
		if quote == 0 && (r == '"' || r == '\'') {
			quote = r
			out = append(out, r)
			continue
		}
		if quote != 0 {
			out = append(out, r)
			if r == quote {
				quote = 0
			}
			continue
		}
		if (r == ';' || r == '#') && (i == 0 || unicode.IsSpace(in[i-1])) {
			break
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
}
func expandEnvRef(s string) string {
	for {
		start := strings.Index(s, "${ENV:")
		if start < 0 {
			break
		}
		end := strings.Index(s[start:], "}")
		if end < 0 {
			break
		}
		end = start + end
		key := s[start+6 : end]
		s = s[:start] + os.Getenv(strings.TrimSpace(key)) + s[end+1:]
	}
	return s
}
