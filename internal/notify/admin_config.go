package notify

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type AdminConfig struct {
	Notifier  AdminNotifierConfig            `json:"notifier"`
	Dedupe    AdminDedupeConfig              `json:"dedupe"`
	Channels  []AdminChannelConfig           `json:"channels"`
	Detectors map[string]AdminDetectorConfig `json:"detectors"`
}

type AdminNotifierConfig struct {
	Enabled          bool   `json:"enabled"`
	DefaultCooldown  string `json:"default_cooldown"`
	JSONLPath        string `json:"jsonl_path"`
	HostnameOverride string `json:"hostname_override"`
	RateLimitPerMin  int    `json:"rate_limit_per_min"`
	SubjectTemplate  string `json:"subject_template"`
	BodyTemplate     string `json:"body_template"`
}

type AdminDedupeConfig struct {
	Key      string `json:"key"`
	Cooldown string `json:"cooldown"`
}

type AdminChannelConfig struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	Enabled            bool     `json:"enabled"`
	To                 []string `json:"to,omitempty"`
	From               string   `json:"from,omitempty"`
	Path               string   `json:"path,omitempty"`
	Host               string   `json:"host,omitempty"`
	User               string   `json:"user,omitempty"`
	Pass               string   `json:"pass,omitempty"`
	StartTLS           bool     `json:"starttls,omitempty"`
	InsecureSkipVerify bool     `json:"insecure_skip_verify,omitempty"`
	WebhookURL         string   `json:"webhook_url,omitempty"`
	Mention            string   `json:"mention,omitempty"`
	Username           string   `json:"username,omitempty"`
	IconEmoji          string   `json:"icon_emoji,omitempty"`
}

type AdminDetectorConfig struct {
	Notify      bool     `json:"notify"`
	Cooldown    string   `json:"cooldown,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty"`
	Channels    []string `json:"channels,omitempty"`
}

func resolveConfigPath(cfgDir string) (path string, exists bool) {
	if cfgDir != "" {
		path = filepath.Join(cfgDir, "notify.conf")
		if fileExists(path) {
			return path, true
		}
	}
	if fileExists("/etc/cfm/notify.conf") {
		return "/etc/cfm/notify.conf", true
	}
	if cfgDir != "" {
		return filepath.Join(cfgDir, "notify.conf"), false
	}
	return "/etc/cfm/notify.conf", false
}

func LoadAdminConfig(cfgDir string) (AdminConfig, string, error) {
	path, exists := resolveConfigPath(cfgDir)
	if !exists {
		return defaultAdminConfig(), path, nil
	}
	ini, err := parseINI(path)
	if err != nil {
		return AdminConfig{}, path, err
	}
	return fromINI(ini), path, nil
}

func SaveAdminConfig(cfgDir string, c AdminConfig) (string, error) {
	path, _ := resolveConfigPath(cfgDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return path, err
	}
	payload := strings.TrimSpace(renderConfig(c)) + "\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		return path, err
	}
	return path, nil
}

func Reload(cfgDir string) error {
	return Init(cfgDir)
}

func defaultAdminConfig() AdminConfig {
	return AdminConfig{
		Notifier: AdminNotifierConfig{
			Enabled:         false,
			DefaultCooldown: "5m",
			JSONLPath:       "/var/lib/cfm/notify.log.jsonl",
		},
		Dedupe: AdminDedupeConfig{
			Key:      "{{.Host}}|{{.Kind}}|{{.SrcIP}}|{{.Reason}}",
			Cooldown: "5m",
		},
		Channels:  []AdminChannelConfig{},
		Detectors: map[string]AdminDetectorConfig{},
	}
}

func fromINI(ini *iniFile) AdminConfig {
	c := defaultAdminConfig()
	if s := ini.getSection("notifier"); s != nil {
		c.Notifier.Enabled = parseBool(s["enabled"], true)
		c.Notifier.DefaultCooldown = zv(s["default_cooldown"], c.Notifier.DefaultCooldown)
		if p := strings.TrimSpace(s["jsonl_path"]); p != "" {
			c.Notifier.JSONLPath = p
		}
		c.Notifier.HostnameOverride = strings.TrimSpace(s["hostname_override"])
		if rl := strings.TrimSpace(s["rate_limit_per_min"]); rl != "" {
			n, _ := strconv.Atoi(strings.TrimSpace(rl))
			if n > 0 {
				c.Notifier.RateLimitPerMin = n
			}
		}
		c.Notifier.SubjectTemplate = strings.TrimSpace(s["subject_template"])
		c.Notifier.BodyTemplate = strings.TrimSpace(s["body_template"])
	}
	if s := ini.getSection("dedupe"); s != nil {
		if key := strings.TrimSpace(s["key"]); key != "" {
			c.Dedupe.Key = key
		}
		if cd := strings.TrimSpace(s["cooldown"]); cd != "" {
			c.Dedupe.Cooldown = cd
		}
	}
	for name, sec := range ini.sectionsWithPrefix(`channel "`) {
		id := between(name, `channel "`, `"`)
		if id == "" {
			continue
		}
		ch := AdminChannelConfig{
			ID:                 id,
			Type:               strings.TrimSpace(sec["type"]),
			Enabled:            parseBool(sec["enabled"], true),
			To:                 splitCSV(sec["to"]),
			From:               strings.TrimSpace(sec["from"]),
			Path:               strings.TrimSpace(sec["path"]),
			Host:               strings.TrimSpace(sec["host"]),
			User:               strings.TrimSpace(sec["user"]),
			Pass:               strings.TrimSpace(sec["pass"]),
			StartTLS:           parseBool(sec["starttls"], true),
			InsecureSkipVerify: parseBool(sec["insecure_skip_verify"], false),
			WebhookURL:         strings.TrimSpace(sec["webhook_url"]),
			Mention:            strings.TrimSpace(sec["mention"]),
			Username:           strings.TrimSpace(sec["username"]),
			IconEmoji:          strings.TrimSpace(sec["icon_emoji"]),
		}
		c.Channels = append(c.Channels, ch)
	}
	sort.Slice(c.Channels, func(i, j int) bool { return c.Channels[i].ID < c.Channels[j].ID })

	c.Detectors = map[string]AdminDetectorConfig{}
	for name, sec := range ini.sectionsWithPrefix(`detector "`) {
		id := strings.ToLower(strings.TrimSpace(between(name, `detector "`, `"`)))
		if id == "" {
			continue
		}
		c.Detectors[id] = AdminDetectorConfig{
			Notify:      parseBool(sec["notify"], true),
			Cooldown:    strings.TrimSpace(sec["cooldown"]),
			MinSeverity: strings.ToLower(strings.TrimSpace(sec["min_severity"])),
			Channels:    splitCSV(sec["channels"]),
		}
	}
	return c
}

func renderConfig(c AdminConfig) string {
	if c.Detectors == nil {
		c.Detectors = map[string]AdminDetectorConfig{}
	}
	var b strings.Builder
	b.WriteString("[notifier]\n")
	b.WriteString(fmt.Sprintf("enabled = %t\n", c.Notifier.Enabled))
	if strings.TrimSpace(c.Notifier.DefaultCooldown) != "" {
		b.WriteString("default_cooldown = " + strings.TrimSpace(c.Notifier.DefaultCooldown) + "\n")
	}
	if strings.TrimSpace(c.Notifier.JSONLPath) != "" {
		b.WriteString("jsonl_path = " + strings.TrimSpace(c.Notifier.JSONLPath) + "\n")
	}
	if strings.TrimSpace(c.Notifier.HostnameOverride) != "" {
		b.WriteString("hostname_override = " + strings.TrimSpace(c.Notifier.HostnameOverride) + "\n")
	}
	if c.Notifier.RateLimitPerMin > 0 {
		b.WriteString(fmt.Sprintf("rate_limit_per_min = %d\n", c.Notifier.RateLimitPerMin))
	}
	if strings.TrimSpace(c.Notifier.SubjectTemplate) != "" {
		b.WriteString("subject_template = " + strings.TrimSpace(c.Notifier.SubjectTemplate) + "\n")
	}
	if strings.TrimSpace(c.Notifier.BodyTemplate) != "" {
		b.WriteString("body_template = " + strings.TrimSpace(c.Notifier.BodyTemplate) + "\n")
	}
	b.WriteString("\n[dedupe]\n")
	if strings.TrimSpace(c.Dedupe.Key) != "" {
		b.WriteString("key = " + strings.TrimSpace(c.Dedupe.Key) + "\n")
	}
	if strings.TrimSpace(c.Dedupe.Cooldown) != "" {
		b.WriteString("cooldown = " + strings.TrimSpace(c.Dedupe.Cooldown) + "\n")
	}

	for _, ch := range c.Channels {
		id := strings.TrimSpace(ch.ID)
		if id == "" {
			continue
		}
		b.WriteString(fmt.Sprintf("\n[channel %q]\n", id))
		b.WriteString(fmt.Sprintf("enabled = %t\n", ch.Enabled))
		if t := strings.TrimSpace(ch.Type); t != "" {
			b.WriteString("type = " + t + "\n")
		}
		writeIf(&b, "to", strings.Join(ch.To, ","))
		writeIf(&b, "from", ch.From)
		writeIf(&b, "path", ch.Path)
		writeIf(&b, "host", ch.Host)
		writeIf(&b, "user", ch.User)
		writeIf(&b, "pass", ch.Pass)
		if ch.Type == "smtp" {
			b.WriteString(fmt.Sprintf("starttls = %t\n", ch.StartTLS))
			b.WriteString(fmt.Sprintf("insecure_skip_verify = %t\n", ch.InsecureSkipVerify))
		}
		writeIf(&b, "webhook_url", ch.WebhookURL)
		writeIf(&b, "mention", ch.Mention)
		writeIf(&b, "username", ch.Username)
		writeIf(&b, "icon_emoji", ch.IconEmoji)
	}

	detectorIDs := make([]string, 0, len(c.Detectors))
	for k := range c.Detectors {
		detectorIDs = append(detectorIDs, strings.TrimSpace(strings.ToLower(k)))
	}
	sort.Strings(detectorIDs)
	for _, id := range detectorIDs {
		if id == "" {
			continue
		}
		d := c.Detectors[id]
		b.WriteString(fmt.Sprintf("\n[detector %q]\n", id))
		b.WriteString(fmt.Sprintf("notify = %t\n", d.Notify))
		writeIf(&b, "cooldown", d.Cooldown)
		writeIf(&b, "min_severity", strings.ToLower(d.MinSeverity))
		writeIf(&b, "channels", strings.Join(d.Channels, ","))
	}
	return b.String()
}

func writeIf(b *strings.Builder, key, value string) {
	v := strings.TrimSpace(value)
	if v == "" {
		return
	}
	b.WriteString(key + " = " + v + "\n")
}
