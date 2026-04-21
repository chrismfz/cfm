package notify

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cfm/internal/notify/configio"
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
	raw, err := configio.ParseFile(path)
	if err != nil {
		return AdminConfig{}, path, err
	}
	return fromRaw(raw), path, nil
}

func SaveAdminConfig(cfgDir string, c AdminConfig) (string, error) {
	path, _ := resolveConfigPath(cfgDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return path, err
	}
	doc := (*configio.Document)(nil)
	if fileExists(path) {
		if existing, err := configio.ParseFile(path); err == nil {
			doc = existing.Doc
		}
	}
	raw := toRaw(c, doc)
	if err := configio.WriteFile(path, []byte(configio.SerializeDeterministic(raw))); err != nil {
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

func fromRaw(raw configio.Config) AdminConfig {
	c := defaultAdminConfig()
	c.Notifier = AdminNotifierConfig{
		Enabled:          raw.Notifier.Enabled,
		DefaultCooldown:  raw.Notifier.DefaultCooldown,
		JSONLPath:        raw.Notifier.JSONLPath,
		HostnameOverride: raw.Notifier.HostnameOverride,
		RateLimitPerMin:  raw.Notifier.RateLimitPerMin,
		SubjectTemplate:  raw.Notifier.SubjectTemplate,
		BodyTemplate:     raw.Notifier.BodyTemplate,
	}
	c.Dedupe = AdminDedupeConfig{Key: raw.Dedupe.Key, Cooldown: raw.Dedupe.Cooldown}
	for _, ch := range raw.Channels {
		c.Channels = append(c.Channels, AdminChannelConfig{
			ID:                 ch.ID,
			Type:               ch.Type,
			Enabled:            ch.Enabled,
			To:                 ch.To,
			From:               ch.From,
			Path:               ch.Path,
			Host:               ch.Host,
			User:               ch.User,
			Pass:               ch.Pass,
			StartTLS:           ch.StartTLS,
			InsecureSkipVerify: ch.InsecureSkipVerify,
			WebhookURL:         ch.WebhookURL,
			Mention:            ch.Mention,
			Username:           ch.Username,
			IconEmoji:          ch.IconEmoji,
		})
	}
	sort.Slice(c.Channels, func(i, j int) bool { return c.Channels[i].ID < c.Channels[j].ID })
	c.Detectors = map[string]AdminDetectorConfig{}
	for _, d := range raw.Detectors {
		c.Detectors[strings.ToLower(strings.TrimSpace(d.Name))] = AdminDetectorConfig{
			Notify:      d.Notify,
			Cooldown:    d.Cooldown,
			MinSeverity: d.MinSeverity,
			Channels:    d.Channels,
		}
	}
	return c
}

func toRaw(c AdminConfig, doc *configio.Document) configio.Config {
	channels := make([]configio.Channel, 0, len(c.Channels))
	for _, ch := range c.Channels {
		id := strings.TrimSpace(ch.ID)
		if id == "" {
			continue
		}
		channels = append(channels, configio.Channel{
			ID:                 id,
			Type:               strings.TrimSpace(ch.Type),
			Enabled:            ch.Enabled,
			To:                 ch.To,
			From:               strings.TrimSpace(ch.From),
			Path:               strings.TrimSpace(ch.Path),
			Host:               strings.TrimSpace(ch.Host),
			User:               strings.TrimSpace(ch.User),
			Pass:               strings.TrimSpace(ch.Pass),
			StartTLS:           ch.StartTLS,
			InsecureSkipVerify: ch.InsecureSkipVerify,
			WebhookURL:         strings.TrimSpace(ch.WebhookURL),
			Mention:            strings.TrimSpace(ch.Mention),
			Username:           strings.TrimSpace(ch.Username),
			IconEmoji:          strings.TrimSpace(ch.IconEmoji),
		})
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].ID < channels[j].ID })

	detectors := make([]configio.DetectorOverride, 0, len(c.Detectors))
	for name, d := range c.Detectors {
		id := strings.ToLower(strings.TrimSpace(name))
		if id == "" {
			continue
		}
		detectors = append(detectors, configio.DetectorOverride{
			Name:        id,
			Notify:      d.Notify,
			Cooldown:    strings.TrimSpace(d.Cooldown),
			MinSeverity: strings.ToLower(strings.TrimSpace(d.MinSeverity)),
			Channels:    d.Channels,
		})
	}
	sort.Slice(detectors, func(i, j int) bool { return detectors[i].Name < detectors[j].Name })

	return configio.Config{
		Notifier: configio.Notifier{
			Enabled:          c.Notifier.Enabled,
			DefaultCooldown:  strings.TrimSpace(c.Notifier.DefaultCooldown),
			JSONLPath:        strings.TrimSpace(c.Notifier.JSONLPath),
			HostnameOverride: strings.TrimSpace(c.Notifier.HostnameOverride),
			RateLimitPerMin:  c.Notifier.RateLimitPerMin,
			SubjectTemplate:  strings.TrimSpace(c.Notifier.SubjectTemplate),
			BodyTemplate:     strings.TrimSpace(c.Notifier.BodyTemplate),
		},
		Dedupe: configio.Dedupe{
			Key:      strings.TrimSpace(c.Dedupe.Key),
			Cooldown: strings.TrimSpace(c.Dedupe.Cooldown),
		},
		Channels:  channels,
		Detectors: detectors,
		Doc:       doc,
	}
}
