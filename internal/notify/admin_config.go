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

type AdminMutations struct {
	Notifier            *AdminNotifierConfig    `json:"notifier,omitempty"`
	Dedupe              *AdminDedupeConfig      `json:"dedupe,omitempty"`
	Channels            []AdminChannelMutation  `json:"channel_mutations,omitempty"`
	Detectors           []AdminDetectorMutation `json:"detector_mutations,omitempty"`
	DeleteChannelIDs    []string                `json:"delete_channels,omitempty"`
	DeleteDetectorNames []string                `json:"delete_detectors,omitempty"`
}

type AdminChannelMutation struct {
	ID                 string    `json:"id"`
	NewID              *string   `json:"new_id,omitempty"`
	Delete             bool      `json:"delete,omitempty"`
	Type               *string   `json:"type,omitempty"`
	Enabled            *bool     `json:"enabled,omitempty"`
	To                 *[]string `json:"to,omitempty"`
	DeleteTo           bool      `json:"delete_to,omitempty"`
	From               *string   `json:"from,omitempty"`
	DeleteFrom         bool      `json:"delete_from,omitempty"`
	Path               *string   `json:"path,omitempty"`
	DeletePath         bool      `json:"delete_path,omitempty"`
	Host               *string   `json:"host,omitempty"`
	DeleteHost         bool      `json:"delete_host,omitempty"`
	User               *string   `json:"user,omitempty"`
	DeleteUser         bool      `json:"delete_user,omitempty"`
	Pass               *string   `json:"pass,omitempty"`
	DeletePass         bool      `json:"delete_pass,omitempty"`
	StartTLS           *bool     `json:"starttls,omitempty"`
	InsecureSkipVerify *bool     `json:"insecure_skip_verify,omitempty"`
	WebhookURL         *string   `json:"webhook_url,omitempty"`
	DeleteWebhookURL   bool      `json:"delete_webhook_url,omitempty"`
	Mention            *string   `json:"mention,omitempty"`
	DeleteMention      bool      `json:"delete_mention,omitempty"`
	Username           *string   `json:"username,omitempty"`
	DeleteUsername     bool      `json:"delete_username,omitempty"`
	IconEmoji          *string   `json:"icon_emoji,omitempty"`
	DeleteIconEmoji    bool      `json:"delete_icon_emoji,omitempty"`
}

type AdminDetectorMutation struct {
	Name              string    `json:"name"`
	NewName           *string   `json:"new_name,omitempty"`
	Delete            bool      `json:"delete,omitempty"`
	Notify            *bool     `json:"notify,omitempty"`
	Cooldown          *string   `json:"cooldown,omitempty"`
	DeleteCooldown    bool      `json:"delete_cooldown,omitempty"`
	MinSeverity       *string   `json:"min_severity,omitempty"`
	DeleteMinSeverity bool      `json:"delete_min_severity,omitempty"`
	Channels          *[]string `json:"channels,omitempty"`
	DeleteChannels    bool      `json:"delete_channels,omitempty"`
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

func SaveAdminConfigMutations(cfgDir string, m AdminMutations) (string, error) {
	path, _ := resolveConfigPath(cfgDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return path, err
	}
	base, err := loadRawConfig(path)
	if err != nil {
		return path, err
	}
	applyMutations(&base, m)
	if err := configio.WriteFile(path, []byte(configio.SerializeDeterministic(base))); err != nil {
		return path, err
	}
	return path, nil
}

func RenderAdminConfig(cfgDir string, c AdminConfig) (string, error) {
	path, _ := resolveConfigPath(cfgDir)
	doc := (*configio.Document)(nil)
	if fileExists(path) {
		existing, err := configio.ParseFile(path)
		if err != nil {
			return "", err
		}
		doc = existing.Doc
	}
	raw := toRaw(c, doc)
	return configio.SerializeDeterministic(raw), nil
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

func loadRawConfig(path string) (configio.Config, error) {
	if fileExists(path) {
		existing, err := configio.ParseFile(path)
		if err == nil {
			return existing, nil
		}
	}
	return toRaw(defaultAdminConfig(), nil), nil
}

func applyMutations(raw *configio.Config, m AdminMutations) {
	if raw == nil {
		return
	}
	if m.Notifier != nil {
		raw.Notifier.Enabled = m.Notifier.Enabled
		raw.Notifier.DefaultCooldown = strings.TrimSpace(m.Notifier.DefaultCooldown)
		raw.Notifier.JSONLPath = strings.TrimSpace(m.Notifier.JSONLPath)
		raw.Notifier.HostnameOverride = strings.TrimSpace(m.Notifier.HostnameOverride)
		raw.Notifier.RateLimitPerMin = m.Notifier.RateLimitPerMin
		raw.Notifier.SubjectTemplate = strings.TrimSpace(m.Notifier.SubjectTemplate)
		raw.Notifier.BodyTemplate = strings.TrimSpace(m.Notifier.BodyTemplate)
	}
	if m.Dedupe != nil {
		raw.Dedupe.Key = strings.TrimSpace(m.Dedupe.Key)
		raw.Dedupe.Cooldown = strings.TrimSpace(m.Dedupe.Cooldown)
	}

	chByID := map[string]configio.Channel{}
	for _, ch := range raw.Channels {
		if id := strings.TrimSpace(ch.ID); id != "" {
			chByID[id] = ch
		}
	}
	for _, id := range m.DeleteChannelIDs {
		delete(chByID, strings.TrimSpace(id))
	}
	for _, mut := range m.Channels {
		id := strings.TrimSpace(mut.ID)
		if id == "" {
			continue
		}
		if mut.Delete {
			delete(chByID, id)
			continue
		}
		ch, ok := chByID[id]
		if !ok {
			ch = configio.Channel{ID: id, Enabled: true, StartTLS: true}
		}
		if mut.Type != nil {
			ch.Type = strings.TrimSpace(*mut.Type)
		}
		if mut.Enabled != nil {
			ch.Enabled = *mut.Enabled
		}
		if mut.To != nil {
			ch.To = normalizeList(*mut.To)
		} else if mut.DeleteTo {
			ch.To = nil
		}
		applyOptionalString(&ch.From, mut.From, mut.DeleteFrom)
		applyOptionalString(&ch.Path, mut.Path, mut.DeletePath)
		applyOptionalString(&ch.Host, mut.Host, mut.DeleteHost)
		applyOptionalString(&ch.User, mut.User, mut.DeleteUser)
		applyOptionalString(&ch.Pass, mut.Pass, mut.DeletePass)
		if mut.StartTLS != nil {
			ch.StartTLS = *mut.StartTLS
		}
		if mut.InsecureSkipVerify != nil {
			ch.InsecureSkipVerify = *mut.InsecureSkipVerify
		}
		applyOptionalString(&ch.WebhookURL, mut.WebhookURL, mut.DeleteWebhookURL)
		applyOptionalString(&ch.Mention, mut.Mention, mut.DeleteMention)
		applyOptionalString(&ch.Username, mut.Username, mut.DeleteUsername)
		applyOptionalString(&ch.IconEmoji, mut.IconEmoji, mut.DeleteIconEmoji)

		targetID := id
		if mut.NewID != nil {
			if v := strings.TrimSpace(*mut.NewID); v != "" {
				targetID = v
			}
		}
		ch.ID = targetID
		delete(chByID, id)
		chByID[targetID] = ch
	}
	raw.Channels = make([]configio.Channel, 0, len(chByID))
	for _, ch := range chByID {
		raw.Channels = append(raw.Channels, ch)
	}
	sort.Slice(raw.Channels, func(i, j int) bool { return raw.Channels[i].ID < raw.Channels[j].ID })

	dByName := map[string]configio.DetectorOverride{}
	for _, d := range raw.Detectors {
		if name := strings.ToLower(strings.TrimSpace(d.Name)); name != "" {
			d.Name = name
			dByName[name] = d
		}
	}
	for _, name := range m.DeleteDetectorNames {
		delete(dByName, strings.ToLower(strings.TrimSpace(name)))
	}
	for _, mut := range m.Detectors {
		name := strings.ToLower(strings.TrimSpace(mut.Name))
		if name == "" {
			continue
		}
		if mut.Delete {
			delete(dByName, name)
			continue
		}
		d, ok := dByName[name]
		if !ok {
			d = configio.DetectorOverride{Name: name, Notify: true}
		}
		if mut.Notify != nil {
			d.Notify = *mut.Notify
		}
		applyOptionalString(&d.Cooldown, mut.Cooldown, mut.DeleteCooldown)
		if mut.MinSeverity != nil {
			d.MinSeverity = strings.ToLower(strings.TrimSpace(*mut.MinSeverity))
		} else if mut.DeleteMinSeverity {
			d.MinSeverity = ""
		}
		if mut.Channels != nil {
			d.Channels = normalizeList(*mut.Channels)
		} else if mut.DeleteChannels {
			d.Channels = nil
		}

		targetName := name
		if mut.NewName != nil {
			if v := strings.ToLower(strings.TrimSpace(*mut.NewName)); v != "" {
				targetName = v
			}
		}
		d.Name = targetName
		delete(dByName, name)
		dByName[targetName] = d
	}
	raw.Detectors = make([]configio.DetectorOverride, 0, len(dByName))
	for _, d := range dByName {
		raw.Detectors = append(raw.Detectors, d)
	}
	sort.Slice(raw.Detectors, func(i, j int) bool { return raw.Detectors[i].Name < raw.Detectors[j].Name })
}

func applyOptionalString(dst *string, src *string, deleteFlag bool) {
	if src != nil {
		*dst = strings.TrimSpace(*src)
		return
	}
	if deleteFlag {
		*dst = ""
	}
}

func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if vv := strings.TrimSpace(v); vv != "" {
			out = append(out, vv)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
