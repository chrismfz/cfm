package detectors

import (
	"context"
	"io"
	"regexp"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/logging"
)

var customState, _ = core.LoadState("")

type customRuleTarget uint8

const (
	customTargetAuto customRuleTarget = iota
	customTargetIP
	customTargetUser
	customTargetBoth
)

type customRule struct {
	target customRuleTarget
	re     *regexp.Regexp
}

type customDetector struct {
	name string
	cfg  customConfig
	src  core.LineSource

	state    *core.State
	stateKey string

	rules   []customRule
	samples *core.SampleRing
	counts  *core.SlidingCounter
	gate    *core.AlertGate
}

type customConfig struct {
	Mode            string
	LogPath         string
	JournalUnit     string
	JournalMatches  []string
	Every           time.Duration
	Window          time.Duration
	Cooldown        time.Duration
	SampleLimit     int
	AuthFailPerIP   int
	AuthFailPerUser int
}

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:             "custom",
		Title:               "Custom regex detector",
		Description:         "Detect authentication-like failures using custom regex rules and key on captured IP/user values.",
		DefaultsTemplate:    map[string]string{"ENABLED": "1", "MODE": "file", "LOG_PATH": "/var/log/auth.log", "EVERY": "2s", "WINDOW": "10m", "COOLDOWN": "20m", "SAMPLE_LIMIT": "10", "AUTHFAIL_IP": "20", "AUTHFAIL_USER": "10", "BLOCK": "dryrun", "BLOCK_COOLDOWN": "20m"},
		LeniencySupported:   true,
		LeniencyRecommended: true,
	})

	Register("custom", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 2*time.Second)
		defWindow := kvDur(global, "DEFAULT_WINDOW", 10*time.Minute)
		defCooldown := kvDur(global, "DEFAULT_COOLDOWN", 20*time.Minute)

		cfg := customConfig{
			Mode:            strings.ToLower(kvStrClean(kv, "MODE", "file")),
			LogPath:         kvStrClean(kv, "LOG_PATH", "/var/log/auth.log"),
			JournalUnit:     kvStrClean(kv, "JOURNAL_UNIT", ""),
			JournalMatches:  strings.Fields(kvStrClean(kv, "JOURNAL_MATCHES", "")),
			Every:           kvDur(kv, "EVERY", defEvery),
			Window:          kvDur(kv, "WINDOW", defWindow),
			Cooldown:        kvDur(kv, "COOLDOWN", defCooldown),
			SampleLimit:     kvInt(kv, "SAMPLE_LIMIT", 10),
			AuthFailPerIP:   kvInt(kv, "AUTHFAIL_IP", 20),
			AuthFailPerUser: kvInt(kv, "AUTHFAIL_USER", 10),
		}

		// Parse auth-like knobs for parity with built-in detectors.
		_ = kvStrClean(kv, "BLOCK", kvStrClean(global, "BLOCK", ""))
		_ = kvDur(kv, "BLOCK_COOLDOWN", kvDur(global, "BLOCK_COOLDOWN", 20*time.Minute))

		rules := parseCustomRules(kv)
		d := &customDetector{
			name:    section,
			cfg:     cfg,
			rules:   rules,
			samples: core.NewSampleRing(cfg.SampleLimit),
			counts:  core.NewSlidingCounter(cfg.Window, 0),
			gate:    core.NewAlertGate(cfg.Cooldown),
		}

		switch cfg.Mode {
		case "journal":
			j := core.NewJournalTailer(cfg.JournalUnit)
			if len(cfg.JournalMatches) > 0 {
				j.Matches = append(j.Matches, cfg.JournalMatches...)
			}
			d.src = j
			if customState != nil {
				d.state = customState
				d.stateKey = core.FileStateKey(section, "journal:"+cfg.JournalUnit+":"+strings.Join(cfg.JournalMatches, " "))
			}
			logging.Logf("[detectors][%s] source=journal unit=%s matches=%v", section, cfg.JournalUnit, cfg.JournalMatches)
		default:
			src := core.NewFileTailer(cfg.LogPath)
			d.src = src
			if customState != nil {
				d.state = customState
				d.stateKey = core.FileStateKey(section, cfg.LogPath)
			}
			logging.Logf("[detectors][%s] source=file path=%s", section, cfg.LogPath)
		}

		logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s mode=%s rules=%d limits: ip=%d user=%d)",
			section, cfg.Every, cfg.Window, cfg.Cooldown, cfg.Mode, len(rules), cfg.AuthFailPerIP, cfg.AuthFailPerUser)
		return d, nil
	})
}

func parseCustomRules(kv KV) []customRule {
	lines := kvLines(kv, "RULES")
	if len(lines) == 0 {
		if raw := strings.TrimSpace(kvStrClean(kv, "RULES", "")); raw != "" {
			lines = append(lines, raw)
		}
	}
	out := make([]customRule, 0, len(lines))
	for _, line := range lines {
		target := customTargetAuto
		reStr := strings.TrimSpace(line)
		if i := strings.Index(line, ":"); i > 0 {
			prefix := strings.ToLower(strings.TrimSpace(line[:i]))
			switch prefix {
			case "ip":
				target = customTargetIP
				reStr = strings.TrimSpace(line[i+1:])
			case "user":
				target = customTargetUser
				reStr = strings.TrimSpace(line[i+1:])
			case "both":
				target = customTargetBoth
				reStr = strings.TrimSpace(line[i+1:])
			}
		}
		if reStr == "" {
			continue
		}
		re, err := regexp.Compile(reStr)
		if err != nil {
			logging.Logf("[detectors][custom] invalid regex %q: %v", line, err)
			continue
		}
		out = append(out, customRule{target: target, re: re})
	}
	return out
}

func (d *customDetector) Name() string { return d.name }
func (d *customDetector) Every() time.Duration {
	if d.cfg.Every > 0 {
		return d.cfg.Every
	}
	return 2 * time.Second
}

func (d *customDetector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	if d.src == nil || len(d.rules) == 0 {
		return nil
	}

	if d.state != nil && d.stateKey != "" {
		if p, ok := d.state.Get(d.stateKey); ok {
			if ft, ok := d.src.(*core.FileTailer); ok {
				ft.ApplyResume(p.Inode, p.Offset)
			}
			if jt, ok := d.src.(*core.JournalTailer); ok {
				jt.ApplyResume(0, 0, p.TS)
			}
		}
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
		d.consume(now, line, out)
	}

	if d.state != nil && d.stateKey != "" {
		off, ino, ts := d.src.Position()
		d.state.Put(d.stateKey, core.Position{Offset: off, Inode: ino, TS: ts})
	}
	return nil
}

func (d *customDetector) consume(now time.Time, line string, out chan<- core.Alert) {
	for _, rule := range d.rules {
		m := rule.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		ip := captureByName(rule.re, m, "ip")
		user := strings.ToLower(captureByName(rule.re, m, "user"))
		if ip == "" && len(m) > 1 {
			ip = m[1]
		}
		if user == "" && len(m) > 2 {
			user = strings.ToLower(m[2])
		}

		switch rule.target {
		case customTargetIP:
			d.bump(now, "AUTHFAIL|ip", ip, line, out)
		case customTargetUser:
			d.bump(now, "AUTHFAIL|user", user, line, out)
		case customTargetBoth:
			d.bump(now, "AUTHFAIL|ip", ip, line, out)
			d.bump(now, "AUTHFAIL|user", user, line, out)
		default:
			if ip != "" {
				d.bump(now, "AUTHFAIL|ip", ip, line, out)
			}
			if user != "" {
				d.bump(now, "AUTHFAIL|user", user, line, out)
			}
		}
	}
}

func captureByName(re *regexp.Regexp, m []string, name string) string {
	idx := re.SubexpIndex(name)
	if idx > 0 && idx < len(m) {
		return m[idx]
	}
	return ""
}

func (d *customDetector) bump(now time.Time, kindKey, key, sample string, out chan<- core.Alert) {
	if key == "" {
		return
	}
	count := d.counts.Add(kindKey+":"+key, now)
	d.samples.Add(kindKey+":"+key, sample)

	threshold := 0
	switch kindKey {
	case "AUTHFAIL|ip":
		threshold = d.cfg.AuthFailPerIP
	case "AUTHFAIL|user":
		threshold = d.cfg.AuthFailPerUser
	}
	if !d.gate.Allow(kindKey+":"+key, now, count, threshold) {
		return
	}

	out <- core.Alert{
		When:    now,
		Kind:    core.AlertKind("CUSTOM/AUTHFAIL"),
		Key:     key,
		Count:   count,
		Samples: d.samples.GetAndClear(kindKey + ":" + key),
		Extra: map[string]string{
			"source": "custom",
			"reason": kindKey,
			"key":    key,
		},
	}
}
