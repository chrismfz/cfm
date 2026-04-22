package detectors

import (
	"context"
	"fmt"
	"io"
	"net"
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
	re      *regexp.Regexp
	hasIP   bool
	hasUser bool
	raw     string
}

type customDetector struct {
	name string
	cfg  customConfig
	src  core.LineSource

	state    *core.State
	stateKey string

	rules   []customRule
	ignores []*regexp.Regexp
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
	MatchTarget     customRuleTarget
}

const (
	customMaxLinesPerTick = 3000
	customRunBudget       = 900 * time.Millisecond
	customMaxLineBytes    = 16 * 1024
	customMaxFailRegex    = 128
)

type customRuleValidationError struct {
	RuleIndex int
	Rule      string
	Message   string
}

type customRuleValidationResult struct {
	rules []customRule
	errs  []customRuleValidationError
}

func (r customRuleValidationResult) strategyOK(target customRuleTarget) bool {
	hasIP := false
	hasUser := false
	for _, rule := range r.rules {
		hasIP = hasIP || rule.hasIP
		hasUser = hasUser || rule.hasUser
	}
	if hasIP {
		return true
	}
	return target == customTargetUser && hasUser
}

type customInitError struct {
	summary     string
	diagnostics []string
}

func (e *customInitError) Error() string { return e.summary }

func (e *customInitError) Diagnostics() []string {
	out := make([]string, len(e.diagnostics))
	copy(out, e.diagnostics)
	return out
}

func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:          "custom",
		Title:            "Custom regex detector",
		Description:      "Detect authentication-like failures using custom regex rules and key on captured IP/user values.",
		DefaultsTemplate: map[string]string{"ENABLED": "1", "MODE": "file", "LOG_PATH": "/var/log/auth.log", "JOURNAL_UNIT": "", "EVERY": "2s", "WINDOW": "10m", "COOLDOWN": "20m", "SAMPLE_LIMIT": "10", "AUTHFAIL_IP": "20", "AUTHFAIL_USER": "10", "MATCH_TARGET": "both", "FAIL_REGEX": "(?P<ip>\\S+) .* invalid user (?P<user>\\S+)", "IGNORE_REGEX": "", "BLOCK": "dryrun", "BLOCK_COOLDOWN": "20m"},
		ExamplePresets: []meta.Preset{
			{
				ID:          "proxmox-auth-failure",
				Title:       "Proxmox-style auth failure",
				Description: "Parses pvedaemon auth failures and keys by source IP and username.",
				Template: map[string]string{
					"MODE":          "file",
					"LOG_PATH":      "/var/log/auth.log",
					"MATCH_TARGET":  "both",
					"AUTHFAIL_IP":   "8",
					"AUTHFAIL_USER": "5",
					"FAIL_REGEX":    "authentication failure; .* rhost=(?P<ip>\\S+) user=(?P<user>\\S+)",
					"IGNORE_REGEX":  "rhost=(127\\.0\\.0\\.1|::1)",
					"BLOCK":         "30m",
				},
			},
			{
				ID:          "pam-unix-auth-failure",
				Title:       "generic pam_unix auth failure",
				Description: "Matches generic pam_unix authentication failures from Linux auth logs.",
				Template: map[string]string{
					"MODE":          "file",
					"LOG_PATH":      "/var/log/auth.log",
					"MATCH_TARGET":  "both",
					"AUTHFAIL_IP":   "12",
					"AUTHFAIL_USER": "8",
					"FAIL_REGEX":    "pam_unix\\([^)]*\\): authentication failure; .*rhost=(?P<ip>\\S+).*user=(?P<user>\\S+)",
					"BLOCK":         "dryrun",
				},
			},
		},
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
			MatchTarget:     parseCustomMatchTarget(kvStrClean(kv, "MATCH_TARGET", "both"), customTargetBoth),
		}

		// Parse auth-like knobs for parity with built-in detectors.
		_ = kvStrClean(kv, "BLOCK", kvStrClean(global, "BLOCK", ""))
		_ = kvDur(kv, "BLOCK_COOLDOWN", kvDur(global, "BLOCK_COOLDOWN", 20*time.Minute))

		parsed := parseCustomRulesResult(kv, cfg.MatchTarget)
		if len(parsed.errs) > 0 {
			diagnostics := make([]string, 0, len(parsed.errs))
			for _, e := range parsed.errs {
				diagnostics = append(diagnostics, fmt.Sprintf("FAIL_REGEX[%d] %s", e.RuleIndex, e.Message))
			}
			return nil, &customInitError{
				summary:     fmt.Sprintf("invalid FAIL_REGEX configuration (%d error(s))", len(parsed.errs)),
				diagnostics: diagnostics,
			}
		}
		if !parsed.strategyOK(cfg.MatchTarget) {
			msg := "at least one target capture strategy is required (named (?P<ip>...) capture or MATCH_TARGET=user with (?P<user>...))"
			return nil, &customInitError{
				summary:     "invalid FAIL_REGEX capture strategy",
				diagnostics: []string{msg},
			}
		}
		rules := parsed.rules
		ignores := parseCustomIgnoreRules(kv)
		d := &customDetector{
			name:    section,
			cfg:     cfg,
			rules:   rules,
			ignores: ignores,
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

func parseCustomRules(kv KV, target customRuleTarget) []customRule {
	result := parseCustomRulesResult(kv, target)
	return result.rules
}

func parseCustomRulesResult(kv KV, target customRuleTarget) customRuleValidationResult {
	lines := kvLines(kv, "FAIL_REGEX")
	if len(lines) == 0 {
		lines = kvLines(kv, "RULES")
	}
	if len(lines) == 0 {
		if raw := strings.TrimSpace(kvStrClean(kv, "FAIL_REGEX", "")); raw != "" {
			lines = append(lines, raw)
		}
	}
	if len(lines) == 0 {
		if raw := strings.TrimSpace(kvStrClean(kv, "RULES", "")); raw != "" {
			lines = append(lines, raw)
		}
	}
	result := customRuleValidationResult{rules: make([]customRule, 0, len(lines))}
	if len(lines) == 0 {
		result.errs = append(result.errs, customRuleValidationError{
			RuleIndex: -1,
			Message:   "FAIL_REGEX is required and must contain at least one regex",
		})
		return result
	}
	if len(lines) > customMaxFailRegex {
		result.errs = append(result.errs, customRuleValidationError{
			RuleIndex: -1,
			Message:   fmt.Sprintf("too many FAIL_REGEX rules (%d > %d)", len(lines), customMaxFailRegex),
		})
		return result
	}
	for idx, line := range lines {
		reStr := strings.TrimSpace(line)
		if reStr == "" {
			result.errs = append(result.errs, customRuleValidationError{
				RuleIndex: idx,
				Rule:      line,
				Message:   "regex is empty",
			})
			continue
		}
		re, err := regexp.Compile(reStr)
		if err != nil {
			result.errs = append(result.errs, customRuleValidationError{
				RuleIndex: idx,
				Rule:      line,
				Message:   fmt.Sprintf("regex does not compile: %v", err),
			})
			continue
		}
		hasIP := re.SubexpIndex("ip") > 0
		hasUser := re.SubexpIndex("user") > 0
		if !validCustomCaptureTarget(target, hasIP, hasUser) {
			result.errs = append(result.errs, customRuleValidationError{
				RuleIndex: idx,
				Rule:      line,
				Message:   fmt.Sprintf("missing required named captures for MATCH_TARGET=%s", customMatchTargetString(target)),
			})
			continue
		}
		result.rules = append(result.rules, customRule{re: re, hasIP: hasIP, hasUser: hasUser, raw: reStr})
	}
	return result
}

func parseCustomIgnoreRules(kv KV) []*regexp.Regexp {
	lines := kvLines(kv, "IGNORE_REGEX")
	if len(lines) == 0 {
		if raw := strings.TrimSpace(kvStrClean(kv, "IGNORE_REGEX", "")); raw != "" {
			lines = append(lines, raw)
		}
	}
	out := make([]*regexp.Regexp, 0, len(lines))
	for _, line := range lines {
		re, err := regexp.Compile(strings.TrimSpace(line))
		if err != nil {
			logging.Logf("[detectors][custom] invalid ignore regex %q: %v", line, err)
			continue
		}
		out = append(out, re)
	}
	return out
}

func parseCustomMatchTarget(raw string, def customRuleTarget) customRuleTarget {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ip":
		return customTargetIP
	case "user":
		return customTargetUser
	case "both":
		return customTargetBoth
	default:
		return def
	}
}

func customMatchTargetString(target customRuleTarget) string {
	switch target {
	case customTargetIP:
		return "ip"
	case customTargetUser:
		return "user"
	case customTargetBoth:
		return "both"
	default:
		return "auto"
	}
}

func validCustomCaptureTarget(target customRuleTarget, hasIP, hasUser bool) bool {
	switch target {
	case customTargetIP:
		return hasIP
	case customTargetUser:
		return hasUser
	case customTargetBoth:
		return hasIP && hasUser
	default:
		return hasIP || hasUser
	}
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
	deadline := now.Add(customRunBudget)
	lines := 0
	for {
		line, err := d.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		lines++
		d.consume(now, line, out)
		if lines >= customMaxLinesPerTick || time.Now().After(deadline) {
			break
		}
	}

	if d.state != nil && d.stateKey != "" {
		off, ino, ts := d.src.Position()
		d.state.Put(d.stateKey, core.Position{Offset: off, Inode: ino, TS: ts})
	}
	return nil
}

func (d *customDetector) consume(now time.Time, line string, out chan<- core.Alert) {
	if len(line) > customMaxLineBytes {
		return
	}
	for _, ignore := range d.ignores {
		if ignore.FindStringSubmatch(line) != nil {
			return
		}
	}

	for _, rule := range d.rules {
		m := rule.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		ip := normalizeCustomIP(captureByName(rule.re, m, "ip"))
		user := strings.ToLower(strings.TrimSpace(captureByName(rule.re, m, "user")))

		switch d.cfg.MatchTarget {
		case customTargetIP:
			if ip == "" {
				continue
			}
			d.bump(now, "AUTHFAIL|ip", ip, line, out)
		case customTargetUser:
			if user == "" {
				continue
			}
			d.bump(now, "AUTHFAIL|user", user, line, out)
		case customTargetBoth:
			if ip == "" || user == "" {
				continue
			}
			d.bump(now, "AUTHFAIL|ip", ip, line, out)
			d.bump(now, "AUTHFAIL|user", user, line, out)
		default:
			if rule.hasIP && ip != "" {
				d.bump(now, "AUTHFAIL|ip", ip, line, out)
			}
			if rule.hasUser && user != "" {
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

func normalizeCustomIP(raw string) string {
	s := strings.Trim(strings.TrimSpace(raw), "[]")
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
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
