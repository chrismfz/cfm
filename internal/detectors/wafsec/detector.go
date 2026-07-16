// Package wafsec is the waf_security detector: it turns the in-path WAF's
// per-hit event stream (published by webdetector.RecordWAFTrigger) into a
// persistent, cross-request nft block via the shared detector framework.
//
// It mirrors internal/detectors/apiabuse in shape (buffer → sliding-window
// per-key counter → threshold → core.Alert), but keys and thresholds by WAF
// reason *family* instead of a global per-IP stage: a family at threshold 1
// (e.g. WAF_SQLI) blocks on the first hit, while a family at 0 is ignored
// entirely (edge-only, no autoblock). Per-rule-id overrides win over the
// family threshold. Blocking, leniency (GR/CY), API reporting and email are
// all handled downstream by the section sink — this detector only emits alerts.
//
// See docs/waf-autoblock-design.md.
package wafsec

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	core "cfm/internal/detectors/core"
)

type Config struct {
	Every       time.Duration
	Window      time.Duration
	SampleLimit int

	// Families maps a WAF reason-family (e.g. "WAF_SQLI") to the number of hits
	// within Window that trips a block. 0 (or absent) = the family never feeds
	// autoblock (edge-only).
	Families map[string]int
	// RuleOverrides maps a numeric rule id (as string, e.g. "437") to a
	// threshold that WINS over the family default — including 0, which disables
	// autoblock for that specific rule while its family stays active.
	RuleOverrides map[string]int

	// DryRun marks every alert enforcement=dryrun: the sink logs "would block"
	// to cfm.detectors.log and reports, but raises no real nft ban. Used for the
	// first-deploy burn-in.
	DryRun bool

	AllowIPs        []string
	AllowNets       []string
	AllowUAContains []string
	PathExceptions  []string
}

type Detector struct {
	cfg  Config
	name string

	mu      sync.Mutex
	events  []core.InputEvent
	counts  *core.SlidingCounter
	samples *core.SampleRing
	fired   map[string]struct{} // key = ip|family, so we alert once per window

	allowIPs  map[string]struct{}
	allowNets []*net.IPNet
}

func New(cfg Config) *Detector {
	if cfg.Every <= 0 {
		cfg.Every = 20 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = 30 * time.Minute
	}
	if cfg.SampleLimit <= 0 {
		cfg.SampleLimit = 10
	}
	if cfg.Families == nil {
		cfg.Families = map[string]int{}
	}
	if cfg.RuleOverrides == nil {
		cfg.RuleOverrides = map[string]int{}
	}

	d := &Detector{
		cfg:      cfg,
		counts:   core.NewSlidingCounter(cfg.Window, 256),
		samples:  core.NewSampleRing(cfg.SampleLimit),
		fired:    make(map[string]struct{}),
		allowIPs: make(map[string]struct{}),
	}
	for _, ip := range cfg.AllowIPs {
		if ip = strings.TrimSpace(ip); ip != "" {
			d.allowIPs[ip] = struct{}{}
		}
	}
	for _, cidr := range cfg.AllowNets {
		if cidr = strings.TrimSpace(cidr); cidr == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			d.allowNets = append(d.allowNets, n)
		}
	}
	return d
}

func (d *Detector) SetName(name string) { d.name = name }
func (d *Detector) Name() string {
	if d.name != "" {
		return d.name
	}
	return "waf_security"
}
func (d *Detector) Every() time.Duration { return d.cfg.Every }

func (d *Detector) Enqueue(ev core.InputEvent) {
	if ev.When.IsZero() {
		ev.When = time.Now()
	}
	if d.allowed(ev) {
		return
	}
	d.mu.Lock()
	d.events = append(d.events, ev)
	d.mu.Unlock()
}

func (d *Detector) allowed(ev core.InputEvent) bool {
	if _, ok := d.allowIPs[ev.SrcIP]; ok && ev.SrcIP != "" {
		return true
	}
	if ip := net.ParseIP(ev.SrcIP); ip != nil {
		for _, n := range d.allowNets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	ua := strings.ToLower(ev.UserAgent)
	for _, token := range d.cfg.AllowUAContains {
		if token = strings.ToLower(strings.TrimSpace(token)); token != "" && strings.Contains(ua, token) {
			return true
		}
	}
	p := strings.ToLower(ev.Path)
	for _, ex := range d.cfg.PathExceptions {
		if ex = strings.ToLower(strings.TrimSpace(ex)); ex != "" && strings.HasPrefix(p, ex) {
			return true
		}
	}
	return false
}

// familyOf returns the WAF reason-family: the reason prefix before the first
// ':'. "WAF_SQLI:UNION_SELECT" → "WAF_SQLI"; "WAF_RCE" → "WAF_RCE".
func familyOf(reason string) string {
	reason = strings.TrimSpace(reason)
	if i := strings.IndexByte(reason, ':'); i >= 0 {
		return reason[:i]
	}
	return reason
}

// cveFromReason extracts a display CVE id from a WAF_CVE reason string. The
// convention is WAF_CVE:CVE_<year>_<suffix>:<PRODUCT>:<TAG>, so the second
// colon-segment carries the CVE with underscores: "CVE_2025_34085" ->
// "CVE-2025-34085". Returns "" when the reason has no CVE_* token (e.g.
// "WAF_CVE:LOG4SHELL:..."), so the caller falls back to the plain family.
func cveFromReason(reason string) string {
	parts := strings.Split(reason, ":")
	if len(parts) < 2 {
		return ""
	}
	seg := parts[1]
	if !strings.HasPrefix(seg, "CVE_") {
		return ""
	}
	return strings.ReplaceAll(seg, "_", "-")
}

// thresholdFor resolves the block threshold for a (family, ruleID). A per-rule
// override wins over the family default — including an override of 0, which
// suppresses autoblock for that rule while the family stays active. Returns
// ok=false when neither is configured (family not fed at all).
func (d *Detector) thresholdFor(family, ruleID string) (int, bool) {
	if ruleID != "" {
		if ov, ok := d.cfg.RuleOverrides[ruleID]; ok {
			return ov, true
		}
	}
	lim, ok := d.cfg.Families[family]
	return lim, ok
}

func (d *Detector) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	d.mu.Lock()
	batch := d.events
	d.events = nil
	d.mu.Unlock()

	now := time.Now()
	for _, ev := range batch {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if ev.SrcIP == "" {
			continue
		}
		family := familyOf(ev.Reason)
		if family == "" {
			continue
		}
		limit, ok := d.thresholdFor(family, ev.Signal)
		if !ok || limit <= 0 {
			continue // family/rule not fed into autoblock
		}

		key := ev.SrcIP + "|" + family
		count := d.counts.Add(key, ev.When)
		d.samples.Add(key, fmt.Sprintf("[%s] reason=%s rule=%s method=%s host=%s uri=%s ua=%q",
			ev.Source, ev.Reason, ev.Signal, ev.Method, ev.Scope, ev.Path, ev.UserAgent))

		if count < limit {
			continue
		}
		if _, done := d.fired[key]; done {
			continue // already alerted this window; the sink owns the live block
		}
		d.fired[key] = struct{}{}

		// Notification identity. For the WAF_CVE family, surface the concrete
		// CVE id (WAF_CVE:CVE_2025_34085:... -> "WAF/CVE-2025-34085") so the
		// alert Kind / notifier line names the vulnerability instead of the
		// generic "WAF/CVE"; rule_id stays in Extra for cross-referencing the
		// Lua/Go registry. Falls back to the plain family for non-CVE hits (and
		// for WAF_CVE reasons without a CVE_* token, e.g. log4shell).
		kindStr := "WAF/" + strings.TrimPrefix(family, "WAF_")
		extra := map[string]string{
			"ip":      ev.SrcIP,
			"source":  ev.Source,
			"reason":  ev.Reason,
			"family":  family,
			"rule_id": ev.Signal,
			"host":    ev.Scope,
			"uri":     ev.Path,
			"method":  ev.Method,
		}
		if family == "WAF_CVE" {
			if cve := cveFromReason(ev.Reason); cve != "" {
				kindStr = "WAF/" + cve
				extra["cve"] = cve
			}
		}
		alert := core.Alert{
			When:    now,
			Kind:    core.AlertKind(kindStr),
			Key:     ev.SrcIP,
			Count:   count,
			Samples: d.samples.GetAndClear(key),
			Extra:   extra,
		}
		if d.cfg.DryRun {
			alert.Extra["enforcement"] = "dryrun"
		}
		out <- alert
	}

	// Prune per-(ip,family) fired state once its window has fully drained, so a
	// later campaign from the same IP re-triggers instead of staying silent.
	for key := range d.fired {
		if d.counts.Count(key, now) == 0 {
			delete(d.fired, key)
			d.samples.GetAndClear(key)
		}
	}
	return nil
}
