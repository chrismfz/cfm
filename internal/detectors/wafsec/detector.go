// Package wafsec is the waf_security detector: it turns the in-path WAF's
// per-hit event stream (published by webdetector.RecordWAFTrigger) into a
// persistent, cross-request nft block via the shared detector framework.
//
// It mirrors internal/detectors/apiabuse in shape (buffer → sliding-window
// per-key counter → threshold → core.Alert), but keys and thresholds by WAF
// reason *family* instead of a global per-IP stage: a family at threshold 1
// (e.g. WAF_SQLI) blocks on the first hit, while a family at 0 is ignored
// entirely (edge-only, no autoblock). Per-rule-id overrides win over the
// family threshold; one above 1 counts that rule's hits alone (counterKey).
// Blocking, leniency (GR/CY), API reporting and email are all handled
// downstream by the section sink — this detector only emits alerts.
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
	// fired: counterKey (ip|family[|rule]) -> its family key (ip|family). One
	// alert per IP and family until the family goes quiet for a Window.
	fired map[string]string
	// famSeen: family key -> the last fed hit of that family from that IP,
	// whichever counter it went to. A fired entry is pruned only once its
	// family has been quiet for a full Window, so a campaign that moves to a
	// rule-scoped rule after the family ban stays one alert, as it was when
	// every rule shared the family counter.
	famSeen map[string]time.Time
	// firedAt: a grouped (IPv6 /64) family key -> when it fired. Its fired
	// entry also ends a Window after the alert, hits or not: if that ban
	// fell back to one address (nft failed to write the /64), the /64's other
	// addresses keep hitting and must still reach an alert.
	firedAt map[string]time.Time

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
		fired:    make(map[string]string),
		famSeen:  make(map[string]time.Time),
		firedAt:  make(map[string]time.Time),
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
	// Its allows guard their /64 (counted and banned per address).
	core.GuardAllows("waf_security", cfg.AllowIPs, cfg.AllowNets)
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
// suppresses autoblock for that rule while the family stays active.
// ruleScoped reports that the threshold came from a RULE_<id> override. Returns
// ok=false when neither is configured (family not fed at all).
func (d *Detector) thresholdFor(family, ruleID string) (limit int, ruleScoped, ok bool) {
	if ruleID != "" {
		if ov, ok := d.cfg.RuleOverrides[ruleID]; ok {
			return ov, true, true
		}
	}
	lim, ok := d.cfg.Families[family]
	return lim, false, ok
}

// counterKey is the sliding-counter / fired key for a hit. Normally
// (ip, family): the family's rules share one count. A RULE_<id> override above
// 1 counts that rule's own hits instead (ip, family, rule), or the other
// rules of its family would fill its count: RULE_X = 3 under a family at 5
// fired on X's first hit after two hits of other rules. At thresholds 0 and 1
// the key does not matter (0 never counts, 1 fires on the first hit), so the
// shipped configs behave exactly as before.
func counterKey(ip, family, ruleID string, limit int, ruleScoped bool) string {
	key := ip + "|" + family
	if ruleScoped && limit > 1 {
		key += "|" + ruleID
	}
	return key
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
		limit, ruleScoped, ok := d.thresholdFor(family, ev.Signal)
		if !ok || limit <= 0 {
			continue // family/rule not fed into autoblock
		}

		// An IPv6 client counts as its /64 (and fires once per window for it:
		// its ban takes the /64); the alert carries this hit's address.
		client := core.ClientKey("|ip", ev.SrcIP)
		famKey := client + "|" + family
		key := counterKey(client, family, ev.Signal, limit, ruleScoped)
		// The alert names the /64's busiest address (core.TopAddr).
		addr := core.TopAddr("wafsec|"+family, client, ev.SrcIP, ev.When, d.cfg.Window)
		count := d.counts.Add(key, ev.When)
		if ev.When.After(d.famSeen[famKey]) {
			d.famSeen[famKey] = ev.When
		}
		d.samples.Add(key, fmt.Sprintf("[%s] reason=%s rule=%s method=%s host=%s uri=%s ua=%q",
			ev.Source, ev.Reason, ev.Signal, ev.Method, ev.Scope, ev.Path, ev.UserAgent))

		if count < limit {
			continue
		}
		if _, done := d.fired[key]; done {
			continue // already alerted this window; the sink owns the live block
		}
		if _, done := d.fired[famKey]; done {
			continue // the family (or one of its rules) already banned this client this window
		}
		d.fired[key] = famKey
		// A rule-scoped trip also marks the family key, so a later family trip
		// for the same IP does not alert a second time (one ban per IP and
		// family per window, as with the shared key).
		d.fired[famKey] = famKey
		if strings.Contains(famKey, "/") {
			d.firedAt[famKey] = ev.When
		}

		// Notification identity. For the WAF_CVE family, surface the concrete
		// CVE id (WAF_CVE:CVE_2025_34085:... -> "WAF/CVE-2025-34085") so the
		// alert Kind / notifier line names the vulnerability instead of the
		// generic "WAF/CVE"; rule_id stays in Extra for cross-referencing the
		// Lua/Go registry. Falls back to the plain family for non-CVE hits (and
		// for WAF_CVE reasons without a CVE_* token, e.g. log4shell).
		kindStr := "WAF/" + strings.TrimPrefix(family, "WAF_")
		extra := map[string]string{
			"ip":      addr,
			"source":  ev.Source,
			"reason":  ev.Reason,
			"family":  family,
			"rule_id": ev.Signal,
			"host":    ev.Scope,
			"uri":     ev.Path,
			"method":  ev.Method,
		}
		core.TagClient(extra, addr)
		if family == "WAF_CVE" {
			if cve := cveFromReason(ev.Reason); cve != "" {
				kindStr = "WAF/" + cve
				extra["cve"] = cve
			}
		}
		alert := core.Alert{
			When:    now,
			Kind:    core.AlertKind(kindStr),
			Key:     addr,
			Count:   count,
			Samples: d.samples.GetAndClear(key),
			Extra:   extra,
		}
		if d.cfg.DryRun {
			alert.Extra["enforcement"] = "dryrun"
		}
		out <- alert
	}

	// Prune fired state once its family has been quiet for a full Window, so
	// a later campaign from the same IP re-triggers instead of staying silent.
	// With one shared key this is exactly "its counter drained": famSeen holds
	// the newest hit any of the family's counters took.
	for key, fam := range d.fired {
		at, grouped := d.firedAt[fam]
		if now.Sub(d.famSeen[fam]) > d.cfg.Window || (grouped && now.Sub(at) > d.cfg.Window) {
			delete(d.fired, key)
			d.samples.GetAndClear(key)
		}
	}
	for fam, at := range d.famSeen {
		if now.Sub(at) > d.cfg.Window {
			delete(d.famSeen, fam)
		}
	}
	for fam := range d.firedAt {
		if _, ok := d.fired[fam]; !ok {
			delete(d.firedAt, fam)
		}
	}
	return nil
}
