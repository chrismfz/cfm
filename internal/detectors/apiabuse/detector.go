package apiabuse

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
	Every              time.Duration
	Window             time.Duration
	SampleLimit        int
	Stage1Threshold    int
	Stage2Threshold    int
	Stage3Threshold    int
	Stage2ChallengeTTL time.Duration
	DryRun             bool
	AllowIPs           []string
	AllowNets          []string
	AllowUAContains    []string
	PathExceptions     []string
}

type Detector struct {
	cfg Config

	name string

	mu      sync.Mutex
	events  []core.InputEvent
	counts  *core.SlidingCounter
	samples *core.SampleRing
	stage   map[string]int

	allowIPs  map[string]struct{}
	allowNets []*net.IPNet
	unsub     []func()
	bypassMu  sync.RWMutex
	bypass    func(string) bool
}

func New(cfg Config) *Detector {
	if cfg.Every <= 0 {
		cfg.Every = 2 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = 2 * time.Minute
	}
	if cfg.SampleLimit <= 0 {
		cfg.SampleLimit = 10
	}
	if cfg.Stage1Threshold <= 0 {
		cfg.Stage1Threshold = 8
	}
	if cfg.Stage2Threshold <= cfg.Stage1Threshold {
		cfg.Stage2Threshold = cfg.Stage1Threshold + 4
	}
	if cfg.Stage3Threshold <= cfg.Stage2Threshold {
		cfg.Stage3Threshold = cfg.Stage2Threshold + 4
	}
	if cfg.Stage2ChallengeTTL <= 0 {
		cfg.Stage2ChallengeTTL = 10 * time.Minute
	}

	d := &Detector{
		cfg:      cfg,
		counts:   core.NewSlidingCounter(cfg.Window, 256),
		samples:  core.NewSampleRing(cfg.SampleLimit),
		stage:    make(map[string]int),
		allowIPs: make(map[string]struct{}),
	}
	for _, ip := range cfg.AllowIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			d.allowIPs[ip] = struct{}{}
		}
	}
	for _, cidr := range cfg.AllowNets {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
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
	return "cfm_endpoints"
}
func (d *Detector) Every() time.Duration { return d.cfg.Every }

func (d *Detector) SetBypassFunc(fn func(string) bool) {
	d.bypassMu.Lock()
	d.bypass = fn
	d.bypassMu.Unlock()
}

func (d *Detector) AddUnsubscribe(fn func()) {
	if fn == nil {
		return
	}
	d.mu.Lock()
	d.unsub = append(d.unsub, fn)
	d.mu.Unlock()
}

func (d *Detector) Shutdown() error {
	d.mu.Lock()
	unsub := d.unsub
	d.unsub = nil
	d.mu.Unlock()
	for _, fn := range unsub {
		fn()
	}
	return nil
}

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
	if ip := net.ParseIP(strings.TrimSpace(ev.SrcIP)); ip != nil {
		if ip.IsLoopback() || core.IsSelfIP(ip.String()) {
			return true
		}
	}
	d.bypassMu.RLock()
	bypass := d.bypass
	d.bypassMu.RUnlock()
	if bypass != nil && bypass(ev.SrcIP) {
		return true
	}
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
		token = strings.ToLower(strings.TrimSpace(token))
		if token != "" && strings.Contains(ua, token) {
			return true
		}
	}
	p := strings.ToLower(ev.Path)
	for _, ex := range d.cfg.PathExceptions {
		ex = strings.ToLower(strings.TrimSpace(ex))
		if ex != "" && strings.HasPrefix(p, ex) {
			return true
		}
	}
	return false
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
		count := d.counts.Add(ev.SrcIP, ev.When)
		d.samples.Add(ev.SrcIP, fmt.Sprintf("[%s] reason=%s signal=%s method=%s path=%s status=%d ua=%q",
			ev.Source, ev.Reason, ev.Signal, ev.Method, ev.Path, ev.Status, ev.UserAgent))
		next := d.stageForCount(count)
		if next <= d.stage[ev.SrcIP] {
			continue
		}
		d.stage[ev.SrcIP] = next

		alert := core.Alert{
			When:    now,
			Kind:    core.AlertKind("CFM/ENDPOINTS"),
			Key:     ev.SrcIP,
			Count:   count,
			Samples: d.samples.GetAndClear(ev.SrcIP),
			Extra: map[string]string{
				"ip":     ev.SrcIP,
				"source": ev.Source,
				"reason": ev.Reason,
				"signal": ev.Signal,
				"stage":  fmt.Sprintf("%d", next),
			},
		}
		if strings.TrimSpace(alert.Extra["reason"]) == "" {
			alert.Extra["reason"] = "api_probe"
		}

		switch next {
		case 1:
			alert.Extra["enforcement"] = "observe"
			alert.Extra["blocked"] = "no"
		case 2:
			alert.Extra["action"] = "challenge"
			alert.Extra["ttl"] = d.cfg.Stage2ChallengeTTL.String()
			if d.cfg.DryRun {
				alert.Extra["challenge_log"] = "1"
			}
		case 3:
			if d.cfg.DryRun {
				alert.Extra["enforcement"] = "dryrun"
			}
		}
		out <- alert
	}

	for ip, stg := range d.stage {
		if d.counts.Count(ip, now) == 0 {
			delete(d.stage, ip)
			if stg > 0 {
				d.samples.GetAndClear(ip)
			}
		}
	}
	return nil
}

func (d *Detector) stageForCount(n int) int {
	switch {
	case n >= d.cfg.Stage3Threshold:
		return 3
	case n >= d.cfg.Stage2Threshold:
		return 2
	case n >= d.cfg.Stage1Threshold:
		return 1
	default:
		return 0
	}
}
