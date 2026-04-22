package proxmox

import (
	"context"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	core "cfm/internal/detectors/core"
)

type Config struct {
	Mode        string // file|journal
	LogPath     string
	JournalUnit string

	Every       time.Duration
	Window      time.Duration
	Cooldown    time.Duration
	SampleLimit int

	AuthFailPerIP   int
	AuthFailPerUser int
}

type pend struct {
	kindKey string // AUTHFAIL|ip | AUTHFAIL|user
	key     string
}

type Auth struct {
	cfg  Config
	name string
	src  core.LineSource

	state    *core.State
	stateKey string

	pending map[string]pend
	samples *core.SampleRing
	gate    *core.AlertGate
	counts  *core.SlidingCounter

	reRHost *regexp.Regexp
	reUser  *regexp.Regexp
}

func NewAuth(cfg Config) *Auth {
	if cfg.Mode == "" {
		cfg.Mode = "journal"
	}
	if cfg.JournalUnit == "" {
		cfg.JournalUnit = "pvedaemon.service"
	}
	if cfg.Every <= 0 {
		cfg.Every = 2 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = 15 * time.Minute
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 20 * time.Minute
	}
	if cfg.SampleLimit <= 0 {
		cfg.SampleLimit = 10
	}

	a := &Auth{cfg: cfg}
	a.pending = make(map[string]pend)
	a.samples = core.NewSampleRing(cfg.SampleLimit)
	a.gate = core.NewAlertGate(cfg.Cooldown)
	a.counts = core.NewSlidingCounter(cfg.Window, 0)

	const ipClass = `[0-9a-f:.]+`
	a.reRHost = regexp.MustCompile(`\brhost=(` + ipClass + `)(?:[\s;,]|$)`)
	a.reUser = regexp.MustCompile(`\buser=([^\s;,]+)`)

	return a
}

func (a *Auth) SetName(n string)              { a.name = n }
func (a *Auth) SetSource(src core.LineSource) { a.src = src }
func (a *Auth) SetState(st *core.State, key string) {
	a.state = st
	a.stateKey = key
}

func (a *Auth) Name() string {
	if a.name != "" {
		return a.name
	}
	return "proxmox/auth"
}

func (a *Auth) Every() time.Duration {
	if a.cfg.Every > 0 {
		return a.cfg.Every
	}
	return 2 * time.Second
}

func (a *Auth) ApplyPosition(p core.Position) {
	if ft, ok := a.src.(*core.FileTailer); ok {
		ft.ApplyResume(p.Inode, p.Offset)
	}
	if jt, ok := a.src.(*core.JournalTailer); ok {
		jt.ApplyResume(0, 0, p.TS)
	}
}

func (a *Auth) Position() core.Position {
	if a.src == nil {
		return core.Position{}
	}
	off, ino, ts := a.src.Position()
	return core.Position{Offset: off, Inode: ino, TS: ts}
}

func (a *Auth) RunOnce(ctx context.Context, out chan<- core.Alert) error {
	for k := range a.pending {
		delete(a.pending, k)
	}
	if a.src == nil {
		return nil
	}
	if a.state != nil && a.stateKey != "" {
		if p, ok := a.state.Get(a.stateKey); ok {
			a.ApplyPosition(p)
		}
	}
	if err := a.src.Open(); err != nil {
		return nil
	}
	defer a.src.Close()
	if a.state != nil && a.stateKey != "" {
		defer func() { a.state.Put(a.stateKey, a.Position()) }()
	}

	now := time.Now()
	const maxLines = 2000
	deadline := now.Add(800 * time.Millisecond)
	processed := 0
	for {
		line, err := a.src.ReadNext(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		a.processLine(now, line)
		processed++
		if processed >= maxLines || time.Now().After(deadline) {
			break
		}
	}

	a.flush(now, out)
	return nil
}

func (a *Auth) processLine(now time.Time, line string) {
	ll := strings.ToLower(line)
	if !strings.Contains(ll, "authentication failure") {
		return
	}
	if !(strings.Contains(ll, "pvedaemon") || strings.Contains(ll, "proxmox-ve-auth") || strings.Contains(ll, "rhost=")) {
		return
	}

	ip := ""
	if m := a.reRHost.FindStringSubmatch(ll); m != nil && m[1] != "" {
		ip = normalizeIP(m[1])
	}
	if ip == "" {
		return
	}
	a.bump(now, "AUTHFAIL|ip", ip, line)

	if m := a.reUser.FindStringSubmatch(ll); m != nil && m[1] != "" {
		a.bump(now, "AUTHFAIL|user", strings.ToLower(m[1]), line)
	}
}

func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func (a *Auth) bump(now time.Time, kindKey, key, line string) {
	sk := kindKey + ":" + key
	if _, ok := a.pending[sk]; !ok {
		a.pending[sk] = pend{kindKey: kindKey, key: key}
	}
	_ = a.counts.Add(sk, now)
	a.samples.Add(sk, line)
}

func (a *Auth) flush(now time.Time, out chan<- core.Alert) {
	for sk, p := range a.pending {
		limit, kind, isIP := a.thresholdAndKind(p.kindKey)
		if limit <= 0 {
			continue
		}
		n := a.counts.Count(sk, now)
		if n < limit {
			continue
		}
		if !a.gate.Allow(sk, now, n, limit) {
			continue
		}

		extra := map[string]string{
			"window":   a.cfg.Window.String(),
			"cooldown": a.cfg.Cooldown.String(),
			"limit":    strconv.Itoa(limit),
		}
		if isIP {
			extra["ip"] = p.key
		}

		out <- core.Alert{
			When:    now,
			Kind:    core.AlertKind(kind),
			Key:     p.key,
			Count:   n,
			Samples: a.samples.GetAndClear(sk),
			Extra:   extra,
		}
	}
}

func (a *Auth) thresholdAndKind(kindKey string) (limit int, kind string, isIP bool) {
	switch kindKey {
	case "AUTHFAIL|ip":
		return a.cfg.AuthFailPerIP, "PROXMOX/AUTHFAIL", true
	case "AUTHFAIL|user":
		return a.cfg.AuthFailPerUser, "PROXMOX/AUTHFAIL", false
	default:
		return 0, "", false
	}
}
