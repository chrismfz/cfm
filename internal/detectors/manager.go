package detectors

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
//	core "cfm/internal/detectors/core"
)

type manager struct {
	opts      Options
	mu        sync.Mutex
	cancelAll context.CancelFunc
	lastStamp int64
	running   bool
}

func Start(parent context.Context, opts Options) {
	if opts.Sink == nil {
		opts.Sink = LoggerSink{}
	}
	if opts.CfgPath == "" {
		logging.Logf("[detectors] disabled (no cfg path provided)")
		return
	}
	logging.Logf("[detectors] watching %s", opts.CfgPath)

	m := &manager{opts: opts}
	go m.loop(parent)
}

func (m *manager) loop(parent context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	m.maybeReload(parent) // first run
	for {
		select {
		case <-parent.Done():
			m.stopAll()
			return
		case <-t.C:
			m.maybeReload(parent)
		}
	}
}

func (m *manager) maybeReload(parent context.Context) {
	path := m.opts.CfgPath
	if path == "" {
		return
	}

	fi, err := os.Stat(path)
	if err != nil {
		// missing: stop all (if needed) and say it once
		if m.running {
			logging.Logf("[detectors] stopping (cfg removed)")
		} else {
			logging.Logf("[detectors] no detections.conf at %s — disabled", path)
		}
		m.stopAll()
		return
	}
	if fi.ModTime().UnixNano() == m.lastStamp && m.running {
		return
	}

	secs, _, _ := readSections(path)

	// stop all on any change (baby steps, clean & robust)
	if m.running {
		logging.Logf("[detectors] reloading config")
	}
	m.stopAll()

	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	m.cancelAll = cancel
	m.lastStamp = secs.StampNS
	m.running = true
	m.mu.Unlock()

	// Summary: list sections & enabled/disabled
	var enabled, disabled []string
	for secName, kv := range secs.ByName {
		if secName == "global" {
			continue
		}
		if kvBool(kv, "ENABLED", true) {
			enabled = append(enabled, secName)
		} else {
			disabled = append(disabled, secName)
		}
	}
	if len(secs.ByName) == 1 { // μόνο global
		logging.Logf("[detectors] no sections found (only [global])")
	} else {
		logging.Logf("[detectors] sections: enabled=[%s] disabled=[%s]",
			strings.Join(enabled, ", "),
			strings.Join(disabled, ", "),
		)
	}

	// instantiate + run all enabled sections
	for secName, kv := range secs.ByName {
		if secName == "global" {
			continue
		}
		if !kvBool(kv, "ENABLED", true) {
			continue
		}

		typ, _ := splitTypeInstance(secName)
		fac, ok := getFactory(typ)
		if !ok {
			logging.Logf("[detectors] unknown section type: %s (section %q) — skipping", typ, secName)
			continue
		}

		det, err := fac(secName, kv, secs.Global) // det: core.PeriodicDetector
		if err != nil || det == nil {
			logging.Logf("[detectors] failed to init %s: %v", secName, err)
			continue
		}

		// Pretty print known config for exim_queues (baby steps)
		if typ == "exim_queues" {
			defEvery := kvDur(secs.Global, "DEFAULT_EVERY", 60*time.Second)
			defTimeout := kvDur(secs.Global, "DEFAULT_TIMEOUT", 8*time.Second)
			defCooldown := kvDur(secs.Global, "DEFAULT_COOLDOWN", 10*time.Minute)

			every := kvDur(kv, "EVERY", defEvery)
			timeout := kvDur(kv, "TIMEOUT", defTimeout)
			cooldown := kvDur(kv, "COOLDOWN", defCooldown)
			totalMax := kvInt(kv, "QUEUE_TOTAL_MAX", 500)
			frozenMax := kvInt(kv, "QUEUE_FROZEN_MAX", 200)
			totalCmd := kvStr(kv, "TOTAL_CMD", "exim -bpc")
			listCmd := kvStr(kv, "LIST_CMD", "exim -bp")

			logging.Logf("[detectors] start %s (every=%s timeout=%s cooldown=%s total>%d frozen>%d total_cmd=%q list_cmd=%q)",
				secName, every, timeout, cooldown, totalMax, frozenMax, totalCmd, listCmd)

		}else if typ == "exim_relays" {
    defEvery := kvDur(secs.Global, "DEFAULT_EVERY", 5*time.Second)
    defCooldown := kvDur(secs.Global, "DEFAULT_COOLDOWN", 10*time.Minute)
    every := kvDur(kv, "EVERY", defEvery)
    window := kvDur(kv, "WINDOW", 15*time.Minute)
    cooldown := kvDur(kv, "COOLDOWN", defCooldown)
    logPath := kvStr(kv, "LOG_PATH", "")
    logDisp := logPath
    if logDisp == "" {
        logDisp = "(autodetect)"
    }
    localUser := kvInt(kv, "LOCAL_USER_MAX", 40)
    authUser := kvInt(kv, "AUTH_USER_MAX", 50)
    authIP := kvInt(kv, "AUTH_IP_MAX", 80)
    authUserIP := kvInt(kv, "AUTH_USERIP_MAX", 40)
    unauthIP := kvInt(kv, "UNAUTH_IP_MAX", 10)

enrichOn := kvBool(kv, "ENRICH", true)
ptrOn    := kvBool(kv, "PTR", true)
dirsDisp := kvStr(kv, "ENRICH_DIRS", "(defaults)")


logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s log=%s thresholds: local/user>%d auth/user>%d auth/ip>%d auth/userip>%d unauth/ip>%d enrich=%t ptr=%t dirs=%s)",
    secName, every, window, cooldown, logDisp,
    localUser, authUser, authIP, authUserIP, unauthIP,
    enrichOn, ptrOn, dirsDisp,
)


}else {
			logging.Logf("[detectors] start %s (every=%s)", secName, det.Every())
		}

		go RunPeriodic(ctx, det, m.opts.Sink)
	}
}

func (m *manager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancelAll != nil {
		m.cancelAll()
		m.cancelAll = nil
	}
	if m.running {
		logging.Logf("[detectors] all stopped")
	}
	m.running = false
}
