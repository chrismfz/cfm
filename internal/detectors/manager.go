package detectors

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"
	"encoding/binary"
	"hash/fnv"
	"syscall"
	"sort"
	"cfm/internal/logging"
	core "cfm/internal/detectors/core"
	"cfm/internal/enrich"

)

type manager struct {
	opts      Options
	mu        sync.Mutex
	wg        sync.WaitGroup
	cancelAll context.CancelFunc
//	lastStamp int64
	lastSig   uint64

	// Debounce reloads: when we see a change, wait for it to be stable
	// for a short period before doing stopAll()+restart.
	pendingSig   uint64
	pendingSince time.Time
	hasPending   bool

	running   bool
	state *core.State

        ignore *IPIgnore // New ignore IP and Subnets
	chalExclude *ChallengeExclude
}

// cfgSig changes when either detections.conf changes (StampNS) OR any watched
// LOG_PATH is rotated (inode/dev changes). Prevents tailers sticking to deleted FD.
func cfgSig(secs *Sections) uint64 {
    h := fnv.New64a()
    var b [8]byte
    binary.LittleEndian.PutUint64(b[:], uint64(secs.StampNS))
    _, _ = h.Write(b[:])


    // IMPORTANT: map iteration order is random -> must hash in stable order,
    // otherwise cfgSig changes every tick and forces reload loops.
    names := make([]string, 0, len(secs.ByName))
    for name := range secs.ByName {
        if name == "global" {
            continue
        }
        names = append(names, name)
    }
    sort.Strings(names)

    for _, name := range names {
        kv := secs.ByName[name]
        p := strings.TrimSpace(kvStrClean(kv, "LOG_PATH", ""))
        if p == "" {
            continue
        }


        // Always incorporate the path so missing/present transitions change sig.
        _, _ = h.Write([]byte("logpath="))
        _, _ = h.Write([]byte(p))
        _, _ = h.Write([]byte{0})

        if st, err := os.Stat(p); err == nil {
            if sys, ok := st.Sys().(*syscall.Stat_t); ok {
                binary.LittleEndian.PutUint64(b[:], uint64(sys.Dev))
                _, _ = h.Write(b[:])
                binary.LittleEndian.PutUint64(b[:], uint64(sys.Ino))
                _, _ = h.Write(b[:])
            }
        } else {
            // Missing / unreadable marker
            _, _ = h.Write([]byte("missing"))
            _, _ = h.Write([]byte{0})
        }
    }
    return h.Sum64()
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
st, err := core.LoadState(core.DefaultStateDir)
if err != nil {
	logging.Logf("[detectors] state load failed: %v", err)
} else {

    m.state = st
}

        // IMPORTANT:
        // Do an initial synchronous load so config-only sections (like [mysql_governor])
        // can populate "pending configs" before Start() returns and the daemon consumes them.
        m.maybeReload(parent)

        go m.loop(parent)

}





func (m *manager) loop(parent context.Context) {

	// Poll frequently, but reload only after debounce (stable signature).
	// Config is tiny, so 1500ms polling is fine.
	t := time.NewTicker(2500 * time.Millisecond)

	defer t.Stop()
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
	const debounceDur = 2000 * time.Millisecond

	path := m.opts.CfgPath
	if path == "" {
		return
	}

    secs, _, err := readSections(path)
	if err != nil {

        // If the config is missing, stop everything (detectors disabled).
        if os.IsNotExist(err) {
            if m.running {
                logging.Logf("[detectors] stopping (cfg removed)")
            } else {
                logging.Logf("[detectors] no detections.conf at %s — disabled", path)
            }
            m.stopAll()
            return
        }
        // IMPORTANT: transient read/parse errors must NOT tear down running detectors.
        // Common during atomic writes/editors: file replaced while we read.
        logging.Logf("[detectors] config read failed (%s): %v — keeping current detectors", path, err)
		return
	}
    sig := cfgSig(&secs)
	// No change from current running config: clear any pending reload.
	if sig == m.lastSig && m.running {
		m.hasPending = false
		return
	}

	// Debounce: require the new signature to remain stable for debounceDur
	// before we actually reload (prevents flapping / transient states).
	now := time.Now()

        // On first-ever load (nothing running yet), do NOT debounce.
        // We want config to be available immediately for consumers in main().
        if !m.running {
                // Pretend we already waited long enough.
                m.pendingSig = sig
                m.pendingSince = now.Add(-debounceDur)
                m.hasPending = true
        }


	if !m.hasPending || m.pendingSig != sig {
		m.pendingSig = sig
		m.pendingSince = now
		m.hasPending = true
		// First observation of this change: wait for stability.
		return
	}
	if now.Sub(m.pendingSince) < debounceDur {
		// Still within debounce window: wait.
		return
	}

	// Stable change confirmed: proceed with reload.
	m.hasPending = false



// --- ΝΕΟ: build global ignore από [global] ---
ig := newIPIgnoreFromGlobal(secs.Global)
if ig != nil {
    logging.Logf("[detectors] global ignore enabled: IGNORE_IPS=%q IGNORE_NETS=%q",
        kvStrClean(secs.Global, "IGNORE_IPS", ""),
        kvStrClean(secs.Global, "IGNORE_NETS", ""),
    )
}
// --------------------------------------------



    // Build a shared enricher from [global], if enabled
    var enr *enrich.Enricher
    if kvBool(secs.Global, "ENRICH", true) {
        rawDirs := kvStrClean(secs.Global, "ENRICH_DIRS", "/var/lib/cfm/maxmind:/etc/cfm")
        // split on comma/colon/space
        var dirs []string
        for _, p := range strings.FieldsFunc(rawDirs, func(r rune) bool { return r == ',' || r == ':' || r == ' ' || r == '\t' }) {
            p = strings.TrimSpace(p)
            if p != "" { dirs = append(dirs, p) }
        }
        if e, err := enrich.New(dirs...); err == nil {
            enr = e
        } else {
            logging.Logf("[detectors] enrich disabled (init failed): %v (dirs=%v)", err, dirs)
        }
    }







    // --- NEW: Challenge exclude rules (whitelist for verified crawlers etc.) ---
    // [global]
    //   CHALLENGE_EXCLUDE=1
    //   CHALLENGE_EXCLUDE_FILE=/etc/cfm/webdetector_challenge_exclude.txt
    var chalExclude *ChallengeExclude
    if kvBool(secs.Global, "CHALLENGE_EXCLUDE", false) {
        p := kvStrClean(secs.Global, "CHALLENGE_EXCLUDE_FILE", "/etc/cfm/webdetector_challenge_exclude.txt")
        if ce, err := LoadChallengeExclude(p); err == nil {
            chalExclude = ce
            if chalExclude != nil {
                logging.Logf("[detectors] challenge exclude enabled: file=%q", p)
            } else {
                logging.Logf("[detectors] challenge exclude enabled but no valid rules: file=%q", p)
            }
        } else {
            logging.Logf("[detectors] challenge exclude disabled (failed to load %q): %v", p, err)
        }
    }










	// stop all on any change (baby steps, clean & robust)
	if m.running {
		logging.Logf("[detectors] reloading config")
	}
	m.stopAll()

	ctx, cancel := context.WithCancel(parent)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancelAll = cancel
//	m.lastStamp = secs.StampNS
	m.lastSig = sig
	m.running = true
	m.ignore  = ig
	m.chalExclude = chalExclude

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
		// Some section types are config-only (no goroutine needed) and intentionally
		// return (nil, nil). Treat that as a successful no-op, not an init failure.
		if err != nil {
			logging.Logf("[detectors] failed to init %s: %v", secName, err)
			continue
		}
		if det == nil {
			logging.Logf("[detectors] %s: no detector instance (config-only) — skipping", secName)
			continue
		}



        // If detector supports enrichment, inject the shared enricher
        if enr != nil {
            if ea, ok := det.(interface{ SetEnricher(*enrich.Enricher) }); ok {
                ea.SetEnricher(enr)
            }
        }

        // ── NEW: wire IGNORE_IPS/IGNORE_NETS bypass ──────────────────────────
        // (belt over the register-level wiring; also covers hot-reload)
        if ig != nil {
            type bypassSetter interface {
                SetBypassFunc(func(string) bool)
            }
            if bs, ok := det.(bypassSetter); ok {
                bs.SetBypassFunc(ig.ShouldIgnore)
            }
        }

        // ── NEW: wire challenge-exclude func (ASN / UA / PTR rules) ──────────
        if chalExclude != nil {
            type chalExcludeSetter interface {
                SetChalExcludeFunc(func(string, string, string, string, string, string) (string, bool))
            }
            if ces, ok := det.(chalExcludeSetter); ok {
                ce  := chalExclude // capture for closure
                enrC := enr        // capture for closure (may be nil)
                ces.SetChalExcludeFunc(func(ip, host, ua, asn, ptr, rule string) (string, bool) {
                    // Engine already does its own enrichment lookup inside isExcluded().
                    // This func only forwards to Match(); the asn/ptr passed here are
                    // from the engine's own lookup, so we don't double-lookup.
                    _ = enrC // suppress unused warning; kept for potential future use
                    act, _, matched := ce.Match(ip, host, ua, asn, ptr, rule)
                    return act, matched
                })
            }
        }
        // ─────────────────────────────────────────────────────────────────────



if pa, ok := det.(core.PositionAware); ok && m.state != nil {
	if p, ok2 := m.state.Get(pa.Name()); ok2 {
		pa.ApplyPosition(p)
	}
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
			totalCmd := kvStrClean(kv, "TOTAL_CMD", "exim -bpc")
			listCmd := kvStrClean(kv, "LIST_CMD", "exim -bp")

			logging.Logf("[detectors] start %s (every=%s timeout=%s cooldown=%s total>%d frozen>%d total_cmd=%q list_cmd=%q)",
				secName, every, timeout, cooldown, totalMax, frozenMax, totalCmd, listCmd)

		}else if typ == "exim_relays" {
    defEvery := kvDur(secs.Global, "DEFAULT_EVERY", 5*time.Second)
    defCooldown := kvDur(secs.Global, "DEFAULT_COOLDOWN", 10*time.Minute)
    every := kvDur(kv, "EVERY", defEvery)
    window := kvDur(kv, "WINDOW", 15*time.Minute)
    cooldown := kvDur(kv, "COOLDOWN", defCooldown)
    logPath := kvStrClean(kv, "LOG_PATH", "")
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
dirsDisp := kvStrClean(kv, "ENRICH_DIRS", "(defaults)")


logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s log=%s thresholds: local/user>%d auth/user>%d auth/ip>%d auth/userip>%d unauth/ip>%d enrich=%t ptr=%t dirs=%s)",
    secName, every, window, cooldown, logDisp,
    localUser, authUser, authIP, authUserIP, unauthIP,
    enrichOn, ptrOn, dirsDisp,
)


}else {
			logging.Logf("[detectors] start %s (every=%s)", secName, det.Every())
		}

		//go RunPeriodic(ctx, det, m.opts.Sink)
		//go RunPeriodicWithState(ctx, det, m.opts.Sink, m.state)

        // per-section blocking policy + wrapped sink
        pol := parseBlockPolicy(kv)

        // NEW: global/per-section challenge cooldown (suppresses re-challenge spam)
        // [global] CHALLENGE_COOLDOWN=30m
        // [webdetector] CHALLENGE_COOLDOWN=5m  (override)
        defChalCooldown := kvDur(secs.Global, "CHALLENGE_COOLDOWN", 30*time.Minute)
        chalCooldown := kvDur(kv, "CHALLENGE_COOLDOWN", defChalCooldown)

        // Allow per-section override for challenge exclude (useful if only webdetector should apply it).
        secExclude := m.chalExclude
        rawEx := strings.TrimSpace(kvStrClean(kv, "CHALLENGE_EXCLUDE", ""))
        if rawEx != "" {
            if kvBool(kv, "CHALLENGE_EXCLUDE", false) {
                p := kvStrClean(kv, "CHALLENGE_EXCLUDE_FILE",
                    kvStrClean(secs.Global, "CHALLENGE_EXCLUDE_FILE", "/etc/cfm/webdetector_challenge_exclude.txt"))
                if ce, err := LoadChallengeExclude(p); err == nil {
                    secExclude = ce
                }
            } else {
                secExclude = nil
            }
        }

        secSink := newSectionSink(secName, pol, m.opts.Sink, m.opts.FW, enr, m.ignore, chalCooldown, secExclude)
        m.wg.Add(1)
        go func() {
            defer m.wg.Done()

            // If a detector goroutine exits unexpectedly (ctx not canceled),
            // it will silently stop. Log exits so we can spot stuck/failed loops.
            if err := RunPeriodicWithState(ctx, det, secSink, m.state); err != nil && err != context.Canceled {
                logging.Logf("[detectors][%s] exited: %v", secName, err)
            } else {
                logging.Logf("[detectors][%s] exited", secName)
            }

        }()
	}
}

func (m *manager) stopAll() {
    // Cancel current run context and wait for detectors to fully exit.
    // This prevents hot-reload port races (e.g. webdetector API/challenge listeners).

    m.mu.Lock()
    defer m.mu.Unlock()
    if m.cancelAll != nil {
        m.cancelAll()
        m.cancelAll = nil
    }
    wasRunning := m.running
    m.running = false


    // Wait outside the mutex.
    m.wg.Wait()

    if wasRunning {
        logging.Logf("[detectors] all stopped")
    }
}








//helpers for autoblock
// internal/detectors/manager.go (top or new file section_sink.go)
type blockPolicy struct {
    Mode     string        // "no", "dryrun", "permanent", "ttl"
    TTL      time.Duration // valid only if Mode == "ttl"
    Cooldown time.Duration // optional
}

func parseBlockPolicy(kv KV) blockPolicy {
    raw := strings.TrimSpace(kvStrClean(kv, "BLOCK", "no"))
    p := blockPolicy{ Mode: "no" }
    switch strings.ToLower(raw) {
    case "", "no", "off", "0":
        p.Mode = "no"
    case "dryrun", "alert":
        p.Mode = "dryrun"
    case "permanent", "perm":
        p.Mode = "permanent"
    default:
        if d, err := time.ParseDuration(raw); err == nil && d > 0 {
            p.Mode = "ttl"
            p.TTL  = d
        } else {
            p.Mode = "no"
        }
    }
    if cd := kvDur(kv, "BLOCK_COOLDOWN", 15*time.Minute); cd > 0 {
        p.Cooldown = cd
    }
    return p
}

