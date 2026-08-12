package detectors

import (
	core "cfm/internal/detectors/core"
	"cfm/internal/detectorstatus"
	"cfm/internal/enrich"
	"cfm/internal/logging"
	"cfm/internal/sslcollector"
	webdet "cfm/internal/webdetector"
	"context"
	"encoding/binary"
	"hash/fnv"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type manager struct {
	opts      Options
	mu        sync.Mutex
	wg        sync.WaitGroup
	cancelAll context.CancelFunc
	//	lastStamp int64
	lastSig uint64

	// Debounce reloads: when we see a change, wait for it to be stable
	// for a short period before doing stopAll()+restart.
	pendingSig   uint64
	pendingSince time.Time
	hasPending   bool

	running bool
	state   *core.State

	ignore      *IPIgnore // New ignore IP and Subnets
	chalExclude *ChallengeExclude
}

type initDiagnosticsError interface {
	error
	Diagnostics() []string
}

func probeSourceStatus(kv KV) (bool, string) {
	mode := strings.ToLower(strings.TrimSpace(kvStrClean(kv, "MODE", "")))
	logPath := strings.TrimSpace(kvStrClean(kv, "LOG_PATH", ""))
	switch mode {
	case "journal":
		return true, "journal source configured"
	case "docker":
		return true, "docker source configured"
	}
	if logPath == "" {
		return false, "log path not configured"
	}
	f, err := os.Open(logPath) // #nosec G304 -- detector LOG_PATH is explicitly configured by admin.
	if err != nil {
		return false, "log file unreadable: " + err.Error()
	}
	_ = f.Close()
	return true, "log file readable"
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
		availableTypes := RegisteredTypes()
		detectorstatus.SetLoadedTypes(len(availableTypes))

		// If the config is missing, stop everything (detectors disabled).
		if os.IsNotExist(err) {
			if m.running {
				logging.Logf("[detectors] stopping (cfg removed)")
			} else {
				logging.Logf("[detectors] no detections.conf at %s — disabled", path)
			}
			detectorstatus.ResetConfiguredSections(nil)
			detectorstatus.SetInventory(availableTypes, nil, 0)
			m.stopAll()
			return
		}
		// IMPORTANT: transient read/parse errors must NOT tear down running detectors.
		// Common during atomic writes/editors: file replaced while we read.
		logging.Logf("[detectors] config read failed (%s): %v — keeping current detectors", path, err)
		return
	}
	sig := cfgSig(&secs)
	configured := make([]detectorstatus.SectionConfig, 0, len(secs.ByName))
	configuredSections := make([]string, 0, len(secs.ByName))
	enabledCount := 0
	for secName, kv := range secs.ByName {
		if secName == "global" || strings.HasSuffix(secName, ".leniency") {
			continue
		}
		typ, _ := splitTypeInstance(secName)
		enabled := kvBool(kv, "ENABLED", true)
		sourceOK, sourceMsg := probeSourceStatus(kv)
		configured = append(configured, detectorstatus.SectionConfig{
			Section:            secName,
			Type:               typ,
			Configured:         true,
			Enabled:            enabled,
			SourceProbeOK:      sourceOK,
			SourceProbeMessage: sourceMsg,
		})
		configuredSections = append(configuredSections, secName)
		if enabled {
			enabledCount++
		}
	}
	availableTypes := RegisteredTypes()
	detectorstatus.UpsertConfiguredSections(configured)
	detectorstatus.SetLoadedTypes(len(availableTypes))
	detectorstatus.SetInventory(availableTypes, configuredSections, enabledCount)
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
	// Mirror the parsed ignore-list to a Lua-readable file so cfm.lua's
	// is_self_origin() bypass honours the same allowlist as the challenge
	// engine. Always call (including on nil ig) so an empty config produces
	// a valid-but-empty table — Lua side then degenerates to the existing
	// self-IPs-only behaviour. The path is the canonical /var/lib/cfm/lua
	// location used for all Lua-side caches.
	if err := ig.WriteLuaCache(IgnoreNetsLuaPath); err != nil {
		logging.Logf("[detectors] ignore-nets lua cache write failed: %v", err)
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
			if p != "" {
				dirs = append(dirs, p)
			}
		}
		if e, err := enrich.New(dirs...); err == nil {
			enr = e
		} else {
			logging.Logf("[detectors] enrich disabled (init failed): %v (dirs=%v)", err, dirs)
		}
	}

	// --- Challenge exclude rules (whitelist for verified crawlers etc.) ---
	// File-presence based: if CHALLENGE_EXCLUDE_FILE exists, its rules are
	// loaded. No on/off knob — drop the file (or delete it) to toggle.
	// [global]
	//   CHALLENGE_EXCLUDE_FILE=/etc/cfm/webdetector_challenge_exclude.txt   (optional override)
	var chalExclude *ChallengeExclude
	{
		p := kvStrClean(secs.Global, "CHALLENGE_EXCLUDE_FILE", "/etc/cfm/webdetector_challenge_exclude.txt")
		ce, err := LoadChallengeExclude(p)
		switch {
		case err != nil && os.IsNotExist(err):
			logging.Logf("[detectors] challenge exclude inactive: file not present: %q", p)
		case err != nil:
			logging.Logf("[detectors] challenge exclude load failed: file=%q err=%v", p, err)
		case ce == nil:
			logging.Logf("[detectors] challenge exclude file has no valid rules: %q", p)
		default:
			chalExclude = ce
			for i, r := range chalExclude.rules {
				logging.Logf("[detectors] challenge exclude rule[%d]: host=%q ua=%q asn=%q ptr=%q verify_fcrdns=%t action=%q",
					i,
					strings.TrimSpace(r.host),
					strings.TrimSpace(r.ua),
					strings.TrimSpace(r.asn),
					strings.TrimSpace(r.ptr),
					r.verifyFcrdns,
					strings.TrimSpace(r.action),
				)
			}
			logging.Logf("[detectors] challenge exclude loaded: file=%q rules=%d", p, len(chalExclude.rules))
		}
	}

	// stop all on any change (baby steps, clean & robust)
	if m.running {
		logging.Logf("[detectors] reloading config")
	}
	m.stopAll()

	// ── Token auto-generation for [webdetector] ───────────────────────────────
	// CHALLENGE_TOKEN signs browser challenge HMACs.  OPENRESTY_TOKEN authenticates
	// Lua→Go socket calls.  Both are rotated to a 48-hex-char random value if
	// absent, too short (<32 chars), or a known placeholder.  The new value is
	// written back to detectors.conf and into the in-memory KV so the detector
	// starts with the correct token on the very first load.
	if wdKV, ok := secs.ByName["webdetector"]; ok {
		cfgPath := m.opts.CfgPath // absolute path to detectors.conf

		// F2: CHALLENGE_TOKEN
		chalTok := kvStrClean(wdKV, "CHALLENGE_TOKEN", "")
		if newTok, err := sslcollector.ValidateOrGenerateTokenKey(cfgPath, "CHALLENGE_TOKEN", chalTok); err != nil {
			logging.Logf("[detectors] CHALLENGE_TOKEN generation failed: %v", err)
		} else if newTok != chalTok {
			logging.Logf("[detectors] CHALLENGE_TOKEN was weak — rotated and persisted to %s", cfgPath)
			wdKV["CHALLENGE_TOKEN"] = newTok
		}

		// F4: OPENRESTY_TOKEN — also writes cfm_bridge_token.lua for cfm.lua
		bridgeTok := kvStrClean(wdKV, "OPENRESTY_TOKEN", "")
		if newTok, err := sslcollector.ValidateOrGenerateTokenKey(cfgPath, "OPENRESTY_TOKEN", bridgeTok); err != nil {
			logging.Logf("[detectors] OPENRESTY_TOKEN generation failed: %v", err)
		} else {
			if newTok != bridgeTok {
				logging.Logf("[detectors] OPENRESTY_TOKEN was weak — rotated and persisted to %s", cfgPath)
				wdKV["OPENRESTY_TOKEN"] = newTok
			}
			cfmGID := sslcollector.CfmGroupID()
			const bridgeTokenPath = "/var/lib/cfm/lua/cfm_bridge_token.lua"
			if err := sslcollector.WriteLuaTokenWithMkdir(bridgeTokenPath, newTok, cfmGID); err != nil {
				logging.Logf("[detectors] cfm_bridge_token.lua write failed path=%s err=%v", bridgeTokenPath, err)
			} else {
				logging.Logf("[detectors] cfm_bridge_token.lua written path=%s", bridgeTokenPath)
			}

			// Webdetector → Lua runtime config (knobs that cfm.lua /
			// cfm_panel.lua need at request time). Sibling to the bridge
			// token so it inherits the same parent dir + permissions.
			const bridgeConfigPath = "/var/lib/cfm/lua/cfm_bridge_config.lua"
			bridgeCfg := sslcollector.WebdetectorBridgeConfig{
				ClearanceRefresh: kvBool(wdKV, "CHALLENGE_COOKIE_REFRESH", true),
				// Origin keepalive (edge → Apache backend connection pooling).
				// Default off; see docs/proxy-performance.md before arming.
				OriginKeepalive: kvBool(wdKV, "ORIGIN_KEEPALIVE", false),
				OriginKAIdleSec: kvInt(wdKV, "ORIGIN_KEEPALIVE_IDLE_SEC", 3),
				OriginKAMaxReqs: kvInt(wdKV, "ORIGIN_KEEPALIVE_MAX_REQS", 1000),
				// Authoritative clearance-cookie lifetime — SAME resolver the
				// webdetector register uses for SetCookieLife, so the edge Lua
				// re-mint TTL can never drift from what the daemon mints.
				CookieLifeSec: int(resolveChallengeCookieLife(secs.Global, wdKV) / time.Second),
				// Panel enforce modes (off|logonly|enforce). Default ENFORCE:
				// the fleet runs panel WAF + bridge-decision enforcement on by
				// default; a node that misbehaves sets PANEL_*_MODE=off|logonly
				// there. Missing/unknown → enforce (token.go re-normalises, and
				// cfm_panel.lua's resolver defaults to enforce for an absent field
				// too). kvStrClean tolerates an inline ;/# comment (§5).
				PanelWAFMode:      kvStrClean(wdKV, "PANEL_WAF_MODE", "enforce"),
				PanelDecisionMode: kvStrClean(wdKV, "PANEL_DECISION_MODE", "enforce"),
			}
			// Guard nonsense values; the Lua side re-guards but keep the
			// published file sane. Idle must stay below Apache's
			// KeepAliveTimeout (EA4 default 5s) — capped at 60s for
			// operators who raised Apache's too.
			if bridgeCfg.OriginKAIdleSec < 1 {
				bridgeCfg.OriginKAIdleSec = 1
			} else if bridgeCfg.OriginKAIdleSec > 60 {
				bridgeCfg.OriginKAIdleSec = 60
			}
			if bridgeCfg.OriginKAMaxReqs < 1 {
				bridgeCfg.OriginKAMaxReqs = 1000
			}
			if err := sslcollector.WriteWebdetectorBridgeConfig(bridgeConfigPath, bridgeCfg, cfmGID); err != nil {
				logging.Logf("[detectors] cfm_bridge_config.lua write failed path=%s err=%v", bridgeConfigPath, err)
			} else {
				logging.Logf("[detectors] cfm_bridge_config.lua written path=%s clearance_refresh=%v origin_keepalive=%v panel_waf_mode=%s panel_decision_mode=%s",
					bridgeConfigPath, bridgeCfg.ClearanceRefresh, bridgeCfg.OriginKeepalive, bridgeCfg.PanelWAFMode, bridgeCfg.PanelDecisionMode)
			}
		}
	}
	// ─────────────────────────────────────────────────────────────────────────

	ctx, cancel := context.WithCancel(parent)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancelAll = cancel
	//	m.lastStamp = secs.StampNS
	m.lastSig = sig
	m.running = true
	m.ignore = ig
	m.chalExclude = chalExclude

	// Summary: list sections & enabled/disabled
	var enabled, disabled []string
	for secName, kv := range secs.ByName {
		if secName == "global" {
			continue
		}
		if strings.HasSuffix(secName, ".leniency") {
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
		if strings.HasSuffix(secName, ".leniency") {
			continue
		}
		if !kvBool(kv, "ENABLED", true) {
			continue
		}

		typ, _ := splitTypeInstance(secName)

		fac, ok := getFactory(typ)
		if !ok {
			logging.Logf("[detectors] unknown section type: %s (section %q) — skipping", typ, secName)
			detectorstatus.MarkInitFailed(secName, "unknown detector type: "+typ)
			continue
		}

		det, err := fac(secName, kv, secs.Global) // det: core.PeriodicDetector
		// Some section types are config-only (no goroutine needed) and intentionally
		// return (nil, nil). Treat that as a successful no-op, not an init failure.
		if err != nil {
			logging.Logf("[detectors] failed to init %s: %v", secName, err)
			if de, ok := err.(initDiagnosticsError); ok {
				detectorstatus.MarkInitFailedWithDiagnostics(secName, err.Error(), de.Diagnostics())
			} else {
				detectorstatus.MarkInitFailed(secName, err.Error())
			}
			continue
		}
		if det == nil {
			logging.Logf("[detectors] %s: no detector instance (config-only) — skipping", secName)
			detectorstatus.MarkInitOK(secName)
			detectorstatus.MarkExit(secName, nil)
			continue
		}
		detectorstatus.MarkInitOK(secName)

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

		} else if typ == "exim_relays" {
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
			ptrOn := kvBool(kv, "PTR", true)
			dirsDisp := kvStrClean(kv, "ENRICH_DIRS", "(defaults)")

			logging.Logf("[detectors] start %s (every=%s window=%s cooldown=%s log=%s thresholds: local/user>%d auth/user>%d auth/ip>%d auth/userip>%d unauth/ip>%d enrich=%t ptr=%t dirs=%s)",
				secName, every, window, cooldown, logDisp,
				localUser, authUser, authIP, authUserIP, unauthIP,
				enrichOn, ptrOn, dirsDisp,
			)

		} else {
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

		// Challenge-exclude rules are global (file-presence based, loaded above).
		secExclude := m.chalExclude

		// Wire challenge-exclude func when rules are present.
		type chalExcludeSetter interface {
			SetChalExcludeFunc(func(string, string, string, string, string, string) (string, bool))
		}
		if ces, ok := det.(chalExcludeSetter); ok {
			if secExclude != nil {
				ce := secExclude // capture effective section/global rules
				ces.SetChalExcludeFunc(func(ip, host, ua, asn, ptr, rule string) (string, bool) {
					act, _, matched := ce.Match(ip, host, ua, asn, ptr, rule)
					return act, matched
				})
				logging.Logf("[detectors][%s] challenge exclude matcher wired (effective rules active)", secName)
			} else {
				// Explicitly clear matcher when section disables excludes or no rules loaded.
				ces.SetChalExcludeFunc(nil)
				logging.Logf("[detectors][%s] challenge exclude matcher not wired (effective rules inactive)", secName)
			}
		}

		// --- Leniency: optional [section.leniency] companion ---
		var leniency *leniencyPolicy
		if lenKV, ok := secs.ByName[secName+".leniency"]; ok {
			leniency = parseLeniencyPolicy(lenKV)
			if leniency != nil {
				mode := leniency.Pol.Mode
				if mode == "ttl" {
					mode = leniency.Pol.TTL.String()
				}
				logging.Logf("[detectors] %s: leniency enabled countries=%v asns=%v block=%s cooldown=%s send_to_api=%t",
					secName, leniency.Countries, leniency.ASNs,
					mode, leniency.Pol.Cooldown, leniency.SendToAPI)
			}
		}

		secSink := newSectionSink(secName, pol, m.opts.Sink, m.opts.FW, enr, m.ignore, chalCooldown, secExclude, leniency)

		m.wg.Add(1)
		go func(sectionName string, detector core.PeriodicDetector) {
			defer m.wg.Done()
			hooks := &RunHooks{
				OnRunStart: func(name string) {
					detectorstatus.MarkRunStart(sectionName, time.Now())
				},
				OnRunComplete: func(name string, runErr error) {
					detectorstatus.MarkRunComplete(sectionName, time.Now(), runErr)
				},
				OnRunTimeout: func(name string) {
					detectorstatus.MarkRunTimeout(sectionName)
				},
			}

			// If a detector goroutine exits unexpectedly (ctx not canceled),
			// it will silently stop. Log exits so we can spot stuck/failed loops.
			if err := RunPeriodicWithStateAndHooks(ctx, detector, secSink, m.state, hooks); err != nil && err != context.Canceled {
				detectorstatus.MarkExit(sectionName, err)
				logging.Logf("[detectors][%s] exited: %v", sectionName, err)
			} else {
				detectorstatus.MarkExit(sectionName, nil)
				logging.Logf("[detectors][%s] exited", sectionName)
			}

		}(secName, det)
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

	// Detector factories re-run on every reload, and challenge-solve subscribers
	// are registered from one. Drop them here so a retired detector's closure
	// stops feeding a buffer nothing drains any more; the new instance
	// re-subscribes as it is built.
	webdet.ResetChallengeSolveSubscribers()

	// Same reasoning for the solver-farm marks the WebUI badges from: they are
	// refreshed by a running detector and expire on their own. A reload that
	// disables or retunes challenge_solver_farm would otherwise leave the last
	// marks to age out with nothing left running to refresh or correct them.
	webdet.ResetSolverFarmMarks()

	// Wait outside the mutex.
	m.wg.Wait()

	if wasRunning {
		logging.Logf("[detectors] all stopped")
	}
}

// helpers for autoblock
// internal/detectors/manager.go (top or new file section_sink.go)
type blockPolicy struct {
	Mode     string        // "no", "dryrun", "permanent", "ttl"
	TTL      time.Duration // valid only if Mode == "ttl"
	Cooldown time.Duration // optional
}

func parseBlockPolicy(kv KV) blockPolicy {
	raw := strings.TrimSpace(kvStrClean(kv, "BLOCK", "no"))
	p := blockPolicy{Mode: "no"}
	switch strings.ToLower(raw) {
	case "", "no", "off", "0":
		p.Mode = "no"
	case "dryrun", "alert":
		p.Mode = "dryrun"
	case "permanent", "perm":
		p.Mode = "permanent"
	default:
		if d, err := parseCfgDuration(raw); err == nil && d > 0 {
			p.Mode = "ttl"
			p.TTL = d
		} else {
			p.Mode = "no"
		}
	}
	if cd := kvDur(kv, "BLOCK_COOLDOWN", 15*time.Minute); cd > 0 {
		p.Cooldown = cd
	}
	return p
}
