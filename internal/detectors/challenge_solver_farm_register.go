package detectors

import (
	"strings"
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/solverfarm"
	"cfm/internal/logging"
	"cfm/internal/webdetector"
)

// challenge_solver_farm turns the challenge-solve event stream into a per-vhost
// "distributed solver farm" finding.
//
// Thresholds are calibrated against 23h of production edge traffic containing a
// live farm: distinct /24s solving one vhost within a 60s window measured 73
// (median), 49 (p01), 110 (max) for the farm, against a maximum of 22 across
// every other vhost on the same server. MIN_SUBNETS defaults to 40 — it caught
// 1380 of 1381 farm-minutes with zero hits on 1605 legitimate vhost-minutes.
//
// That calibration is ONE server over ONE day. A very large vhost with a
// genuinely global mobile audience could legitimately spread wider, which is why
// the threshold is a config knob and the detector ships alert-only.
//
// Alert-only is structural, not a burn-in default: the detector stamps
// ip_scope=host and enforcement=observe on every alert: the first stops the sink
// resolving a source IP for a finding whose Key is a vhost (its fallback would
// otherwise scrape one out of the User-Agents the alert quotes), the second stops
// it short of any block if a BLOCK policy is configured. At ~1 solve per IP a
// per-IP ban cannot work — the address never returns — and the pool is
// residential, so banning it risks a real customer. Deciding what to DO about a
// flagged vhost (raise difficulty, rate-limit issuance, block a cluster) is a
// separate deliberate change.
//
// Leave BLOCK unset on this section: it would not block (enforcement=observe
// wins) but it WOULD move the alert onto the observe path, which logs without
// notifying.
func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:     "challenge_solver_farm",
		Title:       "Challenge solver farm",
		Description: "Detects distributed challenge-solving botnets by the spread of solver subnets per vhost. Alert-only.",
		DefaultsTemplate: map[string]string{
			"ENABLED":          "1",
			"EVERY":            "30s",
			"WINDOW":           "60s",
			"MIN_SUBNETS":      "40",
			"MIN_SOLVES":       "40",
			"COOLDOWN":         "30m",
			"ACTION":           "observe",
			"PREFIX_V4":        "24",
			"PREFIX_V6":        "48",
			"FP_TRACK":         "1",
			"MIN_FP_SUBNETS":   "8",
			"MIN_FP_COUNTRIES": "6",
			"NOTIFY_COOLDOWN":  "6h",
			// Cross-host fingerprint-concentration track (Phase 2). Default-on,
			// log-only through its own burn-in. Share is the primary guard;
			// solves_per_ip is NOT a gate (burn-in showed it does not separate).
			"XH_TRACK":              "1",
			"XH_WINDOW":             "30m",
			"MIN_XH_HOST_SHARE_PCT": "50",
			"MIN_XH_HOSTS":          "4",
			"MIN_XH_COUNTRIES":      "12",
			"MIN_XH_SUBNETS":        "30",
		},
		LeniencySupported:   false,
		LeniencyRecommended: false,
	})

	Register("challenge_solver_farm", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 30*time.Second)

		// ACTION decides what a flagged vhost gets. Absent = observe, so a config
		// predating the key is unchanged. A value we cannot honour falls back to
		// observe and says so loudly — an operator must never be left believing
		// enforcement is on when it is not.
		action, note := solverfarm.ParseAction(kvStrClean(kv, "ACTION", ""))
		if note != "" {
			logging.Logf("[%s] %s", section, note)
		}

		cfg := solverfarm.Config{
			Every:             kvDur(kv, "EVERY", defEvery),
			Action:            action,
			Window:            kvDur(kv, "WINDOW", time.Minute),
			MinSubnets:        kvInt(kv, "MIN_SUBNETS", 40),
			MinSolves:         kvInt(kv, "MIN_SOLVES", 40),
			PrefixV4:          kvInt(kv, "PREFIX_V4", 24),
			PrefixV6:          kvInt(kv, "PREFIX_V6", 48),
			Cooldown:          kvDur(kv, "COOLDOWN", 30*time.Minute),
			MaxTrackedPerHost: kvInt(kv, "MAX_TRACKED_PER_HOST", 20000),
			MaxQueue:          kvInt(kv, "MAX_QUEUE", 20000),
			SampleLimit:       kvInt(kv, "SAMPLE_LIMIT", 10),
			AllowHosts:        csvKV(kv, "ALLOW_HOSTS"),
			AllowIPs:          csvKV(kv, "ALLOW_IPS"),
			AllowNets:         csvKV(kv, "ALLOW_NETS"),
			AllowUAContains:   csvKV(kv, "ALLOW_UA_CONTAINS"),
			FPTrack:           kvBool(kv, "FP_TRACK", true),
			MinFPSubnets:      kvInt(kv, "MIN_FP_SUBNETS", 8),
			MinFPCountries:    kvInt(kv, "MIN_FP_COUNTRIES", 6),
			AllowFPs:          csvKV(kv, "ALLOW_FPS"),
			NotifyCooldown:    kvDur(kv, "NOTIFY_COOLDOWN", 6*time.Hour),
			// Cross-host track. Share is read as an integer percent (idiomatic
			// integer knob) and converted to a fraction; solves_per_ip is not a
			// config gate (evidence only).
			XHTrack:        kvBool(kv, "XH_TRACK", true),
			XHWindow:       kvDur(kv, "XH_WINDOW", 30*time.Minute),
			MinXHHostShare: float64(kvInt(kv, "MIN_XH_HOST_SHARE_PCT", 50)) / 100.0,
			MinXHHosts:     kvInt(kv, "MIN_XH_HOSTS", 4),
			MinXHCountries: kvInt(kv, "MIN_XH_COUNTRIES", 12),
			MinXHSubnets:   kvInt(kv, "MIN_XH_SUBNETS", 30),
		}
		// Setting BLOCK here does not block — enforcement=observe wins — but it
		// moves the alert onto a path that logs without notifying. "BLOCK = dryrun
		// while tuning" is what every other section teaches, so the most likely
		// operator action on a new alert-only detector is exactly the one that
		// makes it go quiet. Say so rather than let them discover it by silence.
		if raw := strings.TrimSpace(kvStrClean(kv, "BLOCK", "")); raw != "" {
			logging.Logf("[%s] BLOCK=%q is set but this detector never blocks; it only suppresses the alert's notification. Remove BLOCK and use ACTION in [%s] instead.",
				section, raw, section)
		}

		d := solverfarm.New(cfg)
		d.SetName(section)

		// Feed the "farmed right now" mark the WebUI badges from. Fires on every
		// over-threshold evaluation rather than on the alert, because the alert
		// is suppressed for COOLDOWN (30m) while the farm keeps running — a badge
		// driven by alerts would blink off mid-attack.
		d.SetFarmHook(webdetector.MarkSolverFarm)

		webdetector.SubscribeChallengeSolveEvents(func(s webdetector.ChallengeSolve) {
			d.Enqueue(s.InputEvent())
		})
		return d, nil
	})
}
