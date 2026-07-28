package detectors

import (
	"time"

	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectors/solverfarm"
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
// enforcement=observe on every alert, so the section sink notifies and returns
// before choosing an IP to block. At ~1 solve per IP a per-IP ban cannot work —
// the address never returns — and the pool is residential, so banning it risks a
// real customer. Deciding what to DO about a flagged vhost (raise difficulty,
// rate-limit issuance, block a cluster) is a separate deliberate change.
func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:     "challenge_solver_farm",
		Title:       "Challenge solver farm",
		Description: "Detects distributed challenge-solving botnets by the spread of solver subnets per vhost. Alert-only.",
		DefaultsTemplate: map[string]string{
			"ENABLED":     "1",
			"EVERY":       "30s",
			"WINDOW":      "60s",
			"MIN_SUBNETS": "40",
			"MIN_SOLVES":  "40",
			"COOLDOWN":    "30m",
		},
		LeniencySupported:   false,
		LeniencyRecommended: false,
	})

	Register("challenge_solver_farm", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 30*time.Second)

		cfg := solverfarm.Config{
			Every:             kvDur(kv, "EVERY", defEvery),
			Window:            kvDur(kv, "WINDOW", time.Minute),
			MinSubnets:        kvInt(kv, "MIN_SUBNETS", 40),
			MinSolves:         kvInt(kv, "MIN_SOLVES", 40),
			PrefixV4:          kvInt(kv, "PREFIX_V4", 24),
			PrefixV6:          kvInt(kv, "PREFIX_V6", 48),
			Cooldown:          kvDur(kv, "COOLDOWN", 30*time.Minute),
			MaxTrackedPerHost: kvInt(kv, "MAX_TRACKED_PER_HOST", 20000),
			SampleLimit:       kvInt(kv, "SAMPLE_LIMIT", 10),
			AllowHosts:        csvKV(kv, "ALLOW_HOSTS"),
			AllowIPs:          csvKV(kv, "ALLOW_IPS"),
			AllowNets:         csvKV(kv, "ALLOW_NETS"),
			AllowUAContains:   csvKV(kv, "ALLOW_UA_CONTAINS"),
		}
		d := solverfarm.New(cfg)
		d.SetName(section)

		webdetector.SubscribeChallengeSolveEvents(func(s webdetector.ChallengeSolve) {
			d.Enqueue(s.InputEvent())
		})
		return d, nil
	})
}
