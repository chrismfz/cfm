package detectors

import (
	"time"

	"cfm/internal/detectors/cookiediscard"
	core "cfm/internal/detectors/core"
	"cfm/internal/detectors/meta"
	"cfm/internal/webdetector"
)

// challenge_cookie_discard turns the challenge-solve event stream into a per-IP
// "this client throws away its clearance cookie" finding.
//
// A solved challenge grants clearance for CHALLENGE_COOKIE_LIFE (45m by
// default), so a browser solves once and is done. An address that solves again
// minutes later never stored the cookie — a request pipeline with no cookie jar,
// driving a headless browser per request.
//
// Thresholds are calibrated against 23h of production edge traffic: over a
// sliding 10-minute window, 99.6% of the 97,556 distinct client addresses never
// solved twice, the plausibly-legitimate repeaters topped out at 4, and no
// address in the capture peaked at exactly 5 — the abusive population resumes at
// 6. MIN_SOLVES defaults to 8, a 2x margin over the busiest legitimate repeater.
// The margin is deliberate: a user who opens several tabs at once is challenged
// in each before any cookie is set, which is a small instantaneous burst, while
// the traffic this detector is for sustains 30+ solves over minutes.
//
// Unlike challenge_solver_farm this detector CAN sensibly block — its Key is one
// real address that is abusing the challenge right now, and it sets Extra["ip"]
// authoritatively so the sink never has to guess. It still ships alert-only
// (no BLOCK in the reference config) so the finding can be burned in first:
// every address observed was a residential proxy exit, which may belong to a
// real visitor by the time a ban expires. Turning enforcement on is one line —
// BLOCK = 6h in [challenge_cookie_discard] — and deliberately the operator's.
func init() {
	meta.Register(meta.DetectorMeta{
		TypeKey:     "challenge_cookie_discard",
		Title:       "Challenge cookie discard",
		Description: "Detects clients that re-solve the challenge while still holding valid clearance, i.e. that never store the cookie. Alert-only unless BLOCK is set.",
		DefaultsTemplate: map[string]string{
			"ENABLED":    "1",
			"EVERY":      "30s",
			"WINDOW":     "10m",
			"MIN_SOLVES": "8",
			"COOLDOWN":   "30m",
		},
		LeniencySupported:   true,
		LeniencyRecommended: false,
	})

	Register("challenge_cookie_discard", func(section string, kv KV, global KV) (core.PeriodicDetector, error) {
		defEvery := kvDur(global, "DEFAULT_EVERY", 30*time.Second)

		cfg := cookiediscard.Config{
			Every:           kvDur(kv, "EVERY", defEvery),
			Window:          kvDur(kv, "WINDOW", 10*time.Minute),
			MinSolves:       kvInt(kv, "MIN_SOLVES", 8),
			Cooldown:        kvDur(kv, "COOLDOWN", 30*time.Minute),
			MaxTrackedIPs:   kvInt(kv, "MAX_TRACKED_IPS", 100000),
			MaxTrackedPerIP: kvInt(kv, "MAX_TRACKED_PER_IP", 2000),
			MaxQueue:        kvInt(kv, "MAX_QUEUE", 20000),
			SampleLimit:     kvInt(kv, "SAMPLE_LIMIT", 10),
			AllowHosts:      csvKV(kv, "ALLOW_HOSTS"),
			AllowIPs:        csvKV(kv, "ALLOW_IPS"),
			AllowNets:       csvKV(kv, "ALLOW_NETS"),
			AllowUAContains: csvKV(kv, "ALLOW_UA_CONTAINS"),
		}

		d := cookiediscard.New(cfg)
		d.SetName(section)

		webdetector.SubscribeChallengeSolveEvents(func(s webdetector.ChallengeSolve) {
			d.Enqueue(s.InputEvent())
		})
		return d, nil
	})
}
