package webdetector

// ChallengeV2 Rung 1 — the passive humanity check (master plan E3, decision
// record docs/traffic-classifier.md § "The ChallengeV2 rung"; guardrails D5
// in docs/abuse-defense-master-plan.md §4).
//
// The v1 PoW is pure CPU and the live solver farms SOLVE it. Rung 1 makes the
// same invisible challenge page also report passive environment/behaviour
// signals with the verify POST; the daemon scores them here. Nothing changes
// for a real user — no puzzle, no extra click, nothing visible.
//
// D5 is the contract this file exists to honour:
//   (a) SCOPE      — the score has TEETH only when the solving client's
//                    fingerprint carries an operator-armed `challenge_v2`
//                    policy (FingerprintPolicyForID); everyone else is scored
//                    shadow/log-only.
//   (b) ABSENCE    — a solve can fail ONLY on positive headless evidence
//                    (webdriver true, a software renderer, a self-contradicting
//                    report). A missing payload (old cached page, blocked JS,
//                    privacy browser) or missing individual signals can never
//                    fail a solve: absent openers score 0, and the one
//                    absence-shaped signal (no input events) is a capped
//                    AMPLIFIER that only adds onto an already-open score.
//   (c) RECOURSE   — a rejected solve gets 403 WITHOUT clearance; the page's
//                    own error path reloads into a fresh challenge, so failure
//                    is retry-able, never a silent wall. Deny-with-no-recourse
//                    stays a D2 decision, not this file's.
//   (d) VISIBILITY — every scored solve carries hs=/tells= on its solve log
//                    line (ChallengeSolve.HumanitySuffix, both writers), a
//                    reject logs result=v2_reject, a would-fail unarmed solve
//                    emits signal=humanity verdict=would_v2 to the abuse
//                    shadow log, and CHALLENGE_V2_DEBUG=1 adds an X-CFM-HS
//                    response header for DevTools-level inspection.
//
// Knobs ([webdetector], applied per reload by ConfigureChallengeV2):
//   CHALLENGE_V2_PASSIVE    (default 1) master for scoring + the armed gate
//   CHALLENGE_V2_FAIL_SCORE (default 100) the fail threshold
//   CHALLENGE_V2_DEBUG      (default 0) X-CFM-HS response header
//
// HONEST LIMITS (documented residuals, not oversights):
//   - The report is CLIENT-authored. A signal-aware farm can strip the body
//     or fabricate a clean one, and D5b makes "clean report" == pass by
//     design. Rung 1 therefore catches standard automation stacks (real
//     headless browsers ship webdriver=true and software GL unless
//     deliberately patched) and raises the farm's per-exit engineering cost —
//     it is a cost lever, not cryptographic proof of humanity. A stripped
//     body is at least VISIBLE (hs=- on the solve line, vs hs=0 for a scored
//     clean one), so evasion shows up in the burn-in data. If a farm adapts,
//     the escalation is Rung 2 (visible interactive check, accessible), per
//     the ladder.
//   - The armed gate keys on the X-CFM-TLS header, which is trustworthy only
//     where the EDGE stamps it (OpenResty/Angie clear + re-stamp it). On the
//     legacy DNAT path the client talks to this server directly and authors
//     its own headers, so an armed farm there can omit/forge the id and slip
//     the gate — Rung-1 TEETH are web/edge-path-only, same limitation family
//     as the slice-2 edge enforcement. (A forged id also taints the fp= on
//     would_v2 shadow lines from DNAT clients; the ledger's solver-farm
//     conviction inputs have the same caveat, internal/tlsfp.)

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// humanitySignals is the JSON body the challenge page posts with the verify.
// Pointer fields distinguish "reported" from "absent" — the D5(b) absence rule
// needs that distinction. Unknown fields are ignored (older/newer pages mix on
// a fleet).
type humanitySignals struct {
	V   int     `json:"v"`   // payload version
	WD  *bool   `json:"wd"`  // navigator.webdriver
	GLR string  `json:"glr"` // WebGL UNMASKED_RENDERER (bounded client-side; re-bounded here)
	OW  *int    `json:"ow"`  // window.outerWidth
	OH  *int    `json:"oh"`  // window.outerHeight
	MTP *int    `json:"mtp"` // navigator.maxTouchPoints
	PTR *int    `json:"ptr"` // pointer-move events observed while solving
	TCH *int    `json:"tch"` // touchstart events observed
	KEY *int    `json:"key"` // keydown events observed
	MV  float64 `json:"mv"`  // accumulated |pointer movement| (recorded, not scored yet)
	HC  int     `json:"hc"`  // hardwareConcurrency (recorded, not scored yet)
	DM  float64 `json:"dm"`  // deviceMemory (recorded, not scored yet)
	DPR float64 `json:"dpr"` // devicePixelRatio (recorded, not scored yet)
	RAF float64 `json:"raf"` // avg requestAnimationFrame delta ms (recorded, not scored yet)
}

// The verify body bound is maxVerifyBodyBytes (challenge_server.go, 1 KB) —
// ONE bound, applied where the body is read (readVerifyBody). The page's
// payload is ~300 bytes; an over-cap read degrades to "no payload".

// Tell weights. Openers are POSITIVE evidence only (D5b); the threshold is
// deliberately sat so that any single medium-confidence opener PASSES:
// sw_renderer alone (60) is a real person on RDP/VDI, outer_zero alone (40)
// or touch_lie alone (50) can be an exotic-but-real setup. Only certain
// evidence (webdriver, a Headless UA token) or a corroborated combination
// crosses the default 100.
const (
	tellWebdriver  = 100 // navigator.webdriver === true: the standard says automation
	tellHeadlessUA = 100 // the UA itself declares HeadlessChrome/PhantomJS
	tellSWRenderer = 60  // SwiftShader/llvmpipe/software GL: headless/VM shaped, but real on RDP
	tellTouchLie   = 50  // claims a phone, reports zero touch points: the report contradicts the claim
	tellOuterZero  = 40  // reports outerWidth==outerHeight==0: no visible window
	ampNoInput     = 30  // zero pointer+touch+key events: AMPLIFIER only, never opens (D5b)
)

const defaultV2FailScore = 100

type challengeV2State struct {
	mu          sync.RWMutex
	enabled     bool
	failScore   int
	debug       bool
	shadowLines bool // emit would_v2 lines to the abuse-shadow log (rides ABUSE_SHADOW)
}

var challengeV2 = challengeV2State{enabled: true, failScore: defaultV2FailScore}

// ConfigureChallengeV2 applies the [webdetector] knobs; called on every
// detectors reload (webdetector_register.go).
func ConfigureChallengeV2(enabled bool, failScore int, debug, shadowLines bool) {
	if failScore <= 0 {
		failScore = defaultV2FailScore
	}
	challengeV2.mu.Lock()
	challengeV2.enabled = enabled
	challengeV2.failScore = failScore
	challengeV2.debug = debug
	challengeV2.shadowLines = shadowLines
	challengeV2.mu.Unlock()
}

func challengeV2Settings() (enabled bool, failScore int, debug, shadowLines bool) {
	challengeV2.mu.RLock()
	defer challengeV2.mu.RUnlock()
	return challengeV2.enabled, challengeV2.failScore, challengeV2.debug, challengeV2.shadowLines
}

// readVerifyBody consumes and closes the verify request body under the
// standard cap, KEEPING the bytes for humanity scoring. It doubles as the
// handler's historical junk-drain (the connection is never pinned by an
// unread body). nil on error/over-cap — "no payload", never evidence. The
// handler must call this exactly once, before anything else touches r.Body:
// the slice-3 review caught a drain-then-parse ordering that silently killed
// every body-borne signal, and TestReadVerifyBodyKeepsPayload pins this.
func readVerifyBody(w http.ResponseWriter, r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxVerifyBodyBytes)
	b, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil || len(b) == 0 {
		return nil
	}
	return b
}

// parseHumanityBody decodes the optional verify-POST body. Absent or
// malformed bodies return nil — which the scorer treats as "nothing
// reported", never as evidence (D5b).
func parseHumanityBody(b []byte) *humanitySignals {
	if len(b) == 0 {
		return nil
	}
	var sig humanitySignals
	if json.Unmarshal(b, &sig) != nil {
		return nil
	}
	return &sig
}

// uaClaimsMobile reports whether the UA presents itself as a touch device.
// Used only for the touch_lie tell — a REPORTED maxTouchPoints of zero under a
// mobile claim is a positive contradiction, not an absence.
func uaClaimsMobile(ua string) bool {
	return strings.Contains(ua, "Android") ||
		strings.Contains(ua, "iPhone") ||
		strings.Contains(ua, "iPad")
}

var softwareRendererMarks = []string{
	"swiftshader", "llvmpipe", "softpipe", "software rasterizer", "mesa offscreen", "angle (google, vulkan 1.1.0 (swiftshader",
}

// scoreHumanity is the pure Rung-1 scorer. sig may be nil (no payload): only
// the UA-borne opener can then fire, and an all-absent report scores 0 — the
// D5b invariant the tests pin.
func scoreHumanity(sig *humanitySignals, ua string) (hs int, tells []string) {
	add := func(name string, w int) {
		hs += w
		tells = append(tells, name)
	}

	// UA-borne opener: needs no payload. uaplausible deliberately declines to
	// family-classify HeadlessChrome; here the token is positive evidence.
	if strings.Contains(ua, "HeadlessChrome") || strings.Contains(ua, "PhantomJS") {
		add("headless_ua", tellHeadlessUA)
	}

	if sig != nil {
		if sig.WD != nil && *sig.WD {
			add("webdriver", tellWebdriver)
		}
		if glr := strings.ToLower(sig.GLR); glr != "" {
			for _, m := range softwareRendererMarks {
				if strings.Contains(glr, m) {
					add("sw_renderer", tellSWRenderer)
					break
				}
			}
		}
		if sig.MTP != nil && *sig.MTP == 0 && uaClaimsMobile(ua) {
			add("touch_lie", tellTouchLie)
		}
		if sig.OW != nil && sig.OH != nil && *sig.OW == 0 && *sig.OH == 0 {
			add("outer_zero", tellOuterZero)
		}
		// Amplifier ONLY (D5b): zero interaction can be a keyboard-less kiosk or
		// a fast tab-switch — it never opens a score, it only corroborates one.
		if hs > 0 &&
			sig.PTR != nil && sig.TCH != nil && sig.KEY != nil &&
			*sig.PTR == 0 && *sig.TCH == 0 && *sig.KEY == 0 {
			add("no_input", ampNoInput)
		}
	}
	return hs, tells
}

// HumanitySuffix renders the Rung-1 fields for a solve log line: " hs=N" plus
// " tells=a,b" when any fired. Empty when scoring was disabled (-1 sentinel),
// so pre-Rung-1 log tooling sees an unchanged line; " hs=-" when NO payload
// arrived and nothing fired, so "scored clean" (hs=0) and "reported nothing"
// stay distinguishable in the burn-in data (a fleet-wide hs=- means a
// regression or a body-stripping farm — D5d). Both solve-line writers
// (challenge_server fallback + the detectors hook) go through this, per the
// two-writers-must-agree convention.
func (s ChallengeSolve) HumanitySuffix() string {
	if s.HumanityScore < 0 {
		return ""
	}
	if s.HumanityNoPayload && s.HumanityScore == 0 {
		return " hs=-"
	}
	out := fmt.Sprintf(" hs=%d", s.HumanityScore)
	if s.HumanityTells != "" {
		out += " tells=" + s.HumanityTells
	}
	return out
}
