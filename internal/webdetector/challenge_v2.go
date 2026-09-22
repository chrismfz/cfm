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
//   (a) SCOPE      — the score has TEETH only for a solve covered by an
//                    operator-armed `challenge_v2` on SOME grain: the client's
//                    fingerprint (FingerprintPolicyForID), a fleet-armed
//                    country/ASN policy (GeoPolicyActionForIP), a v2-tier
//                    manual vhost challenge (challengeV2HostArmed), or a
//                    per-(ip,host) mark a v2-tier source wrote when it
//                    challenged the client (challengeV2Marked; writers: a
//                    traffic rule with action challenge_v2 at decision time,
//                    and a WAF rule set to "challenge_v2" via its ip_push —
//                    same edge-authoritative ip/host inputs as the decision
//                    and verify paths); everyone else is scored
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
//   - The armed gate's inputs (X-CFM-TLS for the fingerprint grain, the
//     verify host for the vhost grain) are trustworthy because verify is
//     reachable ONLY through the edge proxy: the challenge server binds
//     localhost (CHALLENGE_HTTP_LISTEN=127.0.0.1:9098) and the legacy per-IP
//     challenge-DNAT redirect — the one path where clients reached this
//     server directly and authored their own headers — is RETIRED
//     (docs/edge-unification-plan.md; the 9099 TLS listener is gone). The
//     reference edge confs' /__cfm_verify blocks clear+re-stamp X-CFM-TLS
//     AND re-stamp X-Forwarded-Host = $host, so solve.Host / the fp id are
//     edge-authoritative on current confs. Defense-in-depth residuals, not
//     live paths: (a) a deployed edge conf predating the XFH re-stamp leaves
//     solve.Host client-influenced — TELEMETRY only, the teeth still hold
//     because clearance is host-bound and validated against ngx.var.host in
//     cfm.lua; (b) an operator who re-binds CHALLENGE_HTTP_LISTEN off
//     localhost re-opens the direct-client path and with it every
//     client-authored-header caveat — don't.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
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
	// hostArmed reports whether a v2-tier VHOST arm covers this host (the
	// engine's manual challenge store, apex→www expansion included — arm
	// surfaces slice A). Wired at engine start; nil = no vhost arms (tests /
	// pre-wire), fail-open like the geo resolver.
	hostArmed func(host string) bool
}

var challengeV2 = challengeV2State{enabled: true, failScore: defaultV2FailScore}

// ── Per-(ip,host) ChallengeV2 marks (arm-surfaces slice B) ──────────────────
//
// Some v2-tier arm sources are TRANSIENT: a traffic rule with action
// challenge_v2 matches one request's attributes (path/UA/country/…) at
// DECISION time, and a WAF rule in "challenge_v2" mode matches one request's
// payload at the edge (slice C: the ip_push carries the verbatim tier and
// handleIPPush records the mark) — the verify handler cannot re-evaluate
// either later (the verify POST has none of the original request's
// attributes). So the challenging path records the v2 intent per (client IP,
// host) here, and the verify gate ORs the mark in next to the
// fingerprint/geo/vhost grains. The
// key is EXACT (ip, host): the verify POST rides the same origin the
// challenged page was served on. Bounded and fail-open: over the cap a new
// mark is dropped after an expiry sweep (the client then faces a plain v1
// challenge — never an error), matching D5a's "teeth only where armed".
const (
	// challengeV2MarkTTL comfortably covers page load + the solve retry
	// backoff; an unsolved client that keeps browsing re-marks on every
	// decision anyway (challenge answers are never edge-cached).
	challengeV2MarkTTL     = 15 * time.Minute
	challengeV2MarkMaxKeys = 8192
)

type challengeV2MarkStore struct {
	mu       sync.Mutex
	m        map[string]time.Time // "ip|host" → expiry
	fullWarn bool
}

var challengeV2Marks = challengeV2MarkStore{m: map[string]time.Time{}}

// MarkChallengeV2 records that (ip, host) was challenged by a v2-tier source.
func MarkChallengeV2(ip, host string) {
	if ip == "" || host == "" {
		return
	}
	key := ip + "|" + host
	now := time.Now()
	s := &challengeV2Marks
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[key]; !exists && len(s.m) >= challengeV2MarkMaxKeys {
		for k, exp := range s.m { // expiry sweep, only on pressure
			if now.After(exp) {
				delete(s.m, k)
			}
		}
		if len(s.m) >= challengeV2MarkMaxKeys {
			if !s.fullWarn {
				s.fullWarn = true
				logging.Logf("[challenge_v2] per-(ip,host) mark store full (%d) — new v2 marks degrade to plain challenge until pressure drops", challengeV2MarkMaxKeys)
			}
			return // fail-open: plain v1 challenge for the newcomer
		}
	}
	s.m[key] = now.Add(challengeV2MarkTTL)
	// Any successful insert/refresh means the store is not saturated: re-arm
	// the once-per-episode warning so a LATER full episode logs again even if
	// the previous one drained via reads/expiry alone (second-review nit).
	s.fullWarn = false
}

// challengeV2Marked reports whether a live v2 mark covers (ip, host).
func challengeV2Marked(ip, host string) bool {
	if ip == "" || host == "" {
		return false
	}
	key := ip + "|" + host
	s := &challengeV2Marks
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[key]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, key)
		return false
	}
	return true
}

// SetChallengeV2HostArmed wires the per-vhost v2 lookup the verify gate ORs
// in (see the D5 gate in challenge_server.go). Same lifecycle as
// SetFingerprintPolicyGeoResolver: set once from NewEngine.
func SetChallengeV2HostArmed(fn func(host string) bool) {
	challengeV2.mu.Lock()
	challengeV2.hostArmed = fn
	challengeV2.mu.Unlock()
}

// challengeV2HostArmed answers "does a v2 vhost arm cover this host" for the
// verify gate. false when unwired or host is empty (fail-open — D5a: teeth
// only where an operator explicitly armed).
func challengeV2HostArmed(host string) bool {
	challengeV2.mu.RLock()
	fn := challengeV2.hostArmed
	challengeV2.mu.RUnlock()
	if fn == nil || host == "" {
		return false
	}
	return fn(host)
}

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
// every body-borne signal. TestReadVerifyBodyKeepsPayload pins this
// function's keep+drain+degrade contract; the CALL-SITE ordering has no
// end-to-end test yet (the verify handler needs full PoW plumbing to drive),
// so treat the call-site comment in the handler as load-bearing — and watch
// hs=- rates after any refactor there: a fleet-wide hs=- is the symptom.
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
// reported", never as evidence (D5b). String fields are re-bounded here so a
// client cannot smuggle an arbitrarily long value toward a log line, whatever
// the page-side slice said.
func parseHumanityBody(b []byte) *humanitySignals {
	if len(b) == 0 {
		return nil
	}
	var sig humanitySignals
	if json.Unmarshal(b, &sig) != nil {
		return nil
	}
	if len(sig.GLR) > 128 {
		sig.GLR = sig.GLR[:128]
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
