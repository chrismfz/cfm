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
//                    line, sig= with the signals exactly as the client
//                    reported them, and v2=<grain> naming the arm whenever
//                    one covers the solve (HumanitySuffix, both writers):
//                    an armed solve that PASSES must not read like a plain v1
//                    one, or a live tier looks like a forgotten one. A reject
//                    logs result=v2_reject (naming the grain), a would-fail
//                    unarmed solve emits signal=humanity verdict=would_v2 to
//                    the abuse shadow log, and CHALLENGE_V2_DEBUG=1 adds an
//                    X-CFM-HS response header for DevTools-level inspection.
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
	"strconv"
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
	V   int    `json:"v"`   // payload version
	WD  *bool  `json:"wd"`  // navigator.webdriver
	GLR string `json:"glr"` // WebGL UNMASKED_RENDERER (bounded client-side; re-bounded here)
	OW  *int   `json:"ow"`  // window.outerWidth
	OH  *int   `json:"oh"`  // window.outerHeight
	MTP *int   `json:"mtp"` // navigator.maxTouchPoints
	PTR *int   `json:"ptr"` // pointer-move events observed while solving
	TCH *int   `json:"tch"` // touchstart events observed
	KEY *int   `json:"key"` // keydown events observed
	// The five below are RETAINED BUT NEVER SCORED: they are logged verbatim
	// (sig= on the solve line, payload.sig on the history row) to build the
	// corpus from real traffic, so a future tell can be written from measured
	// distributions rather than from memory. They were pointer-less and
	// silently discarded until 2026-09-22 — a `dm` absent on every Firefox
	// then read as a reported 0.0, which is exactly the absence/zero
	// confusion the pointer convention above exists to prevent.
	MV  *float64 `json:"mv"`  // accumulated |pointer movement| in px (page always sends it; 0 = really no movement)
	HC  *int     `json:"hc"`  // hardwareConcurrency
	DM  *float64 `json:"dm"`  // deviceMemory — Chrome-only, genuinely absent on Firefox/Safari
	DPR *float64 `json:"dpr"` // devicePixelRatio
	RAF *float64 `json:"raf"` // avg requestAnimationFrame delta ms; absent when <8 frames elapsed before submit
}

// Sanity bounds for the retained-but-unscored values. The body is
// CLIENT-authored (HONEST LIMITS above), so a value outside what any real
// browser reports is dropped rather than carried: an unbounded float reaches
// a log line and a durable history row, and a corpus built for later analysis
// must not have to defend itself against 1e308. Dropping degrades to
// "absent", which every consumer already handles — never to a fabricated
// zero. JSON has no NaN/Inf literal (such a body fails to parse and scores as
// no payload), so these comparisons cannot be defeated by a non-number.
const (
	sigMaxEvents   = 1_000_000 // ptr/tch/key
	sigMaxMovement = 1e9       // px, accumulated
	sigMaxCores    = 4096
	sigMaxMemoryGB = 4096
	sigMaxDPR      = 64
	sigMaxRAFms    = 60_000
	// sigMinPositive is the floor for the two values whose range legitimately
	// starts at 0 (mv, raf). A positive below it is not something any device
	// reports, and allowing it would force the renderer to either print "0"
	// for a non-zero value — manufacturing the impossible "ptr:1,mv:0" shape
	// — or spend 300 characters of log line proving otherwise. Dropping it to
	// absent keeps sigFloat's no-false-zero guarantee provable.
	sigMinPositive = 1e-6
	// sigMaxDecimals bounds sigFloat's fallback rendering. Paired with
	// sigMinPositive: 1e-6 is exactly representable at 6 decimals, so the
	// fallback can never itself round a surviving value to zero.
	sigMaxDecimals = 6
)

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
	// backoff. Re-marking differs per writer: a v2-tier TRAFFIC RULE re-marks
	// on every decision (the rule re-evaluates per request), but a WAF-rule
	// mark refreshes only when the rule re-fires AND should_push's cooldown
	// window allows — meanwhile the edge keeps serving the challenge off the
	// plain-"challenge" ipState decision. As shipped that decision TTL
	// (default_ttl_sec=600) sits inside this 15m, so the mark outlives the
	// decision; an operator raising default_ttl_sec past ~900s opens a tail
	// where a late solve passes at v1 — fail-open by doctrine, noted here so
	// nobody "fixes" it into fail-closed.
	challengeV2MarkTTL     = 15 * time.Minute
	challengeV2MarkMaxKeys = 8192
)

type challengeV2MarkStore struct {
	mu       sync.Mutex
	m        map[string]time.Time // "ip|host" → expiry
	fullWarn bool
}

var challengeV2Marks = challengeV2MarkStore{m: map[string]time.Time{}}

// challengeV2MarkKey canonicalizes the (ip, host) pair into the store key.
// The WRITERS' inputs pass through normalizeHost (lowercase + port strip)
// while the verify READER's host comes via normalizeClearanceHost, which
// additionally trims a trailing dot and unbrackets a bare IPv6 literal —
// so both sides run normalizeClearanceHost HERE (idempotent for
// already-normalized input) and a `Host: example.com.` write can never
// miss the `example.com` verify lookup. Returns "" when either half is
// empty (callers treat that as "no mark").
func challengeV2MarkKey(ip, host string) string {
	ip = strings.TrimSpace(ip)
	host = normalizeClearanceHost(host)
	if ip == "" || host == "" {
		return ""
	}
	return ip + "|" + host
}

// MarkChallengeV2 records that (ip, host) was challenged by a v2-tier source.
func MarkChallengeV2(ip, host string) {
	key := challengeV2MarkKey(ip, host)
	if key == "" {
		return
	}
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
	key := challengeV2MarkKey(ip, host)
	if key == "" {
		return false
	}
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

// Arm-grain names. They are a grep surface (`v2=` on the solve line), so keep
// them short and stable.
const (
	v2GrainFP    = "fp"    // an armed challenge_v2 fingerprint policy
	v2GrainGeo   = "geo"   // a fleet-armed country/ASN policy covering the IP
	v2GrainVhost = "vhost" // a v2-tier manual vhost challenge on the host
	v2GrainMark  = "mark"  // a per-(ip,host) rung mark (traffic rule / WAF rule)
)

// challengeV2ArmGrain answers D5a's "is this solve covered by an
// operator-armed challenge_v2?" and NAMES the grain that armed it. It is the
// single evaluation of the OR the verify gate applies (challenge_server.go),
// so the teeth and the log line can never disagree about whether a solve was
// armed — the two-writers-must-agree convention, applied to a predicate.
// "" means unarmed: the score is shadow/log-only. Precedence is the gate's
// documented order, and every lookup is fail-open when unwired or absent.
//
// Evaluated on EVERY scored solve, not only a failing one: "armed and passed"
// is exactly what a burn-in operator needs to see (D5d). Without it an armed
// solve that scores clean is byte-identical in cfm.challenges.log to a plain
// v1 one, which reads as "the tier never fired" — the gap this function was
// added to close. Cheap enough at solve rate (map reads plus, when geo
// policies are loaded, one mmdb lookup), and reading a mark never consumes
// it — challengeV2Marked only drops its own expired key — so the eager read
// cannot starve the gate below.
func challengeV2ArmGrain(fpID, ip, host string) string {
	switch {
	case FingerprintPolicyForID(fpID) == "challenge_v2":
		return v2GrainFP
	case GeoPolicyActionForIP(ip) == "challenge_v2":
		return v2GrainGeo
	case challengeV2HostArmed(host):
		return v2GrainVhost
	case challengeV2Marked(ip, host):
		return v2GrainMark
	}
	return ""
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
	sig.sanitize()
	return &sig
}

// sanitize drops retained values a real browser would never report, so the
// log line and the history row can only ever carry plausible numbers. It runs
// at the ONE parse choke point, before anything reads the payload.
//
// SCORING IS UNCHANGED, and that is load-bearing rather than incidental. The
// scorer's own inputs (wd/glr/mtp/ow/oh) are not touched at all. PTR/TCH/KEY
// ARE scorer inputs — the no_input amplifier — but a bound here still cannot
// move a verdict: no_input needs all three REPORTED and all three exactly 0,
// dropping only ever produces absent (never a fabricated zero — D5b), and a
// count that fails these bounds is non-zero anyway, so it already failed the
// `== 0` test before the drop. Net effect on every possible payload: the
// amplifier fires exactly where it fired before. A bound must never become a
// back-door tell.
func (s *humanitySignals) sanitize() {
	dropInt := func(p **int, min, max int) {
		if *p != nil && (**p < min || **p > max) {
			*p = nil
		}
	}
	dropFloat := func(p **float64, min, max float64) {
		if *p != nil && (**p < min || **p > max) {
			*p = nil
		}
	}
	dropInt(&s.PTR, 0, sigMaxEvents)
	dropInt(&s.TCH, 0, sigMaxEvents)
	dropInt(&s.KEY, 0, sigMaxEvents)
	dropFloat(&s.MV, 0, sigMaxMovement)
	dropInt(&s.HC, 1, sigMaxCores)
	// deviceMemory is reported in GiB and can legitimately be fractional
	// (0.25 on low-end Android), so the floor is "greater than zero", not 1.
	dropFloat(&s.DM, 0.001, sigMaxMemoryGB)
	dropFloat(&s.DPR, 0.001, sigMaxDPR)
	dropFloat(&s.RAF, 0, sigMaxRAFms)
	// mv and raf legitimately start at 0, so their range check admits a
	// positive too small for any real device to have produced. Drop those
	// (see sigMinPositive); an exact 0 is a real reading and is kept.
	dropTiny := func(p **float64) {
		if *p != nil && **p > 0 && **p < sigMinPositive {
			*p = nil
		}
	}
	dropTiny(&s.MV)
	dropTiny(&s.RAF)
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

// ── Retained-signal rendering (one source, two surfaces) ───────────────────
//
// The log line and the history row must show the SAME numbers, so both are
// built from the same parsed payload and the same rounding. Rounding is
// deliberate: a raw rAF average is 16.666666666666668, which bloats every row
// and reads as false precision on a value averaged over 8 frames.

// sigFloat formats a retained float at a fixed number of decimals, then trims
// trailing zeros. 'f' (never 'g'/'e') on purpose: scientific notation in a
// log field breaks a `grep`/`cut` corpus pass, and a %g-style verb has
// misrendered a value in this repo before.
func sigFloat(v float64, prec int) string {
	trim := func(in string) string {
		if strings.ContainsRune(in, '.') {
			in = strings.TrimRight(in, "0")
			in = strings.TrimSuffix(in, ".")
		}
		return in
	}
	out := trim(strconv.FormatFloat(v, 'f', prec, 64))
	// A REPORTED non-zero must never render as "0". `ptr:1,mv:0` is a shape
	// no real client produces, and writing it into the corpus is the same
	// fabricated-zero failure the absent-key rule prevents everywhere else —
	// a later analyst would read it as "events fired, pointer never moved".
	// sanitize guarantees any surviving non-zero is >= sigMinPositive, so
	// this fallback always renders something non-zero and stays bounded.
	if out == "0" && v != 0 {
		out = trim(strconv.FormatFloat(v, 'f', sigMaxDecimals, 64))
	}
	return out
}

// sigFields returns the retained signals in ONE fixed order — behavioural
// first (the operational question is "did this client do anything?"), then
// environment — as (key, rendered value) pairs. Absent values are omitted
// entirely: a key that is not on the line was not reported, and no consumer
// has to guess whether a 0 meant "none" or "unknown". Nil receiver / nil
// payload yields nothing.
func (s *humanitySignals) sigFields() [][2]string {
	if s == nil {
		return nil
	}
	var out [][2]string
	addInt := func(k string, v *int) {
		if v != nil {
			out = append(out, [2]string{k, strconv.Itoa(*v)})
		}
	}
	addFloat := func(k string, v *float64, prec int) {
		if v != nil {
			out = append(out, [2]string{k, sigFloat(*v, prec)})
		}
	}
	addInt("ptr", s.PTR)
	addInt("tch", s.TCH)
	addInt("key", s.KEY)
	// mv keeps one decimal: movementX/Y is fractional on HiDPI / fractional
	// display scaling, so a genuine small drag really can total 0.5px.
	addFloat("mv", s.MV, 1)
	addInt("hc", s.HC)
	addFloat("dm", s.DM, 2) // 0.25 / 0.5 / 1 / 2 / 4 / 8 GiB buckets
	addFloat("dpr", s.DPR, 2)
	addFloat("raf", s.RAF, 1)
	return out
}

// SignalSuffix renders " sig=ptr:12,tch:0,key:0,mv:843,hc:8,dpr:1.5,raf:16.7"
// — the Rung-1 report as REPORTED, before any scoring. Empty when nothing was
// retained, so a no-payload solve adds no field.
//
// Precisely: mv/hc/dm/dpr/raf are scored by NOTHING — they are corpus only,
// logged so a future tell can be written from measured distributions instead
// of from memory. ptr/tch/key ARE scorer inputs (the no_input amplifier, and
// only as an all-three-zero combination); logging them is what makes that
// amplifier auditable rather than opaque. Either way the line shows the raw
// reading, never a scored derivative — and "the client never moved the mouse"
// is answerable from the log at all, which it was not: mv was parsed and
// thrown away despite a comment claiming it was recorded.
func (s ChallengeSolve) SignalSuffix() string {
	fields := s.humanity.sigFields()
	if len(fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, f[0]+":"+f[1])
	}
	return " sig=" + strings.Join(parts, ",")
}

// signalMap is the history-row spelling of the same report: payload.sig, with
// the rendered (rounded) values as JSON numbers so a corpus pass can aggregate
// them without re-parsing a log field. nil when nothing was retained, so the
// key is simply absent on such a row — matching the log's "no sig= field".
func (s ChallengeSolve) signalMap() map[string]any {
	fields := s.humanity.sigFields()
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		if n, err := strconv.ParseFloat(f[1], 64); err == nil {
			out[f[0]] = n
			continue
		}
		out[f[0]] = f[1] // unreachable for current fields; never drop a value silently
	}
	return out
}

// HumanitySuffix renders the Rung-1 fields for a solve log line, in order:
// " hs=N", " tells=a,b" when any fired, " sig=..." with the raw reported
// signals (SignalSuffix), and " v2=<grain>" when the solve was covered by an
// operator-armed challenge_v2. Empty when scoring was disabled (-1
// sentinel), so pre-Rung-1 log tooling sees an unchanged line; " hs=-" when NO
// payload arrived and nothing fired, so "scored clean" (hs=0) and "reported
// nothing" stay distinguishable in the burn-in data (a fleet-wide hs=- means a
// regression or a body-stripping farm — D5d). Both solve-line writers
// (challenge_server fallback + the detectors hook) go through this, per the
// two-writers-must-agree convention.
//
// v2= rides here rather than on its own because an ARMED solve that passes is
// otherwise invisible: result=solved with a clean score reads exactly like a
// plain v1 solve, and an operator watching a freshly-promoted rule concludes
// the tier never fired. Absent v2= = unarmed (score was shadow/log-only); a
// rejected solve logs result=v2_reject and names the grain on its own line.
func (s ChallengeSolve) HumanitySuffix() string {
	if s.HumanityScore < 0 {
		return ""
	}
	var out string
	if s.HumanityNoPayload && s.HumanityScore == 0 {
		out = " hs=-"
	} else {
		out = fmt.Sprintf(" hs=%d", s.HumanityScore)
		if s.HumanityTells != "" {
			out += " tells=" + s.HumanityTells
		}
	}
	out += s.SignalSuffix()
	if s.V2Grain != "" {
		out += " v2=" + s.V2Grain
	}
	return out
}
