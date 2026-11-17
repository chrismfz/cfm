package webdetector

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/detectors/core"
)

// challenge_confirm.go — the under-attack confirm step
// (docs/targeted-challenge-design.md §4, increment B / step S4).
//
// While a vhost is UNDER_ATTACK, a solve that passed Rung 1 but carries no
// trusted input at all (ptr, tch and key all 0, or no payload), from a client
// outside the node's audience (CHALLENGE_V2_CONFIRM_AUDIENCE, default GR,CY;
// a datacenter ASN counts as outside), earns no clearance on its first POST.
// The verify answers 403 with an X-CFM-Confirm token instead, and the page
// shows one native "Continue" button. The click re-posts the same solve with
// the token AND the click itself (X-CFM-Click: 1 for a trusted click on the
// button; the approach to it moves the pointer counts too). A re-post with the token and
// still no trusted input is asked again. A confirmed re-post passes (absent
// a certain tell, which Rung 1 already rejected). It is not a reject: D5b
// holds (absence never convicts), and the button is the recourse D5c promised.
//
// The PoW a confirm re-post carries was valid when the confirm was issued.
// Its freshness is checked at the token's issue time, so a visitor who takes
// a minute to click is not sent back to solve again. The token lives
// confirmTokenTTL, but the cfm_chal cookie the re-post also needs expires
// 300 s after it was SET (it is set only when missing), so the real window
// is up to 5 minutes and can be shorter; past it the page reloads into a
// fresh challenge.
//
// HONEST LIMITS. What it buys is cost and a corpus, not a wall:
//   - the counts are client-authored, like all of Rung 1: a farm that reads
//     the 403 and re-posts with the token and X-CFM-Click passes, and a CDP click is a
//     trusted click. It must now handle a second round trip on every solve
//     (today's farm stacks post once), and the click's approach is measured
//     by the page's existing trajectory readings;
//   - a token is not single-use: one (PoW, token) pair can mint clearance
//     again from the same ip and host until the token expires (~7 minutes
//     after the PoW was issued, instead of the PoW's own 2). A PoW is
//     reusable within its TTL already, and clearance is per (ip, host). A
//     re-post is never answered with a NEW token, so that bound holds;
//   - every human outside the audience now makes two verify POSTs, which
//     count toward the verify rate limit (rlVerifyBurst): a busy CGNAT
//     address reaches it sooner while a vhost is under attack;
//   - the default `manual` mode follows the in-memory override, which a
//     cPanel user can also set on their own vhost (24 h max), and which a
//     config reload (a detectors.conf save, a tailed log's rotation) clears;
//   - a shown confirm is a log line only (result=v2_confirm), not a history
//     row: it decides nothing, and under attack it is high volume. The
//     clicked solve's row carries v2_confirm=clicked.
//
// Knobs ([webdetector], read on every reload):
//   CHALLENGE_V2_CONFIRM          off | manual (default) | auto
//                                 manual: only while an operator override
//                                 (`cfm webtop attack on <vhost>`, the
//                                 cfm-admin toggle) holds the vhost UNDER_ATTACK;
//                                 auto: also the detector's automatic entry.
//   CHALLENGE_V2_CONFIRM_AUDIENCE comma-separated ISO countries that never
//                                 see the confirm (default GR,CY); "none" =
//                                 everyone outside.
//
// The confirm is shown only where a challenge is already served: the
// under-attack state alone challenges nobody. To try it on a vhost, arm a
// challenge on it (a manual one, or an automatic one already there) and force
// the state: `cfm webtop challenge add <vhost>` + `cfm webtop attack on <vhost>`.

const (
	confirmHeader   = "X-CFM-Confirm"
	clickHeader     = "X-CFM-Click"
	confirmTokenTTL = 5 * time.Minute

	confirmModeOff    = "off"
	confirmModeManual = "manual"
	confirmModeAuto   = "auto"

	confirmClicked = "clicked"
)

var defaultConfirmAudience = []string{"GR", "CY"}

type challengeConfirmState struct {
	mu       sync.RWMutex
	mode     string
	audience map[string]bool
	// attack reports whether host is UNDER_ATTACK under an operator override
	// (manual) or the detector's automatic state (auto). nil = unwired.
	attack func(host string) (manual, auto bool)
	// record feeds a confirm-asked solve to the under-attack solve rate
	// (Engine.RecordUnderAttackSolve): a solve that never clicks must still
	// count, or `auto` would starve the state that asks it. nil = none.
	record func(ChallengeSolve)
}

var challengeConfirm = challengeConfirmState{
	mode:     confirmModeManual,
	audience: audienceSet(defaultConfirmAudience),
}

func audienceSet(ccs []string) map[string]bool {
	m := make(map[string]bool, len(ccs))
	for _, c := range ccs {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			m[c] = true
		}
	}
	return m
}

// parseConfirmMode maps the knob to a mode; anything unknown is the default
// (manual), so a typo never turns the step on for automatic entries.
func parseConfirmMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "off", "false", "no":
		return confirmModeOff
	case "auto", "all":
		return confirmModeAuto
	default:
		return confirmModeManual
	}
}

// parseConfirmAudience maps the knob to a country set: "" = the default
// (GR,CY), "none" or "-" = no audience (everyone outside).
func parseConfirmAudience(v string) map[string]bool {
	v = strings.TrimSpace(v)
	switch strings.ToLower(v) {
	case "":
		return audienceSet(defaultConfirmAudience)
	case "none", "-":
		return map[string]bool{}
	}
	return audienceSet(strings.Split(v, ","))
}

// ConfigureChallengeV2Confirm applies CHALLENGE_V2_CONFIRM and
// CHALLENGE_V2_CONFIRM_AUDIENCE (every reload).
func ConfigureChallengeV2Confirm(mode, audience string) {
	m, a := parseConfirmMode(mode), parseConfirmAudience(audience)
	challengeConfirm.mu.Lock()
	challengeConfirm.mode = m
	challengeConfirm.audience = a
	challengeConfirm.mu.Unlock()
}

// SetUnderAttackConfirmState wires the under-attack read the gate needs (the
// engine's tracker) and the solve-rate feed for a confirm-asked solve; a nil
// attack unwires, and the step never fires.
func SetUnderAttackConfirmState(attack func(host string) (manual, auto bool), record func(ChallengeSolve)) {
	challengeConfirm.mu.Lock()
	challengeConfirm.attack = attack
	challengeConfirm.record = record
	challengeConfirm.mu.Unlock()
}

// recordConfirmAsked feeds a confirm-asked solve to the solve rate.
func recordConfirmAsked(s ChallengeSolve) {
	challengeConfirm.mu.RLock()
	fn := challengeConfirm.record
	challengeConfirm.mu.RUnlock()
	if fn != nil {
		fn(s)
	}
}

// confirmGoodBot reports whether an FCrDNS-verified good bot skips the
// confirm: it cannot click. The same rules as the Rung-1 waiver
// (challengeV2WaiverBar at the vhost grain: never under a rung mark, never on
// a vhost in lockdown) and the same verdict and CHALLENGE_GOODBOT_EXEMPT knob
// (challengeV2GoodBot, which may forward-confirm a crawler-looking PTR inline,
// bounded; it runs only for a solve about to be asked).
func confirmGoodBot(ctx context.Context, s ChallengeSolve) bool {
	if challengeV2WaiverBar(v2GrainVhost, s.IP, s.Host, s.Scope) != "" {
		return false
	}
	bot, _ := challengeV2GoodBot(ctx, s.IP, s.PTR)
	return bot != ""
}

// confirmInput reports whether a confirm re-post carries trusted input: the
// click on the button (the X-CFM-Click header the page sets on a trusted
// click; a header, so the humanity body and its 1 KB bound are unchanged),
// or pointer, touch or key events.
func confirmInput(sig *humanitySignals, clicked bool) bool {
	return clicked || (sig != nil && intVal(sig.PTR)+intVal(sig.TCH)+intVal(sig.KEY) > 0)
}

// confirmRequired reports whether a solve that passed Rung 1 must still
// confirm. Fail-open everywhere: unwired, mode off, a panel scope, an
// unresolved country, a waived good bot or any trusted input all say no.
func confirmRequired(s ChallengeSolve, sig *humanitySignals) bool {
	if s.Scope != "web" || s.V2Waived != "" || s.CountryISO == "" {
		return false
	}
	if sig != nil && (intVal(sig.PTR) > 0 || intVal(sig.TCH) > 0 || intVal(sig.KEY) > 0) {
		return false
	}
	challengeConfirm.mu.RLock()
	mode, audience, attack := challengeConfirm.mode, challengeConfirm.audience, challengeConfirm.attack
	challengeConfirm.mu.RUnlock()
	if mode == confirmModeOff || attack == nil {
		return false
	}
	if audience[strings.ToUpper(s.CountryISO)] && DatacenterClass(s.ASN, s.ASNName) == "" {
		return false
	}
	manual, auto := attack(normalizeHost(s.Host))
	return manual || (auto && mode == confirmModeAuto)
}

func intVal(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// confirmMAC signs (issued, ip, host, powTok) under the PoW key, domain
// separated, so a confirm token is valid only for the solve it was issued to.
func confirmMAC(issued int64, ip, host, powTok string) []byte {
	mac := hmac.New(sha256.New, powSecretKey())
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(issued))
	mac.Write([]byte("cfm-confirm\x00"))
	mac.Write(ts[:])
	for _, part := range []string{ip, normalizeHost(host), powTok} {
		mac.Write([]byte{0})
		mac.Write([]byte(part))
	}
	return mac.Sum(nil)
}

// issueConfirmToken: base64url( issued_unix_ms(8) || mac(32) ).
func issueConfirmToken(ip, host, powTok string, now time.Time) string {
	issued := now.UnixMilli()
	buf := make([]byte, 8, 40)
	binary.BigEndian.PutUint64(buf, uint64(issued))
	buf = append(buf, confirmMAC(issued, ip, host, powTok)...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// verifyConfirmToken returns when the token was issued, if it is genuine for
// (ip, host, powTok), not from the future and younger than confirmTokenTTL.
func verifyConfirmToken(tok, ip, host, powTok string, now time.Time) (time.Time, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(tok))
	if err != nil || len(raw) != 40 {
		return time.Time{}, false
	}
	issuedMS := int64(binary.BigEndian.Uint64(raw[:8]))
	if !hmac.Equal(raw[8:], confirmMAC(issuedMS, ip, host, powTok)) {
		return time.Time{}, false
	}
	issued := time.UnixMilli(issuedMS).UTC()
	if issued.After(now.Add(5*time.Second)) || now.Sub(issued) > confirmTokenTTL {
		return time.Time{}, false
	}
	return issued, true
}

// ConfirmLine is the result=v2_confirm line: the solve passed Rung 1 and was
// asked to confirm. Same fields as the reject line, so a reader joins a
// v2_confirm to its later v2_confirm=clicked solve by ip and host; one with
// no such solve is a visitor who did not click (the step's human cost, or a
// farm that does not script the click).
func (s ChallengeSolve) ConfirmLine() string {
	via := ""
	if s.V2Via != "" {
		via = " v2_via=" + s.V2Via
	}
	// v2= only when armed, as on the solve line.
	grain := ""
	if s.V2Grain != "" {
		grain = " v2=" + s.V2Grain
	}
	// hs=- and tells=- as the solve line has them: hs 0 is a real score
	// ("scored clean"), and most of this population has no tells.
	hs := strconv.Itoa(s.HumanityScore)
	if core.HumanityNoReport(s.HumanityNoPayload, s.HumanityScore) {
		hs = "-"
	}
	tells := s.HumanityTells
	if tells == "" {
		tells = "-"
	}
	return fmt.Sprintf("[challenge] ip=%s host=%s uri=%s result=v2_confirm hs=%s tells=%s%s%s tls_fp=%s ua=%q%s%s%s%s",
		s.IP, s.Host, s.URI, hs, tells, s.SignalSuffix(), grain, s.TLSFingerprintOrDash(), s.UA,
		s.GeoSuffix(), s.SrcSuffix(), via, s.ScopeSuffix())
}
