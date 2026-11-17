package webdetector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
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
// the token, and it passes (absent a certain tell, which Rung 1 already
// rejected). It is not a reject: D5b holds (absence never convicts), and the
// button is the recourse D5c promised.
//
// What it buys is cost and a corpus, not a wall: a farm must now script a
// click on every solve, and the click's approach is measured by the page's
// existing trajectory readings. A CDP click is a trusted click (the HONEST
// LIMITS block in challenge_v2.go).
//
// The PoW a confirm re-post carries was valid when the confirm was issued.
// Its freshness is checked at the token's issue time, so a visitor who takes
// a minute to click is not sent back to solve again. The token lives
// confirmTokenTTL, which the cfm_chal cookie's own 300 s lifetime bounds
// anyway.
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
// engine's tracker); nil unwires, and the step never fires.
func SetUnderAttackConfirmState(fn func(host string) (manual, auto bool)) {
	challengeConfirm.mu.Lock()
	challengeConfirm.attack = fn
	challengeConfirm.mu.Unlock()
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
	grain := s.V2Grain
	if grain == "" {
		grain = "-"
	}
	return fmt.Sprintf("[challenge] ip=%s host=%s uri=%s result=v2_confirm hs=%d tells=%s%s v2=%s tls_fp=%s ua=%q%s%s%s%s",
		s.IP, s.Host, s.URI, s.HumanityScore, s.HumanityTells, s.SignalSuffix(), grain, s.TLSFingerprintOrDash(), s.UA,
		s.GeoSuffix(), s.SrcSuffix(), via, s.ScopeSuffix())
}
