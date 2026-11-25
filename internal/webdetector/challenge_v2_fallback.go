package webdetector

import (
	"strings"
	"sync"
)

// challenge_v2_fallback.go — the confirm fallback for a Rung-1 reject
// (D5c: "a failed passive check … escalates to a VISIBLE check"; the
// 2026-11-25 v2-everywhere amendment, PR B).
//
// A solve the gate is about to REJECT, with no certain tell (webdriver,
// headless UA) and from the node's audience (CHALLENGE_V2_CONFIRM_AUDIENCE,
// default GR,CY, never a datacenter ASN), is answered like the under-attack
// confirm step instead: 403 with an X-CFM-Confirm token, and the page shows
// its one native "Continue" button. The click re-posts the solve with the
// token and the click (X-CFM-Click, or any pointer / touch / key input), and
// that re-post passes, marked v2_rescued=confirm and v2_confirm=clicked on
// the solve line and history row. A re-post with the token and still no
// input is asked again with the SAME token. A fallback ask is a log line
// (result=v2_confirm … confirm=fallback), not a reject row: it refused
// nothing yet.
//
// Who it is for: the person the gate cannot tell from a farm because their
// machine scores like one (a software renderer, no window size: a VDI/RDS
// desk, an old Windows PC) and who did not move a pointer while the PoW ran
// (keyboard or touch only, or simply waiting). Retrying cannot change their
// score; one click does. Rung 1 measured none of them among the rejects in
// the week before "v2 everywhere" (2026-11-25), which is exactly why the
// fallback is cheap: the farms are outside the audience and never see it.
//
// Where it applies: the grains the good-bot waiver softens and the all grain
// (challengeV2WaiverBar: geo, vhost, all; never under a rung mark, never on a
// vhost in lockdown), web scope only (the token is accepted only there). An
// operator's fingerprint policy and the rule / WAF / malpath marks stay
// strict, as for the waiver; the unsolicited grain withholds instead and
// needs no recourse.
//
// HONEST LIMITS: the click is client-authored, like every Rung-1 reading. A
// farm inside the audience that reads the 403 and re-posts with the token and
// a CDP click passes; that is the corpus this step exists to collect (the
// clicked line's sig= trajectory readings and v2_confirm_ms), scored by
// nothing until the numbers are in (D3). CHALLENGE_V2_FALLBACK = all widens it
// to everyone, off turns it off.

const (
	fallbackOff      = "off"
	fallbackAudience = "audience"
	fallbackAll      = "all"

	// v2RescuedConfirm: a failing solve passed by the fallback's click.
	v2RescuedConfirm = "confirm"
)

var challengeV2Fallback = struct {
	mu   sync.RWMutex
	mode string
}{mode: fallbackAudience}

// ConfigureChallengeV2Fallback applies [webdetector] CHALLENGE_V2_FALLBACK
// (every reload): off | audience (default) | all; anything else is the
// default.
func ConfigureChallengeV2Fallback(mode string) {
	m := strings.ToLower(strings.TrimSpace(mode))
	switch m {
	case fallbackOff, fallbackAudience, fallbackAll:
	default:
		m = fallbackAudience
	}
	challengeV2Fallback.mu.Lock()
	challengeV2Fallback.mode = m
	challengeV2Fallback.mu.Unlock()
}

// challengeV2FallbackOffered reports whether a solve the gate is about to
// reject gets the confirm fallback instead (see the file header).
func challengeV2FallbackOffered(s ChallengeSolve, grain, scope string) bool {
	if scope != "web" || grain == "" || grain == v2GrainUnsolicited {
		return false
	}
	for _, t := range strings.Split(s.HumanityTells, ",") {
		if t == tellNameWebdriver || t == tellNameHeadlessUA {
			return false
		}
	}
	if challengeV2WaiverBar(grain, s.IP, s.Host, scope) != "" {
		return false
	}
	challengeV2Fallback.mu.RLock()
	mode := challengeV2Fallback.mode
	challengeV2Fallback.mu.RUnlock()
	switch mode {
	case fallbackAll:
		return true
	case fallbackAudience:
		challengeConfirm.mu.RLock()
		in := challengeConfirm.audience[strings.ToUpper(s.CountryISO)]
		challengeConfirm.mu.RUnlock()
		return in && DatacenterClass(s.ASN, s.ASNName) == ""
	}
	return false
}
