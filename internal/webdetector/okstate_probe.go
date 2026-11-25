package webdetector

import (
	"time"

	"cfm/internal/logging"
)

// okstate_probe.go — measures the solved-ok grace (okState,
// OPENRESTY_OK_IP_TTL) before it is retired.
//
// okState lets a client through the vhost-wide AND the per-IP challenge for a
// host once its IP solved there (or was cleared), without a clearance cookie
// of its own, and every request with a valid cookie extends it (ok/touch). It
// predates the host-bound clearance cookie (docs/security/
// challenge-scope-mapping.md); what it still buys is a client that loses the
// cookie, at the price of opening the host to everyone behind the same IP
// (CGNAT, a corporate NAT, a residential proxy) for as long as one cleared
// browser stays active (2026-11-25, virgo: an operator's `attack on` showed no
// challenge to a private window from the IP that had solved 25 minutes
// earlier).
//
// A request with a valid clearance cookie returns at cfm.lua Step 2b and never
// reaches /nginx/decision, so a decision okState turns into an allow is a
// request WITHOUT its own cookie. One line per (ip, host, scope) per
// okProbeLogEvery:
//
//	[challenge] okstate mode=allow …  okState let a would-be challenge through
//	                                  (OPENRESTY_OK_IP_TTL > 0);
//	[challenge] okstate mode=would …  a challenge answered to a pair that
//	                                  solved within okProbeWindow, i.e. one
//	                                  okState would have let through: the cost
//	                                  of OPENRESTY_OK_IP_TTL = 0 (or of a
//	                                  shorter TTL that has run out).
//
// solved_ago= is the time since the pair's last solve or clear; vh= and ipa=
// are the challenge the decision held before okState. Log-only: it decides
// nothing.

const (
	// okProbeWindow is how long a solve is remembered for mode=would: the
	// fleet's longest OPENRESTY_OK_IP_TTL (45m on six nodes).
	okProbeWindow   = 45 * time.Minute
	okProbeLogEvery = 10 * time.Minute
)

// okProbeLogf writes the line (a var so a test can read it).
var okProbeLogf = logging.LogfCHALLENGES

var (
	okProbeSolved = pairTTLStore[int64]{
		m:          map[string]time.Time{},
		vals:       map[string]int64{},
		ttl:        okProbeWindow,
		maxKeys:    100000,
		sweepEvery: time.Minute,
		fullMsg:    "[challenge] okstate probe: solved store full (%d): mode=would lines are a sample until pressure drops",
	}
	okProbeLogged = pairTTLStore[struct{}]{
		m:          map[string]time.Time{},
		ttl:        okProbeLogEvery,
		maxKeys:    50000,
		sweepEvery: time.Minute,
		fullMsg:    "[challenge] okstate probe: log throttle full (%d): lines are a sample until pressure drops",
	}
)

func okProbeKey(ip, host, scope string) string {
	return ip + "|" + normalizeHost(host) + "|" + scope
}

// noteOKProbeSolved records a solve (or a clear) of (ip, host, scope).
func noteOKProbeSolved(ip, host, scope string, now time.Time) {
	if ip == "" || host == "" || scope == "" {
		return
	}
	okProbeSolved.put(okProbeKey(ip, host, scope), now.UnixNano(), now)
}

// okStateProbe writes the okstate line for one decision (see the file
// header). origVh / origIP are the actions before okState, finalVh / finalIP
// the answer sent to the edge, overridden whether okState cleared them.
func okStateProbe(ip, host, scope, ua, origVh, origIP, finalVh, finalIP string, overridden bool, now time.Time) {
	mode := ""
	switch {
	case overridden && (origVh == "challenge" || origIP == "challenge"):
		mode = "allow"
	case !overridden && finalIP != "block" && (finalVh == "challenge" || finalIP == "challenge"):
		mode = "would"
	default:
		return
	}
	key := okProbeKey(ip, host, scope)
	solvedAt, ok := okProbeSolved.get(key, now)
	if mode == "would" && !ok {
		return
	}
	if !okProbeLogged.putIfAbsent(key, struct{}{}, now) {
		return
	}
	ago := "-"
	if ok {
		ago = now.Sub(time.Unix(0, solvedAt)).Round(time.Second).String()
	}
	okProbeLogf("[challenge] okstate mode=%s ip=%s host=%s scope=%s vh=%s ipa=%s solved_ago=%s ua=%q",
		mode, ip, host, scope, origVh, origIP, ago, boundStr(ua, solveMaxUA))
}

// resetOKProbeForTest empties both stores.
func resetOKProbeForTest() {
	okProbeSolved.deleteWhere(func(string) bool { return true })
	okProbeLogged.deleteWhere(func(string) bool { return true })
}
