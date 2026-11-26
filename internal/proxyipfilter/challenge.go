package proxyipfilter

import (
	"net/netip"
	"strings"
	"sync/atomic"
)

// CHALLENGE feeds (cfm.blocklists `NAME|CHALLENGE|…`): lists whose members
// include people, where a block is too much (Tor exits). Never written to
// nft; the nginx bridge's decision asks DecideChallenge for EVERY web
// request, direct or behind a trusted proxy (the client is the visitor's
// address there either way), and in enforce mode raises an uncleared listed
// client to a challenge floor, like the geo policy's: a client that solves
// gets its clearance and is not asked again, a real per-IP entry overrides
// it, and the bridge's exemptions (verified good bots, Challenge Access,
// machine-to-machine endpoints) still lift it. Every allow source (the fleet
// whitelist, the node's allow sets) cancels it, as it cancels a block.
//
// [webdetector] LIST_CHALLENGE = log (default: a line per client and outcome
// every 10 minutes, nothing changes) | enforce | off.

// DefaultModeChallenge is LIST_CHALLENGE's default: log, for a burn-in.
const DefaultModeChallenge = ModeLog

var (
	modeChallenge atomic.Value // string

	nChalChecks, nChalWould, nChalEnforced, nChalAllowed atomic.Int64
)

// SetChallengeMode sets LIST_CHALLENGE (empty: the default, unknown: log).
func SetChallengeMode(m string) {
	modeChallenge.Store(normMode("LIST_CHALLENGE", m, DefaultModeChallenge))
}

// ChallengeMode is LIST_CHALLENGE's current value.
func ChallengeMode() string { return modeChallenge.Load().(string) }

// PrepareChallengeFeed builds one CHALLENGE feed's table (see PrepareFeed).
func PrepareChallengeFeed(name string, v4, v6 []string) PreparedFeed {
	return PreparedFeed{name: name, s: &source{label: "feed:" + name, challenge: true, t: buildTable(v4, v6)}}
}

// ChallengeVerdict is the CHALLENGE lists' answer for one address.
type ChallengeVerdict struct {
	Lists   []string // the CHALLENGE feeds it is on
	Allows  []string // the allow sources it is on, when it is on a list
	Enforce bool     // listed, enforce mode, and no allow
}

// CheckChallenge returns the verdict for ip, without logging or counting.
func CheckChallenge(ip string) ChallengeVerdict {
	var v ChallengeVerdict
	m := ChallengeMode()
	if m == ModeOff {
		return v
	}
	snap := cur.Load()
	if len(snap.challenges) == 0 {
		return v
	}
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return v
	}
	a = a.Unmap()
	for _, s := range snap.challenges {
		if s.t.contains(a) {
			v.Lists = append(v.Lists, s.label)
		}
	}
	if len(v.Lists) == 0 {
		return v
	}
	for _, s := range snap.allows {
		if s.t.contains(a) {
			v.Allows = append(v.Allows, s.label)
		}
	}
	v.Enforce = m == ModeEnforce && len(v.Allows) == 0
	return v
}

// DecideChallenge is the bridge's question for a web request: should it raise
// the client to a challenge (enforce), and is the client listed with no allow
// cancelling it (listed: the bridge then keeps the edge from caching its
// allow, so in log mode every request is decided and counted)? It logs what
// it found, once per client and outcome per logEvery.
func DecideChallenge(ip, host string) (enforce, listed bool) {
	v := CheckChallenge(ip)
	if len(v.Lists) == 0 {
		return false, false
	}
	nChalChecks.Add(1)
	var what string
	switch {
	case len(v.Allows) > 0:
		nChalAllowed.Add(1)
		what = "allowed"
	case v.Enforce:
		nChalEnforced.Add(1)
		what = "challenge"
	default:
		nChalWould.Add(1)
		what = "would_challenge"
	}
	if n, ok := logDue("chal|" + ip + "|" + what); ok {
		allow := "-"
		if len(v.Allows) > 0 {
			allow = strings.Join(v.Allows, ",")
		}
		logf("[list_challenge] %s ip=%s host=%s list=%s allow=%s mode=%s n=%d %s",
			what, ip, orDash(host), strings.Join(v.Lists, ","), allow, ChallengeMode(), n, geoFields(ip))
	}
	return v.Enforce, len(v.Allows) == 0
}
