package webdetector

import (
	"sync"
	"sync/atomic"
	"time"
)

// ── Repeated v2 rejects from a malpath-marked IP → a ban ────────────────────
//
// A malpath challenge (CHALLENGE_PATHS) runs at the v2 tier, and a failing
// Rung-1 solve earns no clearance. But the challenge only lives
// CHALLENGE_PATHS_TTL (10m shipped): a rejected scanner that waits it out is
// not challenged again while the section sink's CHALLENGE_COOLDOWN holds
// (45m), and walks back in. A client that asked for /.env-class paths AND
// fails the humanity check is the clearest scanner the rung sees, so its
// rejects escalate to a ban through the webdetector sink (the section's
// BLOCK policy, the edge ban, the notification, DRY_RUN).
//
// Only a web-scope reject from an IP the malpath challenge marked counts
// (challengeV2PathMarks), whatever arm the verify resolved. An IP without
// that mark never does: the fleet's repeated rejects include clients a site
// owner runs on purpose (the Plesk screenshot bot under a traffic-rule mark)
// and farms an operator's fingerprint / geo / vhost arm already holds at the
// challenge.
//
// It counts VISITS, not rejects: the page retries a rejected solve on its
// own (3-4 within ~20 s on the fleet), and a score does not change between
// retries, so counting rejects banned on the first failed visit — a real
// person behind a NAT a scanner had marked, failing the rung once, among
// them. A reject within v2PathsRejectVisitGap of the IP's previous one is
// the same visit. Counting visits alone would close nothing, though: after
// the challenge runs out the sink's cooldown serves no new one, so there is
// no second visit to count. So a failed visit that does not ban HOLDS the
// malpath challenge (with its mark and its clearance revocation) for
// ChallengeV2PathsRejectHold, re-imposed through the bridge (the reject hook
// in the detectors layer): waiting it out takes an hour, and coming back
// sooner to fail again is the second visit that bans. A person on that
// address still gets through by solving it.
//
// [webdetector] CHALLENGE_V2_PATHS_REJECT_BAN = the failed visits within
// v2PathsRejectWindow that ban (default 2; 0 = off, and no hold either).

var v2PathsRejectBanN atomic.Int32

func init() { v2PathsRejectBanN.Store(2) }

// ConfigureChallengeV2PathsRejectBan applies [webdetector]
// CHALLENGE_V2_PATHS_REJECT_BAN (every reload); n <= 0 turns it off.
func ConfigureChallengeV2PathsRejectBan(n int) {
	if n < 0 {
		n = 0
	}
	if n > 1000 {
		n = 1000
	}
	v2PathsRejectBanN.Store(int32(n))
}

// ChallengeV2PathsRejectHold is how long a failed visit that did not ban
// holds the malpath challenge (= v2PathsRejectWindow: the challenge lives as
// long as the next failed visit can still ban).
const ChallengeV2PathsRejectHold = v2PathsRejectWindow

const (
	v2PathsRejectWindow   = time.Hour        // first visit to the banning one
	v2PathsRejectVisitGap = 60 * time.Second // rejects closer than this: one visit
	v2PathsRejectMax      = 4096             // tracked IPs; at the cap a new IP is not counted
)

type v2PathsRejectState struct {
	n     int // visits
	first time.Time
	last  time.Time // the last reject (any, counted or not)
}

var v2PathsRejects = struct {
	mu sync.Mutex
	m  map[string]v2PathsRejectState
}{m: make(map[string]v2PathsRejectState)}

// V2PathsReject is NoteChallengeV2PathsReject's answer.
type V2PathsReject struct {
	Visits   int  // failed visits counted in the window
	NewVisit bool // this reject started a visit (not a retry of the last)
	Ban      bool // this visit reached CHALLENGE_V2_PATHS_REJECT_BAN
}

// Hold reports whether the caller should hold the malpath challenge
// (ChallengeV2PathsRejectHold): a new failed visit that did not ban.
func (r V2PathsReject) Hold() bool { return r.NewVisit && !r.Ban }

// NoteChallengeV2PathsReject counts a Rung-1 reject from a web-scope verify
// of an IP with a live malpath mark. Ban is set once, when the reject starts
// the CHALLENGE_V2_PATHS_REJECT_BAN-th failed visit within
// v2PathsRejectWindow; the count then starts over (a ban that did not hold —
// dry run, an allow list — is asked for again only after as many new
// visits).
func NoteChallengeV2PathsReject(s ChallengeSolve, now time.Time) V2PathsReject {
	limit := int(v2PathsRejectBanN.Load())
	if limit <= 0 || s.IP == "" || (s.Scope != "" && s.Scope != "web") {
		return V2PathsReject{}
	}
	if _, ok := challengeV2PathMarks.get(s.IP, now); !ok {
		return V2PathsReject{}
	}
	v2PathsRejects.mu.Lock()
	defer v2PathsRejects.mu.Unlock()
	st, had := v2PathsRejects.m[s.IP]
	if had && now.Sub(st.first) > v2PathsRejectWindow {
		st, had = v2PathsRejectState{}, false
	}
	if !had {
		if len(v2PathsRejects.m) >= v2PathsRejectMax {
			for k, v := range v2PathsRejects.m {
				if now.Sub(v.first) > v2PathsRejectWindow {
					delete(v2PathsRejects.m, k)
				}
			}
			if len(v2PathsRejects.m) >= v2PathsRejectMax {
				return V2PathsReject{}
			}
		}
		st.first = now
	} else if now.Sub(st.last) < v2PathsRejectVisitGap {
		// The page's retry of the same visit.
		st.last = now
		v2PathsRejects.m[s.IP] = st
		return V2PathsReject{Visits: st.n}
	}
	st.n++
	st.last = now
	if st.n >= limit {
		delete(v2PathsRejects.m, s.IP)
		return V2PathsReject{Visits: st.n, NewVisit: true, Ban: true}
	}
	v2PathsRejects.m[s.IP] = st
	return V2PathsReject{Visits: st.n, NewVisit: true}
}

// forgetChallengeV2PathsRejects drops ip's count (an operator unblock).
func forgetChallengeV2PathsRejects(ip string) {
	v2PathsRejects.mu.Lock()
	delete(v2PathsRejects.m, ip)
	v2PathsRejects.mu.Unlock()
}
