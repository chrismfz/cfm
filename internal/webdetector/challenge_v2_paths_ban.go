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
// Only an IP the malpath challenge marked counts (challengeV2PathMarks, web
// scope). Rejects under the other grains do not: the fleet's repeated rejects
// are the page's own retries (3-4 within seconds), and they include clients
// a site owner runs on purpose (the Plesk screenshot bot under a traffic-rule
// mark) and farms an operator's fingerprint / geo / vhost arm already holds
// at the challenge.
//
// [webdetector] CHALLENGE_V2_PATHS_REJECT_BAN = the rejects within
// v2PathsRejectWindow that ban (default 3: one visit's retries; 0 = off).

var v2PathsRejectBanN atomic.Int32

func init() { v2PathsRejectBanN.Store(3) }

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

const (
	v2PathsRejectWindow = 15 * time.Minute
	v2PathsRejectMax    = 4096 // tracked IPs; at the cap a new IP is not counted
)

type v2PathsRejectState struct {
	n     int
	first time.Time
}

var v2PathsRejects = struct {
	mu sync.Mutex
	m  map[string]v2PathsRejectState
}{m: make(map[string]v2PathsRejectState)}

// NoteChallengeV2PathsReject counts a Rung-1 reject. It answers (count, true)
// once, when a web-scope reject from an IP with a live malpath mark reaches
// CHALLENGE_V2_PATHS_REJECT_BAN within v2PathsRejectWindow; the count then
// starts over (a ban that did not hold — dry run, an allow list — is asked
// for again only after as many new rejects).
func NoteChallengeV2PathsReject(s ChallengeSolve, now time.Time) (int, bool) {
	limit := int(v2PathsRejectBanN.Load())
	if limit <= 0 || s.IP == "" || (s.Scope != "" && s.Scope != "web") {
		return 0, false
	}
	if _, ok := challengeV2PathMarks.get(s.IP, now); !ok {
		return 0, false
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
				return 0, false
			}
		}
		st.first = now
	}
	st.n++
	if st.n >= limit {
		delete(v2PathsRejects.m, s.IP)
		return st.n, true
	}
	v2PathsRejects.m[s.IP] = st
	return st.n, false
}

// forgetChallengeV2PathsRejects drops ip's count (an operator unblock).
func forgetChallengeV2PathsRejects(ip string) {
	v2PathsRejects.mu.Lock()
	delete(v2PathsRejects.m, ip)
	v2PathsRejects.mu.Unlock()
}
