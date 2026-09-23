//go:build linux

package nftlib

import (
	"sort"
	"time"

	"cfm/internal/firewall"
)

// ensureBaseRingCap bounds the retained EnsureBase timing history. EnsureBase
// runs on the daemon tick (~every 20s via LoadPortScanner), so 30 samples is
// ~10 minutes of trend — enough to see a climb without unbounded memory.
const ensureBaseRingCap = 30

// ebSample is one recorded EnsureBase call, split by where the time went.
type ebSample struct {
	at       time.Time
	lockWait time.Duration // time to acquire b.mu (contention)
	nlWork   time.Duration // netlink add+flush under b.mu (kernel round-trip)
	cliWork  time.Duration // applyBaseInputRules (nft CLI: one chain read, at most one write)
	err      error
}

// fwSample is the latest recorded write of one feed/union set (or self set).
type fwSample struct {
	at    time.Time
	elems int
	dur   time.Duration
	err   error
}

// recordEnsureBase appends one EnsureBase timing to the fixed ring. O(1),
// bounded, guarded by statMu (never b.mu).
func (b *Backend) recordEnsureBase(lockWait, nlWork, cliWork time.Duration, err error) {
	b.statMu.Lock()
	b.ebBuf[b.ebN%ensureBaseRingCap] = ebSample{
		at: time.Now(), lockWait: lockWait, nlWork: nlWork, cliWork: cliWork, err: err,
	}
	b.ebN++
	b.statMu.Unlock()
}

// recordFeedWrite records the latest write outcome for one set (latest-wins).
func (b *Backend) recordFeedWrite(set string, elems int, dur time.Duration, err error) {
	b.statMu.Lock()
	if b.feedWrites == nil {
		b.feedWrites = make(map[string]fwSample)
	}
	b.feedWrites[set] = fwSample{at: time.Now(), elems: elems, dur: dur, err: err}
	b.statMu.Unlock()
}

// NftlibSelfTest returns a read-only diagnostics snapshot. Satisfies
// firewall.SelfTester.
func (b *Backend) NftlibSelfTest() firewall.NftlibSelfTest {
	b.statMu.Lock()
	defer b.statMu.Unlock()

	out := firewall.NftlibSelfTest{Engine: "nftlib", Samples: b.ebN}

	n := b.ebN
	if n > ensureBaseRingCap {
		n = ensureBaseRingCap
	}
	// Walk the retained window in chronological order. The oldest retained call
	// is at index (ebN-n); the ring slot is (i % cap).
	var worst *firewall.EnsureBaseSample
	var worstTotal time.Duration
	for i := b.ebN - n; i < b.ebN; i++ {
		s := b.ebBuf[i%ensureBaseRingCap]
		es := firewall.EnsureBaseSample{
			At:         s.at.Format(time.RFC3339),
			LockWaitMs: s.lockWait.Milliseconds(),
			NLWorkMs:   s.nlWork.Milliseconds(),
			CLIWorkMs:  s.cliWork.Milliseconds(),
		}
		if s.err != nil {
			es.Err = s.err.Error()
		}
		out.EnsureBaseRecent = append(out.EnsureBaseRecent, es)
		if total := s.lockWait + s.nlWork + s.cliWork; worst == nil || total > worstTotal {
			worstTotal = total
			cp := es
			worst = &cp
		}
	}
	out.EnsureBaseWorst = worst

	for set, f := range b.feedWrites {
		fs := firewall.FeedWriteSample{
			Set: set, At: f.at.Format(time.RFC3339), Elems: f.elems, DurMs: f.dur.Milliseconds(),
		}
		if f.err != nil {
			fs.Err = f.err.Error()
		}
		out.FeedWrites = append(out.FeedWrites, fs)
	}
	// Deterministic order (map iteration is random): errored sets first (the
	// interesting ones), then by set name.
	sort.Slice(out.FeedWrites, func(i, j int) bool {
		ei, ej := out.FeedWrites[i].Err != "", out.FeedWrites[j].Err != ""
		if ei != ej {
			return ei
		}
		return out.FeedWrites[i].Set < out.FeedWrites[j].Set
	})

	out.Netlink = b.nl.snapshot()
	return out
}

// snapshot returns the netlink stats for firewall_selftest.
func (s *nlStats) snapshot() *firewall.NetlinkStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &firewall.NetlinkStats{
		OpTimeoutMs:         nlOpTimeout.Milliseconds(),
		Ops:                 s.ops,
		Errors:              s.errs,
		Timeouts:            s.timeouts,
		Dials:               s.dials,
		DeadlineUnsupported: s.deadlineErr,
		SlowRecent:          []firewall.NetlinkOpSample{},
	}
	if s.lastTimeout != nil {
		lt := s.lastTimeout.public()
		out.LastTimeout = &lt
	}
	n := s.slowN
	if n > nlSlowRingCap {
		n = nlSlowRingCap
	}
	for i := s.slowN - n; i < s.slowN; i++ {
		out.SlowRecent = append(out.SlowRecent, s.slow[i%nlSlowRingCap].public())
	}
	return out
}

func (x nlSample) public() firewall.NetlinkOpSample {
	return firewall.NetlinkOpSample{
		At: x.at.Format(time.RFC3339), Op: x.op, DurMs: x.dur.Milliseconds(), Err: x.err,
	}
}
