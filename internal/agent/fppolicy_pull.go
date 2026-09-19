package agent

// Runner-side drive for the fingerprint-policy pull. The agent Runner already
// ticks against cfm-web every ~20s (heartbeat / pending-unblocks / file-sync)
// with hot-updated credentials; the policy feed rides the same loop, gated to
// its own coarser interval. On success the full snapshot goes to the sink
// (replace-all — mirrors the feed's semantics); on failure the previous
// snapshot simply stays in force (stale-ok: policies are TTL'd server-side
// and expiry is re-checked at lookup time by the store).

import (
	"context"
	"sync"
	"time"

	"cfm/internal/logging"
)

// fpPolicyPullEvery is how often the Runner actually pulls the feed —
// deliberately coarser than the 20s agent tick. Arm/disarm latency is this
// plus the edge cache TTL (~30s).
const fpPolicyPullEvery = 60 * time.Second

type fpPolicyPullState struct {
	mu       sync.Mutex
	sink     func([]FingerprintPolicyRow)
	last     time.Time
	lastErrT time.Time
	lastN    int
	everOK   bool
}

// SetFingerprintPolicySink wires where pulled policies go (replace-not-append,
// like the detector sinks). A nil sink disables the pull entirely.
func (r *Runner) SetFingerprintPolicySink(fn func([]FingerprintPolicyRow)) {
	r.fpPull.mu.Lock()
	r.fpPull.sink = fn
	r.fpPull.mu.Unlock()
}

func (r *Runner) fetchFPPolicies(ctx context.Context) {
	r.fpPull.mu.Lock()
	sink := r.fpPull.sink
	due := time.Since(r.fpPull.last) >= fpPolicyPullEvery
	if sink != nil && due {
		r.fpPull.last = time.Now()
	}
	r.fpPull.mu.Unlock()
	if sink == nil || !due {
		return
	}

	cfg := r.cur()
	if cfg.BaseURL == "" || cfg.Token == "" {
		return
	}

	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	api := &APIClient{BaseURL: cfg.BaseURL, Token: cfg.Token, HTTP: r.client}
	rows, err := api.FetchFingerprintPolicies(cctx)
	if err != nil {
		// Throttled: a cfm-web outage must not write once per minute forever.
		r.fpPull.mu.Lock()
		quiet := time.Since(r.fpPull.lastErrT) < 10*time.Minute
		if !quiet {
			r.fpPull.lastErrT = time.Now()
		}
		r.fpPull.mu.Unlock()
		if !quiet {
			logging.LogfAPI("[fppolicy] pull failed (keeping last snapshot): %v", err)
		}
		return
	}

	r.fpPull.mu.Lock()
	changed := !r.fpPull.everOK || len(rows) != r.fpPull.lastN
	r.fpPull.everOK = true
	r.fpPull.lastN = len(rows)
	// Reset the error-log throttle on success so the FIRST failure of the
	// next outage is logged even if it starts within the throttle window.
	r.fpPull.lastErrT = time.Time{}
	r.fpPull.mu.Unlock()

	sink(rows)
	if changed {
		logging.LogfAPI("[fppolicy] pulled %d armed fingerprint policies", len(rows))
	}
}
