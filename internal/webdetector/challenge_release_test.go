package webdetector

import (
	"testing"
)

// The post-solve release is bridge-only (the per-IP challenge DNAT is retired,
// edge-unification Phase 1b): releaseSolvedIP must never touch the firewall
// backend and must be safe with a nil bridge (early startup) and an empty IP.
func TestReleaseSolvedIP_BridgeOnlyAndNilSafe(t *testing.T) {
	// nil bridge: must not panic.
	s := &ChallengeServer{}
	s.releaseSolvedIP("203.0.113.9")

	// wired (disabled-config) bridge: ClearIP is a safe no-op; must not panic.
	s = &ChallengeServer{bridge: &NginxBridge{}}
	s.releaseSolvedIP("203.0.113.9")
	s.releaseSolvedIP("") // empty IP: skipped
}
