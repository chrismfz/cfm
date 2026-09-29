package webdetector

// Test-only conveniences over the ONE verify-gate hook and grain resolver
// (challengeV2HostArmedVia / challengeV2ArmGrainVia / SetChallengeV2HostTier).
// Production uses those directly; these keep the older tests' bool-form
// predicates without a second production entry point.

// SetChallengeV2HostArmed wires a bare "is this host v2" predicate (no
// v2_via) through SetChallengeV2HostTier; nil unwires.
func SetChallengeV2HostArmed(fn func(host string) bool) {
	if fn == nil {
		SetChallengeV2HostTier(nil)
		return
	}
	SetChallengeV2HostTier(func(host string) (bool, string) { return fn(host), "" })
}

func challengeV2HostArmed(host string) bool {
	armed, _ := challengeV2HostArmedVia(host)
	return armed
}

func challengeV2ArmGrain(fpID, ip, host string) string {
	grain, _ := challengeV2ArmGrainVia(fpID, ip, host)
	return grain
}
