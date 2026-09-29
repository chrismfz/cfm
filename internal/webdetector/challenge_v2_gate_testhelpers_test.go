package webdetector

import "time"

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
	grain, _ := challengeV2ArmGrainVia(fpID, ip, host, "web")
	return grain
}

// Pin-store conveniences for tests (production goes through applyPin /
// setChallengeTierPinGet, which the handler uses).
func (s *tierPinStore) apply(host, rung string, ttl time.Duration, actor string,
	allowTarget func(string) bool, protect func(tierPin) bool) (target, prev string, changed bool, refusal string) {
	target, prev, changed, refusal, _ = s.applyPin(host, rung, ttl, actor, allowTarget, protect)
	return
}

func (s *tierPinStore) get(host string) (tierPin, bool) {
	if s == nil {
		return tierPin{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLocked(host, time.Now())
}

func (e *Engine) setChallengeTierPin(host, rung string, ttl time.Duration, actor string,
	allowTarget func(string) bool, protect func(tierPin) bool) (target, prev string, changed bool, refusal string) {
	target, prev, changed, refusal, _ = e.setChallengeTierPinGet(host, rung, ttl, actor, allowTarget, protect)
	return
}
