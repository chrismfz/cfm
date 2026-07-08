package webdetector

import (
	"testing"
	"time"
)

// TestRecordIPChallengeIsNew locks the dedup semantics behind the
// [challenge_issued] observability line: it must fire once when an IP enters an
// active challenge, stay quiet while that same challenge is refreshed every
// detector cycle, and fire again on a genuinely new reason (different rule) or
// after the previous challenge expired.
func TestRecordIPChallengeIsNew(t *testing.T) {
	s := NewChallengeAPIStore(1024)

	if !s.RecordIPChallenge("1.2.3.4", "h", "CHALLENGE_SUBNET", "", "", 0, 30*time.Minute) {
		t.Fatal("first issuance should be new")
	}
	// Same (ip,rule) refresh while still active → NOT new (no re-log).
	if s.RecordIPChallenge("1.2.3.4", "h", "CHALLENGE_SUBNET", "", "", 0, 30*time.Minute) {
		t.Fatal("refresh of a live challenge should not be new")
	}
	// Different rule for the same IP → new (genuinely different reason).
	if !s.RecordIPChallenge("1.2.3.4", "h", "CHALLENGE_PATHS", "", "", 0, 30*time.Minute) {
		t.Fatal("different rule should be new")
	}
	// Different IP → new.
	if !s.RecordIPChallenge("5.6.7.8", "h", "CHALLENGE_SUBNET", "", "", 0, 30*time.Minute) {
		t.Fatal("new ip should be new")
	}

	// Expired prior challenge → new again (same-package access to force expiry).
	st := s.ips["5.6.7.8"]
	st.State = "challenge"
	st.Rule = "CHALLENGE_SUBNET"
	st.ExpiresAt = time.Now().Add(-time.Second)
	if !s.RecordIPChallenge("5.6.7.8", "h", "CHALLENGE_SUBNET", "", "", 0, 30*time.Minute) {
		t.Fatal("expired challenge should be new again")
	}
}
