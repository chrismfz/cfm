package webdetector

import (
	"net"
	"sync"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// releaseFakeFW is a minimal firewall.Backend for the release test. It embeds the
// interface (nil) so it satisfies the type; releaseSolvedIP only ever calls
// RemoveChallenge, and the challengeOKer assertion fails (no AddChallengeOK), so
// no other method is reached. RemoveChallenge can be made to block, standing in
// for a wedged nftlib backend hanging on its shared mutex.
type releaseFakeFW struct {
	firewall.Backend
	mu       sync.Mutex
	removed  int
	blockFor time.Duration
}

func (f *releaseFakeFW) RemoveChallenge(ip net.IP) error {
	if f.blockFor > 0 {
		time.Sleep(f.blockFor)
	}
	f.mu.Lock()
	f.removed++
	f.mu.Unlock()
	return nil
}

func (f *releaseFakeFW) removeCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.removed
}

// In edge/OpenResty mode (bridge wired) releaseSolvedIP must NOT call the
// firewall backend — even one that blocks forever must not stall the caller,
// because that stall is exactly what left the clearance cookie unset and looped
// the browser.
func TestReleaseSolvedIP_EdgeModeSkipsFirewall(t *testing.T) {
	fw := &releaseFakeFW{blockFor: 10 * time.Second} // would hang the verify path if called
	s := &ChallengeServer{fw: fw, bridge: &NginxBridge{}}

	done := make(chan struct{})
	go func() {
		s.releaseSolvedIP(net.ParseIP("203.0.113.9"), "203.0.113.9", "webmail.example.com")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("releaseSolvedIP blocked in edge mode; it must not call the firewall backend")
	}
	if n := fw.removeCalls(); n != 0 {
		t.Fatalf("edge mode must not call RemoveChallenge, got %d call(s)", n)
	}
}

// In DNAT mode (no bridge) releaseSolvedIP does drop the IP from the nft set.
func TestReleaseSolvedIP_DNATModeCallsFirewall(t *testing.T) {
	fw := &releaseFakeFW{}
	s := &ChallengeServer{fw: fw} // bridge nil ⇒ DNAT mode

	s.releaseSolvedIP(net.ParseIP("203.0.113.9"), "203.0.113.9", "h")

	if n := fw.removeCalls(); n != 1 {
		t.Fatalf("DNAT mode must call RemoveChallenge once, got %d", n)
	}
}
