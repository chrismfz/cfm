package webdetector

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

// A vhost-wide challenge never looks its visitors up one by one. IGNORE_IPS
// and the challenge-exclude file are applied per request in handleDecision;
// the per-IP walk the tick once did (isExcluded = an inline PTR per IP, then
// a BypassIPTemp that wrote nothing) ran the webdetector tick past its 30 s
// watchdog on qualityweb (~360 timeouts a day, 2026-11-25).
func TestEmitIPChallenges_VhostChallengeWalksNoIPs(t *testing.T) {
	e := newTickTestEngine(t)
	host := "shop.gr"
	var lookups atomic.Int64
	e.SetChalExcludeFunc(func(ip, h, ua, asn, ptr, rule string) (string, bool) {
		if h == host && ua == "" {
			switch rule {
			case "CHALLENGE_VHOST", "CHALLENGE_SUSPICIOUS_VHOST_SCORE", "CHALLENGE_VHOST_UNIQPATHS":
				lookups.Add(1)
			}
		}
		return "", false
	})
	now := time.Now()
	for i := 0; i < 50; i++ {
		e.ingest(LogRec{TS: float64(now.Unix()), IP: fmt.Sprintf("198.51.100.%d", i+1), Host: host, Method: "GET", URI: fmt.Sprintf("/p%d", i), Status: 200, UA: "Mozilla/5.0"}, "")
	}
	e.ManualChallengeVhost(host, time.Hour, "manual", "")
	e.vhostUnderAttack[host] = true

	e.emitIPChallenges(time.Now(), make(chan core.Alert, 256))

	if !bridgeHasVhost(e, host) {
		t.Fatal("precondition: the vhost challenge is on the bridge after the tick")
	}
	if n := lookups.Load(); n != 0 {
		t.Fatalf("the vhost-wide challenge walked its visitors: %d per-IP exclude lookups, want 0", n)
	}
}
