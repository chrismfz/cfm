package webdetector

import (
	"sync"
	"time"
)

// LoginEvent is one login the login ledger counted (the edge's login
// column, an origin answer read as "fail" or "ok"; see authOutcome). It is
// published for the login_bruteforce detector, which bans on the failures
// and lets a success take back the failure just before it on that site (a
// 2FA plugin that sends no cookie on the password step: Two Factor 0.8+).
// Bypass clients (a crawler, a CDN prefix) never reach the ledger, so they
// are never published.
type LoginEvent struct {
	When time.Time
	IP   string // the client address, the ban key
	Host string // the vhost the login was posted to
	Site string // its registrable domain: one owner's www., staging. and bare names are one site
	Tag  string // the login kind (WP_LOGIN, ...)
	OK   bool   // a success; otherwise a failure
	// Owner (failures only) is true when the client had already succeeded on this site at
	// least as often as it failed there (the ledger's 24 h site record): a
	// site's own tool that logs in all day and sometimes fails. Its failures
	// there must not ban it.
	Owner bool
}

var (
	loginSubsMu sync.RWMutex
	loginSubID  int
	loginSubs   = map[int]func(LoginEvent){}
)

// SubscribeLoginEvents registers a callback for every login the ledger
// counts (failures and successes) and returns its unsubscribe. The callback runs inline on the
// ingest path: it must be cheap and must not block.
func SubscribeLoginEvents(fn func(LoginEvent)) func() {
	if fn == nil {
		return func() {}
	}
	loginSubsMu.Lock()
	loginSubID++
	id := loginSubID
	loginSubs[id] = fn
	loginSubsMu.Unlock()
	return func() {
		loginSubsMu.Lock()
		delete(loginSubs, id)
		loginSubsMu.Unlock()
	}
}

func publishLoginEvent(ev LoginEvent) {
	loginSubsMu.RLock()
	if len(loginSubs) == 0 {
		loginSubsMu.RUnlock()
		return
	}
	subs := make([]func(LoginEvent), 0, len(loginSubs))
	for _, fn := range loginSubs {
		subs = append(subs, fn)
	}
	loginSubsMu.RUnlock()
	for _, fn := range subs {
		fn(ev)
	}
}
