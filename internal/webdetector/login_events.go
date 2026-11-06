package webdetector

import (
	"sync"
	"time"
)

// LoginFailEvent is one failed login the login ledger counted (the edge's
// login column, an origin answer read as "fail"; see authOutcome). It is
// published for the login_bruteforce detector, which turns it into an nft
// ban. Bypass clients (a crawler, a CDN prefix) never reach the ledger, so
// they are never published.
type LoginFailEvent struct {
	When time.Time
	IP   string // the client address, the ban key
	Host string // the vhost the login was posted to
	Site string // its registrable domain: one owner's www., staging. and bare names are one site
	Tag  string // the login kind (WP_LOGIN, ...)
	// Owner is true when the client had already succeeded on this site at
	// least as often as it failed there (the ledger's 24 h site record): a
	// site's own tool that logs in all day and sometimes fails. Its failures
	// there must not ban it.
	Owner bool
}

var (
	loginFailSubsMu sync.RWMutex
	loginFailSubID  int
	loginFailSubs   = map[int]func(LoginFailEvent){}
)

// SubscribeLoginFailEvents registers a callback for every failed login the
// ledger counts and returns its unsubscribe. The callback runs inline on the
// ingest path: it must be cheap and must not block.
func SubscribeLoginFailEvents(fn func(LoginFailEvent)) func() {
	if fn == nil {
		return func() {}
	}
	loginFailSubsMu.Lock()
	loginFailSubID++
	id := loginFailSubID
	loginFailSubs[id] = fn
	loginFailSubsMu.Unlock()
	return func() {
		loginFailSubsMu.Lock()
		delete(loginFailSubs, id)
		loginFailSubsMu.Unlock()
	}
}

func publishLoginFailEvent(ev LoginFailEvent) {
	loginFailSubsMu.RLock()
	if len(loginFailSubs) == 0 {
		loginFailSubsMu.RUnlock()
		return
	}
	subs := make([]func(LoginFailEvent), 0, len(loginFailSubs))
	for _, fn := range loginFailSubs {
		subs = append(subs, fn)
	}
	loginFailSubsMu.RUnlock()
	for _, fn := range subs {
		fn(ev)
	}
}
