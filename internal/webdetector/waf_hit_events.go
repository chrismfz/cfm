package webdetector

import (
	"sync"
	"time"

	core "cfm/internal/detectors/core"
)

// WAFHitEvent is a normalized per-hit envelope for one in-path WAF rule match,
// published from Engine.RecordWAFTrigger (the single choke point every edge WAF
// trigger flows through). It carries enough to key a per-IP-per-family counter
// and to attribute a block back to the exact rule.
//
// Reason is the raw cfm_waf reason string, e.g. "WAF_SQLI:UNION_SELECT" — the
// family is its prefix before ':'. Signal is the numeric rule id as a string
// (e.g. "301"); it is "" when the edge could not supply one (older Lua clients
// send waf_rule_id=0). Action is the edge action (logonly/challenge/block) and
// is informational only — the persistent-block decision is family-threshold
// driven and independent of the per-request edge action (see
// docs/waf-autoblock-design.md, "Two orthogonal decisions").
type WAFHitEvent struct {
	When      time.Time
	Source    string // "waf"
	Reason    string // raw reason, family = prefix before ':'
	Signal    string // rule_id as string; "" if unknown
	Scope     string // vhost / host
	SrcIP     string // client IP — the counter / block key
	Method    string
	Path      string // request URI
	Action    string // verbatim edge action: logonly / challenge / challenge_v2 / block (informational)
	UserAgent string
}

// InputEvent converts to the generic detector envelope. Action is intentionally
// not mapped: core.InputEvent has no such field and the waf_security detector
// scores by family threshold regardless of edge action.
func (e WAFHitEvent) InputEvent() core.InputEvent {
	return core.InputEvent{
		When:      e.When,
		Source:    e.Source,
		Reason:    e.Reason,
		Signal:    e.Signal,
		Scope:     e.Scope,
		SrcIP:     e.SrcIP,
		Method:    e.Method,
		Path:      e.Path,
		UserAgent: e.UserAgent,
	}
}

var (
	wafHitSubsMu sync.RWMutex
	wafHitSubs   []func(WAFHitEvent)
)

// SubscribeWAFHitEvents registers a callback invoked for every WAF hit.
// Callbacks must be cheap and non-blocking (they run inline on the publish
// path); the waf_security detector's callback just enqueues into its buffer.
func SubscribeWAFHitEvents(fn func(WAFHitEvent)) {
	if fn == nil {
		return
	}
	wafHitSubsMu.Lock()
	wafHitSubs = append(wafHitSubs, fn)
	wafHitSubsMu.Unlock()
}

func publishWAFHitEvent(ev WAFHitEvent) {
	wafHitSubsMu.RLock()
	subs := append([]func(WAFHitEvent){}, wafHitSubs...)
	wafHitSubsMu.RUnlock()
	for _, fn := range subs {
		fn(ev)
	}
}
