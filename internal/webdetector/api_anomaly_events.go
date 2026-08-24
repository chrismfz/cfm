package webdetector

import (
	"sync"
	"time"

	core "cfm/internal/detectors/core"
)

// APIAnomalyEvent is a normalized anomaly envelope for API abuse detectors.
type APIAnomalyEvent struct {
	When      time.Time
	Source    string
	Reason    string
	Signal    string
	Scope     string
	Count     int
	SrcIP     string
	Method    string
	Path      string
	Status    int
	UserAgent string
}

func (e APIAnomalyEvent) InputEvent() core.InputEvent {
	return core.InputEvent{
		When:      e.When,
		Source:    e.Source,
		Reason:    e.Reason,
		Signal:    e.Signal,
		Scope:     e.Scope,
		Count:     e.Count,
		SrcIP:     e.SrcIP,
		Method:    e.Method,
		Path:      e.Path,
		Status:    e.Status,
		UserAgent: e.UserAgent,
	}
}

var (
	apiAnomalySubsMu sync.RWMutex
	apiAnomalySubs   = map[uint64]func(APIAnomalyEvent){}
	apiAnomalySubID  uint64
)

func SubscribeAPIAnomalyEvents(fn func(APIAnomalyEvent)) func() {
	if fn == nil {
		return func() {}
	}
	apiAnomalySubsMu.Lock()
	apiAnomalySubID++
	id := apiAnomalySubID
	apiAnomalySubs[id] = fn
	apiAnomalySubsMu.Unlock()
	return func() {
		apiAnomalySubsMu.Lock()
		delete(apiAnomalySubs, id)
		apiAnomalySubsMu.Unlock()
	}
}

func publishAPIAnomalyEvent(ev APIAnomalyEvent) {
	apiAnomalySubsMu.RLock()
	subs := make([]func(APIAnomalyEvent), 0, len(apiAnomalySubs))
	for _, fn := range apiAnomalySubs {
		subs = append(subs, fn)
	}
	apiAnomalySubsMu.RUnlock()
	for _, fn := range subs {
		fn(ev)
	}
}
