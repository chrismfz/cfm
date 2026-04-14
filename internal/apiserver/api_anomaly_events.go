package apiserver

import (
	"sync"
	"time"

	core "cfm/internal/detectors/core"
)

// APIAnomalyEvent is the normalized detector input produced by apiserver
// anomaly classification middleware.
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
	apiAnomalySubs   []func(APIAnomalyEvent)
)

func SubscribeAPIAnomalyEvents(fn func(APIAnomalyEvent)) {
	if fn == nil {
		return
	}
	apiAnomalySubsMu.Lock()
	apiAnomalySubs = append(apiAnomalySubs, fn)
	apiAnomalySubsMu.Unlock()
}

func publishAPIAnomalyEvent(ev APIAnomalyEvent) {
	apiAnomalySubsMu.RLock()
	subs := append([]func(APIAnomalyEvent){}, apiAnomalySubs...)
	apiAnomalySubsMu.RUnlock()
	for _, fn := range subs {
		fn(ev)
	}
}
