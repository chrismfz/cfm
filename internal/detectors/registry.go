package detectors

import (
	"sync"

	core "cfm/internal/detectors/core"
)

type Factory func(sectionName string, kv KV, global KV) (core.PeriodicDetector, error)

var (
	regMu    sync.RWMutex
	registry = map[string]Factory{}
)

func Register(typ string, f Factory) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[typ] = f
}

func getFactory(typ string) (Factory, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	f, ok := registry[typ]
	return f, ok
}
