package procbaseline

import (
	"context"
	"errors"
	"sync"
)

// Lifecycle owns one process-baseline store and collector goroutine. Close is
// idempotent and orders shutdown deliberately: stop sampling, wait for the
// collector to exit, then close SQLite so an in-flight sample cannot race the
// database close.
type Lifecycle struct {
	cancel context.CancelFunc
	done   chan struct{}
	store  *Store

	closeOnce sync.Once
	closeErr  error
}

// Start opens the rolling process-baseline store and starts its collector under
// a child of parent. Opening the store is the only startup failure; callers can
// therefore treat this subsystem as best-effort without affecting daemon start.
func Start(parent context.Context, path string) (*Lifecycle, error) {
	if parent == nil {
		return nil, errors.New("procbaseline: parent context is nil")
	}
	store, err := Open(path)
	if err != nil {
		return nil, err
	}
	return startLifecycle(parent, store, NewCollector(store)), nil
}

func startLifecycle(parent context.Context, store *Store, collector *Collector) *Lifecycle {
	ctx, cancel := context.WithCancel(parent)
	lc := &Lifecycle{
		cancel: cancel,
		done:   make(chan struct{}),
		store:  store,
	}
	go func() {
		defer close(lc.done)
		collector.Run(ctx)
	}()
	return lc
}

// Close stops the collector before closing SQLite. It is safe to call more than
// once; concurrent callers all observe the same close result.
func (l *Lifecycle) Close() error {
	if l == nil {
		return nil
	}
	l.closeOnce.Do(func() {
		if l.cancel != nil {
			l.cancel()
		}
		if l.done != nil {
			<-l.done
		}
		if l.store != nil {
			l.closeErr = l.store.Close()
		}
	})
	return l.closeErr
}
