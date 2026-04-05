package sslcollector

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"

	"github.com/fsnotify/fsnotify"

	"io/fs"
	"os"
)

type Watcher struct {
	col *Collector

	mu        sync.Mutex
	timer     *time.Timer
	delay     time.Duration
	running   bool
	lastExact int
	lastWild  int
	haveLast  bool

	fs *fsnotify.Watcher
}

func NewWatcher(col *Collector, delay time.Duration) (*Watcher, error) {
	if delay <= 0 {
		delay = 2 * time.Second
	}

	fs, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Watcher{
		col:   col,
		delay: delay,
		fs:    fs,
	}, nil
}

func (w *Watcher) Start(ctx context.Context, roots []string) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	// add all roots recursively
	for _, root := range roots {
		_ = w.addRecursive(root)
	}

	go w.loop(ctx)
	logging.Logf("[sslcollector] watcher started roots=%v", roots)
	return nil
}

func (w *Watcher) loop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			_ = w.fs.Close()
			return

		case ev, ok := <-w.fs.Events:
			if !ok {
				return
			}

			// only care about meaningful events
			if !w.isRelevant(ev) {
				continue
			}

			// if new dir created → watch it too
			if ev.Op&fsnotify.Create != 0 {
				fi, err := os.Stat(ev.Name)
				if err == nil && fi.IsDir() {
					_ = w.addRecursive(ev.Name)
				}
			}

			w.trigger("fsnotify:" + ev.Name)

		case err := <-w.fs.Errors:
			logging.Logf("[sslcollector] watcher error: %v", err)
		}
	}
}

func (w *Watcher) trigger(reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.timer != nil {
		w.timer.Stop()
	}

	w.timer = time.AfterFunc(w.delay, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		err := w.col.Refresh(ctx)
		if err != nil {
			logging.Logf("[sslcollector] watcher refresh failed reason=%s err=%v", reason, err)
			return
		}

		st := w.col.Stats()
		w.mu.Lock()
		changed := !w.haveLast || st.ExactHosts != w.lastExact || st.WildcardZones != w.lastWild
		w.lastExact = st.ExactHosts
		w.lastWild = st.WildcardZones
		w.haveLast = true
		w.mu.Unlock()

		if changed {
			logging.Logf("[sslcollector] watcher refresh changed reason=%s exact=%d wild=%d files=%d",
				reason, st.ExactHosts, st.WildcardZones, st.KnownFiles)
		}
	})
}

func (w *Watcher) isRelevant(ev fsnotify.Event) bool {
	if ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) == 0 {
		return false
	}

	name := strings.ToLower(ev.Name)

	// filter obvious noise but keep generic
	if strings.HasSuffix(name, ".tmp") ||
		strings.HasSuffix(name, ".swp") ||
		strings.HasSuffix(name, ".bak") {
		return false
	}

	// positive matches
	if strings.Contains(name, ".cert") ||
		strings.Contains(name, "cert") ||
		strings.Contains(name, ".crt") ||
		strings.Contains(name, ".cer") ||
		strings.Contains(name, ".key") ||
		strings.Contains(name, "key") ||
		strings.Contains(name, "pem") ||
		strings.Contains(name, "privkey") ||
		strings.Contains(name, "fullchain") {
		return true
	}

	// Ignore unrelated file churn (locks, caches, journals, wp-content noise, etc).
	return false
}

func (w *Watcher) addRecursive(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = w.fs.Add(path)
		}
		return nil
	})
}
