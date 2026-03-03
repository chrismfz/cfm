// Package filewatch provides a lightweight file-change watcher based on
// mtime + SHA-256 content hash. It is intentionally dependency-free so it
// can be imported by any internal package (dyndns, main, …) without cycles.
package filewatch

import (
	"crypto/sha256"
	"io"
	"os"
	"time"
)

// Watcher watches a single file for content changes.
// Zero value is not usable; create one with New.
type Watcher struct {
	path string
	mod  time.Time
	sum  [32]byte
	have bool
}

// New returns a Watcher for the given path.
func New(path string) *Watcher { return &Watcher{path: path} }

// Path returns the watched file path.
func (w *Watcher) Path() string { return w.path }

// Changed returns (data, true) only when the file contents have changed since
// the last call. If the file is missing, it returns (nil, false) and resets
// internal state so that when the file reappears it is treated as new.
func (w *Watcher) Changed() ([]byte, bool) {
	st, err := os.Stat(w.path)
	if err != nil {
		w.have = false
		return nil, false
	}
	if w.have && st.ModTime().Equal(w.mod) {
		return nil, false
	}
	f, err := os.Open(w.path) // #nosec G304 – path comes from trusted config dir
	if err != nil {
		return nil, false
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, false
	}
	h := sha256.Sum256(b)
	if w.have && st.ModTime().Equal(w.mod) && h == w.sum {
		return nil, false
	}
	w.mod, w.sum, w.have = st.ModTime(), h, true
	return b, true
}
