package core

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const DefaultStateDir = "/var/lib/cfm/detectors.state.d"

type Position struct {
	Offset uint64 `json:"offset"`
	Inode  uint64 `json:"inode"`
	TS     int64  `json:"ts"`
}

type State struct {
	dir string // always a directory path
}

// sanitize detector name -> safe filename
var safeFileRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitize(name string) string {
	if name == "" {
		return "_"
	}
	return safeFileRe.ReplaceAllString(name, "_")
}

// DefaultState returns the dir-mode State for DefaultStateDir WITHOUT touching
// the filesystem. The detectors' shared states are package-level vars, built at
// package init, and building them with LoadState ran its MkdirAll in every
// binary importing the package — test binaries included, so the suite created
// the live /var/lib/cfm/detectors.state.d on any machine it ran on as root.
// Nothing needs the directory before the first position is saved: Put creates
// it (0700, as LoadState would), and Get on a missing directory is a miss.
func DefaultState() *State {
	return &State{dir: DefaultStateDir}
}

// LoadState ensures the directory exists and returns a dir-mode State.
// If path == "", it uses DefaultStateDir.
func LoadState(path string) (*State, error) {
	if path == "" {
		path = DefaultStateDir
	}
	// If someone accidentally passed a file path, reject it clearly.
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		return nil, errors.New("state path is not a directory: " + path)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	return &State{dir: path}, nil
}

// per-detector file path
func (s *State) file(name string) string {
	return filepath.Join(s.dir, sanitize(name)+".json")
}

// FileStateKey builds a stable, unique key for a detector+file path pair.
// Use it to store per-source positions without collisions.
func FileStateKey(detectorName, path string) string {
	if detectorName == "" {
		detectorName = "_"
	}
	abs := path
	if p, err := filepath.Abs(path); err == nil {
		abs = p
	}
	joined := detectorName + "__" + abs
	return sanitize(joined)
}

// Get reads a single detector's position from its file.
func (s *State) Get(name string) (Position, bool) {
	fn := s.file(name)
	b, err := os.ReadFile(fn)
	if err != nil {
		return Position{}, false
	}
	var p Position
	if err := json.Unmarshal(b, &p); err != nil {
		return Position{}, false
	}
	return p, true
}

// Put writes a single detector's position atomically.
func (s *State) Put(name string, p Position) {
	if p.TS == 0 {
		p.TS = time.Now().Unix()
	}
	fn := s.file(name)
	tmp := fn + ".tmp"

	_ = os.MkdirAll(s.dir, 0o700)
	if b, err := json.MarshalIndent(p, "", "  "); err == nil {
		_ = os.WriteFile(tmp, b, 0o600)
		_ = os.Rename(tmp, fn)
		_ = os.Chmod(fn, 0o600)
	}
}

// Save is a no-op in dir mode (kept for API compatibility).
func (s *State) Save() error {
	return nil
}
