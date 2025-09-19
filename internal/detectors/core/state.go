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
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	return &State{dir: path}, nil
}

// per-detector file path
func (s *State) file(name string) string {
	return filepath.Join(s.dir, sanitize(name)+".json")
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

	_ = os.MkdirAll(s.dir, 0o755)
	if b, err := json.MarshalIndent(p, "", "  "); err == nil {
		_ = os.WriteFile(tmp, b, 0o644)
		_ = os.Rename(tmp, fn)
	}
}

// Save is a no-op in dir mode (kept for API compatibility).
func (s *State) Save() error {
	return nil
}
