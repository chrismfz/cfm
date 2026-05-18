package lsm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultBuildVersionMarker is the on-disk path where the daemon
// stamps the cfm build version that pinned the LSM BPF programs
// currently under DefaultPinDir. Lives outside bpffs (which is RAM-
// only) so a daemon restart can compare its own build against the
// build that last pinned the kernel state — when those differ
// (package upgrade since the pins were created), the adopt path
// tears the old pins down and re-enables with the new BPF.
//
// /var/lib/cfm is the established state dir (mmdb, notify.log.jsonl,
// webdetector stores) — adding one more file here is consistent with
// the rest of the daemon.
const DefaultBuildVersionMarker = "/var/lib/cfm/lsm-build-version"

// BuildMarker captures the cfm build that owns the currently-pinned
// LSM state. Single-line serialisation — opaque to operators, only
// compared for equality during the adopt path.
type BuildMarker struct {
	Version   string // ldflags-injected cfm version (e.g. "2026.05.18-1.180744.el10")
	BuildTime string // ldflags-injected build timestamp; tie-break when Version is "dev"
}

// String returns the canonical on-disk form: "<Version>\t<BuildTime>".
// Tab separator survives a `cat` and makes the file human-readable
// without parsing fragility.
func (m BuildMarker) String() string {
	return m.Version + "\t" + m.BuildTime
}

// Equal compares two markers field-by-field. Used by the adopt path:
// running-binary marker vs pinned-build marker. Any difference → refresh.
func (m BuildMarker) Equal(other BuildMarker) bool {
	return m.Version == other.Version && m.BuildTime == other.BuildTime
}

// WriteBuildMarker stamps the marker file at path atomically. Used at
// the end of every successful Enable (CLI or daemon auto-enable) so
// subsequent daemon starts can detect a stale pin.
//
// Best-effort: a write failure does NOT fail the enable — the worst
// case is that the next daemon start treats the marker as absent and
// refreshes once (idempotent). The error is returned so the caller
// can log it.
func WriteBuildMarker(path string, m BuildMarker) error {
	if path == "" {
		return fmt.Errorf("WriteBuildMarker: empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".lsm-build-version.*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op if Rename succeeded
	if _, err := tmp.WriteString(m.String() + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("write marker: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close marker: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod marker: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}

// ReadBuildMarker returns the marker stamped at path. The bool is
// `present`: true if the file exists and parsed cleanly, false on
// any read / parse error (treated by callers as "no marker, refresh
// needed"). The caller logs the underlying error if non-nil so the
// distinction between "file genuinely absent" and "file unreadable"
// is operator-visible.
func ReadBuildMarker(path string) (BuildMarker, bool, error) {
	if path == "" {
		return BuildMarker{}, false, fmt.Errorf("ReadBuildMarker: empty path")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return BuildMarker{}, false, nil
		}
		return BuildMarker{}, false, err
	}
	line := strings.TrimRight(string(b), "\n")
	parts := strings.SplitN(line, "\t", 2)
	m := BuildMarker{Version: parts[0]}
	if len(parts) == 2 {
		m.BuildTime = parts[1]
	}
	if m.Version == "" {
		return BuildMarker{}, false, fmt.Errorf("malformed marker %q", line)
	}
	return m, true, nil
}
