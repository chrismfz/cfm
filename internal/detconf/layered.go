package detconf

// layered.go — the detectors.conf OVERLAY reader
// (docs/detectors-config-unification.md §4, Mechanism B).
//
// ReadLayered parses the base file, then merges every "<dropinDir>/*.conf"
// over it in lexicographic filename order (10-… before 20-…). Merge
// semantics:
//
//   - same section + key      → the later layer's value REPLACES the earlier
//   - "KEY += value"          → the later layer's value APPENDS to the earlier
//     (list scalars join with ", ", multiline blocks with a newline) — for
//     extending common lists (IGNORE_NETS, CHALLENGE_VHOST_IGNORE, ALLOW_*)
//     without forking them
//   - section only in overlay → added whole (named instances, host extras)
//   - StampNS                 → max mtime across ALL read files
//   - LayerSig                → hash of the overlay set (name+mtime+size per
//     file), so hot-reload signatures also change when an overlay is added,
//     removed, or renamed — cases max-mtime alone cannot see (mv / cp -p /
//     rsync -a install files with their ORIGINAL mtime)
//
// The point: /etc/cfm/detectors.conf stays a pristine, package-updateable
// conffile; deliberate per-host deltas live in /etc/cfm/detectors.d/ which
// the package never touches. With no overlay directory or an empty one, the
// result is IDENTICAL to ReadSections(basePath) — asserted by a parity test.
//
// Failure posture: a missing dropin dir is fine (not created yet / older
// install); an unreadable dir or overlay FILE is an error — silently ignoring
// configuration a file was supposed to apply is the exact trap this repo keeps
// re-learning (CLAUDE.md §5). The manager maps that error to "keep current
// detectors" on a hot reload and to a base-only start on first load — never to
// teardown (readSectionsForReload).

import (
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DropinDirName is the overlay directory's basename, next to the base file.
const DropinDirName = "detectors.d"

// DefaultDropinDir returns the overlay directory for a base detectors.conf
// path: "<dir of basePath>/detectors.d".
func DefaultDropinDir(basePath string) string {
	return filepath.Join(filepath.Dir(basePath), DropinDirName)
}

// ReadLayered parses basePath and merges dropinDir/*.conf over it. The raw
// bytes returned are the BASE file's (unchanged contract with ReadSections —
// callers wanting untouched text mean the conffile, not the merge).
func ReadLayered(basePath, dropinDir string) (Sections, []byte, error) {
	s, raw, err := ReadSections(basePath)
	if err != nil {
		return s, raw, err
	}
	names, err := ListDropins(dropinDir)
	if err != nil {
		return s, raw, err
	}
	if len(names) == 0 {
		return s, raw, nil
	}
	h := fnv.New64a()
	for _, name := range names {
		p := filepath.Join(dropinDir, name)
		layer, lraw, err := ReadSections(p)
		if err != nil {
			return s, raw, fmt.Errorf("overlay %s: %w", p, err)
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00", name, layer.StampNS, len(lraw))
		mergeLayer(&s, layer)
	}
	s.LayerSig = h.Sum64()
	return s, raw, nil
}

// ReadLayeredFile is the convenience form: base path plus its default
// "<dir>/detectors.d" overlay directory.
func ReadLayeredFile(basePath string) (Sections, error) {
	s, _, err := ReadLayered(basePath, DefaultDropinDir(basePath))
	return s, err
}

// ListDropins returns the overlay filenames in dropinDir, sorted
// lexicographically (the merge order). A missing directory returns nil, nil;
// only "*.conf" entries count, and hidden files are skipped (systemd .d
// convention — editor lock/temp files like emacs' ".#10-ssh.conf" are often
// dangling symlinks that would otherwise fail the whole layered read).
func ListDropins(dropinDir string) ([]string, error) {
	if dropinDir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dropinDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("overlay dir %s: %w", dropinDir, err)
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// mergeLayer merges one parsed overlay into dst per the semantics above.
func mergeLayer(dst *Sections, layer Sections) {
	names := make([]string, 0, len(layer.ByName))
	for name := range layer.ByName {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic merge (map order is random)

	for _, name := range names {
		kv := layer.ByName[name]
		dkv, ok := dst.ByName[name]
		if !ok {
			// Section only in the overlay: adopt it whole (copied — the layer
			// map must not alias into dst) and register its type once.
			ckv := make(KV, len(kv))
			for k, v := range kv {
				ckv[k] = v
			}
			dst.ByName[name] = ckv
			typ, _ := splitTypeInstance(name)
			dst.ByType[typ] = append(dst.ByType[typ], name)
			continue
		}
		for _, k := range sortedKVKeys(kv) {
			v := kv[k]
			if layer.AppendKeys[name][k] {
				if prev, ok := dkv[k]; ok && prev != "" {
					dkv[k] = joinAppend(prev, v)
					continue
				}
			}
			dkv[k] = v
		}
	}
	// dst.Global aliases dst.ByName["global"], so global merges above are
	// already visible; only the alias itself may need (re)pointing when the
	// base had no global writes yet.
	if g, ok := dst.ByName["global"]; ok {
		dst.Global = g
	}
	if layer.StampNS > dst.StampNS {
		dst.StampNS = layer.StampNS
	}
}

// joinAppend joins an overlay "+=" value onto the earlier layers' value:
// multiline rule blocks stack with a newline, list scalars with ", ".
//
// On the scalar path any inline ";"/"#" comment carried by the EARLIER value
// is dropped first: scalar readers cut at the first ";"/"#" (cleanScalar,
// CLAUDE.md §5), so "10.0.0.0/8 ; office" + "203.0.113.0/24" must merge to
// "10.0.0.0/8, 203.0.113.0/24" — appending after the comment would silently
// discard the appended value at read time.
func joinAppend(prev, add string) string {
	if strings.Contains(prev, "\n") || strings.Contains(add, "\n") {
		return prev + "\n" + add
	}
	if i := strings.IndexAny(prev, ";#"); i >= 0 {
		prev = strings.TrimSpace(prev[:i])
	}
	if prev == "" {
		return add
	}
	return prev + ", " + add
}

func sortedKVKeys(kv KV) []string {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
