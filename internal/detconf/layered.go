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
//   - StampNS                 → the BASE file's mtime (unchanged from the plain
//     read); NOT max'd up by a newer overlay, so a base edit always moves it
//   - LayerSig                → hash of the overlay set (name+mtime+size per
//     file), the sole overlay-change signal: it changes when an overlay is
//     edited, added, removed, or renamed — including files installed with an
//     ORIGINAL (older) mtime (mv / cp -p / rsync -a), which a max-mtime scheme
//     cannot see. The two signals are independent, so an overlay can never
//     shadow a base change nor vice-versa.
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
// lexicographically (the merge order). A missing directory returns nil, nil.
//
// Only real, REGULAR "*.conf" files count. Everything else is ignored, not an
// error, so one stray entry never drops the other overlays:
//   - non-".conf" names (.bak, .txt, case-mismatched .CONF) — not overlays
//   - hidden files (".#…" editor locks, ".foo.conf") — systemd .d convention
//   - symlinks of ANY kind — a config dir for a security daemon does not follow
//     links out to arbitrary (mutable, possibly dangling) targets; put a real
//     file here, not a link
//   - directories, device nodes, other special files
//
// e.Type() is lstat-like (it never follows a symlink), so a symlink reports
// ModeSymlink and fails IsRegular. A regular *.conf file that then fails to
// READ or PARSE is still a hard error (never silently skipped).
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
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		if !e.Type().IsRegular() {
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
					dkv[k] = joinAppend(k, prev, v)
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
	// StampNS deliberately stays the BASE file's mtime — it is NOT raised to
	// the overlay's. A max would let a newer overlay MASK a base edit deployed
	// with an older preserved mtime (rsync -a / cp -p): StampNS would not move
	// and the base change would never hot-reload. Overlay changes are carried
	// by LayerSig instead, so the two signals never shadow each other.
}

// multilineAppendKeys are the detectors.conf keys whose values are RULE BLOCKS
// read one line at a time (internal/detectors kvLines splits on "\n"), NOT
// comma/space lists. A "+=" onto one of these MUST join with a newline: a
// comma-joined block collapses into a single line that the reader either can't
// parse or truncates at the first inline ";"/"#", silently dropping every rule.
// The choice cannot be a content heuristic — a rule ("user:5m:kill") is
// indistinguishable from an IPv6 CIDR list ("2001:db8::/32") by content — so it
// is keyed by NAME. This set MUST track the kvLines() call sites in
// internal/detectors: QUERY_RULES/CONN_RULES (mysql_register.go),
// FAIL_REGEX/RULES/IGNORE_REGEX (custom_register.go). Keys are compared
// upper-cased (the parser upper-cases every key).
var multilineAppendKeys = map[string]bool{
	"QUERY_RULES":  true,
	"CONN_RULES":   true,
	"FAIL_REGEX":   true,
	"RULES":        true,
	"IGNORE_REGEX": true,
}

// joinAppend joins an overlay "+=" value onto the earlier layers' value.
// Rule-block keys (multilineAppendKeys), and any value that already spans
// lines, stack with a newline; list scalars join with ", ".
//
// On the scalar path any inline ";"/"#" comment carried by the EARLIER value
// is dropped first: scalar readers cut at the first ";"/"#" (cleanScalar,
// CLAUDE.md §5), so "10.0.0.0/8 ; office" + "203.0.113.0/24" must merge to
// "10.0.0.0/8, 203.0.113.0/24" — appending after the comment would silently
// discard the appended value at read time. The newline path needs no such
// strip: kvLines strips each line's inline comment as it reads it.
func joinAppend(key, prev, add string) string {
	if multilineAppendKeys[strings.ToUpper(key)] || strings.Contains(prev, "\n") || strings.Contains(add, "\n") {
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
