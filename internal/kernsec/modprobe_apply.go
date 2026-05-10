package kernsec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ModprobePath is where kernsec persists the module blacklist.
//
// Declared as var (not const) so tests can redirect it to t.TempDir().
var ModprobePath = "/etc/modprobe.d/cfm-kernsec.conf"

// RenderModprobeFile produces the content of
// /etc/modprobe.d/cfm-kernsec.conf for the given module set. Each
// rule emits two lines:
//
//	blacklist <name>
//	install <name> /bin/false
//
// The `blacklist` line stops auto-loading via aliases. The `install
// /bin/false` line stops direct `modprobe X` calls — defense in depth
// matches the design doc. Rules are grouped by `Group` so operators
// can grep / read the file.
func RenderModprobeFile(rules []ModuleRule) []byte {
	var b strings.Builder
	b.WriteString("# Managed by cfm kernsec — do not edit by hand.\n")
	b.WriteString("# Generated from /etc/cfm/kernsec.conf.\n")
	b.WriteString("# See docs/kernsec.md for the rule set and rationale.\n")
	b.WriteString("\n")

	if len(rules) == 0 {
		b.WriteString("# (no module rules selected by current tier / overrides)\n")
		return []byte(b.String())
	}

	var prevGroup string
	for _, r := range rules {
		if r.Group != prevGroup {
			if prevGroup != "" {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "# Group: %s\n", r.Group)
			prevGroup = r.Group
		}
		fmt.Fprintf(&b, "blacklist %s\n", r.Name)
		fmt.Fprintf(&b, "install %s /bin/false\n", r.Name)
	}
	return []byte(b.String())
}

// WriteModprobeFile writes the rendered modprobe content to
// ModprobePath atomically. Same two-tier backup as WriteSysctlFile:
// one-shot `.cfm-kernsec.bak` of the first version seen, plus a
// per-run timestamped backup whenever operator edits are detected.
//
// w is the writer used for the unmanaged-line warning. Pass io.Discard
// when warnings shouldn't surface (tests, programmatic callers).
func WriteModprobeFile(w io.Writer, content []byte) error {
	if err := BackupOnce(ModprobePath, ModprobePath+BackupSuffix); err != nil {
		return err
	}
	if _, err := preserveAndWarnOnExtras(w, ModprobePath, content, "modprobe drop-in"); err != nil {
		return err
	}
	return AtomicWriteFile(ModprobePath, content, 0o644)
}

// ParseManagedBlacklist reads the existing managed modprobe file and
// returns the set of module names it currently blacklists. Used for
// "is this module already in our managed file?" checks. Lines from
// other modprobe.d files are not considered — this is strictly the
// kernsec-owned file.
func ParseManagedBlacklist() map[string]struct{} {
	out := map[string]struct{}{}
	f, err := os.Open(ModprobePath)
	if err != nil {
		return out
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// "blacklist <name>" — we only look at this; the install
		// line is redundant for membership purposes.
		const prefix = "blacklist "
		if strings.HasPrefix(line, prefix) {
			name := strings.TrimSpace(line[len(prefix):])
			if name != "" {
				out[name] = struct{}{}
			}
		}
	}
	return out
}

// ModulePresentOnKernel reports whether the kernel build supplies the
// named module — i.e. whether <name>.ko or <name>.ko.xz is present
// under /lib/modules/$(uname -r).
//
// O(1) lookup against a per-process cache built once on first call by
// walking /lib/modules/<rel> exactly once. Previously this walked the
// full tree per module: with ~70 module rules and a typical
// /lib/modules tree of ~5000 entries that was ~350K stat() calls per
// audit pass; now it's ~5000 once and a map lookup thereafter.
//
// Returns false on any error (kernel without /lib/modules entry,
// permission, etc.). Treating "unknown" as "not present" produces
// SKIP rows in the audit, which is the right outcome — kernsec can't
// prove the module is reachable, so it can't promise blacklisting it
// matters here.
func ModulePresentOnKernel(name string) bool {
	cache := loadModuleFileCache()
	if cache == nil {
		return false
	}
	for _, suffix := range []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"} {
		if _, ok := cache[name+suffix]; ok {
			return true
		}
	}
	return false
}

var (
	moduleFileCacheOnce sync.Once
	moduleFileCacheVal  map[string]struct{}
)

// loadModuleFileCache walks /lib/modules/<release> once per process
// and returns the set of basenames found under it. nil on any error
// (no /lib/modules tree, permission, missing release).
//
// Exported indirectly via ResetModuleFileCache so tests can rebuild
// the cache against a fixture path.
func loadModuleFileCache() map[string]struct{} {
	moduleFileCacheOnce.Do(func() {
		moduleFileCacheVal = buildModuleFileCache()
	})
	return moduleFileCacheVal
}

// moduleFileCacheRoot is the root of the module tree to walk; var so
// tests can redirect to a fixture without a real /lib/modules layout.
var moduleFileCacheRoot = func() string {
	rel := unameRelease()
	if rel == "" {
		return ""
	}
	return filepath.Join("/lib/modules", rel)
}

// buildModuleFileCache walks moduleFileCacheRoot() once and returns
// the set of basenames it finds. Returns nil when the root is empty
// or unreadable.
func buildModuleFileCache() map[string]struct{} {
	root := moduleFileCacheRoot()
	if root == "" {
		return nil
	}
	out := map[string]struct{}{}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		out[d.Name()] = struct{}{}
		return nil
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

// ResetModuleFileCache forces the next loadModuleFileCache call to
// rebuild from disk. Test-only: allows redirecting moduleFileCacheRoot
// and re-populating the cache against a fixture tree.
func ResetModuleFileCache() {
	moduleFileCacheOnce = sync.Once{}
	moduleFileCacheVal = nil
}

// LoadedModules returns the set of module names currently in
// /proc/modules. One read per audit pass — callers should call this
// once and pass the map around.
func LoadedModules() map[string]struct{} {
	out := map[string]struct{}{}
	b, err := os.ReadFile("/proc/modules")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			out[fields[0]] = struct{}{}
		}
	}
	return out
}
