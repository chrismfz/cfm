package kernsec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
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

// UnloadState classifies the per-module result of an `UnloadManaged`
// pass. Surfaced unchanged into apply's output and the TUI flash so
// operators see "removed from running kernel" vs "will clear at
// reboot" without parsing free text.
type UnloadState string

const (
	// UnloadStateUnloaded means `modprobe -r` succeeded and the module
	// is no longer in /proc/modules.
	UnloadStateUnloaded UnloadState = "UNLOADED"
	// UnloadStateBusy means the module is still in use (refcount > 0
	// or held by a sibling we can't pull). Blacklist on disk prevents
	// future loads; the live module clears at reboot.
	UnloadStateBusy UnloadState = "BUSY"
	// UnloadStateBuiltin means the module is built into the running
	// kernel (not loadable). The modprobe.d blacklist is a no-op for
	// builtins; only kernel cmdline / rebuild can change them.
	UnloadStateBuiltin UnloadState = "BUILTIN"
	// UnloadStateNotLoaded means the module was already absent from
	// /proc/modules by the time the unload pass ran. Treated as a
	// success row — nothing to do.
	UnloadStateNotLoaded UnloadState = "NOT-LOADED"
	// UnloadStateError covers everything else: missing modprobe
	// binary, permission denied, parse failures, exec errors.
	UnloadStateError UnloadState = "ERROR"
)

// UnloadResult is one row in the unload report.
type UnloadResult struct {
	Name   string
	State  UnloadState
	Detail string // operator-facing hint when State != UNLOADED
}

// modprobeRunner is the test seam for UnloadManaged: real callers
// spawn `modprobe -r <name>` and collect stdout+stderr. Tests override
// this to inject UNLOADED / BUSY / BUILTIN / ERROR responses without
// touching the system modprobe.
var modprobeRunner = func(name string) (output string, err error) {
	cmd := exec.Command("modprobe", "-r", name)
	out, runErr := cmd.CombinedOutput()
	return string(out), runErr
}

// loadedModulesForUnload is the test seam for UnloadManaged's
// pre-flight "is this module actually loaded?" check. Default
// delegates to LoadedModules (reads /proc/modules); tests override to
// simulate a custom loaded set without depending on kernel state.
var loadedModulesForUnload = LoadedModules

// UnloadManaged attempts to remove every name in `names` from the
// running kernel using `modprobe -r`. Names that aren't currently in
// /proc/modules are reported as NOT-LOADED (success).
//
// Each row is classified independently — a BUSY module never fails
// the whole pass, the blacklist is already on disk and reboot
// finishes the job. BUILTIN means the module is compiled into vmlinuz
// (the modprobe.d blacklist is a no-op for those; only a kernel
// cmdline change or rebuild can disable them).
//
// `modprobe -r` (not `rmmod`) is used so the kernel's dep graph is
// respected: unloading e.g. `esp4` will also unload `xfrm_algo` only
// if no other transform still holds it. Raw `rmmod` would either fail
// on deps or, with `--force`, risk a crash — neither acceptable from
// an automated security tool.
func UnloadManaged(names []string) []UnloadResult {
	if len(names) == 0 {
		return nil
	}
	loadedBefore := loadedModulesForUnload()
	out := make([]UnloadResult, 0, len(names))
	for _, name := range names {
		if _, live := loadedBefore[name]; !live {
			out = append(out, UnloadResult{
				Name:  name,
				State: UnloadStateNotLoaded,
			})
			continue
		}
		output, err := modprobeRunner(name)
		out = append(out, classifyUnload(name, output, err))
	}
	return out
}

// classifyUnload parses modprobe's combined output + exit error into
// an UnloadResult. modprobe's error strings vary slightly across
// distros (kmod versions) but the substrings checked here are stable
// across the RHEL/Debian families.
func classifyUnload(name, output string, err error) UnloadResult {
	low := strings.ToLower(output)
	switch {
	case err == nil:
		return UnloadResult{Name: name, State: UnloadStateUnloaded}
	case strings.Contains(low, "in use"),
		strings.Contains(low, "is in use"),
		strings.Contains(low, "module is busy"):
		return UnloadResult{
			Name:   name,
			State:  UnloadStateBusy,
			Detail: "in use by another holder — will clear at reboot",
		}
	case strings.Contains(low, "is builtin"),
		strings.Contains(low, "built-in"):
		return UnloadResult{
			Name:   name,
			State:  UnloadStateBuiltin,
			Detail: "compiled into the kernel — modprobe.d blacklist has no effect; needs kernel rebuild or cmdline change",
		}
	}
	// Other failure (exec error, permission, missing modprobe). Keep
	// the operator-facing detail short — full output stays in
	// stderr/journal for them to read if they need it.
	detail := strings.TrimSpace(output)
	if detail == "" {
		detail = err.Error()
	}
	return UnloadResult{
		Name:   name,
		State:  UnloadStateError,
		Detail: firstLine(detail),
	}
}

// firstLine returns the first non-empty line of s. Used to keep the
// per-row Detail field human-readable in apply's table even when
// modprobe spilled a multi-line error.
func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			return ln
		}
	}
	return ""
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
