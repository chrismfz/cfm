package kernsec

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
// ModprobePath atomically, taking a one-shot backup of any prior
// version first.
func WriteModprobeFile(content []byte) error {
	if err := BackupOnce(ModprobePath, ModprobePath+BackupSuffix); err != nil {
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
// under /lib/modules/$(uname -r). Cheap glob; cached implicitly by
// the OS dentry cache.
//
// Returns false on any error (kernel without /lib/modules entry,
// permission, etc.). Treating "unknown" as "not present" produces
// SKIP rows in the audit, which is the right outcome — kernsec can't
// prove the module is reachable, so it can't promise blacklisting it
// matters here.
func ModulePresentOnKernel(name string) bool {
	rel := unameRelease()
	if rel == "" {
		return false
	}
	root := filepath.Join("/lib/modules", rel)
	for _, suffix := range []string{".ko", ".ko.xz", ".ko.zst", ".ko.gz"} {
		matches, _ := filepath.Glob(filepath.Join(root, "**", name+suffix))
		if len(matches) > 0 {
			return true
		}
		// Glob doesn't recurse with **; fall back to a Walk for the
		// modules tree. Cap depth at the kernel module conventions
		// (drivers/<subsys>/<name>.ko etc).
		if found := walkModuleFile(root, name+suffix); found {
			return true
		}
	}
	return false
}

func walkModuleFile(root, leaf string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() == leaf {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
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
