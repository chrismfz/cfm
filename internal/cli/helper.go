// internal/cli/helpers.go
package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// UpsertConfKey rewrites cfm.conf so that `key = value` is set, preserving
// the rest of the file (comments, ordering, surrounding keys). If the key
// is already present (case-insensitive match on the key, ignoring spaces
// around '='), its value is replaced; otherwise the key is appended.
//
// Mirrors the regex-and-rewrite approach used by
// sslcollector.ValidateOrGenerateTokenKey for token rotation, so both
// daemon-side and CLI-side mutations of cfm.conf stay shape-compatible.
// The daemon's fsnotify watcher on cfm.conf picks up the change and
// triggers the existing reload path — no SIGHUP needed.
//
// path must be absolute. key must match `[A-Za-z0-9_]+`.
func UpsertConfKey(path, key, value string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("UpsertConfKey: path must be absolute, got %q", path)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_]+$`).MatchString(key) {
		return fmt.Errorf("UpsertConfKey: invalid key %q", key)
	}

	data, err := os.ReadFile(path) // #nosec G304 -- caller-supplied admin path
	if err != nil {
		return fmt.Errorf("UpsertConfKey: read %s: %w", path, err)
	}
	mode := os.FileMode(0640)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode()
	}

	re := regexp.MustCompile(`(?mi)^(` + regexp.QuoteMeta(key) + `\s*=\s*).*$`)
	var updated string
	if re.Match(data) {
		updated = re.ReplaceAllString(string(data), "${1}"+value)
	} else {
		s := string(data)
		if len(s) > 0 && s[len(s)-1] != '\n' {
			s += "\n"
		}
		updated = s + key + " = " + value + "\n"
	}
	if updated == string(data) {
		return nil
	}
	// tmp + rename: a crash, ENOSPC, or signal between truncate and the
	// final write must not leave cfm.conf half-written — the daemon's
	// fsnotify watcher would then re-parse garbage and could zero out
	// unrelated keys. The sibling Lua writers (WriteWebdetectorBridgeConfig,
	// WriteClamavLuaConfig) already follow this pattern.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(updated), mode); err != nil { // #nosec G306 -- preserve existing perms
		return fmt.Errorf("UpsertConfKey: write tmp %s: %w", tmp, err)
	}
	// Preserve owner across the rename when caller is root and the target
	// is owned by a different uid:gid (e.g. root:cfm). Best-effort — if we
	// cannot stat we fall through to the rename, accepting that the new
	// file inherits the writer's effective uid/gid.
	if info, statErr := os.Stat(path); statErr == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(tmp, int(st.Uid), int(st.Gid))
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("UpsertConfKey: rename %s: %w", tmp, err)
	}
	return nil
}

// ----------------------------------------------------------------------------
// Binary / module detection
// ----------------------------------------------------------------------------

func LookPath(name string) (string, bool) {
	p, err := exec.LookPath(name)
	return p, err == nil
}

func HasBinary(name string) (string, bool) {
	if p, ok := LookPath(name); ok {
		return p, true
	}
	return "not found in PATH", false
}

func HasModule(mod string) (string, bool) {
	if f, err := os.Open("/proc/modules"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, mod+" ") {
				return "present in /proc/modules", true
			}
		}
	}
	if _, err := exec.LookPath("modprobe"); err == nil {
		out, _ := exec.Command("modprobe", "-n", "-v", mod).CombinedOutput()
		if txt := strings.TrimSpace(string(out)); txt != "" {
			return "modprobe reports: " + Short(txt, 120), true
		}
	}
	return "not loaded (and modprobe check inconclusive)", false
}

func Short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ----------------------------------------------------------------------------
// Config dir resolution
// ----------------------------------------------------------------------------

const cfmStatePath = "/run/cfm/config.path"

func WriteConfigState(dir string) {
	_ = os.MkdirAll(filepath.Dir(cfmStatePath), 0750)
	_ = os.WriteFile(cfmStatePath, []byte(dir), 0600)
}

func readConfigState() (string, bool) {
	b, err := os.ReadFile(cfmStatePath)
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", false
	}
	return s, true
}

func ResolveConfigDir(explicit string) (string, bool) {
	if explicit != "" {
		if DirExists(explicit) {
			return explicit, true
		}
		return "", false
	}
	if env := strings.TrimSpace(os.Getenv("CFM_CONFIG_DIR")); env != "" {
		if DirExists(env) {
			return env, true
		}
	}
	if s, ok := readConfigState(); ok && DirExists(s) {
		return s, true
	}
	if DirExists("/etc/cfm") {
		return "/etc/cfm", true
	}
	if d, ok := nearestConfigsDir(); ok {
		return d, true
	}
	return "", false
}

func DirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func nearestConfigsDir() (string, bool) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	d := cwd
	for {
		cand := filepath.Join(d, "configs")
		if DirExists(cand) {
			return cand, true
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	return "", false
}

func EnsureDir(p string) error {
	return os.MkdirAll(p, 0750)
}

// ----------------------------------------------------------------------------
// IP / file helpers
// ----------------------------------------------------------------------------

// NormalizeTarget canonicalizes an input to either an IP string or a CIDR string.
// Returns: isCIDR, ipStr, cidrStr, error
func NormalizeTarget(s string) (bool, string, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return false, "", "", fmt.Errorf("empty target")
	}
	if ip := net.ParseIP(s); ip != nil {
		return false, ip.String(), "", nil
	}
	if strings.ContainsRune(s, '/') {
		if _, nw, err := net.ParseCIDR(s); err == nil {
			nw.IP = nw.IP.Mask(nw.Mask)
			return true, "", nw.String(), nil
		}
		return false, "", "", fmt.Errorf("invalid CIDR")
	}
	return false, "", "", fmt.Errorf("invalid IP or CIDR")
}

func RemoveIPFromFile(dir, filename, target string) error {
	isCIDR, ipStr, cidrStr, err := NormalizeTarget(target)
	if err != nil {
		return err
	}
	want := ipStr
	if isCIDR {
		want = cidrStr
	}

	path := filepath.Clean(filepath.Join(dir, filename))
	b, err := os.ReadFile(path) // #nosec G304
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			out = append(out, raw)
			continue
		}
		head := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		fields := strings.Fields(head)
		if len(fields) == 0 {
			out = append(out, raw)
			continue
		}
		if fields[0] == want {
			continue // drop this line
		}
		out = append(out, raw)
	}
	if err != nil {
		// file didn't exist — nothing to remove, not an error
		return nil
	}
	return os.WriteFile(path, []byte(strings.Join(out, "\n")+"\n"), 0600)
}

func AppendUniqueLine(dir, filename, line string) error {
	path := filepath.Clean(filepath.Join(dir, filename))
	b, _ := os.ReadFile(path) // #nosec G304
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == strings.TrimSpace(line) {
			return nil
		}
	}
	// #nosec G304
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

// SplitFlagsAndPositionals separates flag args from positional args.
// valueFlags names the flags that take a value, in any spelling ("ttl",
// "-ttl" or "--ttl" all mean the same flag, as for the flag package). The
// lookup used to strip the dashes from the argument but not from the keys, so
// with the callers' "--ttl" / "-r" keys no value was ever attached: `cfm block
// IP -r why --ttl 10m` parsed reason "--ttl" and NO TTL — a permanent block,
// persisted to cfm.deny and reported to cfm-web as permanent.
func SplitFlagsAndPositionals(args []string, valueFlags map[string]bool) (flagArgs []string, posArgs []string) {
	takesValue := make(map[string]bool, len(valueFlags))
	for k, v := range valueFlags {
		takesValue[strings.TrimLeft(k, "-")] = v
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			name := a
			if idx := strings.Index(a, "="); idx != -1 {
				flagArgs = append(flagArgs, a)
				continue
			}
			flagArgs = append(flagArgs, name)
			if takesValue[strings.TrimLeft(name, "-")] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flagArgs = append(flagArgs, args[i+1])
				i++
			}
			continue
		}
		posArgs = append(posArgs, a)
	}
	return
}
