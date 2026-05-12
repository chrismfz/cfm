//go:build linux

package lsm

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
)

// Map populator paths. Declared as vars so tests can redirect them
// to fixtures in t.TempDir().
var (
	passwdPath            = "/etc/passwd"
	cpanelUserDomainsTSV  = "/etc/userdomains"
	directAdminDomainsTSV = "/etc/virtual/domainowners"
	setuidWalkRoots       = []string{"/usr/bin", "/usr/sbin", "/usr/libexec", "/bin", "/sbin"}
)

// inodeKey mirrors struct cfm_inode_key in internal/lsm/bpf/common.bpf.h.
// Dev is syscall.Stat_t.Dev (the filesystem identity exposed by stat(2));
// Ino is syscall.Stat_t.Ino. Together they match the BPF-side
// stat-compatible super_block->s_dev encoding + inode->i_ino key.
type inodeKey struct {
	Dev uint64
	Ino uint64
}

// WebUserNames is the static set of system user names that are
// considered "web-class" — i.e. any uid we should watch for
// sensitive-file modification attempts. Extended at runtime with
// every uid managed by cPanel / DirectAdmin if those panels are
// detected.
//
// The list is conservative: an extra match (treating a non-web
// system user as watched) is a false positive on the FS-005 detector,
// not a false negative on a real attack — and even FPs are gated
// by also requiring a filesystem+inode match against the sensitive-paths set.
var WebUserNames = []string{
	"apache",
	"nginx",
	"www-data",
	"http",
	"php",
	"lsphp",
	"proxy",
}

// WebUserNamePrefixes is the prefix-match set. CloudLinux's
// alt-php-* per-version PHP-FPM workers run as alt-php-N4 / alt-php-N5
// (one uid per minor version), and those uids need to be in the
// watched set without enumerating every version.
var WebUserNamePrefixes = []string{
	"alt-php-",
	"alt-php-fpm-",
}

// DefaultSensitivePaths is the initial set of host paths whose
// inodes the CFML-FS-005 detector watches for write-class
// operations. Operators extend this via /etc/cfm/lsm.conf in a
// later PR; today it is the shipped baseline.
//
// Two categories of entry:
//   - file paths: the file's own inode is watched (matches inode_setattr,
//     inode_setxattr, inode_unlink on that specific file).
//   - directory paths: the directory's inode is watched (matches
//     inode_create / inode_link / inode_rename / inode_unlink against
//     files INSIDE the directory, since the BPF program checks
//     dentry->d_parent for create operations).
//
// Globs are NOT supported in the bpf path — we resolve a glob at
// population time and add each matched inode individually.
var DefaultSensitivePaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d",
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/etc/crontab",
	"/etc/cron.allow",
	"/etc/cron.deny",
	"/etc/at.allow",
	"/etc/at.deny",
	"/etc/pam.d",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d",
	"/root",
	"/root/.ssh",
	"/root/.bashrc",
	"/root/.profile",
}

// PopulateMaps populates the cfm-lsm map state from the live host
// at adoption time. Called by the daemon's lifecycle.go after
// AdoptPinned succeeds. Errors are logged but never fatal — a
// partial population is far better than the daemon refusing to
// start.
//
// The three maps:
//   - cfm_watched_uids:    web-class user uids (from /etc/passwd +
//     panel manifests)
//   - cfm_watched_inodes:  sensitive-path filesystem+inode keys (DefaultSensitivePaths)
//   - cfm_setuid_inodes:   setuid-binary filesystem+inode keys (walks setuidWalkRoots)
func PopulateMaps(l *Loader) (uidsAdded, inodesAdded, setuidAdded int, err error) {
	uidsAdded, err = populateWatchedUids(l.WatchedUidsMap())
	if err != nil {
		return uidsAdded, 0, 0, fmt.Errorf("watched uids: %w", err)
	}
	inodesAdded, err = populateWatchedInodes(l.WatchedInodesMap(), DefaultSensitivePaths)
	if err != nil {
		return uidsAdded, inodesAdded, 0, fmt.Errorf("watched inodes: %w", err)
	}
	setuidAdded, err = populateSetuidInodes(l.SetuidInodesMap(), setuidWalkRoots)
	if err != nil {
		return uidsAdded, inodesAdded, setuidAdded, fmt.Errorf("setuid inodes: %w", err)
	}
	return uidsAdded, inodesAdded, setuidAdded, nil
}

// populateWatchedUids walks /etc/passwd, identifies web-class
// system users, and adds every cPanel / DirectAdmin account user.
// Writes uid → 1 to the supplied BPF map. Returns the count of
// uids added.
func populateWatchedUids(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("nil map")
	}

	// Read /etc/passwd ONCE into a name→uid map. Both code paths
	// (web-user-name match + panel-manifest lookup) consume the
	// same map, so a host with 500 cPanel accounts walks
	// /etc/passwd once total instead of 501 times.
	nameToUID, err := loadPasswdMap()
	if err != nil {
		return 0, err
	}

	uids := map[uint32]struct{}{}

	// Static web-user-name match.
	for name, uid := range nameToUID {
		if isWebUserName(name) {
			uids[uid] = struct{}{}
		}
	}

	// Panel-managed accounts: every uid that owns a hosted vhost is
	// also a web-class user. Best-effort — missing manifest files
	// just mean no panel accounts to add.
	for _, uid := range panelDomainOwnersToUIDs(cpanelUserDomainsTSV, nameToUID) {
		uids[uid] = struct{}{}
	}
	for _, uid := range panelDomainOwnersToUIDs(directAdminDomainsTSV, nameToUID) {
		uids[uid] = struct{}{}
	}

	one := uint8(1)
	count := 0
	for uid := range uids {
		key := uid
		if err := m.Put(key, one); err != nil {
			// Best-effort: keep going on per-uid failures (e.g. a
			// transient EBUSY on map mutation). The map remains a
			// useful partial subset.
			continue
		}
		count++
	}
	return count, nil
}

// loadPasswdMap reads /etc/passwd once and returns username→uid for
// every parseable line. Used by populateWatchedUids and the panel-
// manifest path to avoid re-opening the file per user.
func loadPasswdMap() (map[string]uint32, error) {
	out := map[string]uint32{}
	f, err := os.Open(passwdPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", passwdPath, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			continue
		}
		out[fields[0]] = uint32(uid)
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("scan %s: %w", passwdPath, err)
	}
	return out, nil
}

// isWebUserName matches static names and known web-user prefixes
// (alt-php-N for CloudLinux alt-php).
func isWebUserName(name string) bool {
	for _, n := range WebUserNames {
		if name == n {
			return true
		}
	}
	for _, pfx := range WebUserNamePrefixes {
		if strings.HasPrefix(name, pfx) {
			return true
		}
	}
	return false
}

// panelDomainOwnersToUIDs reads a panel manifest (cPanel
// /etc/userdomains or DirectAdmin /etc/virtual/domainowners — both
// use `domain.com: username` per line) and resolves usernames to
// uids via the supplied passwd map. Returns nil on any IO error
// (best-effort: missing manifest = no panel accounts).
//
// The passwd map is shared with the caller so we do not re-read
// /etc/passwd per manifest file. Was O(panel_accounts * passwd_lines)
// before this refactor; now O(panel_accounts + passwd_lines).
func panelDomainOwnersToUIDs(path string, nameToUID map[string]uint32) []uint32 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	users := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.LastIndex(line, ":")
		if idx < 0 {
			continue
		}
		username := strings.TrimSpace(line[idx+1:])
		if username == "" {
			continue
		}
		users[username] = struct{}{}
	}

	uids := []uint32{}
	for username := range users {
		if uid, ok := nameToUID[username]; ok {
			uids = append(uids, uid)
		}
	}
	return uids
}

// populateWatchedInodes stat()s every path in `paths`, looks up the
// compound filesystem+inode key, and writes it to the BPF map with value 1. Paths
// that don't exist are silently skipped — `/etc/sudoers.d/` may not
// exist on minimal distros, and that's fine, we just don't watch it.
func populateWatchedInodes(m *ebpf.Map, paths []string) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("nil map")
	}
	one := uint8(1)
	count := 0
	for _, p := range paths {
		key, ok := statInodeKey(p)
		if !ok {
			continue
		}
		if err := m.Put(key, one); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// statInodeKey returns the kernel-visible filesystem identity and inode
// number for path. Used to populate maps whose keys match what BPF
// programs read via BPF_CORE_READ(inode, i_sb)->s_dev and
// BPF_CORE_READ(inode, i_ino). Returns (inodeKey{}, false) on stat
// failure.
func statInodeKey(path string) (inodeKey, bool) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return inodeKey{}, false
	}
	return inodeKey{Dev: uint64(st.Dev), Ino: uint64(st.Ino)}, true
}

// populateSetuidInodes walks every directory in `roots`, finds files
// with the setuid bit set, and writes their filesystem+inode keys to
// the BPF map. Used by CFML-CRED-002 as a whitelist: a uid→0 transition
// in a process whose mm->exe_file is in this map is treated as
// legitimate.
//
// Walk is bounded: roots are short, walks stay on a single
// filesystem (no symlinked traversal into sibling mounts), and
// per-entry stat is cheap.
func populateSetuidInodes(m *ebpf.Map, roots []string) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("nil map")
	}
	one := uint8(1)
	count := 0

	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			// Root doesn't exist (e.g. /usr/libexec on some distros).
			continue
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Permission denied on a subdir — skip without
				// failing the whole walk.
				return nil //nolint:nilerr
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Mode()&os.ModeSetuid == 0 {
				return nil
			}
			key, ok := statInodeKey(path)
			if !ok {
				return nil
			}
			if perr := m.Put(key, one); perr == nil {
				count++
			}
			return nil
		})
		if err != nil {
			return count, fmt.Errorf("walk %s: %w", root, err)
		}
	}
	return count, nil
}
