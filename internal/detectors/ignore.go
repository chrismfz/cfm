package detectors

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IgnoreNetsLuaPath is the canonical location for the Lua-readable mirror of
// [global] IGNORE_IPS / IGNORE_NETS. Consumed by cfm.lua's is_self_origin()
// helper. Promoted from inlined string literals at the two former call sites
// (manager.go and webdetector_register.go) so the path is defined once.
const IgnoreNetsLuaPath = "/var/lib/cfm/lua/cfm_ignore_nets.lua"

type IPIgnore struct {
	exact      map[string]struct{}
	nets       []*net.IPNet
	logIgnored bool
}

func newIPIgnoreFromGlobal(global KV) *IPIgnore {
	rawIPs := kvStrClean(global, "IGNORE_IPS", "")
	rawNets := kvStrClean(global, "IGNORE_NETS", "")

	// Default: δεν κάνουμε log τα ignored στο sink (LOG_IGNORED absent → false)
	logIgnored := kvBool(global, "LOG_IGNORED", false)

	exact := make(map[string]struct{})
	var nets []*net.IPNet

	// helper: split σε comma/space
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == ';'
		})
	}

	for _, tok := range split(rawIPs) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		exact[tok] = struct{}{}
		if ip := net.ParseIP(tok); ip != nil {
			exact[ip.String()] = struct{}{}
		}
	}

	for _, tok := range split(rawNets) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if _, netw, err := net.ParseCIDR(tok); err == nil {
			nets = append(nets, netw)
		}
	}

	if len(exact) == 0 && len(nets) == 0 {
		return nil
	}
	return &IPIgnore{
		exact:      exact,
		nets:       nets,
		logIgnored: logIgnored,
	}

}

func (ig *IPIgnore) ShouldIgnore(ipStr string) bool {
	if ig == nil {
		return false
	}
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return false
	}

	if _, ok := ig.exact[ipStr]; ok {
		return true
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if _, ok := ig.exact[ip.String()]; ok {
		return true
	}
	for _, n := range ig.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// OverlapsPrefix reports whether any IGNORE_IPS address or IGNORE_NETS network
// lies in p, even in part: a /64 ban must not drop it
// (firewall.SetClientNetExempt).
func (ig *IPIgnore) OverlapsPrefix(p netip.Prefix) bool {
	if ig == nil || !p.IsValid() {
		return false
	}
	p = p.Masked()
	for k := range ig.exact {
		if a, err := netip.ParseAddr(k); err == nil && p.Contains(a.Unmap()) {
			return true
		}
	}
	for _, n := range ig.nets {
		ones, _ := n.Mask.Size()
		a, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		q := netip.PrefixFrom(a.Unmap(), ones)
		if a.Is4In6() || a.Is4() {
			if l := len(n.Mask); l == net.IPv6len {
				q = netip.PrefixFrom(a.Unmap(), ones-96)
			}
		}
		if q.IsValid() && q.Overlaps(p) {
			return true
		}
	}
	return false
}

// LogIgnoredReports επιστρέφει αν πρέπει να περνάνε τα ignored events στα sinks.
// Ελέγχεται από το LOG_IGNORED στο [global].
func (ig *IPIgnore) LogIgnoredReports() bool {
	if ig == nil {
		return false
	}
	return ig.logIgnored
}

// WriteLuaCache dumps the parsed IGNORE_IPS / IGNORE_NETS to a Lua table file
// so cfm.lua's is_self_origin() helper can honour the same allowlist as the
// Go-side challenge-engine bypass predicate. Format:
//
//	return {
//	  generated_at = "2026-05-19T17:35:00Z",
//	  ips = { ["1.2.3.4"] = true, ["::1"] = true },
//	  v4_ranges = {
//	    { 1412837632, 1412837887 },  -- 84.54.49.0/24 as uint32 [first, last]
//	    ...
//	  },
//	  v6_ranges = {
//	    { "2a0145f8000000000000000000000000", 32 },  -- 2a01:45f8::/32
//	    ...
//	  },
//	}
//
// IPv4 CIDR blocks are precomputed to uint32 [first, last] pairs so the Lua
// caller does a cheap numeric range check instead of bit-twiddling per
// request. IPv6 CIDR blocks are written as the network address in 32
// lowercase hex digits plus the prefix length; cfm_selfip.lua expands the
// client address the same way and compares the leading prefix bits (whole
// nibbles as a string prefix, the last partial nibble numerically). Before
// v6_ranges an IPv6 IGNORE_NETS entry was honoured by Go only: the edge
// still challenged / WAF-checked it (a client behind Cloudflare reaches the
// edge with its own IPv6 address today).
//
// A nil receiver writes an empty file (so cfm.lua sees a valid-but-empty
// table even when no IGNORE_* keys are configured). Writes are atomic via
// the .tmp + rename pattern; concurrent callers race-safely overwrite.
func (ig *IPIgnore) WriteLuaCache(path string) error {
	if path == "" {
		return fmt.Errorf("ignore-nets lua cache: empty path")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("ignore-nets lua cache mkdir: %w", err)
	}
	// Chown the directory too — nft.writeSelfIPsLua does the same. If
	// detectors runs before nft has created /var/lib/cfm/lua, the dir ends
	// up root:root 0750 and the cfm-group worker can't traverse in to reach
	// the file even though the file itself is group-readable.
	ensureCFMGroupRead(dir)

	var buf bytes.Buffer
	buf.WriteString("-- generated by cfm (detectors.IPIgnore.WriteLuaCache); do not edit\n")
	buf.WriteString("return {\n")
	buf.WriteString(fmt.Sprintf("  generated_at = %q,\n", time.Now().UTC().Format(time.RFC3339Nano)))

	// Exact IPs (sorted for deterministic output).
	buf.WriteString("  ips = {\n")
	if ig != nil {
		keys := make([]string, 0, len(ig.exact))
		for k := range ig.exact {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, ip := range keys {
			buf.WriteString(fmt.Sprintf("    [%q] = true,\n", ip))
		}
	}
	buf.WriteString("  },\n")

	// IPv4 CIDR ranges precomputed to uint32 pairs (IPv6 ones go to v6_ranges below).
	buf.WriteString("  v4_ranges = {\n")
	if ig != nil {
		type rng struct{ first, last uint32 }
		var ranges []rng
		for _, n := range ig.nets {
			ip4 := n.IP.To4()
			if ip4 == nil {
				continue // IPv6 — written to v6_ranges below
			}
			first := binary.BigEndian.Uint32(ip4)
			ones, bits := n.Mask.Size()
			if bits != 32 {
				continue // malformed mask; skip defensively
			}
			// Number of host bits = 32 - ones. last = first | ((1 << hostBits) - 1).
			var hostMask uint32
			if ones >= 32 {
				hostMask = 0
			} else {
				hostMask = (1 << (32 - uint(ones))) - 1
			}
			ranges = append(ranges, rng{first: first, last: first | hostMask})
		}
		sort.Slice(ranges, func(i, j int) bool {
			if ranges[i].first != ranges[j].first {
				return ranges[i].first < ranges[j].first
			}
			return ranges[i].last < ranges[j].last
		})
		for _, r := range ranges {
			buf.WriteString(fmt.Sprintf("    { %d, %d },\n", r.first, r.last))
		}
	}
	buf.WriteString("  },\n")

	// IPv6 CIDR blocks: network address as 32 hex digits + prefix length.
	buf.WriteString("  v6_ranges = {\n")
	if ig != nil {
		type rng6 struct {
			hex  string
			ones int
		}
		var ranges6 []rng6
		for _, n := range ig.nets {
			if n.IP.To4() != nil {
				continue // IPv4 (incl. v4-mapped) is v4_ranges' job
			}
			ip16 := n.IP.To16()
			ones, bits := n.Mask.Size()
			if ip16 == nil || bits != 128 {
				continue // malformed mask; skip defensively
			}
			ranges6 = append(ranges6, rng6{hex: hex.EncodeToString(ip16.Mask(n.Mask)), ones: ones})
		}
		sort.Slice(ranges6, func(i, j int) bool {
			if ranges6[i].hex != ranges6[j].hex {
				return ranges6[i].hex < ranges6[j].hex
			}
			return ranges6[i].ones < ranges6[j].ones
		})
		for _, r := range ranges6 {
			buf.WriteString(fmt.Sprintf("    { %q, %d },\n", r.hex, r.ones))
		}
	}
	buf.WriteString("  },\n")
	buf.WriteString("}\n")

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o640); err != nil {
		return fmt.Errorf("ignore-nets lua cache write: %w", err)
	}
	// Force the on-disk mode to 0640 independently of the daemon's umask.
	// os.WriteFile's perm arg is umask-filtered, so under a hardened service
	// umask of 0077 the file lands 0600 — the `cfm`-group openresty worker
	// then can't read it, loadfile() returns nil (no panic, nothing logged),
	// the ignore-nets ranges load empty, and the entire IGNORE_IPS/NETS edge
	// bypass (cfm.lua is_self_origin → Step 0a hard-bypass) goes SILENTLY dead
	// in production. os.Chmod is NOT umask-filtered. Twin of nft.writeSelfIPsLua
	// and the sslcollector snapshot writer, which already carry this guard;
	// this writer had missed it (operator hit it: own-subnet WordPress
	// pingbacks got WAF-challenged because is_self_origin read an empty cache).
	if err := os.Chmod(tmp, 0o640); err != nil { // #nosec G302 -- 0640 group-read is intentional and the whole point of this fix: the cfm-group edge worker must read the cache. 0600 (what gosec wants / what a hardened umask produces) is the bug.
		_ = os.Remove(tmp)
		return fmt.Errorf("ignore-nets lua cache chmod: %w", err)
	}
	// root:cfm ownership so the group-read bit above actually reaches the worker.
	ensureCFMGroupRead(tmp)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("ignore-nets lua cache rename: %w", err)
	}
	// Defensive re-assert: rename carries tmp's mode, but force it again in case
	// `path` pre-existed with a tighter mode on some filesystem.
	if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- 0640 group-read intentional (same rationale as the tmp chmod above): cfm group == edge worker.
		return fmt.Errorf("ignore-nets lua cache chmod (post-rename): %w", err)
	}
	ensureCFMGroupRead(path)
	return nil
}

// ensureCFMGroupRead chowns path to the `cfm` group (uid unchanged). Twin of
// the nft.Backend.ensureCFMGroupRead helper — duplicated here to avoid a
// cross-package import (nft depends on detectors via the registration path,
// not the other way around). Silent no-op if the cfm group doesn't exist.
func ensureCFMGroupRead(path string) {
	g, err := user.LookupGroup("cfm")
	if err != nil || g == nil {
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	_ = os.Chown(path, -1, gid)
}

// GlobalIgnoreFromFile reads [global] IGNORE_IPS / IGNORE_NETS from the
// detectors config at path (with its detectors.d overlays) for code that runs
// before the manager does (the daemon's TTL ban restore). It returns nil when
// the file can't be read or ignores nothing; ShouldIgnore on nil is false.
func GlobalIgnoreFromFile(path string) (*IPIgnore, error) {
	secs, err := ReadLayeredFile(path)
	if err != nil {
		return nil, err
	}
	return newIPIgnoreFromGlobal(secs.Global), nil
}
