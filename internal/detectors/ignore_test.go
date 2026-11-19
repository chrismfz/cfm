package detectors

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIPIgnoreCanonicalizesExactIPv6(t *testing.T) {
	ig := newIPIgnoreFromGlobal(KV{"IGNORE_IPS": "2001:0db8:0:0:0:0:0:1"})
	if ig == nil || !ig.ShouldIgnore("2001:db8::1") {
		t.Fatal("equivalent IPv6 representation did not match IGNORE_IPS")
	}
}

func TestIPIgnore_WriteLuaCache_EmptyReceiver(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm_ignore_nets.lua")

	var ig *IPIgnore // nil — operator has no IGNORE_* keys configured
	if err := ig.WriteLuaCache(path); err != nil {
		t.Fatalf("WriteLuaCache(nil): %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(got)
	for _, want := range []string{
		"return {",
		"  ips = {",
		"  },",
		"  v4_ranges = {",
		"}",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("nil-receiver output missing %q\n--- output ---\n%s", want, s)
		}
	}
}

func TestIPIgnore_WriteLuaCache_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm_ignore_nets.lua")

	// 84.54.49.0/24 — the canonical example from the 2026-05 production-log
	// review (myip.gr customer fleet pingbacks).
	_, n1, _ := net.ParseCIDR("84.54.49.0/24")
	_, n2, _ := net.ParseCIDR("10.0.0.0/8")
	// IPv6 CIDR — must be silently skipped (no Lua-side support yet).
	_, n3, _ := net.ParseCIDR("2001:db8::/32")

	ig := &IPIgnore{
		exact: map[string]struct{}{
			"1.2.3.4": {},
			"::1":     {},
		},
		nets: []*net.IPNet{n1, n2, n3},
	}
	if err := ig.WriteLuaCache(path); err != nil {
		t.Fatalf("WriteLuaCache: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(got)

	if !strings.Contains(s, `["1.2.3.4"] = true,`) {
		t.Errorf("missing exact IPv4 1.2.3.4:\n%s", s)
	}
	if !strings.Contains(s, `["::1"] = true,`) {
		t.Errorf("missing exact IPv6 ::1:\n%s", s)
	}

	// 84.54.49.0 = 1412837632, 84.54.49.255 = 1412837887 — verified via the
	// `binary.BigEndian.Uint32(net.IPv4(...).To4())` round-trip.
	{
		first := binary.BigEndian.Uint32(net.IPv4(84, 54, 49, 0).To4())
		last := binary.BigEndian.Uint32(net.IPv4(84, 54, 49, 255).To4())
		needle := fmtRange(first, last)
		if !strings.Contains(s, needle) {
			t.Errorf("missing 84.54.49.0/24 range %s:\n%s", needle, s)
		}
	}
	// 10.0.0.0 = 167772160, 10.255.255.255 = 184549375
	{
		first := binary.BigEndian.Uint32(net.IPv4(10, 0, 0, 0).To4())
		last := binary.BigEndian.Uint32(net.IPv4(10, 255, 255, 255).To4())
		needle := fmtRange(first, last)
		if !strings.Contains(s, needle) {
			t.Errorf("missing 10.0.0.0/8 range %s:\n%s", needle, s)
		}
	}
	// IPv6 CIDR goes to v6_ranges (network as 32 hex digits + prefix), the
	// form cfm_ipkey.lua's ipv6_to_hex32 (used by cfm_selfip.lua) compares against; never v4_ranges.
	v4 := s[strings.Index(s, "v4_ranges"):strings.Index(s, "v6_ranges")]
	if strings.Contains(v4, "2001") || strings.Contains(v4, "db8") {
		t.Errorf("IPv6 CIDR leaked into v4_ranges:\n%s", s)
	}
	if !strings.Contains(s, `{ "20010db8000000000000000000000000", 32 },`) {
		t.Errorf("missing 2001:db8::/32 v6_ranges entry:\n%s", s)
	}
}

// A v6 CIDR written with host bits set (2001:db8::5/48 parses to the masked
// network) and a /128 land as their network address; a v4-mapped CIDR stays
// out of v6_ranges (its To4() is non-nil, and its 128-bit mask is not v4's).
func TestIPIgnore_WriteLuaCache_V6Ranges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfm_ignore_nets.lua")
	var nets []*net.IPNet
	for _, c := range []string{"2001:db8:abcd:12::5/48", "2a14:4280:1:1::7/128", "::ffff:10.0.0.0/104"} {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR(%s): %v", c, err)
		}
		nets = append(nets, n)
	}
	ig := &IPIgnore{exact: map[string]struct{}{}, nets: nets}
	if err := ig.WriteLuaCache(path); err != nil {
		t.Fatalf("WriteLuaCache: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	s := string(got)
	v6 := s[strings.Index(s, "v6_ranges"):]
	for _, want := range []string{
		`{ "20010db8abcd00000000000000000000", 48 },`,
		`{ "2a144280000100010000000000000007", 128 },`,
	} {
		if !strings.Contains(v6, want) {
			t.Errorf("missing %s in v6_ranges:\n%s", want, s)
		}
	}
	if strings.Contains(v6, "ffff") {
		t.Errorf("v4-mapped CIDR leaked into v6_ranges:\n%s", s)
	}
}

func TestIPIgnore_WriteLuaCache_AtomicAndDeterministic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm_ignore_nets.lua")

	_, n1, _ := net.ParseCIDR("192.168.0.0/16")
	_, n2, _ := net.ParseCIDR("10.0.0.0/8")
	ig := &IPIgnore{
		exact: map[string]struct{}{"z.z.z.z": {}, "a.a.a.a": {}},
		nets:  []*net.IPNet{n1, n2},
	}
	if err := ig.WriteLuaCache(path); err != nil {
		t.Fatalf("first write: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	if err := ig.WriteLuaCache(path); err != nil {
		t.Fatalf("second write: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}

	// generated_at differs across calls — strip it for the byte-equality
	// check on the rest of the payload.
	firstNoTS := stripGenerated(string(first))
	secondNoTS := stripGenerated(string(second))
	if firstNoTS != secondNoTS {
		t.Errorf("non-deterministic output (sort drift?):\n--- 1 ---\n%s\n--- 2 ---\n%s", firstNoTS, secondNoTS)
	}

	// Sorted exact keys: a.a.a.a before z.z.z.z.
	posA := strings.Index(firstNoTS, "a.a.a.a")
	posZ := strings.Index(firstNoTS, "z.z.z.z")
	if posA < 0 || posZ < 0 || posA > posZ {
		t.Errorf("exact-IP keys not sorted: a@%d z@%d", posA, posZ)
	}

	// Sorted ranges: 10.0.0.0/8 (167772160) before 192.168.0.0/16 (3232235520).
	posTen := strings.Index(firstNoTS, "167772160")
	posOneNineTwo := strings.Index(firstNoTS, "3232235520")
	if posTen < 0 || posOneNineTwo < 0 || posTen > posOneNineTwo {
		t.Errorf("v4_ranges not sorted: 10/8@%d 192.168/16@%d", posTen, posOneNineTwo)
	}
}

// TestIPIgnore_WriteLuaCache_OverridesRestrictiveUmask is the regression test
// for the operator-reported bug: under a hardened daemon umask of 0077
// (systemd's default for locked-down services) os.WriteFile(..., 0o640)
// produced 0600 on disk, so the cfm-group openresty worker could not read
// /var/lib/cfm/lua/cfm_ignore_nets.lua. cfm.lua's loadfile() then returned nil
// (no panic, nothing logged), the ignore-nets ranges loaded empty, and the
// whole IGNORE_IPS/NETS edge bypass went silently dead — a customer browsing
// from the server's OWN subnet (84.54.49.0/24) got WAF-challenged because
// is_self_origin() saw an empty cache. The fix is the explicit os.Chmod calls
// in WriteLuaCache; this flips the process umask in-test and asserts the mode
// still ends up 0640.
func TestIPIgnore_WriteLuaCache_OverridesRestrictiveUmask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfm_ignore_nets.lua")

	_, n1, _ := net.ParseCIDR("84.54.49.0/24")
	ig := &IPIgnore{nets: []*net.IPNet{n1}}

	prevMask := syscallUmask(0o077)
	defer syscallUmask(prevMask)

	if err := ig.WriteLuaCache(path); err != nil {
		t.Fatalf("WriteLuaCache: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o640 {
		t.Fatalf("under umask 0077 the explicit chmod did not stick: mode=%o want 640", perm)
	}
}

func fmtRange(first, last uint32) string {
	return "{ " + uint32Dec(first) + ", " + uint32Dec(last) + " }"
}

func uint32Dec(v uint32) string {
	// fmt.Sprintf in the package under test produces "%d"; mirror that.
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func stripGenerated(s string) string {
	start := strings.Index(s, "generated_at")
	if start < 0 {
		return s
	}
	end := strings.IndexByte(s[start:], '\n')
	if end < 0 {
		return s
	}
	return s[:start] + s[start+end:]
}

// OverlapsPrefix (firewall.SetClientNetExempt): any IGNORE_IPS address or
// IGNORE_NETS network touching the /64, even in part, keeps it from being
// banned as a whole.
func TestIPIgnoreOverlapsPrefix(t *testing.T) {
	ig := newIPIgnoreFromGlobal(KV{
		"IGNORE_IPS":  "203.0.113.9, 2001:db8:1:2::77",
		"IGNORE_NETS": "2001:db8:9::/48, 198.51.100.0/24, 2001:db8:5:6:8000::/65",
	})
	for p, want := range map[string]bool{
		"2001:db8:1:2::/64": true,  // an ignored address inside
		"2001:db8:1:3::/64": false, // next door
		"2001:db8:9:4::/64": true,  // inside an ignored /48
		"2001:db8:5:6::/64": true,  // holds an ignored /65
		"2001:db8:7::/64":   false,
	} {
		if got := ig.OverlapsPrefix(netip.MustParsePrefix(p)); got != want {
			t.Errorf("OverlapsPrefix(%s) = %v, want %v", p, got, want)
		}
	}
	var nilIG *IPIgnore
	if nilIG.OverlapsPrefix(netip.MustParsePrefix("2001:db8:1:2::/64")) {
		t.Error("a nil ignore list overlaps nothing")
	}
}
