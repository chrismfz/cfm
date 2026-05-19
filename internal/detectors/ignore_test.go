package detectors

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
	// IPv6 CIDR must NOT have produced a v4_ranges entry.
	if strings.Contains(s, "2001") || strings.Contains(s, "db8") {
		t.Errorf("IPv6 CIDR leaked into Lua cache:\n%s", s)
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
