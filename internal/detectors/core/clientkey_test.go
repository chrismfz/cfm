package core

import "testing"

func TestClientKey(t *testing.T) {
	for _, c := range []struct{ kind, key, want string }{
		{"AUTHFAIL|ip", "2001:db8:1:2::a", "2001:db8:1:2::/64"},
		{"AUTHFAIL|ip", "203.0.113.7", "203.0.113.7"},
		{"AUTHFAIL|ip", "fe80::1", "fe80::1"}, // ungrouped (ipkey)
		{"AUTHFAIL|user", "2001:db8:1:2::a", "2001:db8:1:2::a"},
		{"AUTHFAIL|userip", "bob@2001:db8:1:2::a", "bob@2001:db8:1:2::a"},
	} {
		if got := ClientKey(c.kind, c.key); got != c.want {
			t.Errorf("ClientKey(%q, %q) = %q, want %q", c.kind, c.key, got, c.want)
		}
	}
	e := map[string]string{}
	TagClient(e, "203.0.113.7")
	if _, ok := e["client"]; ok {
		t.Fatalf("IPv4 tagged: %v", e)
	}
	TagClient(e, "2001:db8:1:2::a")
	if e["client"] != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 tag: %v", e)
	}
}

// A detector's allow guards its /64: the neighbours of an allowed IPv6
// address are counted (and banned) per address.
func TestGuardAllows(t *testing.T) {
	t.Cleanup(func() { GuardAllows("core-test") })
	if got := ClientKey("AUTHFAIL|ip", "2001:db8:3:3::9"); got != "2001:db8:3:3::/64" {
		t.Fatalf("before: %q", got)
	}
	GuardAllows("core-test", []string{"2001:db8:3:3::1", "203.0.113.7"}, []string{"2001:db8:4::/48", "bogus"})
	for ip, want := range map[string]string{
		"2001:db8:3:3::9": "2001:db8:3:3::9",
		"2001:db8:4:5::9": "2001:db8:4:5::9",
		"2001:db8:3:4::9": "2001:db8:3:4::/64",
	} {
		if got := ClientKey("AUTHFAIL|ip", ip); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	GuardAllows("core-test")
	if got := ClientKey("AUTHFAIL|ip", "2001:db8:3:3::9"); got != "2001:db8:3:3::/64" {
		t.Fatalf("after removal: %q", got)
	}
}
