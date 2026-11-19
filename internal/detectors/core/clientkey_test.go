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
