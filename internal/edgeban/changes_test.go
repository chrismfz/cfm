package edgeban

import (
	"net"
	"testing"
	"time"

	"cfm/internal/firewall"
)

// A ban, an unban and a reconcile's drop are logged as their keys; a change
// that moves every answer starts a new generation; a reader the log was
// trimmed past, or of an older generation, must rebuild.
func TestChangeLog(t *testing.T) {
	s := New("")
	SetDefault(s)
	t.Cleanup(func() { SetDefault(nil) })
	s.Reconcile(Snapshot{ReadAt: time.Now()})
	gen, seq := ChangePos()

	ttl := time.Hour
	s.Add(net.ParseIP("192.0.2.1"), &ttl, "waf_security", false)
	s.Add(net.ParseIP("192.0.2.1"), &ttl, "waf_security", true) // logged twice, listed once
	s.Add(net.ParseIP("2001:db8:5:5::9"), &ttl, "waf_security", false)
	s.Remove("192.0.2.9") // not held: nothing logged
	keys, g, n, ok := ChangesSince(gen, seq)
	if !ok || g != gen || len(keys) != 2 || keys[0] != "192.0.2.1" || keys[1] != "2001:db8:5:5::9" {
		t.Fatalf("after two bans: %v ok=%v", keys, ok)
	}
	if it, ok := Lookup("192.0.2.1"); !ok || it.Expires.IsZero() {
		t.Errorf("Lookup of a ban: %+v %v", it, ok)
	}
	s.Remove("192.0.2.1")
	if keys, _, _, ok := ChangesSince(g, n); !ok || len(keys) != 1 || keys[0] != "192.0.2.1" {
		t.Fatalf("after an unban: %v", keys)
	}
	if _, ok := Lookup("192.0.2.1"); ok {
		t.Error("Lookup answers an unbanned key")
	}
	_, n = ChangePos()

	// A reconcile that drops a ban nft no longer holds: its key.
	s.Reconcile(Snapshot{ReadAt: time.Now().Add(time.Second)})
	if keys, _, _, ok := ChangesSince(g, n); !ok || len(keys) != 1 || keys[0] != "2001:db8:5:5::9" {
		t.Fatalf("after a reconcile's drop: %v ok=%v", keys, ok)
	}
	// One that changes the allow sets: a new generation.
	_, n = ChangePos()
	s.Reconcile(Snapshot{ReadAt: time.Now(), Allows: []string{"198.51.100.0/24"}})
	if _, g2, _, ok := ChangesSince(g, n); ok || g2 == g {
		t.Fatal("an allow change did not start a new generation")
	}
	for name, f := range map[string]func(){
		"kill switch":     func() { SetEnabled(false); SetEnabled(true) },
		"trusted proxies": func() { SetTrustedProxies(nil) },
		"clear":           func() { s.Clear() },
	} {
		g, n := ChangePos()
		f()
		if _, _, _, ok := ChangesSince(g, n); ok {
			t.Errorf("%s did not start a new generation", name)
		}
	}

	// Trimmed past the reader.
	s.Reconcile(Snapshot{ReadAt: time.Now(), Blocks: []firewall.SetElementTimed{}})
	g, n = ChangePos()
	for i := 0; i <= changeLogMax; i++ {
		markKeys("k")
	}
	if _, _, _, ok := ChangesSince(g, n); ok {
		t.Error("a reader the log was trimmed past was not told to rebuild")
	}
	if _, _, _, ok := ChangesSince(g, n+2); !ok {
		t.Error("a reader the log still reaches was told to rebuild")
	}
}
