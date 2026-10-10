package main

import (
	"errors"
	"net"
	"path/filepath"
	"testing"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
)

// setsFake answers ListSetElementsTimed from a map; a name in fail errors.
type setsFake struct {
	firewall.Backend
	sets map[string][]firewall.SetElementTimed
	fail map[string]bool
}

func (f *setsFake) ListSetElementsTimed(name string) ([]firewall.SetElementTimed, error) {
	if f.fail[name] {
		return nil, errors.New("nft: timeout")
	}
	return f.sets[name], nil
}

func newReconcileStore(t *testing.T, ips ...string) *edgeban.Store {
	t.Helper()
	s := edgeban.New(filepath.Join(t.TempDir(), "edgeban.json"))
	for _, ip := range ips {
		s.Add(net.ParseIP(ip), nil, "waf_security", false)
	}
	return s
}

// One read covers every set or none: a set that fails must not reconcile
// (an empty or partial read drops real bans).
func TestEdgeBanReconcileAllOrNone(t *testing.T) {
	s := newReconcileStore(t, "203.0.113.5")
	be := &setsFake{sets: map[string][]firewall.SetElementTimed{"block_v4": {{Elem: "203.0.113.5"}}}, fail: map[string]bool{}}
	if f := edgeBanReconcileOnce(s, be, 0); f != 0 || !s.Ready() {
		t.Fatalf("a full read: fails=%d ready=%v", f, s.Ready())
	}
	if ok, _ := s.Banned("203.0.113.5"); !ok {
		t.Fatal("ban held by nft must be answered")
	}
	// block_v4 now unreadable, everything else empty: must NOT drop the ban.
	be.fail["block_v4"] = true
	if f := edgeBanReconcileOnce(s, be, 0); f != 1 {
		t.Fatalf("a failed read: fails=%d, want 1", f)
	}
	if ok, _ := s.Banned("203.0.113.5"); !ok {
		t.Fatal("a failed read dropped the ban")
	}
	// An allow set failing is a failed read too.
	be.fail = map[string]bool{"allow_ext_v4_nets": true}
	if f := edgeBanReconcileOnce(s, be, 0); f != 1 {
		t.Fatalf("an allow set failing: fails=%d, want 1", f)
	}
}

// Three failed reads in a row empty the store and make it answer nothing
// until a read works again.
func TestEdgeBanReconcileClearsAfterThreeFailures(t *testing.T) {
	s := newReconcileStore(t, "203.0.113.6")
	be := &setsFake{sets: map[string][]firewall.SetElementTimed{"block_v4": {{Elem: "203.0.113.6"}}}, fail: map[string]bool{}}
	edgeBanReconcileOnce(s, be, 0)
	be.fail["block_v4"] = true
	f := 0
	for i := 0; i < edgeBanFailClear; i++ {
		f = edgeBanReconcileOnce(s, be, f)
	}
	if s.Ready() || s.Len() != 0 {
		t.Fatalf("after %d failures: ready=%v len=%d, want emptied and not ready", f, s.Ready(), s.Len())
	}
	// A ban added while nft is unreadable is not answered unchecked.
	s.Add(net.ParseIP("203.0.113.7"), nil, "manual", true)
	if ok, _ := s.Banned("203.0.113.7"); ok {
		t.Fatal("a ban was answered while nft was unreadable")
	}
	be.fail = map[string]bool{}
	be.sets["block_v4"] = []firewall.SetElementTimed{{Elem: "203.0.113.7"}}
	if f = edgeBanReconcileOnce(s, be, f); f != 0 {
		t.Fatalf("recovery: fails=%d", f)
	}
	if ok, _ := s.Banned("203.0.113.7"); !ok {
		t.Fatal("after recovery the ban held by nft is answered again")
	}
}

// The self sets count as allows (nft accepts them before the drops).
func TestEdgeBanReconcileSelfIsAllowed(t *testing.T) {
	s := newReconcileStore(t, "84.54.49.200")
	be := &setsFake{sets: map[string][]firewall.SetElementTimed{
		"block_v4": {{Elem: "84.54.49.200"}},
		"self_v4":  {{Elem: "84.54.49.0/24"}},
	}, fail: map[string]bool{}}
	edgeBanReconcileOnce(s, be, 0)
	if ok, _ := s.Banned("84.54.49.200"); ok {
		t.Fatal("a self address was edge-banned")
	}
}
