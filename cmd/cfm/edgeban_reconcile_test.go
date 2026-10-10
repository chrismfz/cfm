package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

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

// Both lists are the input chain's own: every set EnsureBase accepts before
// its block drops, on both backends, and the two host block sets.
func TestEdgeBanSetsMatchTheInputChain(t *testing.T) {
	acceptRe := regexp.MustCompile("saddr @([a-z0-9_]+) accept`")
	for _, src := range []string{"../../internal/firewall/nft/nft.go", "../../internal/firewall/nftlib/lifecycle.go"} {
		raw, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, m := range acceptRe.FindAllStringSubmatch(string(raw), -1) {
			got[m[1]] = true
		}
		want := map[string]bool{}
		for _, s := range edgeBanAllowSets {
			want[s] = true
		}
		for s := range got {
			if !want[s] && !strings.HasPrefix(s, "debug") {
				t.Errorf("%s: the input chain accepts @%s, edgeBanAllowSets does not read it", src, s)
			}
		}
		for s := range want {
			if !got[s] {
				t.Errorf("%s: edgeBanAllowSets reads %s, the input chain accepts no such set", src, s)
			}
		}
		for _, s := range edgeBanBlockSets {
			if !strings.Contains(string(raw), "saddr @"+s+" drop`") {
				t.Errorf("%s: no `saddr @%s drop` rule", src, s)
			}
		}
	}
}

// The first file with a parsable range wins; an empty one falls through.
func TestLoadEdgeBanTrustedProxies(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.conf")
	good := filepath.Join(dir, "trusted_proxies.conf")
	_ = os.WriteFile(empty, []byte("# nothing\nreal_ip_header CF-Connecting-IP;\n"), 0o600)
	_ = os.WriteFile(good, []byte("set_real_ip_from 173.245.48.0/20;\n"), 0o600)
	old := edgeBanTrustedProxyFiles
	edgeBanTrustedProxyFiles = []string{filepath.Join(dir, "missing.conf"), empty, good}
	t.Cleanup(func() { edgeBanTrustedProxyFiles = old; edgeban.SetTrustedProxies(nil) })

	loadEdgeBanTrustedProxies()
	s := newReconcileStore(t, "173.245.48.10", "203.0.113.5")
	s.Reconcile(edgeban.Snapshot{Blocks: []firewall.SetElementTimed{{Elem: "173.245.48.10"}, {Elem: "203.0.113.5"}}, ReadAt: time.Now().Add(time.Second)})
	if b, _ := s.Banned("173.245.48.10"); b {
		t.Error("a Cloudflare address from the loaded file is edge-banned")
	}
	if b, _ := s.Banned("203.0.113.5"); !b {
		t.Error("an ordinary banned address is not")
	}
}
