package firewall

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"
)

// A probe answers what a dump would, for the addresses asked: PlanBlockBatch
// must then plan the same writes from either (random sets, random bans:
// absent, permanent, shorter, longer, at the slack edge).
func TestReadHostElems_ProbeAndDumpPlanAlike(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for round := 0; round < 300; round++ {
		set := map[string]time.Duration{}
		var dump []SetElementTimed
		for i := 0; i < 40; i++ {
			ip := fmt.Sprintf("10.0.%d.%d", r.Intn(3), r.Intn(30))
			left := []time.Duration{0, time.Millisecond, time.Minute, time.Hour, 7 * 24 * time.Hour}[r.Intn(5)]
			if _, dup := set[ip]; dup {
				continue
			}
			set[ip] = left
			dump = append(dump, SetElementTimed{Elem: ip, Expires: left})
		}
		dump = append(dump, SetElementTimed{Elem: "10.0.9.0/24"}) // a CIDR: never a host block
		var entries []BlockEntry
		for i := 0; i < 1+r.Intn(HostProbeMax); i++ {
			e := BlockEntry{IP: net.ParseIP(fmt.Sprintf("10.0.%d.%d", r.Intn(3), r.Intn(30)))}
			if r.Intn(6) == 0 {
				e.Permanent = true
			} else {
				e.TTL = []time.Duration{time.Second, 59 * time.Second, time.Hour, 6 * time.Hour, 7 * 24 * time.Hour}[r.Intn(5)]
			}
			entries = append(entries, e)
		}
		want, _, _ := SplitBlockEntries(entries)
		probe := func(_ string, ips []net.IP) ([]bool, []time.Duration, error) {
			found, exp := make([]bool, len(ips)), make([]time.Duration, len(ips))
			for i, ip := range ips {
				exp[i], found[i] = set[ip.String()]
			}
			return found, exp, nil
		}
		dumped := false
		cur, err := ReadHostElems("block_v4", want, probe, func() ([]SetElementTimed, error) { dumped = true; return dump, nil })
		if err != nil || dumped {
			t.Fatalf("round %d: err=%v dumped=%v, want the probe", round, err, dumped)
		}
		if got, exp := PlanBlockBatch(want, cur), PlanBlockBatch(want, dump); !reflect.DeepEqual(got, exp) {
			t.Fatalf("round %d: probe plans %+v, dump plans %+v", round, got, exp)
		}
	}
}

// Above HostProbeMax, with no probe, or when the probe fails or answers for
// the wrong number of addresses, the set is dumped.
func TestReadHostElems_FallsBackToTheDump(t *testing.T) {
	dump := []SetElementTimed{{Elem: "192.0.2.1", Expires: time.Hour}}
	one := []BlockEntry{{IP: net.ParseIP("192.0.2.1"), TTL: time.Hour}}
	many := make([]BlockEntry, HostProbeMax+1)
	for i := range many {
		many[i] = BlockEntry{IP: net.IPv4(192, 0, 2, byte(i+1)), TTL: time.Hour}
	}
	probeCalls := 0
	ok := func(_ string, ips []net.IP) ([]bool, []time.Duration, error) {
		probeCalls++
		return make([]bool, len(ips)), make([]time.Duration, len(ips)), nil
	}
	failing := func(string, []net.IP) ([]bool, []time.Duration, error) { return nil, nil, errors.New("no netlink") }
	short := func(string, []net.IP) ([]bool, []time.Duration, error) { return []bool{}, nil, nil }
	for name, c := range map[string]struct {
		want  []BlockEntry
		probe HostProbe
	}{
		"too many": {many, ok},
		"no probe": {one, nil},
		"fails":    {one, failing},
		"short":    {one, short},
	} {
		dumped := false
		cur, err := ReadHostElems("block_v4", c.want, c.probe, func() ([]SetElementTimed, error) { dumped = true; return dump, nil })
		if err != nil || !dumped || !reflect.DeepEqual(cur, dump) {
			t.Errorf("%s: err=%v dumped=%v cur=%v, want the dump", name, err, dumped, cur)
		}
	}
	if probeCalls != 0 {
		t.Errorf("probed a batch of %d (max %d)", len(many), HostProbeMax)
	}
	dumpErr := errors.New("nft timed out")
	if _, err := ReadHostElems("block_v4", one, failing, func() ([]SetElementTimed, error) { return nil, dumpErr }); !errors.Is(err, dumpErr) {
		t.Errorf("a failed dump after a failed probe: err=%v, want the dump's", err)
	}
}
