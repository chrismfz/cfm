package feedutil

import (
	"fmt"
	"testing"
)

func TestSplitHostsNetsLargeV4Fixture(t *testing.T) {
	hostCount := 100000
	netCount := 2048
	in := make([]string, 0, hostCount+netCount+3)
	for i := 0; i < hostCount; i++ {
		in = append(in, fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff))
	}
	for i := 0; i < netCount; i++ {
		in = append(in, fmt.Sprintf("172.%d.%d.0/24", (i>>8)&0xff, i&0xff))
	}
	in = append(in, "invalid", "10.0.0.1/33", "")

	hosts, nets := SplitHostsNets(in, false)
	got := len(hosts) + len(nets)
	expected := hostCount + netCount
	if got == 0 {
		t.Fatalf("expected non-zero cardinality")
	}
	if delta := expected - got; delta < 0 || delta > 10 {
		t.Fatalf("unexpected cardinality: got=%d expected=%d", got, expected)
	}
}

func TestSplitHostsNetsLargeV6Fixture(t *testing.T) {
	hostCount := 100000
	netCount := 2048
	in := make([]string, 0, hostCount+netCount+3)
	for i := 0; i < hostCount; i++ {
		in = append(in, fmt.Sprintf("2001:db8:%x:%x::1", (i>>16)&0xffff, i&0xffff))
	}
	for i := 0; i < netCount; i++ {
		in = append(in, fmt.Sprintf("2001:db8:%x::/64", i+1))
	}
	in = append(in, "bad::ip::", "2001:db8::/129", "")

	hosts, nets := SplitHostsNets(in, true)
	got := len(hosts) + len(nets)
	expected := hostCount + netCount
	if got == 0 {
		t.Fatalf("expected non-zero cardinality")
	}
	if delta := expected - got; delta < 0 || delta > 10 {
		t.Fatalf("unexpected cardinality: got=%d expected=%d", got, expected)
	}
}
