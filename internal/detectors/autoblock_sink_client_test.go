package detectors

import (
	"testing"
	"time"

	"cfm/internal/detectors/core"
	"cfm/internal/firewall"
)

// netSinkFake is sinkSetFake with block_v6_clients: an IPv6 client's ban
// takes its /64 (firewall.SetElemWriter).
type netSinkFake struct {
	*sinkSetFake
}

func (f netSinkFake) ListSetElementsTimed(set string) ([]firewall.SetElementTimed, error) {
	if set != firewall.BlockV6Clients {
		return nil, nil // the guard sets: empty
	}
	var out []firewall.SetElementTimed
	for e, d := range f.left {
		out = append(out, firewall.SetElementTimed{Elem: e, Expires: d})
	}
	return out, nil
}

func (f netSinkFake) WriteSetElem(_, elem string, ttl *time.Duration, _ bool) error {
	f.left[elem] = 0
	if ttl != nil {
		f.left[elem] = *ttl
	}
	return nil
}

func (f netSinkFake) WriteSetElems(set string, elems []firewall.SetElemWrite) error {
	for _, e := range elems {
		_ = f.WriteSetElem(set, e.Elem, e.TTL, e.Replace)
	}
	return nil
}

func (f netSinkFake) DeleteSetElem(_, elem string) error { delete(f.left, elem); return nil }

// The section cooldown follows what the ban took: another address of a /64
// banned as a whole is the same client (skipped inside the cooldown), while
// another IPv4 address is not.
func TestSectionSinkCooldownCoversTheBannedSlash64(t *testing.T) {
	fw := netSinkFake{&sinkSetFake{left: map[string]time.Duration{}}}
	s := &sectionSink{section: "ssh_auth", pol: blockPolicy{Mode: "ttl", TTL: time.Hour, Cooldown: 30 * time.Minute},
		fw: fw, inner: &capturingSink{}, last: map[string]time.Time{}}
	pub := func(ip string) {
		s.Publish(core.Alert{When: time.Now(), Kind: "SSH/AUTHFAIL", Key: ip, Extra: map[string]string{"ip": ip}})
	}
	pub("2001:db8:1:2::a")
	if fw.left["2001:db8:1:2::/64"] != time.Hour || len(fw.reports) != 1 {
		t.Fatalf("first ban: %v reports=%v", fw.left, fw.reports)
	}
	if _, ok := s.last["2001:db8:1:2::/64"]; !ok {
		t.Fatalf("cooldown stamped %v, want the /64", s.last)
	}
	pub("2001:db8:1:2::b")
	if len(fw.reports) != 1 {
		t.Fatalf("another address of the banned /64 inside the cooldown: reports=%v", fw.reports)
	}
	pub("2001:db8:1:3::b") // another /64
	if len(fw.reports) != 2 || fw.left["2001:db8:1:3::/64"] != time.Hour {
		t.Fatalf("another /64: %v reports=%v", fw.left, fw.reports)
	}
	pub("203.0.113.7")
	pub("203.0.113.8")
	if len(fw.reports) != 4 {
		t.Fatalf("two IPv4 addresses: reports=%v, want both banned", fw.reports)
	}
}

// The /64 a ban took reaches the notification ("Banned as:").
func TestCopyAlertFieldsCarriesBlockNet(t *testing.T) {
	dst := map[string]string{}
	copyAlertFields(dst, map[string]string{"block_net": "2001:db8:1:2::/64", "client": "x"})
	if dst["block_net"] != "2001:db8:1:2::/64" {
		t.Fatalf("block_net not copied: %v", dst)
	}
}
