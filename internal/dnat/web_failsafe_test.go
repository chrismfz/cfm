package dnat

import (
	"cfm/internal/firewall"
	"errors"
	"testing"
)

type webFailSafeBackend struct {
	firewall.Backend
	statusFamily string
	statusTable  string
	offFamily    string
	offTable     string
	offCalls     int
}

func (b *webFailSafeBackend) DNATStatus(family, table string) (bool, error) {
	b.statusFamily = family
	b.statusTable = table
	return true, nil
}

func (b *webFailSafeBackend) DNATOff(family, table string) error {
	b.offFamily = family
	b.offTable = table
	b.offCalls++
	return nil
}

func TestWebDNATFailSafeTargetCleanupWiring(t *testing.T) {
	backend := &webFailSafeBackend{}
	target, ok := newWebDNATFailSafeTarget(backend)
	if !ok {
		t.Fatalf("expected web failsafe target")
	}

	on, err := target.StatusCheck()
	if err != nil || !on {
		t.Fatalf("unexpected status result on=%v err=%v", on, err)
	}
	target.Cleanup(3, webDNATProbeError{addr: "127.0.0.1:9043", err: errors.New("connection refused")})

	if backend.statusFamily != "inet" || backend.statusTable != "cfm_redirect" {
		t.Fatalf("unexpected status target family/table: %s/%s", backend.statusFamily, backend.statusTable)
	}
	if backend.offCalls != 1 {
		t.Fatalf("expected DNATOff once, got %d", backend.offCalls)
	}
	if backend.offFamily != "inet" || backend.offTable != "cfm_redirect" {
		t.Fatalf("unexpected cleanup target family/table: %s/%s", backend.offFamily, backend.offTable)
	}
}

func TestWebDNATFailSafeTargetNilBackend(t *testing.T) {
	if _, ok := newWebDNATFailSafeTarget(nil); ok {
		t.Fatalf("nil backend should not produce a web failsafe target")
	}
}
