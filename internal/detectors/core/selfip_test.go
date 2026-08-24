package core

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestSelfIPSetRetainsLastSnapshotOnEnumerationFailure(t *testing.T) {
	selfMu.Lock()
	originalInterfaces := interfaces
	originalSet := selfSet
	originalRefresh := selfRefresh
	selfSet = map[string]struct{}{"192.0.2.10": {}}
	selfRefresh = time.Time{}
	interfaces = func() ([]net.Interface, error) { return nil, errors.New("temporary failure") }
	selfMu.Unlock()
	t.Cleanup(func() {
		selfMu.Lock()
		interfaces = originalInterfaces
		selfSet = originalSet
		selfRefresh = originalRefresh
		selfMu.Unlock()
	})

	if _, ok := SelfIPSet()["192.0.2.10"]; !ok {
		t.Fatal("transient interface error discarded the last self-IP snapshot")
	}
}

func TestSelfIPSetRetainsLastSnapshotOnAddressFailure(t *testing.T) {
	selfMu.Lock()
	originalInterfaces := interfaces
	originalAddresses := addresses
	originalSet := selfSet
	originalRefresh := selfRefresh
	selfSet = map[string]struct{}{"192.0.2.11": {}}
	selfRefresh = time.Time{}
	interfaces = func() ([]net.Interface, error) { return []net.Interface{{Index: 1}}, nil }
	addresses = func(net.Interface) ([]net.Addr, error) { return nil, errors.New("temporary failure") }
	selfMu.Unlock()
	t.Cleanup(func() {
		selfMu.Lock()
		interfaces = originalInterfaces
		addresses = originalAddresses
		selfSet = originalSet
		selfRefresh = originalRefresh
		selfMu.Unlock()
	})

	if _, ok := SelfIPSet()["192.0.2.11"]; !ok {
		t.Fatal("transient address error discarded the last self-IP snapshot")
	}
}
