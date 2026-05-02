package dnat

import "testing"

func TestParseManagedRuleLine(t *testing.T) {
	port, handle, ok := parseManagedRuleLine(`tcp dport 12082 ct state new accept comment "cfm_cpanel_dnat:12082" # handle 44`)
	if !ok || port != "12082" || handle != "44" {
		t.Fatalf("unexpected parse: ok=%v port=%s handle=%s", ok, port, handle)
	}
}

func TestParseManagedRuleLine_IgnoresUnmanaged(t *testing.T) {
	if _, _, ok := parseManagedRuleLine(`tcp dport 12082 accept comment "admin" # handle 55`); ok {
		t.Fatal("expected unmanaged rule to be ignored")
	}
}
