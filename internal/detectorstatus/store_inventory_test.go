package detectorstatus

import "testing"

func TestSetInventoryComputesDriftAndCounts(t *testing.T) {
	SetInventory([]string{"ssh_auth", "nginx_4xx"}, []string{"ssh_auth", "legacy_detector"}, 1)
	ResetConfiguredSections([]SectionConfig{
		{Section: "ssh_auth", Type: "ssh_auth", Configured: true, Enabled: true},
		{Section: "legacy_detector", Type: "legacy_detector", Configured: true, Enabled: false},
	})
	SetLoadedTypes(2)
	MarkInitOK("ssh_auth")
	snap := GetSnapshot()

	if got, want := snap.Inventory.Counts.Loaded, 2; got != want {
		t.Fatalf("loaded=%d want=%d", got, want)
	}
	if got, want := snap.Inventory.Counts.Configured, 2; got != want {
		t.Fatalf("configured=%d want=%d", got, want)
	}
	if got, want := snap.Inventory.Counts.Enabled, 1; got != want {
		t.Fatalf("enabled=%d want=%d", got, want)
	}
	if got, want := snap.Inventory.Counts.Active, 1; got != want {
		t.Fatalf("active=%d want=%d", got, want)
	}
	if len(snap.Inventory.MissingConfigForAvailable) != 1 || snap.Inventory.MissingConfigForAvailable[0] != "nginx_4xx" {
		t.Fatalf("missing=%v", snap.Inventory.MissingConfigForAvailable)
	}
	if len(snap.Inventory.UnknownSections) != 1 || snap.Inventory.UnknownSections[0] != "legacy_detector" {
		t.Fatalf("unknown=%v", snap.Inventory.UnknownSections)
	}
}
