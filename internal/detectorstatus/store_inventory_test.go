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

func TestUpsertConfiguredSectionsPreservesRuntimeState(t *testing.T) {
	ResetConfiguredSections([]SectionConfig{{Section: "ssh_auth", Type: "ssh_auth", Configured: true, Enabled: true, SourceProbeOK: true}})
	MarkInitOK("ssh_auth")
	before := GetSnapshot()
	if len(before.Sections) != 1 || !before.Sections[0].InitOK || !before.Sections[0].Active {
		t.Fatalf("unexpected precondition snapshot: %+v", before.Sections)
	}

	UpsertConfiguredSections([]SectionConfig{{Section: "ssh_auth", Type: "ssh_auth", Configured: true, Enabled: true, SourceProbeOK: true}})
	after := GetSnapshot()
	if len(after.Sections) != 1 {
		t.Fatalf("expected one section, got %d", len(after.Sections))
	}
	if !after.Sections[0].InitOK {
		t.Fatalf("expected init_ok to be preserved")
	}
	if !after.Sections[0].Active {
		t.Fatalf("expected active to be preserved")
	}
}
