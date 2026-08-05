package webdetector

import (
	"testing"
	"time"
)

// Reproduces the 2026-08-05 "drops from the list" incident: an operator sets a
// manual vhost challenge on the apex (e-vafeiadis.gr), the suspicious-vhost auto
// scorer cycles on www.e-vafeiadis.gr, and when it cools the www row must NOT
// read as inactive — the manual challenge covers www (apex→www expansion) and
// was still being enforced at the edge the whole time.
func TestChallengeAPIStore_ManualCoversWWWacrossAutoCycle(t *testing.T) {
	s := NewChallengeAPIStore(1000)

	// Operator: manual challenge on the apex only (this is what the CLI/API
	// records — RecordVhostManual is called with the arg host).
	s.RecordVhostManual("e-vafeiadis.gr", true, 24*time.Hour, "manual")

	// Both apex and www must now show manual/active in the list, because the
	// bridge enforces the apex manual on both variants.
	for _, h := range []string{"e-vafeiadis.gr", "www.e-vafeiadis.gr"} {
		v, ok := s.GetVhost(h)
		if !ok {
			t.Fatalf("%s: expected a status record after manual_on", h)
		}
		if v.Status != "active" || v.Mode != "manual" {
			t.Fatalf("%s: expected active/manual, got %s/%s", h, v.Status, v.Mode)
		}
	}

	row := SuspiciousRow{Host: "www.e-vafeiadis.gr", Score: 0.55, UniqueIPs: 123, RPS: 7.0, Reasons: []string{"scanner_like_path_diversity"}}

	// Auto scorer turns ON for www while the manual is active — manual must
	// still own the row.
	s.RecordVhostAuto("www.e-vafeiadis.gr", true, row, 0.70, 0.60, 35*time.Minute)
	if v, _ := s.GetVhost("www.e-vafeiadis.gr"); v.Status != "active" || v.Mode != "manual" {
		t.Fatalf("auto_on under manual: expected active/manual, got %s/%s", v.Status, v.Mode)
	}

	// Auto scorer COOLS (the incident trigger): this must NOT mask the manual.
	rowOff := SuspiciousRow{Host: "www.e-vafeiadis.gr", Score: 0.38, UniqueIPs: 89, RPS: 6.1, Reasons: []string{"scanner_like_path_diversity"}}
	s.RecordVhostAuto("www.e-vafeiadis.gr", false, rowOff, 0.70, 0.60, 35*time.Minute)

	v, _ := s.GetVhost("www.e-vafeiadis.gr")
	if v.Status != "active" || v.Mode != "manual" {
		t.Fatalf("auto_off under manual: www dropped from the list (got %s/%s), regression of the incident", v.Status, v.Mode)
	}
	if v.LastAction != "auto_off_keep_manual" {
		t.Fatalf("expected LastAction=auto_off_keep_manual, got %q", v.LastAction)
	}
	// The manual reason must survive (not be overwritten by the auto scanner reason).
	if len(v.Reasons) == 0 || v.Reasons[0] != "manual" {
		t.Fatalf("expected manual reason to survive auto_off, got %v", v.Reasons)
	}

	// It must still appear in an active/manual-filtered list view.
	if got := s.ListVhosts("active", "manual", 100); !containsHost(got, "www.e-vafeiadis.gr") {
		t.Fatal("www.e-vafeiadis.gr missing from active/manual list view after auto_off")
	}

	// Summary must still count it as an active vhost (apex + www = 2).
	if sum := s.Summary(); sum.ActiveVhosts != 2 {
		t.Fatalf("expected 2 active vhosts (apex+www), got %d", sum.ActiveVhosts)
	}
}

// Once the manual challenge is cleared, an auto_off must be free to mark the
// host inactive again — manual-wins is scoped to an ACTIVE manual challenge.
func TestChallengeAPIStore_AutoOffAppliesAfterManualCleared(t *testing.T) {
	s := NewChallengeAPIStore(1000)
	s.RecordVhostManual("shop.gr", true, time.Hour, "manual")
	row := SuspiciousRow{Host: "www.shop.gr", Score: 0.4, UniqueIPs: 90, RPS: 5}

	// Clear the manual (apex→www expansion clears both).
	s.RecordVhostManual("shop.gr", false, 0, "manual_off")
	if v, _ := s.GetVhost("www.shop.gr"); v.manualUntil.After(time.Now()) {
		t.Fatal("manual_off should clear manualUntil on the www variant too")
	}

	s.RecordVhostAuto("www.shop.gr", false, row, 0.70, 0.60, 0)
	if v, _ := s.GetVhost("www.shop.gr"); v.Status != "inactive" || v.Mode != "auto" {
		t.Fatalf("after manual cleared, auto_off should apply: got %s/%s", v.Status, v.Mode)
	}
}

func containsHost(list []ChallengeVhostState, host string) bool {
	for _, v := range list {
		if v.Host == host {
			return true
		}
	}
	return false
}
