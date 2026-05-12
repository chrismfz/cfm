package lsm

import "testing"

// TestAllPolicies_Scope confirms exactly the four currently-supported
// policies are registered. Bumping the count requires updating
// docs/cfm-lsm.md and configs/lsm.conf in lockstep.
func TestAllPolicies_Scope(t *testing.T) {
	policies := AllPolicies()
	if len(policies) != 4 {
		t.Fatalf("policy catalog should have exactly four entries; got %d", len(policies))
	}
	want := map[PolicyID]bool{
		PolicyMemfdExec:      false,
		PolicyReverseShell:   false,
		PolicySensitiveWrite: false,
		PolicyCredEscal:      false,
	}
	for _, p := range policies {
		if _, ok := want[p.ID]; !ok {
			t.Errorf("unexpected policy %s in catalog", p.ID)
			continue
		}
		want[p.ID] = true
		if p.Title == "" {
			t.Errorf("policy %s has empty Title", p.ID)
		}
		if p.Hook == "" {
			t.Errorf("policy %s has empty Hook", p.ID)
		}
		if p.Description == "" {
			t.Errorf("policy %s has empty Description", p.ID)
		}
		// Every policy defaults to disabled; the operator opts in
		// per policy via /etc/cfm/lsm.conf.
		if p.DefaultMode != ModeDisabled {
			t.Errorf("policy %s default mode is %v; expected disabled", p.ID, p.DefaultMode)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("policy %s missing from AllPolicies()", id)
		}
	}
}

func TestPolicyByID(t *testing.T) {
	for _, p := range AllPolicies() {
		got, ok := PolicyByID(p.ID)
		if !ok {
			t.Errorf("PolicyByID(%s) returned !ok", p.ID)
			continue
		}
		if got.Title != p.Title {
			t.Errorf("PolicyByID(%s): title mismatch", p.ID)
		}
	}
	if _, ok := PolicyByID("CFML-BOGUS-999"); ok {
		t.Error("PolicyByID with unknown ID should return ok=false")
	}
}

func TestMode_String(t *testing.T) {
	cases := map[Mode]string{
		ModeDisabled: "disabled",
		ModeMonitor:  "monitor",
		ModeEnforce:  "enforce",
	}
	for m, want := range cases {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", m, got, want)
		}
	}
}

func TestCheckStatus_String(t *testing.T) {
	cases := map[CheckStatus]string{
		CheckPass:    "PASS",
		CheckFail:    "FAIL",
		CheckUnknown: "UNKNOWN",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("CheckStatus(%d).String() = %q, want %q", s, got, want)
		}
	}
}
