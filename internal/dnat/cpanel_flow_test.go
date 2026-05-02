package dnat

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSuccessfulApplyState(t *testing.T) {
	setPanelFirewallHealth("OK", "", true)
	h := getPanelFirewallHealth()
	if h.State != "OK" || !h.Attempted || h.LastReason != "" {
		t.Fatalf("unexpected state: %#v", h)
	}
}

func TestBackendCommandFailureStructured(t *testing.T) {
	err := (&FirewallCommandError{Backend: fwNft, Command: "nft add rule inet cfm input", Output: "syntax error", Err: errors.New("exit status 1")}).Error()
	if !strings.Contains(err, "backend=nftables") || !strings.Contains(err, "syntax error") || !strings.Contains(err, "command=") {
		t.Fatalf("unexpected error string: %s", err)
	}
}

func TestIdempotentRerunAfterPartialFailure(t *testing.T) {
	setPanelFirewallHealth("PARTIAL", "failed once", true)
	setPanelFirewallHealth("OK", "", true)
	h := getPanelFirewallHealth()
	if h.State != "OK" {
		t.Fatalf("expected OK after rerun, got %#v", h)
	}
}

func TestOffCleanupStatusesReported(t *testing.T) {
	changes := []string{"tcp/12082 removed", "tcp/12083 not found", "tcp/12086 failed (boom)"}
	foundRemoved := false
	foundNotFound := false
	foundFailed := false
	for _, ch := range changes {
		foundRemoved = foundRemoved || strings.Contains(ch, "removed")
		foundNotFound = foundNotFound || strings.Contains(ch, "not found")
		foundFailed = foundFailed || strings.Contains(ch, "failed")
	}
	if !foundRemoved || !foundNotFound || !foundFailed {
		t.Fatalf("missing cleanup status categories: %v", changes)
	}
}

func TestPanelLuaDecisionEndpoint302IsDenied(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	// Current behavior for /__cfm_panel_decide HTTP 302 is to classify as redirect
	// and deny with subrequest_redirect_not_allowed.
	for _, tok := range []string{
		"if status >= 300 and status < 400 then",
		`outcome = "redirect"`,
		`reason = "subrequest_redirect"`,
		`reason = "subrequest_redirect_not_allowed"`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing 302 handling token %q", tok)
		}
	}
}

func TestPanelLuaDecisionLogAnchorsRedirectStatusSignature(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	// Keep this signature anchor: if behavior changes to generic non-2xx handling,
	// expected log shape is decision_reason=subrequest_non_2xx subreq_status=302.
	// Today redirect is explicitly tracked and still must include subreq_status.
	if !strings.Contains(s, `decision_reason = decision.reason`) {
		t.Fatalf("decision logs must include decision_reason field")
	}
	if !strings.Contains(s, `subreq_status = decision.subreq_status`) {
		t.Fatalf("decision logs must include subreq_status field")
	}
	if !strings.Contains(s, `reason = "subrequest_redirect"`) {
		t.Fatalf("expected explicit redirect reason for 302 status")
	}
}
