package dnat

import (
	"errors"
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
