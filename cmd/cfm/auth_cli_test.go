package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrismfz/goauth"
	"github.com/spf13/cobra"
)

func TestAuthCmdMFAResetSuccessWritesAuditEntry(t *testing.T) {
	dbPath := createAuthTestDB(t)
	m := mustOpenAuthManager(t, dbPath)
	if err := m.Users.Create("alice", "Password123!", []string{"admin"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	_ = m.Close()

	cmd := authCmdMFAReset(&dbPath)
	out, err := runCommandCapture(t, cmd,
		"-u", "alice",
		"--actor", "secops",
		"--source-ip", "10.0.0.15",
		"--source-host", "admin01",
		"--reason", "compromise cleanup",
		"--ticket", "INC-1001",
	)
	if err != nil {
		t.Fatalf("execute reset: %v", err)
	}
	if !strings.Contains(out, `MFA reset for "alice"`) {
		t.Fatalf("unexpected output: %q", out)
	}

	m = mustOpenAuthManager(t, dbPath)
	defer m.Close()
	entries, err := m.QueryAuthLogMFAAdmin(goauth.MFAAdminQueryFilter{Target: "alice", Limit: 5})
	if err != nil {
		t.Fatalf("query auth log: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected mfa admin audit entry")
	}
	e := entries[0]
	if e.Event != goauth.LogEventMFAReset {
		t.Fatalf("unexpected event: %s", e.Event)
	}
	if e.Actor != "secops" || e.IP != "10.0.0.15" || e.Host != "admin01" || e.Ticket != "INC-1001" {
		t.Fatalf("unexpected audit context: %+v", e)
	}
}

func TestAuthCmdMFARecoveryRegenerateSuccess(t *testing.T) {
	dbPath := createAuthTestDB(t)
	m := mustOpenAuthManager(t, dbPath)
	if err := m.Users.Create("alice", "Password123!", []string{"admin"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	_ = m.Close()

	cmd := authCmdMFARecoveryRegenerate(&dbPath)
	out, err := runCommandCapture(t, cmd,
		"-u", "alice",
		"--count", "6",
		"--actor", "secops",
		"--source-ip", "10.0.0.16",
		"--source-host", "admin01",
		"--reason", "rotate recovery codes",
		"--ticket", "INC-1002",
	)
	if err != nil {
		t.Fatalf("execute recovery-regenerate: %v", err)
	}
	if !strings.Contains(out, "(6 code(s))") {
		t.Fatalf("unexpected output: %q", out)
	}

	m = mustOpenAuthManager(t, dbPath)
	defer m.Close()
	remaining, err := m.Users.CountRecoveryCodes("alice")
	if err != nil {
		t.Fatalf("count recovery codes: %v", err)
	}
	if remaining != 6 {
		t.Fatalf("expected 6 recovery codes, got %d", remaining)
	}

	entries, err := m.QueryAuthLogMFAAdmin(goauth.MFAAdminQueryFilter{Target: "alice", Limit: 5})
	if err != nil {
		t.Fatalf("query auth log: %v", err)
	}
	if len(entries) == 0 || entries[0].Event != goauth.LogEventMFARecoveryRotate {
		t.Fatalf("expected latest mfa recovery rotate event, got %+v", entries)
	}
}

func TestAuthCmdMFARequiredFlagsAndValidation(t *testing.T) {
	dbPath := createAuthTestDB(t)
	m := mustOpenAuthManager(t, dbPath)
	if err := m.Users.Create("alice", "Password123!", []string{"admin"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	_ = m.Close()

	cmd := authCmdMFAReset(&dbPath)
	_, err := runCommandCapture(t, cmd, "-u", "alice")
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected required flag error, got %v", err)
	}

	cmd = authCmdMFAReset(&dbPath)
	_, err = runCommandCapture(t, cmd,
		"-u", "alice",
		"--actor", "a",
		"--source-ip", "not-an-ip",
		"--source-host", "h",
		"--reason", "short",
		"--ticket", "x",
	)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "--actor must be at least 3 characters") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestAuthCmdMFAStatusUnknownUser(t *testing.T) {
	dbPath := createAuthTestDB(t)
	cmd := authCmdMFAStatus(&dbPath)
	_, err := runCommandCapture(t, cmd, "-u", "ghost")
	if !errors.Is(err, goauth.ErrUserNotFound) {
		t.Fatalf("expected goauth.ErrUserNotFound, got %v", err)
	}
}

func createAuthTestDB(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "auth.db")
}

func mustOpenAuthManager(t *testing.T, dbPath string) *goauth.Manager {
	t.Helper()
	m, err := goauth.New(goauth.Config{
		DBPath:           dbPath,
		SessionTTL:       time.Hour,
		SecureCookie:     false,
		MFAEncryptionKey: "cfm-auth-cli-mfa-key-32-bytes!!!",
		MFAIssuer:        "cfm-admin",
	})
	if err != nil {
		t.Fatalf("open auth manager: %v", err)
	}
	return m
}

func runCommandCapture(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	cmd.SetArgs(args)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	execErr := cmd.Execute()

	_ = w.Close()
	os.Stdout = origStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String(), execErr
}
