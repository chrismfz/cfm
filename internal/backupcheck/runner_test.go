package backupcheck

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerCapsOutput(t *testing.T) {
	_, err := ExecRunner(context.Background(), "sh", "-c", "head -c 20000000 /dev/zero")
	if err == nil || !strings.Contains(err.Error(), "output over") {
		t.Fatalf("want the cap to refuse 20 MB, got %v", err)
	}
}

func TestExecRunnerKeepsStderrAndKillsTheGroupOnTimeout(t *testing.T) {
	_, err := ExecRunner(context.Background(), "sh", "-c", "echo 'license expired' >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "license expired") {
		t.Fatalf("want stderr in the error, got %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	// a grandchild keeps stdout open; the group kill + WaitDelay must still return
	_, err = ExecRunner(ctx, "sh", "-c", "sleep 30 & sleep 30")
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("want a prompt timeout error, got %v after %s", err, time.Since(start))
	}
}
