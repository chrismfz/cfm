//go:build linux

package lsm

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeProc builds a synthetic /proc tree under t.TempDir() and points
// procRoot at it for the duration of the test.
func fakeProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
	return root
}

func writeProcFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mkProc materialises one pid dir with exe/cwd symlinks + cmdline +
// status + comm + loginuid.
func mkProc(t *testing.T, root string, pid int, exeTarget, cwdTarget, cmdlineNUL, comm string, ppid int, loginuid string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if exeTarget != "" {
		if err := os.Symlink(exeTarget, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	if cwdTarget != "" {
		if err := os.Symlink(cwdTarget, filepath.Join(dir, "cwd")); err != nil {
			t.Fatal(err)
		}
	}
	writeProcFile(t, filepath.Join(dir, "cmdline"), cmdlineNUL)
	writeProcFile(t, filepath.Join(dir, "status"), "Name:\t"+comm+"\nPPid:\t"+strconv.Itoa(ppid)+"\n")
	writeProcFile(t, filepath.Join(dir, "comm"), comm+"\n")
	writeProcFile(t, filepath.Join(dir, "loginuid"), loginuid)
}

func TestSnapshotProc_FullForensics(t *testing.T) {
	root := fakeProc(t)

	payload := filepath.Join(root, "payload")
	writeProcFile(t, payload, "MZ-not-really-but-hashable")
	cronBin := filepath.Join(root, "cronbin")
	writeProcFile(t, cronBin, "cron")

	mkProc(t, root, 4242, payload, filepath.Join(root, "home", "bob"), "pgrep\x00-f\x00systemd\x00", "pgrep", 999, "1234")
	mkProc(t, root, 999, cronBin, "/", "", "cron", 1, "4294967295")

	s := snapshotProc(4242, 0, true)
	if !s.Alive {
		t.Fatal("expected Alive")
	}
	if s.Exe != payload {
		t.Errorf("exe = %q, want %q", s.Exe, payload)
	}
	if s.ExeDeleted {
		t.Error("exe should not be flagged deleted")
	}
	if s.Cmdline != "pgrep -f systemd" {
		t.Errorf("cmdline = %q, want %q", s.Cmdline, "pgrep -f systemd")
	}
	if s.PPid != 999 {
		t.Errorf("ppid = %d, want 999", s.PPid)
	}
	if s.ParentComm != "cron" {
		t.Errorf("parent comm = %q, want cron", s.ParentComm)
	}
	if s.ParentExe != cronBin {
		t.Errorf("parent exe = %q, want %q", s.ParentExe, cronBin)
	}
	if s.LoginUID != 1234 {
		t.Errorf("loginuid = %d, want 1234", s.LoginUID)
	}
	if s.SHA256 == "" {
		t.Error("expected a non-empty sha256")
	}

	ls := s.logSuffix()
	for _, want := range []string{"exe=" + payload, "sha256=", "cwd=", "cmdline=", "ppid=999(cron)", "loginuid=1234"} {
		if !strings.Contains(ls, want) {
			t.Errorf("logSuffix %q missing %q", ls, want)
		}
	}
	// The parent's loginuid was the (uint32)-1 sentinel: unset -> -1.
	ps := snapshotProc(999, 0, false)
	if ps.LoginUID != -1 {
		t.Errorf("parent loginuid = %d, want -1 (unset sentinel)", ps.LoginUID)
	}
}

func TestSnapshotProc_ProcessGone(t *testing.T) {
	fakeProc(t)
	s := snapshotProc(12345, 4242, true)
	if s.Alive {
		t.Fatal("expected not-alive for a missing pid")
	}
	if !strings.Contains(s.logSuffix(), "proc=gone") {
		t.Errorf("logSuffix %q missing proc=gone", s.logSuffix())
	}
}

func TestProcReadlink_DeletedSuffix(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "exe")
	// The kernel appends " (deleted)" to an unlinked exe target; emulate
	// by pointing the symlink at a path literally ending that way.
	if err := os.Symlink("/tmp/.x/loader (deleted)", link); err != nil {
		t.Fatal(err)
	}
	target, deleted := procReadlink(link)
	if !deleted {
		t.Fatal("expected deleted=true")
	}
	if target != "/tmp/.x/loader" {
		t.Errorf("target = %q, want /tmp/.x/loader", target)
	}
}

func TestSnapshotUIDRoster_SwarmUnderOneUID(t *testing.T) {
	root := fakeProc(t)

	// A swarm: three processes with distinct spoofed comms, all owned by
	// the same uid and all pointing at one dropped binary under /tmp.
	dropper := "/tmp/.hidden/loader"
	mkProc(t, root, 100, dropper, "/", "pgrep\x00", "pgrep", 1, "1234")
	mkProc(t, root, 101, dropper, "/", "systemd\x00", "systemd", 1, "1234")
	mkProc(t, root, 102, dropper, "/", "kworker\x00", "kworker", 1, "1234")
	// An unrelated process under a DIFFERENT uid must not appear.
	mkProc(t, root, 200, filepath.Join(root, "other"), "/", "bash\x00", "bash", 1, "0")
	writeProcFile(t, filepath.Join(root, "other"), "x")

	// chown the swarm's proc dirs to a test uid we can match on. We can't
	// chown as non-root reliably, so match on the current process uid
	// instead: rewrite the roster to look up our own uid.
	uid := uint32(os.Getuid())
	// Re-stat: the dirs are owned by the test-runner uid already, so all
	// four match `uid`. Distinguish the "other" one by content instead:
	// give it a different exe so DistinctExe / Suspicious still make sense.
	r := snapshotUIDRoster(uid, rosterPeerLimit)
	if r.Total < 4 {
		t.Fatalf("expected at least 4 peers under uid %d, got %d", uid, r.Total)
	}
	// The dropped binary path must be flagged suspicious.
	foundSusp := false
	for _, s := range r.Suspicious {
		if s == dropper {
			foundSusp = true
		}
	}
	if !foundSusp {
		t.Errorf("expected %q in Suspicious, got %v", dropper, r.Suspicious)
	}
	// samples must include the spoofed-comm peers.
	joined := strings.Join(r.samples(), "\n")
	for _, want := range []string{"comm=systemd", "comm=kworker", "exe=" + dropper} {
		if !strings.Contains(joined, want) {
			t.Errorf("roster samples missing %q:\n%s", want, joined)
		}
	}
	if !strings.Contains(r.summary(), "suspicious_exe="+dropper) {
		t.Errorf("summary %q missing suspicious exe", r.summary())
	}
}

func TestCaptureExe_PreservesAndDedupes(t *testing.T) {
	root := fakeProc(t)
	capDir := filepath.Join(t.TempDir(), "capture")

	payload := filepath.Join(root, "payload")
	content := "malicious-bytes-v1"
	writeProcFile(t, payload, content)
	mkProc(t, root, 700, payload, "/", "x\x00", "x", 1, "0")

	cf, err := captureExe(700, capDir, maxExeHashBytes)
	if err != nil {
		t.Fatalf("captureExe: %v", err)
	}
	if cf.SHA256 == "" || cf.Path == "" {
		t.Fatalf("expected non-empty capture, got %+v", cf)
	}
	got, err := os.ReadFile(cf.Path)
	if err != nil {
		t.Fatalf("read captured: %v", err)
	}
	if string(got) != content {
		t.Errorf("captured content = %q, want %q", got, content)
	}
	if !strings.HasSuffix(cf.Path, cf.SHA256+".bin") {
		t.Errorf("captured path %q not named by sha", cf.Path)
	}
	// mode must be root-only.
	if fi, err := os.Stat(cf.Path); err == nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("captured mode = %v, want 0600", fi.Mode().Perm())
	}
	// Second capture of the same content must dedupe to the same file
	// (no duplicate).
	cf2, err := captureExe(700, capDir, maxExeHashBytes)
	if err != nil {
		t.Fatalf("second captureExe: %v", err)
	}
	if cf2.Path != cf.Path {
		t.Errorf("dedupe failed: %q vs %q", cf2.Path, cf.Path)
	}
	if n := dirFileCount(capDir); n != 1 {
		t.Errorf("capture dir has %d files, want 1 (deduped)", n)
	}
}

func TestGatherEnrichment_DisabledIsNoOp(t *testing.T) {
	fakeProc(t)
	e := gatherEnrichment(1, 0, enrichConf{Enrich: false}, time.Unix(1_700_000_000, 0))
	if e.on {
		t.Error("enrichment should be off")
	}
	if e.logSuffix() != "" || e.identitySuffix() != "" || e.samples() != nil {
		t.Error("disabled enrichment must render nothing")
	}
	extra := map[string]string{}
	e.addExtra(extra)
	if len(extra) != 0 {
		t.Errorf("disabled enrichment must not touch extra, got %v", extra)
	}
}
