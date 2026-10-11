package clam

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeClamd serves the INSTREAM protocol on a unix socket: it consumes the
// command + chunks and answers with `reply`. hang=true accepts and never
// responds (the hung-clamd case the inline timeout must survive).
func fakeClamd(t *testing.T, reply string, hang bool) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "clamd.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if hang {
					time.Sleep(5 * time.Second)
					return
				}
				// "zINSTREAM\x00" then length-prefixed chunks until the
				// zero-length terminator.
				cmd := make([]byte, 10)
				if _, err := io.ReadFull(c, cmd); err != nil {
					return
				}
				var hdr [4]byte
				for {
					if _, err := io.ReadFull(c, hdr[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(hdr[:])
					if n == 0 {
						break
					}
					if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
						return
					}
				}
				_, _ = c.Write([]byte(reply))
			}(conn)
		}
	}()
	return sock
}

// zip returns a path to a small zip-magic file (in scope for archives).
func zipFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "u.bin")
	if err := os.WriteFile(p, []byte("PK\x03\x04payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func inlineManager(t *testing.T, sock string, mut func(*Config)) *Manager {
	t.Helper()
	cfg := Config{
		Enabled: true, Network: "unix", Address: sock,
		ScanScope: ScanScopeArchives, InlineTimeout: 500 * time.Millisecond,
		QueueSize: 8,
	}
	if mut != nil {
		mut(&cfg)
	}
	m := NewManager(cfg)
	m.started = true // no workers: sync path only; fallback jobs stay queued
	return m
}

func TestScanUploadSync_CleanAllows(t *testing.T) {
	sock := fakeClamd(t, "stream: OK\x00", false)
	m := inlineManager(t, sock, nil)
	v := m.ScanUploadSync(Job{Path: zipFile(t), Host: "h.example.com", IP: "203.0.113.1"})
	if v.Verdict != "clean" || v.Block || v.WouldBlock {
		t.Fatalf("clean verdict wrong: %+v", v)
	}
}

func TestScanUploadSync_InfectedBlocksAndQuarantines(t *testing.T) {
	t.Cleanup(func() { SetScanEventSink(nil) })
	var got ScanEvent
	SetScanEventSink(func(ev ScanEvent) { got = ev })

	sock := fakeClamd(t, "stream: Win.Trojan.Hide-1 FOUND\x00", false)
	inf := t.TempDir()
	m := inlineManager(t, sock, nil)
	p := zipFile(t)
	v := m.ScanUploadSync(Job{Path: p, Host: "h.example.com", IP: "203.0.113.1", InfectedDir: inf})
	if !v.Block || v.Verdict != "infected" || v.Signature != "Win.Trojan.Hide-1" {
		t.Fatalf("infected verdict wrong: %+v", v)
	}
	// Evidence copied (a new file named after the spool), original left for
	// the caller to clean.
	if filepath.Dir(got.Evidence) != inf || !strings.HasPrefix(filepath.Base(got.Evidence), filepath.Base(p)+".") {
		t.Fatalf("evidence path %q", got.Evidence)
	}
	if b, err := os.ReadFile(got.Evidence); err != nil || string(b) != "PK\x03\x04payload" {
		t.Fatalf("quarantine copy: %q %v", b, err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("original spool must remain (caller owns it): %v", err)
	}
	if got.Mode != "inline" || got.SigIgnored {
		t.Fatalf("published event wrong: %+v", got)
	}
	if m.Health().InlineBlocked != 1 {
		t.Fatal("InlineBlocked counter not bumped")
	}
}

func TestScanUploadSync_DryRunNeverBlocks(t *testing.T) {
	t.Cleanup(func() { SetScanEventSink(nil) })
	var got ScanEvent
	SetScanEventSink(func(ev ScanEvent) { got = ev })

	sock := fakeClamd(t, "stream: Win.Trojan.Hide-1 FOUND\x00", false)
	m := inlineManager(t, sock, func(c *Config) { c.InlineDryRun = true })
	v := m.ScanUploadSync(Job{Path: zipFile(t), Host: "h.example.com"})
	if v.Block {
		t.Fatal("DRY_RUN must never block")
	}
	if !v.WouldBlock || v.Verdict != "infected" {
		t.Fatalf("dry-run verdict wrong: %+v", v)
	}
	if got.Mode != "inline_dryrun" {
		t.Fatalf("event mode = %q, want inline_dryrun", got.Mode)
	}
	if h := m.Health(); h.InlineDryRunHits != 1 || h.InlineBlocked != 0 {
		t.Fatalf("counters wrong: %+v", h)
	}
}

func TestScanUploadSync_SigIgnoredAllows(t *testing.T) {
	t.Cleanup(func() { SetScanEventSink(nil) })
	var got ScanEvent
	SetScanEventSink(func(ev ScanEvent) { got = ev })

	sock := fakeClamd(t, "stream: YARA.X_Hunting.UNOFFICIAL FOUND\x00", false)
	m := inlineManager(t, sock, func(c *Config) { c.SigIgnore = []string{"*_Hunting.UNOFFICIAL"} })
	v := m.ScanUploadSync(Job{Path: zipFile(t), Host: "h.example.com"})
	if v.Block || v.Verdict != "skipped_ignored" {
		t.Fatalf("sig-ignored verdict wrong: %+v", v)
	}
	if !got.SigIgnored || got.IgnoredBy == "" {
		t.Fatalf("event not flagged: %+v", got)
	}
}

// The critical property: a hung clamd must resolve to allow (fail open)
// within the inline timeout, and the file must land on the async queue so
// coverage degrades to notify-only instead of disappearing.
func TestScanUploadSync_HungClamdFailsOpen(t *testing.T) {
	sock := fakeClamd(t, "", true)
	pending := t.TempDir()
	m := inlineManager(t, sock, func(c *Config) {
		c.InlineTimeout = 200 * time.Millisecond
		c.PendingDir = pending
	})
	start := time.Now()
	v := m.ScanUploadSync(Job{Path: zipFile(t), Host: "h.example.com"})
	if v.Block {
		t.Fatal("FAIL-OPEN VIOLATION: hung clamd produced a block")
	}
	if v.Verdict != "error" {
		t.Fatalf("verdict = %q, want error", v.Verdict)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("inline scan not bounded: took %s", el)
	}
	if ql, _ := m.QueueDepth(); ql != 1 {
		t.Fatalf("async fallback not enqueued (queue=%d)", ql)
	}
}

// clamd's "size limit exceeded" ERROR reply is a failure, never a clean
// verdict: allow + async fallback.
func TestScanUploadSync_StreamRejectedFailsOpen(t *testing.T) {
	sock := fakeClamd(t, "INSTREAM size limit exceeded. ERROR\x00", false)
	m := inlineManager(t, sock, func(c *Config) { c.PendingDir = t.TempDir() })
	v := m.ScanUploadSync(Job{Path: zipFile(t), Host: "h.example.com"})
	if v.Block || v.Verdict != "error" {
		t.Fatalf("rejected stream must fail open: %+v", v)
	}
	if ql, _ := m.QueueDepth(); ql != 1 {
		t.Fatal("async fallback not enqueued after stream rejection")
	}
}

func TestScanUploadSync_BreakerOpenSkipsWithoutDialing(t *testing.T) {
	// Address points nowhere; an attempted dial would error loudly, but the
	// open breaker must short-circuit first.
	m := inlineManager(t, "/nonexistent/clamd.sock", nil)
	for i := 0; i < breakerFailThreshold; i++ {
		m.health.record(false, "down")
	}
	v := m.ScanUploadSync(Job{Path: zipFile(t), Host: "h.example.com"})
	if v.Block || v.Verdict != "skipped_breaker" {
		t.Fatalf("breaker-open verdict wrong: %+v", v)
	}
}

func TestScanUploadSync_ScopeSkipsNonArchive(t *testing.T) {
	m := inlineManager(t, "/nonexistent/clamd.sock", nil)
	p := filepath.Join(t.TempDir(), "img.png")
	if err := os.WriteFile(p, []byte{0x89, 'P', 'N', 'G', 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	v := m.ScanUploadSync(Job{Path: p, Host: "h.example.com"})
	if v.Block || v.Verdict != "skipped_scope" {
		t.Fatalf("scope-skip verdict wrong: %+v", v)
	}
}

// pending and infected are root:cfm 0770: the edge's user can plant names
// there. The fallback copy (pending/inline_fb_<spool>) and the evidence copy
// (infected/<spool>) were os.WriteFile to a fixed name, which followed a
// planted symlink: root wrote the upload's bytes wherever it pointed.
func TestInlineCopiesDoNotFollowPlantedSymlinks(t *testing.T) {
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "cron")
	if err := os.WriteFile(victim, []byte("ORIGINAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	spool := zipFile(t)

	// Fallback: clamd hangs, the spool is copied into pending.
	pending := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(pending, "inline_fb_"+filepath.Base(spool))); err != nil {
		t.Fatal(err)
	}
	m := inlineManager(t, fakeClamd(t, "", true), func(c *Config) {
		c.InlineTimeout = 200 * time.Millisecond
		c.PendingDir = pending
	})
	m.ScanUploadSync(Job{Path: spool, Host: "h.example.com"})
	if ql, _ := m.QueueDepth(); ql != 1 {
		t.Fatalf("fallback not enqueued (queue=%d)", ql)
	}

	// Evidence: an infected verdict copies the spool into infected.
	inf := t.TempDir()
	if err := os.Symlink(victim, filepath.Join(inf, filepath.Base(spool))); err != nil {
		t.Fatal(err)
	}
	m2 := inlineManager(t, fakeClamd(t, "stream: Eicar FOUND\x00", false), nil)
	if v := m2.ScanUploadSync(Job{Path: spool, Host: "h.example.com", InfectedDir: inf}); !v.Block {
		t.Fatalf("verdict %+v", v)
	}

	if b, _ := os.ReadFile(victim); string(b) != "ORIGINAL" {
		t.Fatalf("symlink target overwritten: %q", b)
	}
}
