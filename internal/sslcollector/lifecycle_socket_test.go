package sslcollector

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	cfgpkg "cfm/internal/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

// strongToken is a 48-char value so ValidateOrGenerateToken treats it as
// already-strong and does not try to patch cfm.conf.
const strongToken = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"

func newTestCollector(t *testing.T) *Collector {
	t.Helper()
	return New(Config{
		Enabled:        true,
		CacheDir:       t.TempDir(),
		StatEvery:      time.Hour,
		DiscoveryEvery: time.Hour,
		NegativeTTL:    30 * time.Second,
		MaxCertCache:   10,
	})
}

// newTestLifecycle builds a SockLifecycle whose shared-Lua writes are redirected
// into t.TempDir(), so a test never clobbers the LIVE /var/lib/cfm/lua/cfm_token.lua
// that running edge workers read (which on a root host would break socket auth —
// the very outage class F27/F28 fix).
func newTestLifecycle(t *testing.T, col *Collector) *SockLifecycle {
	t.Helper()
	lc := NewSockLifecycle(col, "")
	d := t.TempDir()
	lc.luaTokenPath = filepath.Join(d, "cfm_token.lua")
	lc.luaConfigPath = filepath.Join(d, "cfm_sslcollector_config.lua")
	return lc
}

// Test-only accessors — read the guarded fields under the same lock the
// ServeSock goroutine uses, so the race detector sees a happens-before edge.
func (l *SockLifecycle) testRunning() bool  { l.mu.Lock(); defer l.mu.Unlock(); return l.running }
func (l *SockLifecycle) testCfgKey() string { l.mu.Lock(); defer l.mu.Unlock(); return l.cfgKey }
func (l *SockLifecycle) testFailCount() int { l.mu.Lock(); defer l.mu.Unlock(); return l.failCount }
func (l *SockLifecycle) testSeq() uint64    { l.mu.Lock(); defer l.mu.Unlock(); return l.gen }
func (l *SockLifecycle) testClearBackoff() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextAttempt = time.Time{}
}

// inodeOf returns the inode the socket name currently resolves to. ok is false
// while the name is absent (e.g. the brief os.Remove→net.Listen window).
func inodeOf(path string) (uint64, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true
}

func dialOK(path string) bool {
	c, err := net.DialTimeout("unix", path, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	// 30s ceiling, not 5s: the condition is polled every 5ms and returns the
	// instant it holds, so a generous deadline costs nothing on the happy path
	// (these tests finish in ~1s locally). The old 5s bound flaked on loaded CI
	// runners where a socket rebind/respawn occasionally took longer, failing
	// TestSockLifecycle_ConfigChangeRestartStaysDialable with a false "timed out".
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// ─────────────────────────────────────────────────────────────────────────────
// F28 — a server that exits unexpectedly (here: a transient startup bind
// failure) must be respawned by a later ApplyConfig tick, not wedged forever.
// ─────────────────────────────────────────────────────────────────────────────
func TestSockLifecycle_RespawnsAfterTransientBindFailure(t *testing.T) {
	col := newTestCollector(t)
	dir := t.TempDir()
	notyet := filepath.Join(dir, "notyet") // deliberately NOT created yet
	sock := filepath.Join(notyet, "s.sock")

	lc := newTestLifecycle(t, col)
	cfg := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: strongToken}
	ctx := context.Background()

	// Tick 1: parent dir is missing → net.Listen ENOENT → ServeSock returns an
	// error with ctx not cancelled → the goroutine clears running and arms backoff.
	lc.ApplyConfig(ctx, cfg)
	waitFor(t, "server goroutine to record the bind failure", func() bool {
		return !lc.testRunning() && lc.testFailCount() >= 1
	})
	// The pre-fix guard was `key==cfgKey && cancel!=nil`; cfgKey stays set here,
	// so the OLD code would early-return on every later tick and never recover.
	if lc.testCfgKey() == "" {
		t.Fatalf("cfgKey unexpectedly cleared; guard-wedge repro is invalid")
	}

	// Heal: create the parent dir and clear the backoff cooldown (as a later
	// past-cooldown tick would), then apply again.
	if err := os.MkdirAll(notyet, 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	lc.testClearBackoff()

	// Tick 2: must respawn and actually bind now.
	lc.ApplyConfig(ctx, cfg)
	waitFor(t, "server to respawn and become dialable", func() bool {
		return lc.testRunning() && dialOK(sock)
	})
	lc.Stop()
}

// ─────────────────────────────────────────────────────────────────────────────
// F28 (wiring) — the daemon re-invokes ApplyConfig only on a cfm.conf change,
// so the autonomous respawn is driven by the per-tick Tick() call, NOT by
// ApplyConfig. A server that failed its initial bind must be healed by Tick
// alone (with no further ApplyConfig), must not thrash during the backoff
// window, and must stay down after Stop. Reverting the main.go Tick wiring — or
// Tick itself — wedges the socket exactly as the original F28 bug did.
// ─────────────────────────────────────────────────────────────────────────────
func TestSockLifecycle_TickRespawnsDeadServer(t *testing.T) {
	col := newTestCollector(t)
	dir := t.TempDir()
	notyet := filepath.Join(dir, "notyet") // deliberately NOT created yet
	sock := filepath.Join(notyet, "s.sock")

	lc := newTestLifecycle(t, col)
	cfg := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: strongToken}
	ctx := context.Background()

	// Initial apply: parent dir missing → net.Listen ENOENT → the goroutine
	// clears running and arms the backoff cooldown.
	lc.ApplyConfig(ctx, cfg)
	waitFor(t, "initial bind failure recorded", func() bool {
		return !lc.testRunning() && lc.testFailCount() >= 1
	})

	// A Tick inside the backoff window must NOT respawn (no per-tick thrash on a
	// permanently unbindable path): the generation counter must not advance.
	genDuringBackoff := lc.testSeq()
	lc.Tick(ctx)
	if got := lc.testSeq(); got != genDuringBackoff {
		t.Fatalf("Tick respawned during backoff cooldown: gen %d -> %d", genDuringBackoff, got)
	}

	// Heal the environment and clear the cooldown, then let Tick — NOT another
	// ApplyConfig — drive the respawn. This is the exact path the daemon uses.
	if err := os.MkdirAll(notyet, 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	lc.testClearBackoff()
	lc.Tick(ctx)
	waitFor(t, "Tick to respawn a dialable server", func() bool {
		return lc.testRunning() && dialOK(sock)
	})

	// Tick on a healthy server is a no-op: it clears backoff without churning gen.
	genHealthy := lc.testSeq()
	lc.Tick(ctx)
	if got := lc.testSeq(); got != genHealthy {
		t.Fatalf("Tick respawned a healthy server: gen %d -> %d", genHealthy, got)
	}
	if lc.testFailCount() != 0 {
		t.Fatalf("healthy Tick did not clear failCount: got %d", lc.testFailCount())
	}

	// After Stop, Tick must never respawn.
	lc.Stop()
	waitFor(t, "server to stop", func() bool { return !lc.testRunning() })
	genStopped := lc.testSeq()
	lc.Tick(ctx)
	if got := lc.testSeq(); got != genStopped {
		t.Fatalf("Tick respawned after Stop: gen %d -> %d", genStopped, got)
	}
	if lc.testRunning() {
		t.Fatalf("Tick respawned a stopped lifecycle")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F27 — during a restart the OLD listener's Close() must not unlink the NEW
// listener's socket by name. Reproduces the exact race deterministically:
// bind B on the same path, THEN close A after B is live.
// ─────────────────────────────────────────────────────────────────────────────
func TestServeSock_RestartDoesNotUnlinkNewSocket(t *testing.T) {
	col := newTestCollector(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	scfg := SockServerConfig{Enabled: true, SockPath: sock, Token: strongToken, PEMTTL: time.Minute, PEMMax: 100}

	// Server A (inode A named at sock).
	ctxA, cancelA := context.WithCancel(context.Background())
	doneA := make(chan error, 1)
	go func() { doneA <- ServeSock(ctxA, col, scfg) }()
	waitFor(t, "server A to accept", func() bool { return dialOK(sock) })
	inoA, ok := inodeOf(sock)
	if !ok {
		t.Fatalf("could not stat server A's socket")
	}

	// Server B on the SAME path: its os.Remove(sock) unlinks A's name, its
	// net.Listen makes a fresh inode B and names it at sock. A now listens on an
	// unnamed fd; B owns the name. Wait for the NAME to resolve to a NEW inode —
	// deterministic proof B is bound (dialOK alone can't tell A from B, since A's
	// name lingers until B rebinds).
	ctxB, cancelB := context.WithCancel(context.Background())
	doneB := make(chan error, 1)
	go func() { doneB <- ServeSock(ctxB, col, scfg) }()
	waitFor(t, "server B to rebind the name to a new inode", func() bool {
		ino, ok := inodeOf(sock)
		return ok && ino != inoA
	})
	inoB, _ := inodeOf(sock)

	// Tear down A AFTER B is live — the exact F27 ordering. Pre-fix, A.Close()
	// (UnlinkOnClose=true) unlinks B's name here.
	cancelA()
	<-doneA

	ino, ok := inodeOf(sock)
	if !ok {
		t.Fatalf("F27: socket path missing after old server closed — old Close() unlinked the new inode")
	}
	if ino != inoB {
		t.Fatalf("F27: socket path now resolves to inode %d, want B's %d", ino, inoB)
	}
	if !dialOK(sock) {
		t.Fatalf("F27: socket not dialable after old server closed — the new listener was orphaned")
	}

	cancelB()
	<-doneB
}

// ─────────────────────────────────────────────────────────────────────────────
// Stop — after Stop the socket is removed and ApplyConfig never respawns it.
// ─────────────────────────────────────────────────────────────────────────────
func TestSockLifecycle_NoRespawnAfterStop(t *testing.T) {
	col := newTestCollector(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	lc := newTestLifecycle(t, col)
	cfg := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: strongToken}
	ctx := context.Background()

	lc.ApplyConfig(ctx, cfg)
	waitFor(t, "server to accept", func() bool { return dialOK(sock) })

	lc.Stop()
	waitFor(t, "server goroutine to exit", func() bool { return !lc.testRunning() })
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("Stop: expected socket file removed, stat err=%v", err)
	}

	// A tick after Stop must be a no-op — no respawn.
	lc.ApplyConfig(ctx, cfg)
	if lc.testRunning() {
		t.Fatalf("Stop: server respawned after Stop()")
	}
	if dialOK(sock) {
		t.Fatalf("Stop: socket dialable after Stop()")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Backoff — a same-config respawn is gated by nextAttempt so a permanently
// unbindable socket cannot thrash net.Listen every tick.
// ─────────────────────────────────────────────────────────────────────────────
func TestSockLifecycle_BackoffGatesRespawn(t *testing.T) {
	col := newTestCollector(t)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing") // never created → every bind fails
	sock := filepath.Join(missing, "s.sock")
	lc := newTestLifecycle(t, col)
	cfg := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: strongToken}
	ctx := context.Background()

	// First attempt fails and arms a ~5s cooldown.
	lc.ApplyConfig(ctx, cfg)
	waitFor(t, "first bind failure recorded", func() bool {
		return !lc.testRunning() && lc.testFailCount() == 1
	})
	seqAfter1 := lc.testSeq()

	// A tick within the cooldown must NOT respawn (generation unchanged, no new failure).
	lc.ApplyConfig(ctx, cfg)
	if got := lc.testSeq(); got != seqAfter1 {
		t.Fatalf("backoff: respawned within cooldown (gen %d -> %d)", seqAfter1, got)
	}
	if got := lc.testFailCount(); got != 1 {
		t.Fatalf("backoff: failCount advanced within cooldown, want 1 got %d", got)
	}

	// Clear the cooldown → next tick respawns (and fails again → failCount grows).
	lc.testClearBackoff()
	lc.ApplyConfig(ctx, cfg)
	waitFor(t, "second bind failure recorded", func() bool {
		return lc.testSeq() > seqAfter1 && lc.testFailCount() == 2
	})
	lc.Stop()
}

// ─────────────────────────────────────────────────────────────────────────────
// Config-change restart — the real production F27 path (a token rotation
// changes the key → ApplyConfig cancels the old server and spawns a new one on
// the SAME path). The socket must end up dialable on a fresh inode, not orphaned
// by the old generation's Close().
// ─────────────────────────────────────────────────────────────────────────────
func TestSockLifecycle_ConfigChangeRestartStaysDialable(t *testing.T) {
	col := newTestCollector(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	lc := newTestLifecycle(t, col)
	ctx := context.Background()

	cfgA := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: strongToken, PEMTTL: time.Minute}
	lc.ApplyConfig(ctx, cfgA)
	waitFor(t, "A dialable", func() bool { return dialOK(sock) })
	inoA, ok := inodeOf(sock)
	if !ok {
		t.Fatalf("could not stat A's socket")
	}
	keyA := lc.testCfgKey()

	// Rotate the token → different key → restart on the same path.
	cfgB := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: strongToken + "rotated", PEMTTL: time.Minute}
	lc.ApplyConfig(ctx, cfgB)
	if lc.testCfgKey() == keyA {
		t.Fatalf("restart: cfgKey did not change on a config change")
	}
	// New server must rebind (fresh inode) and be dialable — proves the old
	// generation's Close() did not orphan the new socket by name.
	waitFor(t, "restart: new inode live and dialable", func() bool {
		ino, ok := inodeOf(sock)
		return ok && ino != inoA && lc.testRunning() && dialOK(sock)
	})
	lc.Stop()
}

// ─────────────────────────────────────────────────────────────────────────────
// Disable → re-enable — disable removes the socket name (Close no longer
// unlinks), and a later re-enable brings it back dialable.
// ─────────────────────────────────────────────────────────────────────────────
func TestSockLifecycle_DisableThenReEnable(t *testing.T) {
	col := newTestCollector(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	lc := newTestLifecycle(t, col)
	ctx := context.Background()
	on := &cfgpkg.SSLCollectorSockConfig{Enabled: true, SockPath: sock, Token: strongToken}
	off := &cfgpkg.SSLCollectorSockConfig{Enabled: false, SockPath: sock, Token: strongToken}

	lc.ApplyConfig(ctx, on)
	waitFor(t, "enabled: dialable", func() bool { return dialOK(sock) })

	lc.ApplyConfig(ctx, off)
	waitFor(t, "disabled: goroutine exits", func() bool { return !lc.testRunning() })
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("disable: expected socket name removed, stat err=%v", err)
	}

	lc.ApplyConfig(ctx, on)
	waitFor(t, "re-enabled: dialable again", func() bool { return lc.testRunning() && dialOK(sock) })
	lc.Stop()
}
