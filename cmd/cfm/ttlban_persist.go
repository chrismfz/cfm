package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"cfm/internal/allowlist"
	"cfm/internal/detectors"
	"cfm/internal/edgeban"
	"cfm/internal/firewall"
	"cfm/internal/logging"
	"cfm/internal/ttlban"
)

// ttlBanExcludeSets are the sets whose addresses a restored ban must not
// cover: everything `inet cfm input` accepts before its block drops (the
// edge ban reconcile's allow list), plus cfm.ignore's sets.
var ttlBanExcludeSets = append(append([]string(nil), edgeBanAllowSets...),
	"ignore_v4", "ignore_v6", "ignore_v4_nets", "ignore_v6_nets")

// ttlBanShutdownBudget bounds the SIGTERM snapshot, well inside the unit's
// TimeoutStopSec (30s).
const ttlBanShutdownBudget = 10 * time.Second

// ttlBanExclude builds the restore's "must not be blocked" test: nft's allow
// and ignore sets as they are now (a warm restart), cfm.allow / cfm.ignore
// (a fresh table: the daemon loads them only later in startup) and [global]
// IGNORE_IPS / IGNORE_NETS. An unreadable source is logged and skipped: the
// others still apply, and nft's own allow accepts come before its drops.
func ttlBanExclude(be firewall.Backend, cfgDir string) func(net.IP) bool {
	var elems []string
	for _, set := range ttlBanExcludeSets {
		got, err := be.ListSetElementsTimed(set)
		if err != nil {
			logging.Logf("[ttlban] restore: cannot read %s (%v); not excluded from it", set, err)
			continue
		}
		for _, e := range got {
			elems = append(elems, e.Elem)
		}
	}
	var ig *detectors.IPIgnore
	if cfgDir != "" {
		for _, name := range []string{"cfm.allow", "cfm.ignore"} {
			// Hostnames resolved as the daemon's own cfm.allow apply does.
			opts := allowlist.ReadOptions{ResolveHostnames: name == "cfm.allow", ResolverTimeout: 2 * time.Second}
			entries, _, err := allowlist.ReadEntriesFromFile(context.Background(), filepath.Join(cfgDir, name), opts)
			if err != nil {
				logging.Logf("[ttlban] restore: cannot read %s (%v); not excluded from it", name, err)
				continue
			}
			for _, e := range entries {
				if e.Kind == allowlist.KindCIDR {
					elems = append(elems, e.CIDR)
				} else if e.IP != nil {
					elems = append(elems, e.IP.String())
				}
			}
		}
		var err error
		if ig, err = detectors.GlobalIgnoreFromFile(filepath.Join(cfgDir, "detectors.conf")); err != nil {
			logging.Logf("[ttlban] restore: cannot read IGNORE_IPS (%v); not excluded from it", err)
		}
	}
	inSets := edgeban.AddrMatcher(elems)
	return func(ip net.IP) bool {
		return inSets(ip) || ig.ShouldIgnore(ip.String())
	}
}

// ttlBanRestoreWait bounds how long the first edge ban reconcile waits for
// the restore (a hung nft must not keep the edge from answering bans
// forever; the store stays unarmed, so nothing is saved over the file).
// Until then the edge answers no ban (as before every first reconcile); an
// empty store returns at once.
const ttlBanRestoreWait = 30 * time.Second

// restoreTTLBans loads the persisted TTL bans, re-adds those with time left
// and installs the store as the default (Forget, the snapshots). Called once,
// after EnsureBase and before the first edge ban reconcile reads nft.
func restoreTTLBans(be firewall.Backend, cfgDir string) *ttlban.Store {
	s := ttlban.New(ttlban.DefaultPath)
	if err := s.Load(); err != nil {
		logging.Logf("[ttlban] %v; starting empty", err)
	}
	// Installed first: an unblock during the restore must reach the store.
	ttlban.SetDefault(s)
	exclude := func(net.IP) bool { return false }
	if s.Len() > 0 { // the exclude reads 16 sets: only when there is something to restore
		exclude = ttlBanExclude(be, cfgDir)
	}
	res, err := s.Restore(be, exclude)
	b := res.Batch
	logging.Logf("[ttlban] restore: stored=%d expired=%d excluded=%d added=%d extended=%d kept=%d present=%d skipped=%d",
		res.Stored, res.Expired, res.Excluded, b.Added, b.Extended, b.Kept, b.Present, b.Skipped)
	if err != nil {
		logging.Logf("[ttlban] restore failed: %v", err)
		fmt.Fprintln(os.Stderr, "ttlban restore error:", err)
	}
	return s
}

// startTTLBans runs the restore in the background (on the exec backend each
// set read is an nft process; startup must not wait on them) and returns a
// channel closed when it is done, or after ttlBanRestoreWait.
func startTTLBans(be firewall.Backend, cfgDir string) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchTTLBanShutdown(restoreTTLBans(be, cfgDir), be)
	}()
	waited := make(chan struct{})
	go func() {
		defer close(waited)
		select {
		case <-done:
		case <-time.After(ttlBanRestoreWait):
			logging.Logf("[ttlban] restore still running after %s; the edge ban reconcile starts without it", ttlBanRestoreWait)
		}
	}()
	return waited
}

// snapshotTTLBans reads the block sets and saves their timed elements. Any
// set failing to read skips the save: a partial read would drop real bans.
func snapshotTTLBans(s *ttlban.Store, be firewall.Backend) error {
	readAt, elems, err := readBlockSets(be)
	if err != nil {
		return err
	}
	return s.Snapshot(readAt, elems)
}

// watchTTLBanShutdown takes a last snapshot when the daemon is told to stop
// (systemctl stop/restart, an upgrade, a reboot), so a ban added since the
// last edge ban reconcile survives too. It then dies of the same signal, as
// it did before it caught any.
func watchTTLBanShutdown(s *ttlban.Store, be firewall.Backend) {
	sigs := []os.Signal{syscall.SIGTERM}
	// Catching a signal the process was started with ignored (nohup) would
	// un-ignore it: leave those alone.
	for _, sig := range []os.Signal{syscall.SIGINT, syscall.SIGHUP} {
		if !signal.Ignored(sig) {
			sigs = append(sigs, sig)
		}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sigs...)
	go func() {
		sig := <-ch
		done := make(chan error, 1)
		go func() { done <- snapshotTTLBans(s, be) }()
		select {
		case err := <-done:
			if err != nil {
				logging.Logf("[ttlban] shutdown snapshot skipped (%s): %v", sig, err)
			} else {
				logging.Logf("[ttlban] shutdown snapshot saved (%s): %d bans", sig, s.Len())
			}
		case <-time.After(ttlBanShutdownBudget):
			logging.Logf("[ttlban] shutdown snapshot timed out after %s (%s); the last periodic one stands", ttlBanShutdownBudget, sig)
		}
		signal.Reset(sig)
		if ss, ok := sig.(syscall.Signal); ok {
			_ = syscall.Kill(os.Getpid(), ss)
		}
		time.Sleep(time.Second) // the re-raised signal ends the process
		os.Exit(1)
	}()
}
