package webdetector

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// Vhost LOCKDOWN — "nothing gets past this vhost challenge".
//
// A vhost challenge lets some clients through by design: the crawler bypass
// list (cfm.lua Step 0, challenge_waf_bypass.conf), FCrDNS-verified good bots,
// Challenge Access-Control entries and the operator exclude file. That is
// right on an ordinary day and wrong when those very clients are the problem
// (a crawl from 1 300 Applebot IPs on one shop, 2026-10-27): a vhost
// challenge could not stop them, and nothing else at the edge reached a
// bypass-listed client either (Step 0 returns before every other step).
//
// A lockdown is an attribute of a MANUAL vhost challenge, with its own expiry
// (default 30 min, at most 6 h, never past the arm's). While it holds, the
// vhost's challenge has no client exemption:
//   - cfm.lua Step 0 withdraws the bypass of the crawler ("1") prefixes for a
//     locked host (cfm_lockdown.lua, fed from /nginx/lockdown). CDN prefixes
//     ("2", QUIC.cloud) keep it: their requests are a site's visitors;
//   - handleDecision skips the good-bot downgrade, Access-Control and the
//     exclude-file lift;
//   - the challenge page grants no exemption (challengePageExempt);
//   - a v2 arm waives no good bot at verify.
// The vhost uniqIP count is left as it is (vhostChallengeExemptClient says
// why), and a crawler held at Step 0 skips the inline WAF as its bypass always
// did (cfm.lua): an armed rule tripped by bait on the locked site would
// otherwise have waf_security nft-ban Googlebot for the whole node.
// Crawlers cannot solve the challenge, so they are in effect shut out of that
// vhost, while people solve it as on any challenged vhost. What a lockdown
// leaves alone is about paths and the node, not clients: /.well-known/ (ACME),
// the challenge-exempt machine endpoints (payment webhooks), the panel
// passthroughs, the server's own IPs, IGNORE_IPS / CHALLENGE_HOST_BYPASS, and
// a client that already holds a clearance cookie or solved.
//
// The expiry is the guard rail: a crawler kept out for hours starts to cost a
// shop its search ranking, so a lockdown always ends on its own.

const (
	defaultLockdownTTL = 30 * time.Minute
	maxLockdownTTL     = 6 * time.Hour
)

// SetManualChallengeLockdownAs sets (ttl > 0) or lifts (ttl <= 0) the lockdown
// of the manual challenge on target, as resolved by manualRungTarget (the
// caller scope-checks THAT host). ttl is capped at maxLockdownTTL and the
// lockdown never outlives the arm. It returns the stored expiry (zero =
// lifted), whether the ttl was capped (by the maximum or by the arm),
// whether anything changed, and ok=false when target has no active manual
// challenge. A no-op (lifting an absent lockdown) writes no audit row.
func (e *Engine) SetManualChallengeLockdownAs(target string, ttl time.Duration, actor string) (until time.Time, capped, changed, ok bool) {
	var want time.Time
	if ttl > 0 {
		if ttl > maxLockdownTTL {
			ttl, capped = maxLockdownTTL, true
		}
		want = time.Now().Add(ttl)
	}
	prev, stored, ok := e.manualChal.setLockdown(target, want)
	if !ok {
		return time.Time{}, false, false, false
	}
	if !want.IsZero() && stored.Before(want.Add(-time.Second)) {
		capped = true // the arm ends first
	}
	if prev.IsZero() && stored.IsZero() {
		return stored, capped, false, true
	}
	e.syncVhostLockdowns()

	on := !stored.IsZero()
	untilStr := "-"
	payload := map[string]interface{}{"lockdown": on}
	if on {
		untilStr = stored.UTC().Format(time.RFC3339)
		payload["until"] = stored.Unix()
	}
	if actor != "" {
		payload["actor"] = actor
	}
	logging.LogfCHALLENGES("[challenge][vhost] action=manual_lockdown host=%s lockdown=%v until=%s actor=%s",
		target, on, untilStr, actorOrDash(actor))
	e.appendHistory(HistoryEvent{TsUnix: time.Now().Unix(), Type: "challenge_vhost_lockdown", Host: target, Mode: "manual", Payload: payload})
	return stored, capped, true, true
}

// vhostLockdownUntil is host's EFFECTIVE lockdown expiry, or zero: the later
// of its own arm's lockdown and, for a www. host, its apex arm's. A lockdown
// on an apex covers www. even when www. has an arm of its own (the canonical
// host of most shops), and lifting www.'s own lockdown never unlocks it while
// the apex's holds — a scoped token holding only www. cannot undo an
// operator's apex lockdown.
func (e *Engine) vhostLockdownUntil(host string) time.Time {
	host = normalizeHost(host)
	t := e.manualChal.lockdownUntil(host)
	if apex, isWWW := strings.CutPrefix(host, "www."); isWWW && apex != "" {
		if a := e.manualChal.lockdownUntil(apex); a.After(t) {
			t = a
		}
	}
	return t
}

// syncVhostLockdowns republishes every active lockdown to the bridge, which
// answers the edge feed and the in-daemon checks: each locked arm's host and
// its bridge variants (an apex arm's www.), the later expiry winning
// (vhostLockdownUntil's union).
func (e *Engine) syncVhostLockdowns() {
	if e.nginxBridge == nil {
		return
	}
	e.lockdownSync.Lock()
	defer e.lockdownSync.Unlock()
	m := map[string]time.Time{}
	now := time.Now()
	for host, ent := range e.manualChal.snapshot() {
		if !ent.LockdownUntil.After(now) {
			continue
		}
		for _, v := range vhostVariantsForBridge(host) {
			if ent.LockdownUntil.After(m[v]) {
				m[v] = ent.LockdownUntil
			}
		}
	}
	// The usual case: no lockdown anywhere, and the bridge already knows.
	if len(m) == 0 && !e.nginxBridge.hasVhostLockdowns() {
		return
	}
	e.nginxBridge.setVhostLockdowns(m)
}

// lockdownPtr is until as an optional JSON time (nil = no lockdown).
func lockdownPtr(until time.Time) *time.Time {
	if until.IsZero() {
		return nil
	}
	return &until
}

// ── Bridge side ─────────────────────────────────────────────────────────────

// bridgeLockdown is the bridge's copy of the active lockdowns: host → expiry.
// Replaced whole on every change (syncVhostLockdowns), read per decision.
type bridgeLockdown struct {
	mu    sync.RWMutex
	until map[string]time.Time
}

// hasVhostLockdowns reports whether the bridge holds any lockdown entry.
func (b *NginxBridge) hasVhostLockdowns() bool {
	if b == nil {
		return false
	}
	b.lockdown.mu.RLock()
	defer b.lockdown.mu.RUnlock()
	return len(b.lockdown.until) > 0
}

func (b *NginxBridge) setVhostLockdowns(m map[string]time.Time) {
	if b == nil {
		return
	}
	b.lockdown.mu.Lock()
	b.lockdown.until = m
	b.lockdown.mu.Unlock()
}

// vhostLockedDown reports whether host is under a lockdown at now. One
// read-locked map lookup; an empty map (the usual case) costs the lock only.
func (b *NginxBridge) vhostLockedDown(host string, now time.Time) bool {
	if b == nil {
		return false
	}
	b.lockdown.mu.RLock()
	defer b.lockdown.mu.RUnlock()
	if len(b.lockdown.until) == 0 {
		return false
	}
	t, ok := b.lockdown.until[normalizeHost(host)]
	return ok && now.Before(t)
}

// handleLockdownFeed serves the active lockdowns to the edge
// (configs/lua/cfm_lockdown.lua, polled every few seconds): {"hosts":
// {"<host>": <expiry unix>}}. Each entry carries its expiry, so the edge stops
// honouring it on time even if a later poll fails. An explicit
// Content-Length, as the minimal Lua cosocket reader needs (handleCacheConfig).
func (b *NginxBridge) handleLockdownFeed(w http.ResponseWriter, r *http.Request) {
	if !b.checkToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now()
	hosts := map[string]int64{}
	b.lockdown.mu.RLock()
	for h, t := range b.lockdown.until {
		if now.Before(t) {
			hosts[h] = t.Unix()
		}
	}
	b.lockdown.mu.RUnlock()
	body, err := json.Marshal(map[string]any{"hosts": hosts})
	if err != nil {
		http.Error(w, "marshal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}
