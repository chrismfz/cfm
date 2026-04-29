# CFM — Firewall Backend Abstraction Roadmap

**Status:** Phase 1 complete (no behavior change; production default remains nft shell backend)  
**Scope:** `internal/firewall/` — interface, nft implementation, future backends  
**Goal:** Decouple *what CFM tells the firewall to do* from *how a specific firewall does it*

---

## Table of Contents

1. [Why this matters](#1-why-this-matters)
2. [Current state — the problem in detail](#2-current-state--the-problem-in-detail)
3. [The Architecture](#3-the-architecture)
4. [Phase 1 — Complete the interface (nft exec, no behaviour change)](#4-phase-1--complete-the-interface-nft-exec-no-behaviour-change)
   - [4a. The full Backend interface](#4a-the-full-backend-interface)
   - [4b. Files that change](#4b-files-that-change)
   - [4c. Removing the type-assertion workarounds](#4c-removing-the-type-assertion-workarounds)
   - [4d. Fixing the direct nft.New() escapes](#4d-fixing-the-direct-nftnew-escapes)
5. [Phase 2 — nftlib backend (google/nftables netlink)](#5-phase-2--nftlib-backend-googlehttpsgnftables-netlink)
   - [5a. Why bother](#5a-why-bother)
   - [5b. New package layout](#5b-new-package-layout)
   - [5c. Example: AddBlock via netlink vs exec](#5c-example-addblock-via-netlink-vs-exec)
   - [5d. Example: AddElementsBulk — the fork-storm fix](#5d-example-addelementsbulk--the-fork-storm-fix)
   - [5e. Wiring the selection in main.go](#5e-wiring-the-selection-in-maingo)
6. [Phase 3 — pf backend (BSD, future)](#6-phase-3--pf-backend-bsd-future)
7. [Compatibility contract](#7-compatibility-contract)
8. [Progress tracking](#8-progress-tracking)

---

## 1. Why this matters

CFM's firewall logic is split across two layers:

- **`internal/firewall/backend.go`** — the `Backend` interface: *what* CFM needs from a firewall, in implementation-neutral terms.
- **`internal/firewall/nft/`** — the `nft.Backend` concrete type: *how* nftables does it, using `exec.Command("nft", ...)` subprocess calls.

The idea is correct. The execution is incomplete. Only ~14 of the ~45 public methods on `nft.Backend` are declared in the interface. The remaining ~31 are reached through type assertions, direct `nft.New()` calls, and a mini-interface in `internal/dnat/cli.go` that was added specifically to avoid touching `firewall.Backend`.

This means:

- Every new caller of a missing method has to write a type-assertion workaround.
- Swapping the engine (netlink library instead of subprocess, or pf for BSD) requires touching every workaround site.
- A production fork-storm incident was caused by `nft` subprocess spawning; the fix is a batch-write API that already exists on `nft.Backend` but is unreachable through the interface.

**The fix is Phase 1**: complete the interface so that `nft.Backend` satisfies it fully, remove all workarounds, and let the architecture do what it was designed to do. Zero behaviour change, zero risk.

The firewall backend Phase 1 also unblocks Phase 2 (nftlib) which fixes the fork storm — a production incident that already happened once. 
That's not hypothetical future-proofing, it's patching a known failure mode.
One more concrete reason: the scanner work touches internal/agent/agent.go and cmd/cfm/main.go — the same files that need to be clean for the firewall backend refactor. 
Do the refactor first so those files are in good shape when the scanner wiring lands.

---

## 2. Current state — the problem in detail

### 2a. Methods in the interface (14)

```
EnsureBase()
AddBlock / RemoveBlock / ListBlocks
AddAllow / RemoveAllow / ListAllows
AddBlockNet / RemoveBlockNet
AddAllowNet / RemoveAllowNet
AddIgnore / RemoveIgnore / AddIgnoreNet / RemoveIgnoreNet
AddChallenge / RemoveChallenge
ReportBlock
```

### 2b. Methods on nft.Backend NOT in the interface (~31)

These are the gaps. Grouped by what they do:

**Lifecycle**
```
DropEverything() error
ResetTable() error
ResetCFMTable() error
```

**Challenge redirect** (DNAT)
```
SetChallengeDNATEnabled(enabled bool)
CleanupChallengeDNAT() error
EnsureChallengeRedirect(httpListen, httpsListen string) error
```

**Policy application**
```
ApplyPortsPolicy(cfg *config.PortsConfig) error
ApplyFloodRules(cfg *config.Config) error
ApplyHardeningRules(cfg *config.Config) error
ApplyConnlimit(rules []config.ConnlimitRule) error
ApplyPortFlood(rules []config.PortFloodRule) error
ApplySMTPBlock(cfg *config.SMTPBlockConfig) error
ApplyOutboundObserve(cfg *config.OutboundConfig) error
```

**External feed management**
```
ApplyFeed(ctx context.Context, f blocklists.Feed, res *blocklists.FetchResult) error
RebuildExternalUnions() error
RemoveFeedByKey(feedKey string) error
PruneExternalFeeds(activeKeys []string) error
```

**Bulk / set operations**
```
AddElementsBulk(setName string, elems []string, ttl *time.Duration) error
ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) error
RemoveBlockBatch(ips []net.IP) error
EnsureSetDynamic(name string, v6 bool, isNet bool) error
DeleteSetIfExists(name string) error
HasElem(setName, elem string) (bool, error)
ListSetElementsRaw(setName string) ([]string, error)
```

**Diagnostics**
```
DumpFloodCounters()
DumpThrottledIPs()
LoadPortScanner()
```

**Wiring**
```
SetEnricher(e *enrich.Enricher)
GetEnricher() *enrich.Enricher
SetReporter(r reporting.Reporter)
SetChallengeLogger(f func(format string, args ...any))
```

**DNAT CLI** (currently behind a separate `dnat.Capable` mini-interface)
```
DNATStatus(family, table string) (bool, error)
DNATShow(family, table string) (string, error)
DNATOn(family, table string, httpPort, httpsPort int) error
DNATOff(family, table string) error
```

### 2c. The workarounds these gaps produce

**`internal/detectors/webdetector_register.go` lines 185–187, 548–550:**
```go
// CURRENT — type assertions because the interface is incomplete
if t, ok := any(fwBackend).(interface{ SetChallengeDNATEnabled(bool) }); ok {
    t.SetChallengeDNATEnabled(false)
} else if t, ok := any(fwBackend).(interface{ CleanupChallengeDNAT() error }); ok {
    _ = t.CleanupChallengeDNAT()
}
```

**`internal/dnat/cli.go` lines 18–25:**
```go
// CURRENT — mini-interface created specifically to avoid touching firewall.Backend
// "We do NOT force firewall.Backend interface changes."
type Capable interface {
    DNATStatus(family, table string) (bool, error)
    DNATShow(family, table string) (string, error)
    DNATOn(family, table string, httpPort, httpsPort int) error
    DNATOff(family, table string) error
}
```

**`internal/status/status.go` line 479:**
```go
// CURRENT — bypasses the Backend abstraction entirely, hardcodes nft
if on, err := dnat.Status(nft.New()); err == nil && on {
```

**`cmd/cfm/main.go` getBackend():**
```go
// CURRENT — only returns nft or nil; no path for future backends
func getBackend() firewall.Backend {
    if _, ok := cli.LookPath("nft"); ok {
        return nft.New()
    }
    return nil
}
```

---

## 3. The Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Callers (detectors, autoblock_sink, apiserver, CLI, agent) │
│  — they hold a  firewall.Backend  and call methods on it    │
│  — they NEVER import  internal/firewall/nft  directly       │
└─────────────────────────┬───────────────────────────────────┘
                          │  firewall.Backend interface
           ┌──────────────┼──────────────┬──────────────────┐
           ▼              ▼              ▼                  ▼
    ┌─────────────┐ ┌──────────────┐ ┌────────┐   ┌──────────────┐
    │  nft/       │ │  nftlib/     │ │  pf/   │   │  mock/       │
    │  (Phase 1)  │ │  (Phase 2)   │ │ (Ph.3) │   │  (tests)     │
    │  exec nft   │ │  go netlink  │ │  BSD   │   │              │
    └─────────────┘ └──────────────┘ └────────┘   └──────────────┘

  "Backend" = the vocabulary (what)
  "Engine"  = the translation (how)
```

The vocabulary is in `internal/firewall/backend.go`. Every engine file is an independent `package` that imports `firewall` and declares its struct as satisfying `firewall.Backend`. Callers only import `firewall`, never any engine package directly.

---

## 4. Phase 1 — Complete the interface (nft exec, no behaviour change)

Phase 1 is a **pure refactor**. `nft.Backend` already implements everything. We are not adding new code — we are promoting existing code into the interface so it is reachable without type assertions.

**Status note (2026-04-29):** Phase 1 completed. This was a refactor-only milestone: production default remains the nft **shell** backend and runtime behavior is unchanged.

**Checklist:**
- [x] full backend contract exposed through `firewall.Backend`
- [x] type-assertion workarounds removed
- [x] `dnat.Capable` removed/merged into backend surface
- [x] direct `nft.New()` escapes removed except intended selector path
- [x] compile-time assertion for nft backend conformance
- [x] backend selector skeleton in `cmd/cfm/main.go` with nft default

**Verification summary (2026-04-29):**
- `exec.Command("nft", ...)` usage is confined to `internal/firewall/nft/*`.
- Only selector/wiring paths import the concrete `internal/firewall/nft` package.
- `nft.New()` appears only in the selector path.

**Phase 1.5 (hardening while keeping nft shell backend as default):**
- [ ] Shell backend hardening: enforce timeouts and centralized command runner for all nft subprocess execution.
- [ ] Shell backend concurrency controls: lock/serialize high-volume mutation paths to reduce process pressure.
- [ ] Add targeted stress/regression coverage for large feed updates and concurrent applies.

**Phase 2 (new engine, opt-in):**
- [ ] Introduce `internal/firewall/nftlib` backend (`github.com/google/nftables`, netlink-based).
- [ ] Add experimental wiring/selection path for `nftlib` while keeping nft shell as production default.
- [ ] Validate parity for DNAT/challenge redirect, feed management, and bulk set operations.

### Phase 2 operation/owner matrix (planned split)

| Operation group | Backend operations | Phase 2 engine owner | Required guardrails |
|---|---|---|---|
| Base lifecycle + list primitives | `EnsureBase`, `ResetTable`, `List*` reads, JSON/text dump helpers | **nftlib** | Use transaction-style `Flush` boundaries and normalized wrapped errors (include table/set/op context). |
| Manual element writes (single + batch) | `AddBlock`, `RemoveBlock`, `AddAllow`, `RemoveAllow`, `RemoveBlockBatch`, `Add*Net`, `Remove*Net`, `AddIgnore*`, `RemoveIgnore*`, `AddChallenge`, `RemoveChallenge` | **nftlib** | Batch related mutations in one transaction when possible; return typed errors for parse/not-found/conflict classes. |
| Set/bulk operations | `EnsureSetDynamic`, `DeleteSetIfExists`, `ReplaceSetFlushAdd`, `AddElementsBulk`, `HasElem`, `ListSetElementsRaw`, `FlushSet` | **nftlib** | Prefer single netlink transaction per batch apply; fail closed on partial mutation; emit deterministic error envelopes. |
| Feed lifecycle | `ApplyFeed`, `RebuildExternalUnions`, `PruneExternalFeeds`, `DropFeedSets`, `RemoveFeedByKey` | **nftlib** | Transaction boundary per feed generation; rollback/retry strategy for interrupted set replace. |
| Policy/rules programming | `ApplyFloodRules`, `ApplyHardeningRules`, `ApplyPortsPolicy`, `ApplyConnlimit`, `ApplyPortFlood`, `ApplySMTPBlock`, `ApplyOutboundObserve` | **hybrid: nftcli (initial)** | Keep existing command timeout and backpressure protections (bounded workers/serialization) until rule synthesis reaches nftlib parity. |
| Challenge redirect/DNAT control | `SetChallengeRedirectEnabled`, `CleanupChallengeRedirect`, `EnsureChallengeRedirect`, `DNATStatus`, `DNATShow`, `DNATOn`, `DNATOff` | **hybrid: nftcli (initial)** | Keep timeout + retry/backpressure controls on subprocess calls; preserve idempotent cleanup semantics. |
| Reporting/wiring | `SetConfigDir`, `EnableEnrichment`, `GetEnricher`, `SetReporter`, `SetChallengeLogger`, `ReportBlock`, `LoadPortScanner`, dumps | **non-engine (shared)** | No engine split; preserve thread-safety and nil-safe adapters. |

**Standards for Phase 2 execution paths**
- **Any operation still on nftcli must keep timeout and backpressure protections** (central command runner, bounded concurrency, cancellation propagation).
- **Any operation owned by nftlib must adopt transaction + error-handling standards**:
  - Group logically-related netlink changes into a single commit boundary.
  - Wrap all errors with operation metadata (`op`, `family`, `table`, `chain/set`, `attempt`).
  - Distinguish retryable netlink interruption/resource pressure from non-retryable semantic errors.
  - Reject silent partial success; either commit the whole unit or surface explicit degraded-state errors.

**What remains (concise):**
- Shell backend hardening (timeouts, runner centralization, locking).
- nftlib backend introduction plus experimental wiring.
- Optional hybrid model and future pf backend.

### 4a. The full Backend interface

**`internal/firewall/backend.go` — replace entirely:**

```go
package firewall

import (
    "context"
    "net"
    "time"

    "cfm/internal/blocklists"
    "cfm/internal/config"
    "cfm/internal/enrich"
    "cfm/internal/reporting"
)

// BlockedEntry is a shared return type for listing set contents.
type BlockedEntry struct {
    IP      net.IP
    Expires *time.Time
    Comment string
}

// Backend is the complete vocabulary CFM uses to communicate with a firewall.
//
// Method groups:
//   1. Lifecycle        — create/destroy CFM-owned firewall state
//   2. IP / net         — block, allow, ignore, challenge individual IPs and CIDRs
//   3. Policy           — apply structured config to the firewall ruleset
//   4. Challenge redir  — redirect HTTP/S for challenged IPs to the challenge server
//   5. Feed management  — named sets populated from external blocklist feeds
//   6. Bulk / sets      — batch writes and set inspection
//   7. Diagnostics      — counters, throttle dumps, portscan loader
//   8. Wiring           — enricher, reporter, logger injection
//
// All method names are implementation-neutral. An nftables backend
// implements "challenge redirect" with DNAT prerouting rules; a pf backend
// would use rdr-to anchors; both satisfy the same method signatures.
type Backend interface {

    // ── 1. Lifecycle ─────────────────────────────────────────────────────────

    // EnsureBase creates all tables, chains, and sets owned by CFM.
    // Idempotent — safe to call on every daemon start.
    EnsureBase() error

    // DropEverything removes all CFM-owned firewall state.
    // Used on clean uninstall or forced reset.
    DropEverything() error

    // ResetTable flushes and rebuilds all rules from current in-memory config.
    // Called after a reload that changes flood/port/hardening policy.
    ResetTable() error

    // ── 2. IP / net management ───────────────────────────────────────────────

    // Block: drop all traffic from this IP (or subnet).
    AddBlock(ip net.IP, comment string, ttl *time.Duration) error
    RemoveBlock(ip net.IP) error
    RemoveBlockBatch(ips []net.IP) error
    ListBlocks() ([]BlockedEntry, error)

    AddBlockNet(cidr string, ttl *time.Duration) error
    RemoveBlockNet(cidr string) error

    // Allow: bypass all CFM enforcement rules for this IP (or subnet).
    AddAllow(ip net.IP, ttl *time.Duration) error
    RemoveAllow(ip net.IP) error
    ListAllows() ([]BlockedEntry, error)

    AddAllowNet(cidr string, ttl *time.Duration) error
    RemoveAllowNet(cidr string) error

    // Ignore: let traffic through but still log / notify / report.
    AddIgnore(ip net.IP, ttl *time.Duration) error
    RemoveIgnore(ip net.IP) error
    AddIgnoreNet(cidr string, ttl *time.Duration) error
    RemoveIgnoreNet(cidr string) error

    // Challenge: redirect this IP to the interactive proof-of-work server.
    AddChallenge(ip net.IP, ttl *time.Duration) error
    RemoveChallenge(ip net.IP) error

    // ── 3. Policy application ────────────────────────────────────────────────
    //
    // These express *what* policy to enforce; the implementation decides *how*.
    //   nftables exec : nft add rule inet cfm ...
    //   nftlib        : conn.AddRule(...)
    //   pf            : pfctl -a cfm/ports -f -
    //
    // ApplyPortsPolicy installs the TCP/UDP IN/OUT allowlist.
    ApplyPortsPolicy(cfg *config.PortsConfig) error

    // ApplyFloodRules installs per-packet-rate and new-connection-rate limits.
    ApplyFloodRules(cfg *config.Config) error

    // ApplyHardeningRules installs stateless packet filtering:
    // bad TCP flags (NULL/XMAS/SYN+FIN/SYN+RST), ICMP rate limiting, etc.
    ApplyHardeningRules(cfg *config.Config) error

    // ApplyConnlimit installs per-port concurrent-connection limits per source IP.
    ApplyConnlimit(rules []config.ConnlimitRule) error

    // ApplyPortFlood installs per-port new-connection rate limits per source IP.
    ApplyPortFlood(rules []config.PortFloodRule) error

    // ApplySMTPBlock restricts outbound SMTP to explicitly allowed UIDs/GIDs.
    // nftables: skuid/skgid match. pf: authpf anchor or tagged rules.
    ApplySMTPBlock(cfg *config.SMTPBlockConfig) error

    // ApplyOutboundObserve installs per-UID outbound traffic observation.
    // Linux/nftables: NFLOG chain. BSD/pf: pflog interface + bpf tap.
    // Returns nil if the platform supports the mechanism, error otherwise.
    ApplyOutboundObserve(cfg *config.OutboundConfig) error

    // ── 4. Challenge redirect ────────────────────────────────────────────────
    //
    // "When an IP is in the challenge set, redirect its HTTP/HTTPS to
    //  the challenge listener."
    //
    // nftables: DNAT prerouting rules.
    // pf:       rdr-to rules in a cfm anchor.
    // In-path (OpenResty/Angie bridge mode): no-op — the bridge handles it.

    // EnsureChallengeRedirect installs (or repairs) the redirect rules
    // pointing challenged traffic at httpListen / httpsListen.
    // Idempotent. Called periodically as a self-healing watchdog.
    EnsureChallengeRedirect(httpListen, httpsListen string) error

    // SetChallengeRedirectEnabled enables or disables the redirect mechanism.
    // In OpenResty/Angie in-path mode the webdetector calls this with false
    // so DNAT rules are not installed (the bridge owns the decision path).
    SetChallengeRedirectEnabled(enabled bool)

    // CleanupChallengeRedirect removes all challenge redirect rules and sets.
    CleanupChallengeRedirect() error

    // DNAT CLI surface — used by `cfm webtop dnat` and status reporting.
    // Names kept as-is for CLI compatibility; in-path backends return
    // (false, nil) for Status and no-op for On/Off.
    DNATStatus(family, table string) (bool, error)
    DNATShow(family, table string) (string, error)
    DNATOn(family, table string, httpPort, httpsPort int) error
    DNATOff(family, table string) error

    // ── 5. External feed management ──────────────────────────────────────────

    // ApplyFeed installs one external blocklist/allowlist feed result
    // into dedicated named sets.
    ApplyFeed(ctx context.Context, f blocklists.Feed, res *blocklists.FetchResult) error

    // RebuildExternalUnions refreshes the union sets that merge all active
    // feed sets into a single block_ext_v4 / block_ext_v6 set pair.
    RebuildExternalUnions() error

    // RemoveFeedByKey removes all sets belonging to a feed that has been
    // deleted from the config.
    RemoveFeedByKey(feedKey string) error

    // PruneExternalFeeds removes sets for feeds not in activeKeys.
    // Called after config reload to clean up stale feed data.
    PruneExternalFeeds(activeKeys []string) error

    // ── 6. Bulk / set operations ─────────────────────────────────────────────

    // AddElementsBulk adds a large list of IPs/CIDRs to a named set in
    // batches. The implementation decides the batch size.
    AddElementsBulk(setName string, elems []string, ttl *time.Duration) error

    // ReplaceSetFlushAdd atomically flushes a set and repopulates it.
    // Used by blocklist applier to replace a feed set in one operation.
    ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) error

    // EnsureSetDynamic creates a named dynamic set if it does not exist.
    // v6=true creates an IPv6 set; isNet=true creates a prefix (CIDR) set.
    EnsureSetDynamic(name string, v6 bool, isNet bool) error

    // DeleteSetIfExists removes a named set, ignoring "not found" errors.
    DeleteSetIfExists(name string) error

    // HasElem returns true if elem is currently in setName.
    HasElem(setName, elem string) (bool, error)

    // ListSetElementsRaw returns all elements of a named set as strings.
    ListSetElementsRaw(setName string) ([]string, error)

    // ── 7. Diagnostics ───────────────────────────────────────────────────────

    // DumpFloodCounters prints current PPS / new-connection counter values.
    DumpFloodCounters()

    // DumpThrottledIPs prints IPs currently in the throttle tracking sets.
    DumpThrottledIPs()

    // LoadPortScanner starts the portscan detection goroutine.
    LoadPortScanner()

    // ── 8. Wiring ────────────────────────────────────────────────────────────

    SetEnricher(e *enrich.Enricher)
    GetEnricher() *enrich.Enricher
    SetReporter(r reporting.Reporter)
    SetChallengeLogger(f func(format string, args ...any))

    // ReportBlock centralises policy-aware API reporting.
    // source: "detector" | "autoblock" | "manual"
    // mode:   "ttl" | "permanent" | "dryrun"
    ReportBlock(ip, comment, source, mode string, ttlSeconds int) error
}
```

### 4b. Files that change

**`internal/firewall/nft/nft.go`** — two method renames only:

```go
// BEFORE
func (b *Backend) SetChallengeDNATEnabled(enabled bool) { ... }
func (b *Backend) CleanupChallengeDNAT() error          { ... }

// AFTER — implementation-neutral names; internal variable names unchanged
func (b *Backend) SetChallengeRedirectEnabled(enabled bool) { ... }
func (b *Backend) CleanupChallengeRedirect() error          { ... }
```

**`internal/firewall/nft/nft.go`** — add a compile-time assertion after the imports.
This makes the compiler tell you immediately if the interface grows and `nft.Backend` falls behind:

```go
// Compile-time check: nft.Backend must satisfy firewall.Backend.
// If this line fails to compile, a method is missing from one or the other.
var _ firewall.Backend = (*Backend)(nil)
```

Place this immediately after the import block, before the first type declaration.

**`internal/dnat/cli.go`** — the `Capable` mini-interface is now redundant.
Replace it with a direct reference to the main interface:

```go
// BEFORE — mini-interface workaround
// "We do NOT force firewall.Backend interface changes."
type Capable interface {
    DNATStatus(family, table string) (bool, error)
    DNATShow(family, table string) (string, error)
    DNATOn(family, table string, httpPort, httpsPort int) error
    DNATOff(family, table string) error
}

// AFTER — use the main interface directly
// dnat.Capable was a workaround for an incomplete firewall.Backend.
// Now that firewall.Backend includes the DNAT surface, use it directly.
// All callers of dnat CLI functions pass firewall.Backend.
import "cfm/internal/firewall"

// Any function that previously accepted dnat.Capable now accepts firewall.Backend.
// Example:
func Status(be firewall.Backend) (bool, error) {
    return be.DNATStatus("ip", "nat")
}
```

### 4c. Removing the type-assertion workarounds

**`internal/detectors/webdetector_register.go`** — both occurrences (lines ~185 and ~548):

```go
// BEFORE — type assertion because interface was incomplete
if fwBackend != nil {
    if t, ok := any(fwBackend).(interface{ SetChallengeDNATEnabled(bool) }); ok {
        t.SetChallengeDNATEnabled(false)
    } else if t, ok := any(fwBackend).(interface{ CleanupChallengeDNAT() error }); ok {
        _ = t.CleanupChallengeDNAT()
    }
}

// AFTER — direct call through the interface
if fwBackend != nil {
    fwBackend.SetChallengeRedirectEnabled(false)
}
```

And the `EnsureChallengeRedirect` assertion in `webdetector_register.go`:

```go
// BEFORE
cr, ok := any(fwBackend).(interface {
    EnsureChallengeRedirect(httpListen, httpsListen string) error
})
if !ok {
    logging.Logf("[webdetector] firewall backend does not support EnsureChallengeRedirect")
    return
}
if err := cr.EnsureChallengeRedirect(w.cfg.ChallengeHTTPListen, w.cfg.ChallengeHTTPSListen); err != nil {

// AFTER — it's in the interface, just call it
if err := fwBackend.EnsureChallengeRedirect(
    w.cfg.ChallengeHTTPListen,
    w.cfg.ChallengeHTTPSListen,
); err != nil {
```

### 4d. Fixing the direct nft.New() escapes

**`internal/status/status.go` line 479:**

```go
// BEFORE — hardcodes nft, bypasses Backend abstraction entirely
if on, err := dnat.Status(nft.New()); err == nil && on {

// AFTER — status.go needs a reference to the running backend.
// Wire it at startup via a package-level setter (same pattern as apiserver):
var statusBackend firewall.Backend

func SetBackend(be firewall.Backend) { statusBackend = be }

// Then in the status check:
if statusBackend != nil {
    if on, err := statusBackend.DNATStatus("ip", "nat"); err == nil && on {
```

**`cmd/cfm/main.go` `getBackend()`:**

```go
// BEFORE — returns nft or nil; no path for alternative engines
func getBackend() firewall.Backend {
    if _, ok := cli.LookPath("nft"); ok {
        return nft.New()
    }
    return nil
}

// AFTER — selects engine based on config or environment variable.
// CFM_FIREWALL_ENGINE=nft (default) | nftlib | pf
// The nftlib and pf cases are stubs that return nil until those
// packages are implemented (Phases 2 and 3).
func getBackend() firewall.Backend {
    engine := strings.ToLower(strings.TrimSpace(os.Getenv("CFM_FIREWALL_ENGINE")))
    if engine == "" {
        engine = "nft" // default
    }
    switch engine {
    case "nft":
        if _, ok := cli.LookPath("nft"); ok {
            return nft.New()
        }
        logging.Logf("[firewall] nft binary not found; firewall disabled")
        return nil
    case "nftlib":
        // Phase 2: return nftlib.New()
        logging.Logf("[firewall] nftlib engine not yet implemented")
        return nil
    case "pf":
        // Phase 3: return pf.New()
        logging.Logf("[firewall] pf engine not yet implemented")
        return nil
    default:
        logging.Logf("[firewall] unknown engine %q; falling back to nft", engine)
        return nft.New()
    }
}
```

---

## 5. Phase 2 — nftlib backend (google/nftables netlink)

> **Pre-requisite:** Phase 1 complete and merged. The interface is the contract;
> this phase is an alternative implementation of it.

### 5a. Why bother

The exec-based `nft.Backend` works. The production reason to add an alternative:

**The fork storm.** When CFM applies a large blocklist (thousands of IPs after a feed update), `nft.Backend` calls `exec.Command("nft", ...)` per batch. Each call is a fork+exec of the `nft` binary. Under load this produces hundreds of concurrent child processes, saturating the fork table and triggering OOM behaviour. This happened in production.

`github.com/google/nftables` communicates directly over a netlink socket — no subprocess, no fork. All operations are accumulated in a `nftables.Conn` and flushed in a single kernel roundtrip with `conn.Flush()`. A 10,000-IP blocklist becomes one syscall.

|  | nft exec | nftlib netlink |
|---|---|---|
| Fork per batch | Yes | No |
| Fork storm risk | Yes (production incident) | None |
| Batch as one kernel op | No (multiple execs) | Yes (`conn.Flush()`) |
| `nft` binary required | Yes | No |
| Rule expression | Readable nft text | Go struct trees |
| Error type | Parse text stderr | Structured Go error |
| Debug | `nft list ruleset` | Same, plus `nft monitor` |

### 5b. New package layout

```
internal/firewall/
  backend.go          ← the interface (Phase 1 — complete)
  nft/                ← exec-based, current default (Phase 1 — no change)
    nft.go
    nft_hardening.go
    nft_rules.go
    ports.go
    smtpblock.go
    outbound.go
    dnat.go
    blocklists_applier.go
  nftlib/             ← netlink-based, Phase 2 (new directory)
    backend.go        ← struct, New(), compile-time assertion
    sets.go           ← AddBlock, AddAllow, bulk operations
    policy.go         ← ApplyFloodRules, ApplyHardeningRules, ApplyConnlimit, etc.
    feeds.go          ← ApplyFeed, RebuildExternalUnions, etc.
    challenge.go      ← EnsureChallengeRedirect (DNAT via netlink)
    dnat.go           ← DNATStatus, DNATOn, DNATOff
    diagnostics.go    ← DumpFloodCounters, LoadPortScanner
    wiring.go         ← SetEnricher, SetReporter, etc.
```

### 5c. Example: AddBlock via netlink vs exec

**Current `nft.Backend.AddBlock` (exec):**

```go
// internal/firewall/nft/nft.go
func (b *Backend) AddBlock(ip net.IP, comment string, ttl *time.Duration) error {
    set := setV4
    if ip.To4() == nil {
        set = setV6
    }
    if ttl != nil {
        ttlStr := humanTimeout(*ttl)
        return b.nftExpr(fmt.Sprintf(
            `add element inet cfm %s { %s timeout %s }`, set, ip, ttlStr,
        ))
    }
    return b.nftExpr(fmt.Sprintf(`add element inet cfm %s { %s }`, set, ip))
}

// nftExpr shells out:
func (b *Backend) nftExpr(expr string) error {
    cmd := exec.Command("nft", "-f", "-")   // fork + exec
    cmd.Stdin = strings.NewReader(expr + "\n")
    ...
}
```

**Future `nftlib.Backend.AddBlock` (netlink):**

```go
// internal/firewall/nftlib/sets.go
func (b *Backend) AddBlock(ip net.IP, comment string, ttl *time.Duration) error {
    b.mu.Lock()
    defer b.mu.Unlock()

    set := b.setBlockV4
    if ip.To4() == nil {
        set = b.setBlockV6
    }

    elem := nftables.SetElement{Key: normalizeIP(ip)}
    if ttl != nil {
        elem.Timeout = *ttl
    }

    if err := b.conn.SetAddElements(set, []nftables.SetElement{elem}); err != nil {
        return fmt.Errorf("AddBlock %s: %w", ip, err)
    }
    return b.conn.Flush()   // single netlink roundtrip — no fork
}
```

The caller (`autoblock_sink.go`, `webdetector_register.go`, etc.) calls `fwBackend.AddBlock(...)` — identical regardless of which backend is wired.

### 5d. Example: AddElementsBulk — the fork-storm fix

This is the most important method for production stability.

**Current `nft.Backend.AddElementsBulk`:**

```go
// internal/firewall/nft/nft.go
func (b *Backend) AddElementsBulk(setName string, elems []string, ttl *time.Duration) error {
    return b.nftAddElementsExpr(setName, elems, ttlStr, batchSize)
    // nftAddElementsExpr loops, calling nftExpr() per batch
    // Each nftExpr() = one fork of "nft -f -"
    // 10,000 IPs in batches of 500 = 20 fork+exec calls
    // Under concurrent load from multiple feed updates = fork storm
}
```

**Future `nftlib.Backend.AddElementsBulk`:**

```go
// internal/firewall/nftlib/sets.go
func (b *Backend) AddElementsBulk(setName string, elems []string, ttl *time.Duration) error {
    b.mu.Lock()
    defer b.mu.Unlock()

    set := b.namedSet(setName) // look up nftables.Set by name

    var nftElems []nftables.SetElement
    for _, e := range elems {
        ip := net.ParseIP(strings.TrimSpace(e))
        if ip == nil {
            continue
        }
        elem := nftables.SetElement{Key: normalizeIP(ip)}
        if ttl != nil {
            elem.Timeout = *ttl
        }
        nftElems = append(nftElems, elem)
    }

    if err := b.conn.SetAddElements(set, nftElems); err != nil {
        return fmt.Errorf("AddElementsBulk %s (%d elems): %w", setName, len(nftElems), err)
    }
    return b.conn.Flush()
    // All 10,000 IPs sent in one netlink message. Zero forks.
}
```

### 5e. Wiring the selection in main.go

After Phase 2 is complete, `main.go` becomes:

```go
import (
    "cfm/internal/firewall"
    "cfm/internal/firewall/nft"
    "cfm/internal/firewall/nftlib"
)

func getBackend() firewall.Backend {
    engine := strings.ToLower(strings.TrimSpace(os.Getenv("CFM_FIREWALL_ENGINE")))
    if engine == "" {
        engine = "nft" // exec-based default — no change for existing deployments
    }
    switch engine {
    case "nft":
        if _, ok := cli.LookPath("nft"); !ok {
            logging.Logf("[firewall] nft binary not found")
            return nil
        }
        return nft.New()
    case "nftlib":
        return nftlib.New()  // no nft binary required
    case "pf":
        // Phase 3
        logging.Logf("[firewall] pf engine not yet implemented")
        return nil
    default:
        logging.Logf("[firewall] unknown engine %q, using nft", engine)
        return nft.New()
    }
}
```

**Zero changes to anything above `getBackend()`**. The agent, detectors, autoblock sink, webdetector, apiserver, CLI — all hold `firewall.Backend` and are unaffected.

---

## 6. Phase 3 — pf backend (BSD, future)

> **Pre-requisite:** Phase 1 complete. Phase 2 is not a prerequisite — pf can
> be implemented independently.

BSD's `pf` does not have nftables sets or NFLOG, but every concept in the interface has a pf equivalent.

```
internal/firewall/pf/
  backend.go     ← struct, New(), compile-time assertion
  sets.go        ← pfctl tables for block/allow
  policy.go      ← pf.conf anchor generation
  challenge.go   ← rdr-to rules instead of DNAT
  outbound.go    ← pflog interface + bpf instead of NFLOG
  ...
```

**Method mapping, nftables → pf:**

| Backend method | nftables implementation | pf implementation |
|---|---|---|
| `AddBlock` | `add element inet cfm block_v4 { ip }` | `pfctl -t cfm_block -T add ip` |
| `AddBlockNet` | `add element inet cfm block_v4_nets { cidr }` | `pfctl -t cfm_block_net -T add cidr` |
| `ApplyPortsPolicy` | `nft -f` with set of port ranges | Generate `pass in proto tcp to port { ... }` pf anchor rules |
| `ApplyHardeningRules` | `tcp flags & (syn|fin) == (syn|fin) drop` | `block in quick proto tcp flags SF/SFRA` in pf anchor |
| `ApplySMTPBlock` | `skuid != allowedUIDs drop` outbound chain | `authpf` anchor or `block out proto tcp to port 25 !user { uid }` |
| `ApplyOutboundObserve` | nftables NFLOG chain → user-space NFLOG | pflog interface + bpf tap → user-space capture |
| `EnsureChallengeRedirect` | DNAT prerouting: `dnat to 127.0.0.1:port` | `rdr pass on em0 proto tcp to port 80 -> 127.0.0.1 port 8080` |
| `SetChallengeRedirectEnabled` | flush/recreate DNAT chain | flush/recreate rdr anchor |
| `DNATOn` | `nft add rule inet nat prerouting ...` | `echo "rdr-to ..." \| pfctl -a cfm/dnat -f -` |
| `DNATOff` | flush the nat prerouting chain | `pfctl -a cfm/dnat -F rules` |
| `AddElementsBulk` | `nft add element` batch | `pfctl -t tablename -T add ip1 ip2 ...` (pf tables are bulk-native) |
| `DumpFloodCounters` | `nft list counters` | `pfctl -s rules -vv` |

**Compile-time assertion in `pf/backend.go`:**

```go
// Ensures pf.Backend satisfies the interface at compile time.
// Any missing method causes a build error here, not a runtime panic.
var _ firewall.Backend = (*Backend)(nil)
```

---

## 7. Compatibility contract

Any implementation of `firewall.Backend` must follow these rules:

**Idempotency.** `EnsureBase()`, `EnsureChallengeRedirect()`, all `Apply*` methods, and `EnsureSetDynamic()` must be safe to call multiple times with the same arguments. Re-running them should produce the same state, not errors.

**AddBlock on an already-blocked IP must not error.** The autoblock sink calls `AddBlock` without pre-checking; if the IP is already blocked (from a previous daemon run), the method must update the TTL or no-op — not return an error.

**`DropEverything` is destructive.** It removes all CFM-owned rules and sets. It is only called on clean uninstall. It must not affect rules/sets owned by other software (CSF, Imunify, stock firewalld rules).

**`SetChallengeRedirectEnabled(false)` must be safe to call before `EnsureChallengeRedirect`.** The webdetector calls this on startup in OpenResty mode before any redirect rules have been created. The implementation must tolerate this gracefully (no error, nothing to remove).

**Bulk operations prefer all-or-nothing.** `AddElementsBulk` and `ReplaceSetFlushAdd` should apply all elements or none (atomic batch). If the underlying mechanism does not support atomic batches, the implementation must document this.

**DNAT methods on in-path backends.** When OpenResty/Angie in-path mode is active, `DNATOn/Off` are no-ops (the bridge handles decisions). `DNATStatus` returns `(false, nil)`. This is not an error condition.

---

## 8. Progress tracking

### Phase 1 — Complete the interface

| Task | File | Status |
|---|---|---|
| Write full `Backend` interface | `internal/firewall/backend.go` | ☐ |
| Rename `SetChallengeDNATEnabled` → `SetChallengeRedirectEnabled` | `internal/firewall/nft/nft.go` | ☐ |
| Rename `CleanupChallengeDNAT` → `CleanupChallengeRedirect` | `internal/firewall/nft/nft.go` | ☐ |
| Add compile-time assertion `var _ firewall.Backend = (*Backend)(nil)` | `internal/firewall/nft/nft.go` | ☐ |
| Remove `SetChallengeDNATEnabled` type assertion (×2) | `internal/detectors/webdetector_register.go` | ☐ |
| Remove `EnsureChallengeRedirect` type assertion | `internal/detectors/webdetector_register.go` | ☐ |
| Replace `dnat.Capable` mini-interface with `firewall.Backend` | `internal/dnat/cli.go` | ☐ |
| Fix `dnat.Status(nft.New())` direct call | `internal/status/status.go` | ☐ |
| Add engine selector to `getBackend()` | `cmd/cfm/main.go` | ☐ |

### Phase 2 — nftlib backend

| Task | File | Status |
|---|---|---|
| Add `github.com/google/nftables` to go.mod | `go.mod` | ☐ |
| Create `nftlib/backend.go` with struct + `New()` + compile assertion | `internal/firewall/nftlib/backend.go` | ☐ |
| Implement IP/net management (sets) | `internal/firewall/nftlib/sets.go` | ☐ |
| Implement bulk operations (fork-storm fix) | `internal/firewall/nftlib/sets.go` | ☐ |
| Implement policy methods | `internal/firewall/nftlib/policy.go` | ☐ |
| Implement feed management | `internal/firewall/nftlib/feeds.go` | ☐ |
| Implement challenge redirect (DNAT via netlink) | `internal/firewall/nftlib/challenge.go` | ☐ |
| Implement DNAT CLI surface | `internal/firewall/nftlib/dnat.go` | ☐ |
| Implement diagnostics | `internal/firewall/nftlib/diagnostics.go` | ☐ |
| Implement wiring methods | `internal/firewall/nftlib/wiring.go` | ☐ |
| Wire `CFM_FIREWALL_ENGINE=nftlib` in `getBackend()` | `cmd/cfm/main.go` | ☐ |
| Integration test: apply blocklist, verify nft list | `internal/firewall/nftlib/*_test.go` | ☐ |

### Phase 3 — pf backend (BSD)

| Task | File | Status |
|---|---|---|
| Create `pf/backend.go` with struct + `New()` + compile assertion | `internal/firewall/pf/backend.go` | ☐ |
| Implement all interface methods using `pfctl` | `internal/firewall/pf/` | ☐ |
| Build tag: `//go:build freebsd \|\| openbsd` | all `pf/` files | ☐ |
| Wire `CFM_FIREWALL_ENGINE=pf` in `getBackend()` | `cmd/cfm/main.go` | ☐ |

---

## 9. Portability audit — Linux-specific features in current nft.Backend

This section documents every Linux/nftables-specific mechanism currently used in
`internal/firewall/nft/` and grades its portability to alternative backends
(pf/BSD, future eBPF, hypothetical next-generation systems). Used as a reference
when implementing Phase 3 and beyond.

**Grades:**
- ✅ **Ports cleanly** — concept exists, syntax differs, direct translation
- ⚠️ **Ports with work** — concept exists but mechanism is significantly different
- ❌ **No direct equivalent** — requires redesign or user-space workaround

---

### 9a. Feature inventory

#### `ct state` — conntrack state matching
**Used in:** `nft.go` (block rules on established/related), `nft_rules.go` (ConnLimit, PortFlood, PortScanner)

```nft
# nftables
ct state established,related ip saddr @block_v4 drop
ct state new tcp dport 80 meter cl_80_v4 { ip saddr ct count over 20 } drop
```

**Grade: ✅ Ports cleanly to pf**

pf has native stateful tracking. Direct translation:
```pf
# pf
block in quick proto tcp from <cfm_block> flags S/SA
pass in proto tcp to port 80 flags S/SA keep state (max-src-conn 20, ...)
```
The connection-count limit (`ct count over N`) maps to pf's `max-src-conn N` in a
`pass` rule's state options. Semantics are close enough.

**Future eBPF note:** eBPF conntrack maps (`BPF_MAP_TYPE_SK_STORAGE`, or reading
`/proc/net/nf_conntrack`) can replicate this, but it is non-trivial. eBPF is not
a concern for the near term.

---

#### `meter` — per-IP stateful rate limiting
**Used in:** `nft_rules.go` (PortFlood, ConnLimit, PPS, SYN rate)

```nft
# nftables — token bucket per source IP, kernel-maintained
meter pf_80_v4 { ip saddr limit rate over 100/second burst 200 packets } drop
meter cl_80_v4 size 65535 { ip saddr ct count over 20 } drop
```

Meters are a first-class nftables data structure: a kernel-side hash map keyed
by source IP, storing per-IP rate/count state. No subprocess, no user space —
the kernel enforces the limit inline.

**Grade: ⚠️ Ports with work to pf**

pf has per-source rate limiting via state options, but the model differs:

```pf
# pf — per-source connection rate in pass rules
pass in proto tcp to port 80 flags S/SA keep state \
    (max-src-conn-rate 100/1, overload <cfm_throttled> flush global)
```

The `overload <table>` mechanism adds the offending IP to a pf table, from which
you then block it. The token-bucket burst semantics of `meter` are not directly
replicable — pf uses connection-rate windows, not packets-per-second burst.

**For a pf backend:** `ApplyPortFlood` and `ApplyConnlimit` need to generate
`pass ... keep state (max-src-conn-rate ..., overload <t> flush)` rules and
manage the overload tables. The Go side reads the overload table and calls
`AddBlock` on those IPs rather than having the kernel auto-drop. Slightly more
user-space involvement than the current nft approach but functionally equivalent.

**Future concern:** if nftables ever deprecates the `meter` keyword in favour of
something else (there has been upstream discussion), the nftlib backend isolates
this change to one package.

---

#### `meta skuid` / `meta skgid` — socket owner UID/GID matching
**Used in:** `smtpblock.go` (SMTP allow by UID/GID), `outbound.go` (skip root traffic)

```nft
# nftables — match outbound packets by the Linux UID/GID that owns the socket
meta skuid 0 return
meta skuid @smtp_allow_uids tcp dport @smtp_ports accept
meta skgid @smtp_allow_gids tcp dport @smtp_ports accept
```

This is a Linux kernel feature: the `sk_uid` / `sk_gid` fields on a socket's
`struct sock`. The network stack can match these at the OUTPUT hook because the
socket is still attached to the packet at that point.

**Grade: ❌ No direct equivalent on BSD/pf**

pf processes packets at the network layer after the socket has handed off the
packet to the IP stack. The user/group context is gone. BSD has no mechanism
equivalent to `meta skuid`.

**Impact on affected methods:**
- `ApplySMTPBlock` — the UID/GID allowlist cannot be enforced at the packet level on BSD.
- `ApplyOutboundObserve` — the root-traffic exemption (`meta skuid 0 return`) cannot be done at the kernel boundary on BSD.

**pf backend design decision (document for Phase 3):**

For `ApplySMTPBlock` on BSD, two options:
1. **Shim via `authpf`** — `authpf` creates per-user firewall anchors when users
   authenticate via SSH. Covers managed-user scenarios but not arbitrary daemons.
2. **User-space enforcement** — a small setuid helper (`cfm-smtpguard`) that
   uses `getpeername` + `/proc` (Linux) or `sockstat` (BSD) to map connections
   to UIDs, and calls `pfctl` to block/unblock. Slower than kernel enforcement
   but platform-portable.

For `ApplyOutboundObserve` on BSD, the root exemption becomes a post-capture
filter in user space — the pflog tap captures everything, and the Go collector
filters out root-owned connections by checking the process table.

**Interface note:** `ApplySMTPBlock` and `ApplyOutboundObserve` must return a
`PlatformCapability` result (or equivalent) so callers know which features are
active. A pf backend can return `ErrNotSupported` with a clear message and the
daemon disables the feature gracefully, rather than silently doing nothing.

---

#### `flags timeout` on sets — per-element TTL auto-expiry
**Used in:** `nft.go` — every IP set (block, allow, ignore, challenge, throttle, external feeds)

```nft
# nftables — kernel auto-removes elements when their TTL expires
add set inet cfm block_v4 { type ipv4_addr; flags timeout; }
add element inet cfm block_v4 { 1.2.3.4 timeout 1h }
# element disappears automatically after 1 hour — no user-space cron needed
```

This is heavily used. Every temporary ban, every challenge assignment, every
throttle entry relies on the kernel cleaning it up automatically. The current
`nft.Backend` has no expiry goroutine — it just sets the timeout and lets the
kernel handle it.

**Grade: ❌ No direct equivalent on BSD/pf**

pf tables have no per-element TTL. An element added to a pf table stays there
until explicitly removed. There is no `pfctl -t <table> -T add 1.2.3.4 timeout 1h`.

**Impact:** This is the most pervasive portability gap. Every TTL-based operation
in CFM (`AddBlock` with a `*time.Duration`, `AddChallenge`, `AddElementsBulk`
with TTL, external feed TTLs) relies on kernel TTL enforcement.

**pf backend design decision (document for Phase 3):**

The pf backend must maintain its own expiry store — a goroutine with a min-heap
(or `time.AfterFunc` per entry) that removes elements from pf tables when they
expire:

```go
// internal/firewall/pf/expiry.go (Phase 3 design)
type expiryEntry struct {
    table   string
    element string
    expiry  time.Time
}

// ExpiryManager runs a goroutine that removes elements from pf tables on TTL.
// Backed by a min-heap sorted by expiry time.
// On daemon restart, state is reconstructed from a bbolt/SQLite store so
// entries survive restarts.
type ExpiryManager struct {
    heap  expiryHeap
    store ExpiryStore   // persistent: bbolt, SQLite, or flat file
    mu    sync.Mutex
    wake  chan struct{}
}
```

This is non-trivial but well-understood engineering. The expiry manager is
internal to the pf backend — callers still just call `AddBlock(ip, ttl)` and
the backend handles the rest. The interface contract is identical.

**Restart durability note:** nftables sets with `flags timeout` survive daemon
restarts because the kernel owns the state. A pf backend expiry manager must
persist its heap to disk so a daemon restart does not leave IPs permanently
blocked past their TTL. This is an operational difference that must be
documented for pf deployments.

---

#### Concatenated sets (`ipv4_addr . inet_service`) — portscan detection
**Used in:** `nft_rules.go` — portscan pair tracking sets

```nft
# nftables — composite key: one set element = (source_ip, destination_port)
add set inet cfm ps_pairs_v4 { type ipv4_addr . inet_service; flags timeout; }
add element inet cfm ps_pairs_v4 { 1.2.3.4 . 22 }
add element inet cfm ps_pairs_v4 { 1.2.3.4 . 3389 }
# If count(distinct ports for 1.2.3.4) > threshold → autoblock
```

Concatenated sets are nftables-specific. They store tuples as a single element,
making it efficient to track which (IP, port) pairs have been seen.

**Grade: ❌ No direct equivalent on BSD/pf**

pf tables store only addresses or CIDRs. There is no composite-key table type.
Portscan detection using pf alone would require either:
1. A separate table per tracked port (impractical for large port ranges).
2. Full user-space tracking — capture SYN packets via pflog, maintain the
   `map[ip]set[port]` in Go, call `pfctl -t cfm_block -T add ip` when
   threshold is exceeded.

**pf backend design decision (document for Phase 3):**

`LoadPortScanner` on a pf backend captures via the pflog BPF tap instead of
reading kernel sets. The Go-side counting logic (`dumpPortscanPairs` equivalent)
moves entirely to user space. This is actually architecturally cleaner — it
removes the dependency on `nft list set` text parsing and the associated fragility.

The interface method `LoadPortScanner()` remains identical. The implementation
is just a different data source.

---

#### `NFLOG` — kernel→userspace packet metadata channel
**Used in:** `outbound.go` (OutboundObserve), `smtpblock.go` (SMTP log group)

```nft
# nftables — send matching packet metadata to user space via netlink NFLOG
log prefix "CFM_OUT: " group 100 snaplen 96
```

User space reads from `/proc/net/netfilter/nfnetlink_log` via netlink socket
(group 100). The Go outbound collector binds to this group and receives packet
events without the packet leaving the kernel's network stack.

**Grade: ⚠️ Ports with work to BSD — pflog**

BSD pf logs to a BPF device (`/dev/pflog0`, or named pflog interfaces). You
read it with a raw BPF socket:

```pf
# pf — log matching packets to pflog0
pass out log proto tcp to port { 25 465 587 } flags S/SA keep state
```

```go
// BSD: open /dev/pflog0 as a BPF device and read struct pfloghdr records
fd, _ := syscall.Open("/dev/pflog0", syscall.O_RDONLY, 0)
```

The Go code changes significantly (NFLOG netlink → BPF read loop) but the
`ApplyOutboundObserve` interface method is unchanged. The outbound collector
package needs a build-tag split:

```
internal/outbound/
  collector_linux.go    // NFLOG via netlink (current)
  collector_bsd.go      // pflog via BPF (Phase 3)
  collector_other.go    // stub returning ErrNotSupported
```

---

#### DNAT / NAT prerouting — challenge redirect
**Used in:** `nft.go` (`EnsureChallengeRedirect`), `dnat.go` (`DNATOn/Off`)

```nft
# nftables — redirect challenged IPs' HTTP/S to local challenge listener
ip saddr @challenge_v4 tcp dport 80 dnat to 127.0.0.1:8080
ip saddr @challenge_v4 tcp dport 443 dnat to 127.0.0.1:8443
```

**Grade: ✅ Ports cleanly to pf**

pf `rdr-to` is the direct equivalent:

```pf
# pf
rdr pass on egress proto tcp from <cfm_challenge> to port 80 -> 127.0.0.1 port 8080
rdr pass on egress proto tcp from <cfm_challenge> to port 443 -> 127.0.0.1 port 8443
```

Managed via `pfctl -a cfm/challenge -f -` (anchor). `DNATOn` generates the
anchor rules, `DNATOff` flushes the anchor. The method signatures on the
interface don't change.

---

#### Bad TCP flag filtering
**Used in:** `nft_hardening.go`

```nft
# nftables
tcp flags & (syn|fin) == (syn|fin) drop   # SYN+FIN
tcp flags & (syn|rst) == (syn|rst) drop   # SYN+RST
tcp flags & (fin|psh|urg) == (fin|psh|urg) drop  # XMAS
tcp flags & (fin|psh|urg|rst|syn|ack) == 0 drop  # NULL
```

**Grade: ✅ Ports cleanly to pf**

pf has direct flag matching:
```pf
block in quick proto tcp flags FUP/FUAP   # XMAS
block in quick proto tcp flags SF/SFRA    # SYN+FIN
block in quick proto tcp flags SR/SFRA    # SYN+RST
block in quick proto tcp flags /SFRA      # NULL
```

---

#### Hook priorities — execution order relative to other stacks
**Used in:** multiple chains (`priority -100`, `priority 10`, `priority dstnat`)

```nft
# nftables — numeric priority controls where this chain runs relative to others
# (CSF, Imunify, stock rules)
add chain inet cfm input { type filter hook input priority -100; }
add chain inet cfm smtpblock { type filter hook output priority -100; }
add chain inet cfm cfm_outbound_observe { type filter hook output priority 10; }
```

**Grade: ⚠️ Different model on pf**

pf uses anchors for layering — the main pf ruleset calls sub-anchors in order.
There is no numeric priority; ordering is explicit and positional:

```pf
# /etc/pf.conf
anchor "cfm/*"   # CFM rules evaluated before default rules
```

Sub-anchors within CFM can be ordered:
```pf
# cfm anchor
anchor "block"
anchor "challenge"
anchor "flood"
anchor "ports"
```

The `NFT_INPUT_PRIORITY` config knob (which lets CFM run before CSF/Imunify on
nftables) has no direct pf equivalent because pf is typically the only firewall
on BSD. This is a Linux-specific concern and can be documented as
"not applicable on BSD".

---

### 9b. Summary table

| Feature | Where used | pf grade | Workaround for pf |
|---|---|---|---|
| `ct state` matching | Block rules, ConnLimit, PortFlood | ✅ | `max-src-conn`, state tracking |
| `meter` (rate/count per IP) | PortFlood, ConnLimit, PPS | ⚠️ | `max-src-conn-rate` + overload tables |
| `meta skuid` / `meta skgid` | SMTPBlock, OutboundObserve | ❌ | User-space UID lookup + separate pfctl calls |
| `flags timeout` (set TTL) | Every IP set | ❌ | User-space ExpiryManager with persistent store |
| Concatenated sets (`ip . port`) | Portscan detection | ❌ | Full user-space tracking via pflog BPF tap |
| `NFLOG` | OutboundObserve, SMTP log | ⚠️ | pflog interface via BPF read loop |
| DNAT / NAT redirect | Challenge redirect, DNATOn/Off | ✅ | pf `rdr-to` anchors |
| Bad TCP flags | Hardening rules | ✅ | pf `block in quick ... flags` |
| Hook priorities | All chains | ⚠️ | pf anchor ordering (not applicable on BSD) |
| `reject with tcp reset` | SMTPBlock deny | ✅ | pf `block return-rst` |
| CIDR interval sets | Block/allow nets, feeds | ✅ | pf tables support CIDR natively |

### 9c. What this means for the interface

Two methods need special treatment when implementing non-Linux backends:

**`ApplySMTPBlock`** — the UID/GID enforcement path is Linux-only.
A pf backend implements the port-blocking part (block outbound SMTP) but cannot
enforce the UID allowlist at the kernel level. The method should succeed but log
a warning that UID-based SMTP exemptions are not enforced. Operators on BSD who
need per-user SMTP control must use `authpf` separately.

**`ApplyOutboundObserve`** — NFLOG is Linux-only.
A pf backend can implement observation via pflog/BPF but the wiring is in a
different package. The method signature on the interface is unchanged; the
implementation diverges at the build-tag boundary.

**Recommended interface addition for Phase 3:**

```go
// Capabilities returns which optional features are active on this backend.
// Callers use this to log warnings or disable UI elements for unsupported
// features rather than silently failing.
Capabilities() BackendCapabilities
```

```go
// BackendCapabilities describes which optional features a backend supports.
type BackendCapabilities struct {
    // UIDBasedSMTPBlock indicates whether ApplySMTPBlock enforces the
    // UID/GID allowlist at the kernel level (true on Linux/nftables,
    // false on pf/BSD where only port-level blocking is applied).
    UIDBasedSMTPBlock bool

    // KernelSetTTL indicates whether IP set TTLs are enforced by the
    // kernel (true on nftables, false on pf where user-space expiry
    // management is used instead).
    KernelSetTTL bool

    // KernelPortscanTracking indicates whether portscan pair tracking
    // uses kernel-side sets (true on nftables, false on pf where
    // user-space pflog capture is used).
    KernelPortscanTracking bool

    // NFLOGOutbound indicates whether outbound observation uses NFLOG
    // (true on Linux, false on BSD where pflog/BPF is used).
    NFLOGOutbound bool
}
```

This can be added to the interface in Phase 1 with a simple default
implementation on `nft.Backend` that returns all `true`, and implemented
correctly per-backend in later phases.
