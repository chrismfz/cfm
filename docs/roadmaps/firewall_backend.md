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
6. [Phase 2.5 — nftlib independence (drop nft package dependency)](#6-phase-25--nftlib-independence-drop-nft-package-dependency)
   - [6a. What still delegates to cli](#6a-what-still-delegates-to-cli)
   - [6b. Table lifecycle — native nftlib](#6b-table-lifecycle--native-nftlib)
   - [6c. Policy rule synthesis — native nftlib](#6c-policy-rule-synthesis--native-nftlib)
   - [6d. DNAT / challenge redirect — native nftlib](#6d-dnat--challenge-redirect--native-nftlib)
   - [6e. Diagnostic text / JSON output — native nftlib](#6e-diagnostic-text--json-output--native-nftlib)
   - [6f. Removing the embedded cli field](#6f-removing-the-embedded-cli-field)
7. [Phase 3 — BSD backend (firewall TBD: pf / ipfw / ipf)](#7-phase-3--bsd-backend-firewall-tbd-pf--ipfw--ipf)
8. [Compatibility contract](#8-compatibility-contract)
9. [Progress tracking](#9-progress-tracking)

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
- [x] Shell backend hardening: centralized command runner (`command_runner.go`) for all nft subprocess execution.
- [x] Shell backend concurrency controls: bounded semaphore (`nftSem`, cap=4) in `command_runner.go` serializes high-volume mutation paths.
- [ ] Add targeted stress/regression coverage for large feed updates and concurrent applies.

**Phase 2 (new engine, opt-in) — 2026-04-29:**
- [x] Introduce `internal/firewall/nftlib` backend (`github.com/google/nftables`, netlink-based).
- [x] Set/bulk operations implemented natively via netlink: `AddBlock`, `RemoveBlock`, `RemoveBlockBatch`, `AddAllow`, `RemoveAllow`, `Add/RemoveBlockNet`, `Add/RemoveAllowNet`, `Add/RemoveIgnore`, `Add/RemoveIgnoreNet`, `AddChallenge`, `RemoveChallenge`, `AddElementsBulk`, `ReplaceSetFlushAdd`.
- [x] Hybrid wiring: policy/DNAT/inspection/feeds/diagnostics delegate to embedded `*nft.Backend`.
- [x] Compile-time assertion `var _ firewall.Backend = (*Backend)(nil)` in `nftlib/backend.go`.
- [x] `CFM_FIREWALL_ENGINE=nftlib` selector wired in `cmd/cfm/main.go`; nft remains production default.
- [ ] Validate parity for DNAT/challenge redirect and bulk set operations.
- [x] Native nftlib inspection (`ListBlocks`, `ListAllows`, `HasElem`, `ListSetElementsRaw`) — `conn.GetSetElements`; CIDR interval pairs reconstructed via `keysToCIDR`.
- [x] Native nftlib feed management (`ApplyFeed`, `RebuildExternalUnions`, `PruneExternalFeeds`, `DropFeedSets`, `RemoveFeedByKey`) — calls own `ReplaceSetFlushAdd`; set discovery uses `conn.GetSets`. Full feed path now zero-fork.

### Phase 2 exit criteria to move `nftlib` beyond experimental

`nftlib` remains experimental until all criteria below are green in CI and in a staged environment.

1. **Functional parity tests (set operations)**
   - Scope: `AddElementsBulk`/add, `Remove*`/remove, `ReplaceSetFlushAdd`/replace, `HasElem`/has, `ListSetElementsRaw`/list.
   - Test matrix: IPv4 + IPv6, empty set, duplicate inserts, missing element removal, and mixed TTL/non-TTL entries.
   - Pass criteria:
     - `nftlib` and `nftcli` produce byte-equivalent normalized set snapshots for identical test inputs.
     - Zero unexpected diffs across 100 consecutive parity runs.
     - No leaked temporary sets/chains after test teardown.

2. **Performance benchmark on large feed updates vs `nftcli`**
   - Benchmark profile: at least 10k, 50k, and 100k element feed updates using `ApplyFeed` + union rebuild paths.
   - Measurements: p50/p95 apply latency, CPU time, peak RSS, and syscall/fork counts.
   - Pass criteria:
     - `nftlib` p95 apply latency is **at least 2x better** than `nftcli` at 50k+ entries.
     - `nftlib` process fork count is zero for feed apply path.
     - No regression >10% in memory usage versus agreed baseline envelope.

3. **Failure-mode tests (netlink errors, interruptions, partial updates)**
   - Injected faults: transient netlink `EINTR`/`ENOBUFS`, permission errors, context cancellation mid-apply, and kernel-side rejection on one element in batch.
   - Pass criteria:
     - Retryable failures are classified and retried according to policy.
     - Non-retryable semantic failures return typed errors with operation metadata.
     - Partial mutation is not silent: either full transaction commits, or degraded-state error is emitted and detected.

4. **Runtime fallback behavior**
   - Required behavior definition: if an `nftlib` mutation op fails, request handling must return an explicit failure to caller; there is **no implicit per-op fallback** to `nftcli` in the same execution path.
   - Startup/selection fallback: unknown engine or disabled experimental flag falls back to `nft` selector default.
   - Pass criteria:
     - Integration tests verify explicit error propagation for failed `nftlib` ops.
     - Selector tests verify deterministic fallback only at engine selection boundaries.

5. **Observability metrics per engine**
   - Required counters/histograms (labeled by `engine` + `operation`):
     - latency distribution,
     - error count by class (retryable/non-retryable/semantic),
     - timeout count,
     - fallback count (selection-level only).
   - Pass criteria:
     - Metrics emitted for both `nft` and `nftlib` in equivalent code paths.
     - Dashboard and alert thresholds defined for p95 latency and error/timeout spikes.
     - On-call runbook updated with metric interpretation and initial triage steps.

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
- Optional hybrid model and future BSD backend (pf recommended; ipfw as alternative).

### 4a. The full Backend interface

> **Live source of truth:** `internal/firewall/backend.go`  
> The block below reflects the interface as it exists today. If they diverge, the file wins.

```go
package firewall

import (
	"cfm/internal/blocklists"
	"cfm/internal/config"
	"cfm/internal/enrich"
	"cfm/internal/reporting"
	"context"
	"net"
	"time"
)

type BlockedEntry struct {
	IP      net.IP
	Expires *time.Time
	Comment string
}

type Backend interface {
	// Lifecycle / wiring
	EnsureBase() error
	DropEverything() error
	ResetTable() error
	SetConfigDir(dir string)
	EnableEnrichment(dirs ...string)
	GetEnricher() *enrich.Enricher
	SetReporter(r reporting.Reporter)
	SetChallengeLogger(f func(format string, args ...any))

	// Policy
	ApplyFloodRules(c *config.Config) error
	ApplyHardeningRules(c *config.Config) error
	ApplyPortsPolicy(cfg *config.PortsConfig) error
	ApplyConnlimit(rules []config.ConnlimitRule) error
	ApplyPortFlood(rules []config.PortFloodRule) error
	ApplySMTPBlock(cfg *config.SMTPBlockConfig) error
	ApplyOutboundObserve(cfg *config.OutboundConfig) error
	DumpFloodCounters()
	DumpThrottledIPs()
	LoadPortScanner()

	// Manual lists
	AddBlock(ip net.IP, comment string, ttl *time.Duration) error
	RemoveBlock(ip net.IP) error
	RemoveBlockBatch(ips []net.IP) error
	ListBlocks() ([]BlockedEntry, error)
	ListAllows() ([]BlockedEntry, error)
	AddAllow(ip net.IP, ttl *time.Duration) error
	RemoveAllow(ip net.IP) error

	// CIDR subnets (manual)
	AddBlockNet(cidr string, ttl *time.Duration) error
	RemoveBlockNet(cidr string) error
	AddAllowNet(cidr string, ttl *time.Duration) error
	RemoveAllowNet(cidr string) error

	// Ignore — skip enforcement but still log/notify/report
	AddIgnore(ip net.IP, ttl *time.Duration) error
	RemoveIgnore(ip net.IP) error
	AddIgnoreNet(cidr string, ttl *time.Duration) error
	RemoveIgnoreNet(cidr string) error

	// Challenge (HTTP/HTTPS redirect for selected source IPs)
	AddChallenge(ip net.IP, ttl *time.Duration) error
	RemoveChallenge(ip net.IP) error
	SetChallengeRedirectEnabled(enabled bool)
	CleanupChallengeRedirect() error
	EnsureChallengeRedirect(httpListen, httpsListen string) error

	// Feed / bulk / set ops
	ApplyFeed(ctx context.Context, f blocklists.Feed, res *blocklists.FetchResult) error
	RebuildExternalUnions() error
	PruneExternalFeeds(activeKeys []string) error
	DropFeedSets(feedName string)
	RemoveFeedByKey(feedKey string) error
	DeleteSetIfExists(name string) error
	EnsureSetDynamic(name string, v6 bool, isNet bool) error
	ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) error
	AddElementsBulk(setName string, elems []string, ttl *time.Duration) error
	HasElem(setName, elem string) (bool, error)
	ListSetElementsRaw(setName string) ([]string, error)
	ListTableJSON(family, table string) ([]byte, error)
	ListSetJSON(family, table, set string) ([]byte, error)
	ListTableTextNoDNS(family, table string) (string, error)
	ListChainText(family, table, chain string) (string, error)
	FlushSet(family, table, set string) error

	// DNAT / redirect surface (used by `cfm webtop dnat` and status reporting)
	DNATStatus(family, table string) (bool, error)
	DNATShow(family, table string) (string, error)
	DNATOn(family, table string, httpPort, httpsPort int) error
	DNATOff(family, table string) error

	// ReportBlock: centralized policy-aware API reporting.
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

## 6. Phase 2.5 — nftlib independence (drop nft package dependency)

> **Pre-requisite:** Phase 2 complete.  
> **Goal:** Remove the embedded `*nft.Backend` from `nftlib.Backend` so nftlib is
> a self-contained zero-fork implementation with no subprocess dependency.  
> **Why not now:** The remaining delegated methods require building nftables rule
> expression trees — non-trivial but tractable. Documented here so the work is
> scoped and ready to pick up.

After Phase 2, the `nftlib.Backend` still embeds `*nft.Backend` (the cli backend)
and delegates 24 methods to it. Deleting the `nft` import from `nftlib` today would
break the build. This phase tracks what each delegation group needs to go native.

---

### 6a. What still delegates to cli

| Group | Methods | Count |
|---|---|---|
| Table lifecycle | `EnsureBase`, `DropEverything`, `ResetTable`, `EnsureSetDynamic`, `DeleteSetIfExists`, `FlushSet` | 6 |
| Policy rule synthesis | `ApplyFloodRules`, `ApplyHardeningRules`, `ApplyPortsPolicy`, `ApplyConnlimit`, `ApplyPortFlood`, `ApplySMTPBlock`, `ApplyOutboundObserve`, `DumpFloodCounters`, `DumpThrottledIPs`, `LoadPortScanner` | 10 |
| DNAT / challenge redirect | `SetChallengeRedirectEnabled`, `CleanupChallengeRedirect`, `EnsureChallengeRedirect`, `DNATStatus`, `DNATShow`, `DNATOn`, `DNATOff` | 7 |
| Diagnostic text/JSON output | `ListTableJSON`, `ListSetJSON`, `ListTableTextNoDNS`, `ListChainText` | 4 |

Total: **27 delegated methods** remaining. All subprocess invocations in nftlib
trace back to one of these four groups.

---

### 6b. Table lifecycle — native nftlib

**Current delegation:** `EnsureBase`, `DropEverything`, `ResetTable`,
`EnsureSetDynamic`, `DeleteSetIfExists`, `FlushSet` call `b.cli.*`.

**What native implementation requires:**

- `EnsureBase` — use `conn.AddTable` + `conn.AddChain` + `conn.AddSet` to
  programmatically declare the full `inet cfm` table, all chains (`input`,
  `forward`, `output`, `prerouting`), and all static named sets. Then
  `conn.Flush()`. Complex but mechanical — no expression trees involved, just
  structure declarations. The nft ruleset DSL in `nft/rules/` defines exactly
  which objects to create; translate them once.
- `DropEverything` — `conn.DelTable(table)` + `conn.Flush()`. One line once the
  table handle is known.
- `ResetTable` — `DropEverything` + `EnsureBase` + re-apply policy. With the
  above two native, this follows automatically.
- `EnsureSetDynamic` — `conn.AddSet` for a dynamically-named set with the right
  `KeyType` (`TypeIPAddr` or `TypeIP6Addr`) and `Interval: true` for net sets.
  The `google/nftables` API supports this directly.
- `DeleteSetIfExists` — `conn.DelSet` guarded by a `lookupSet` check. Already
  partially wired via `invalidateCache()`.
- `FlushSet` — `conn.FlushSet(set)` + `conn.Flush()`. Direct API call.

**Effort estimate:** medium. No rule expression trees. Purely structural
declarations. The main work is translating the base ruleset template into
`nftables.Table`/`Chain`/`Set` struct instantiations.

**File:** `internal/firewall/nftlib/lifecycle.go`

---

### 6c. Policy rule synthesis — native nftlib

**Current delegation:** `ApplyFloodRules`, `ApplyHardeningRules`,
`ApplyPortsPolicy`, `ApplyConnlimit`, `ApplyPortFlood`, `ApplySMTPBlock`,
`ApplyOutboundObserve`, `DumpFloodCounters`, `DumpThrottledIPs`, `LoadPortScanner`.

**What native implementation requires:**

These methods write nftables *rules* — sequences of match expressions plus a
verdict. The `google/nftables` library exposes them via the `expr` package
(`expr.Meta`, `expr.Cmp`, `expr.CT`, `expr.Limit`, `expr.Counter`, etc.).

Each method translates a config struct into a chain of `[]expr.Any` and calls
`conn.AddRule`. The mapping is:

- `ApplyHardeningRules` — stateful conntrack accept (`CT state established/related`),
  ICMP rate limits, invalid-state drop. Translates to ~10 `conn.AddRule` calls.
- `ApplyPortsPolicy` — per-port TCP/UDP `Meta l4proto` + `Payload dport` + `Verdict`
  accept/drop. Number of rules scales with config entries.
- `ApplyConnlimit` — `expr.Connlimit` + `expr.Verdict`. One rule per
  `ConnlimitRule` entry.
- `ApplyPortFlood` — `expr.Limit` (rate limiting) + `expr.Verdict`. One rule per
  `PortFloodRule` entry.
- `ApplySMTPBlock` — `Meta l4proto tcp` + `Payload dport 25` + `Verdict drop`
  (outbound chain). Simple.
- `ApplyFloodRules` — flood counters (`expr.Counter`) + rate limits on input chain.
- `ApplyOutboundObserve` — mark/log outbound traffic matching config.
- `DumpFloodCounters` / `DumpThrottledIPs` — read named counter/quota objects
  via `conn.GetObjects` or parse from `conn.GetRules`. Alternative: keep these
  two as cli delegates long-term since they are diagnostic-only (rare calls, no
  fork-storm risk).
- `LoadPortScanner` — attaches a BPF/nflog collector; not rule synthesis. Can
  remain a cli delegate or be wired to a native nflog socket.

**Effort estimate:** high. Each `Apply*` method needs careful translation of the
existing nft ruleset template into `expr` chains. The `google/nftables/expr`
package is well-documented but verbose. Recommend implementing one method at a
time, validated by `nft list chain` diffing against the cli output.

**File:** `internal/firewall/nftlib/policy.go`

**Suggested order:** `ApplyHardeningRules` → `ApplyPortsPolicy` → `ApplyConnlimit`
→ `ApplyPortFlood` → `ApplySMTPBlock` → `ApplyFloodRules` → `ApplyOutboundObserve`.
Leave `DumpFloodCounters`, `DumpThrottledIPs`, `LoadPortScanner` as cli delegates
until the others are done (they are read/diagnostic paths with no fork-storm impact).

---

### 6d. DNAT / challenge redirect — native nftlib

**Current delegation:** `SetChallengeRedirectEnabled`, `CleanupChallengeRedirect`,
`EnsureChallengeRedirect`, `DNATStatus`, `DNATShow`, `DNATOn`, `DNATOff`.

**What native implementation requires:**

Challenge redirect works by inserting a DNAT prerouting rule that redirects HTTP/S
traffic from challenged IPs to cfm's local challenge server. The `google/nftables`
library supports DNAT via `expr.NAT` with `Type: expr.NATTypeDestNAT`.

- `DNATOn` — `conn.AddRule` on the prerouting chain with:
  `[expr.Meta{Key: expr.MetaKeyL4PROTO}, expr.Cmp{...tcp}, expr.Payload{...dport},
   expr.Cmp{...targetPort}, expr.NAT{Type: NATTypeDestNAT, ...redirectPort}]`
- `DNATOff` — find and delete the DNAT rule: `conn.GetRules` + match by handle +
  `conn.DelRule` + `conn.Flush`.
- `DNATStatus` / `DNATShow` — `conn.GetRules` on prerouting chain, scan for
  `expr.NAT` elements. No subprocess needed.
- `EnsureChallengeRedirect` — idempotent: check `DNATStatus`, call `DNATOn` if not
  already active.
- `CleanupChallengeRedirect` — `DNATOff` if active.
- `SetChallengeRedirectEnabled` — boolean gate (in-memory flag), no kernel call.

**Effort estimate:** medium. DNAT rule construction via `expr.NAT` is well-supported
in `google/nftables`. The trickiest part is rule identity for `DNATOff` — rules
must be found by content (port match) rather than handle, since handles are not
stable across `EnsureBase` calls. A named map or rule comment can anchor identity.

**File:** `internal/firewall/nftlib/challenge.go`

---

### 6e. Diagnostic text / JSON output — native nftlib

**Current delegation:** `ListTableJSON`, `ListSetJSON`, `ListTableTextNoDNS`,
`ListChainText`.

**What native implementation requires:**

These four methods are called by diagnostic/admin commands, not by hot paths.
They currently shell out to `nft -j list table` / `nft list chain` etc.

Options:
1. **Keep as cli delegates permanently.** These are diagnostic-only, called rarely
   (human inspection, not automated loops). The fork-storm was never caused by
   these. Cost: the `nft` binary must remain available even after full nftlib
   migration.
2. **Implement as JSON serialisers over `conn.GetRules`/`conn.GetSets` output.**
   The nftables JSON schema is documented. Building a serialiser is mechanical but
   requires keeping in sync with the schema version. Not recommended unless `nft`
   binary availability becomes a constraint.
3. **Replace with structured Go types.** Change callers to accept structured data
   (Go structs) instead of raw JSON/text blobs, then populate from netlink reads.
   This is the cleanest long-term approach but requires changing the `Backend`
   interface.

**Architecture decision (Phase 2.5):** **Option 1** is adopted for Phase 2.5
completion: keep `ListTableJSON`, `ListSetJSON`, `ListTableTextNoDNS`, and
`ListChainText` as CLI delegates for diagnostics only, and explicitly document
that `nft` binary availability remains a runtime prerequisite for these
inspection paths.

**Phase 2.5 completion criterion for this decision:**
- `CFM_FIREWALL_ENGINE=nftlib` removes CLI delegation from policy/sets/lifecycle/
  challenge mutation paths, while the four diagnostic inspection methods above
  continue to shell out to `nft` by design.
- Operator docs must state that diagnostic commands requiring these methods need
  a working `nft` binary in `PATH`.

If a future phase requires zero-CLI operation for diagnostics as well, open a new
ADR/update and migrate to option 2 (structured netlink output + internal
formatter).

---

### 6f. Removing the embedded cli field

Once groups 6b, 6c, and 6d are fully native (or 6e is resolved via option 1/3),
the `cli *nft.Backend` field in `nftlib.Backend` can be removed:

1. Delete the `cli` field from `internal/firewall/nftlib/backend.go`.
2. Remove `nft.New()` call from `nftlib.New()`.
3. Remove `"cfm/internal/firewall/nft"` import from all `nftlib/*.go` files.
4. Run `go build ./...` — compile-time assertion catches any missed delegation.
5. The `nft` package itself remains (it is still the production-default backend
   behind `CFM_FIREWALL_ENGINE=nft`). Only nftlib stops importing it.

After this, `CFM_FIREWALL_ENGINE=nftlib` requires zero `nft` binary presence.

---

## 7. Phase 3 — BSD backend (firewall TBD: pf / ipfw / ipf)

> **Pre-requisite:** Phase 1 complete. Phase 2 is not a prerequisite — the BSD
> backend can be implemented independently.  
> **Decision deferred:** FreeBSD ships three firewalls in base — pf, ipfw, and
> ipfilter (ipf). The right choice depends on which CFM features matter most on
> the target BSD platform. This section documents the comparison so the decision
> can be made when implementation begins.

---

### 7a. FreeBSD firewall options — overview

| | **pf** | **ipfw** | **ipfilter (ipf)** |
|---|---|---|---|
| Origin | OpenBSD, ported to FreeBSD | FreeBSD native | Darren Reed; multi-platform |
| Availability | FreeBSD, OpenBSD, NetBSD, macOS | FreeBSD only | FreeBSD, Solaris, NetBSD |
| Rule syntax | `pf.conf` (declarative) | Numbered rules (sequential) | `ipf.conf` (declarative) |
| IP tables / sets | ✅ `pfctl -t name -T add` — bulk native | ✅ `ipfw table name add` | ✅ `pool` hash tables |
| Per-element TTL | ❌ tables have no expiry — user-space manager required | ❌ same gap | ❌ same gap |
| Connection tracking | ✅ `keep state` / `max-src-conn` | ✅ `keep-state` / `limit` option | ✅ state tables |
| Per-src conn limit | ✅ `max-src-conn N` in rule | ✅ `limit src-addr N` | ⚠️ state limit only, less expressive |
| Per-port rate limit | ✅ `max-src-conn-rate N/M` | ✅ `dummynet` pipe + `limit` | ⚠️ limited, no native rate-per-port |
| UID/GID match | ✅ `user { uid N }` in rule | ✅ `uid N` / `gid N` match | ❌ no UID/GID matching |
| DNAT / redirect | ✅ `rdr-to` in anchors | ✅ `fwd` rule action | ✅ `rdr-to` in NAT rules |
| Traffic observation | ✅ pflog interface + bpf tap | ✅ divert sockets / ngx | ⚠️ limited; no equivalent of pflog |
| Bandwidth shaping | ✅ ALTQ (tightly coupled) | ✅ dummynet (tightly coupled) | ❌ no native shaper |
| Anchor / namespace | ✅ anchors isolate CFM rules cleanly | ⚠️ rule numbers must be reserved | ⚠️ groups exist but less isolation |
| Active development | ✅ actively maintained | ✅ actively maintained | ⚠️ less active; considered legacy |

**Per-element TTL gap (all three):** None of the BSD firewalls support per-table-entry expiry natively. CFM uses TTL on blocks (`AddBlock(ip, ttl)`). A BSD backend must run a user-space expiry goroutine (min-heap of `{ip, expireAt}` entries, timer fires `RemoveBlock` when due). The design is the same regardless of which firewall is chosen.

---

### 7b. Capability mapping against CFM Backend methods

| Backend method group | pf | ipfw | ipf |
|---|---|---|---|
| `AddBlock` / `RemoveBlock` / bulk | ✅ tables | ✅ tables | ✅ pools |
| `AddBlockNet` / CIDR subnets | ✅ table entries accept CIDR | ✅ table accepts CIDR | ✅ pool accepts CIDR |
| `AddAllow` / `AddIgnore` / `AddChallenge` | ✅ separate named tables | ✅ separate named tables | ✅ separate pools |
| `ApplyPortsPolicy` (TCP/UDP allowlist) | ✅ `pass in proto tcp to port { ... }` anchor | ✅ numbered `allow tcp from any to any dst-port ...` | ✅ `pass in proto tcp to port ...` |
| `ApplyHardeningRules` (bad flags, ICMP rate) | ✅ `block in quick proto tcp flags SF/SFRA` | ✅ `deny tcp from any to any tcpflags syn,fin` | ✅ similar; less expressive rate limiting |
| `ApplyConnlimit` (per-src conn count) | ✅ `max-src-conn N` | ✅ `limit src-addr N` | ⚠️ state table limits only |
| `ApplyPortFlood` (per-port conn rate) | ✅ `max-src-conn-rate N/M` | ✅ dummynet pipe per port | ⚠️ not directly supported |
| `ApplySMTPBlock` (outbound, UID-aware) | ✅ `block out proto tcp to port 25 user { N }` | ✅ `deny tcp from me to any dst-port 25 uid N` | ❌ no UID match — cannot implement natively |
| `ApplyOutboundObserve` (per-UID logging) | ✅ `user { uid }` match + pflog + bpf | ✅ `uid` match + divert socket | ❌ no UID match |
| `EnsureChallengeRedirect` / `DNATOn` | ✅ `rdr-to` in cfm anchor | ✅ `fwd` rule | ✅ `rdr-to` in NAT rules |
| `AddElementsBulk` (batch performance) | ✅ tables are bulk-native | ✅ tables are bulk-native | ✅ pools support bulk load |
| `DumpFloodCounters` / `DumpThrottledIPs` | ✅ `pfctl -s rules -vv` | ✅ `ipfw show` | ✅ `ipfstat -i` |
| `ListBlocks` / `HasElem` (read back) | ✅ `pfctl -t name -T show` | ✅ `ipfw table name list` | ✅ `ippool -l` |

---

### 7c. Recommendation

**Primary choice: pf.** Covers every CFM Backend method including UID-based
`ApplySMTPBlock` and `ApplyOutboundObserve`. Runs on FreeBSD, OpenBSD, NetBSD,
and macOS. Anchors provide clean namespace isolation. Established Go tooling
(`pfctl` subprocess, or direct `/dev/pf` ioctl). The only structural gap vs
nftables — per-element TTL — requires the same user-space expiry manager
regardless of which BSD firewall is chosen.

**Fallback consideration: ipfw.** If pf proves insufficient for a specific
deployment (e.g., dummynet-based bandwidth control is needed alongside CFM),
ipfw is a viable alternative. It supports UID matching and tables.
FreeBSD-only — not portable to OpenBSD or NetBSD.

**Do not use ipfilter.** Missing UID/GID matching makes `ApplySMTPBlock` and
`ApplyOutboundObserve` impossible to implement natively. Treating them as
`ErrNotSupported` stubs is an option, but ipf has no advantage over pf or ipfw
for the features it does support.

**The decision can be deferred** until someone picks up Phase 3. The Backend
interface is firewall-agnostic; the compile-time assertion will catch any
incomplete implementation. Both pf and ipfw would produce the same package
layout (`internal/firewall/pf/` or `internal/firewall/ipfw/`) with identical
method signatures.

---

### 7d. pf package layout and method mapping (reference)

If pf is chosen, the package structure and core method translations are:

```
internal/firewall/pf/
  backend.go     ← struct, New(), compile-time assertion
  sets.go        ← pfctl tables for block/allow/ignore/challenge
  policy.go      ← pf.conf anchor generation for port/flood/hardening rules
  challenge.go   ← rdr-to rules instead of DNAT
  outbound.go    ← pflog interface + bpf instead of NFLOG
  expiry.go      ← user-space TTL manager (min-heap goroutine)
```

**Key nftables → pf method translations:**

| Backend method | nftables | pf |
|---|---|---|
| `AddBlock(ip, ttl)` | `add element inet cfm block_v4 { ip timeout ttl }` | `pfctl -t cfm_block -T add ip` + expiry goroutine schedules `RemoveBlock` |
| `AddBlockNet(cidr, ttl)` | `add element inet cfm block_v4_nets { cidr }` | `pfctl -t cfm_block_net -T add cidr` + expiry goroutine |
| `ApplyHardeningRules` | `tcp flags & (syn\|fin) == (syn\|fin) drop` | `block in quick proto tcp flags SF/SFRA` in cfm anchor |
| `ApplySMTPBlock` | `skuid != allowedUIDs drop` outbound | `block out quick proto tcp to port 25 user { uid }` |
| `ApplyOutboundObserve` | nftables NFLOG chain | pflog interface + bpf tap |
| `EnsureChallengeRedirect` | DNAT prerouting: `dnat to 127.0.0.1:port` | `rdr pass proto tcp to port 80 -> 127.0.0.1 port 8080` in cfm/dnat anchor |
| `DNATOn` | `nft add rule inet nat prerouting ...` | `echo "rdr-to ..." \| pfctl -a cfm/dnat -f -` |
| `DNATOff` | flush nat prerouting chain | `pfctl -a cfm/dnat -F rules` |
| `AddElementsBulk` | `nft add element` batch | `pfctl -t name -T add ip1 ip2 ...` (tables are bulk-native) |
| `DumpFloodCounters` | `nft list counters` | `pfctl -s rules -vv` |

**Compile-time assertion (`pf/backend.go`):**

```go
var _ firewall.Backend = (*Backend)(nil)
```

---

## 8. Compatibility contract

Any implementation of `firewall.Backend` must follow these rules:

**Idempotency.** `EnsureBase()`, `EnsureChallengeRedirect()`, all `Apply*` methods, and `EnsureSetDynamic()` must be safe to call multiple times with the same arguments. Re-running them should produce the same state, not errors.

**AddBlock on an already-blocked IP must not error.** The autoblock sink calls `AddBlock` without pre-checking; if the IP is already blocked (from a previous daemon run), the method must update the TTL or no-op — not return an error.

**`DropEverything` is destructive.** It removes all CFM-owned rules and sets. It is only called on clean uninstall. It must not affect rules/sets owned by other software (CSF, Imunify, stock firewalld rules).

**`SetChallengeRedirectEnabled(false)` must be safe to call before `EnsureChallengeRedirect`.** The webdetector calls this on startup in OpenResty mode before any redirect rules have been created. The implementation must tolerate this gracefully (no error, nothing to remove).

**Bulk operations prefer all-or-nothing.** `AddElementsBulk` and `ReplaceSetFlushAdd` should apply all elements or none (atomic batch). If the underlying mechanism does not support atomic batches, the implementation must document this.

**DNAT methods on in-path backends.** When OpenResty/Angie in-path mode is active, `DNATOn/Off` are no-ops (the bridge handles decisions). `DNATStatus` returns `(false, nil)`. This is not an error condition.

---

## 9. Progress tracking

### Phase 1 — Complete the interface

| Task | File | Status |
|---|---|---|
| Write full `Backend` interface | `internal/firewall/backend.go` | ✅ |
| Rename `SetChallengeDNATEnabled` → `SetChallengeRedirectEnabled` | `internal/firewall/nft/nft.go` | ✅ (old name kept as compat alias) |
| Rename `CleanupChallengeDNAT` → `CleanupChallengeRedirect` | `internal/firewall/nft/nft.go` | ✅ (old name kept as compat alias) |
| Add compile-time assertion `var _ firewall.Backend = (*Backend)(nil)` | `internal/firewall/nft/nft.go` | ✅ |
| Remove `SetChallengeDNATEnabled` type assertion (×2) | `internal/detectors/webdetector_register.go` | ✅ |
| Remove `EnsureChallengeRedirect` type assertion | `internal/detectors/webdetector_register.go` | ✅ |
| Replace `dnat.Capable` mini-interface with `firewall.Backend` | `internal/dnat/cli.go` | ✅ |
| Fix `dnat.Status(nft.New())` direct call | `internal/status/status.go` | ✅ |
| Add engine selector to `getBackend()` | `cmd/cfm/main.go` | ✅ |

### Phase 2 — nftlib backend

| Task | File | Status |
|---|---|---|
| Add `github.com/google/nftables` to go.mod | `go.mod` | ✅ (v0.3.0) |
| Create `nftlib/backend.go` with struct + `New()` + compile assertion | `internal/firewall/nftlib/backend.go` | ✅ |
| Implement IP/net management (sets) — native netlink | `internal/firewall/nftlib/sets.go` | ✅ |
| Implement bulk operations (fork-storm fix) — native netlink | `internal/firewall/nftlib/bulk.go` | ✅ |
| Conn helpers: lookupTable, lookupSet, cache invalidation, normalizeIP, CIDR interval encoding | `internal/firewall/nftlib/conn.go` | ✅ |
| Lifecycle methods | `internal/firewall/nftlib/lifecycle.go` | ✅ (native) |
| Inspection methods | `internal/firewall/nftlib/inspect.go` | ✅ (mixed: `ListBlocks`/`ListAllows`/`HasElem`/`ListSetElementsRaw`/`ListTableJSON`/`ListSetJSON` native; `ListTableTextNoDNS`/`ListChainText` delegated) |
| Feed management | `internal/firewall/nftlib/feeds.go` | ✅ (native) |
| Policy methods | `internal/firewall/nftlib/policy.go` | ✅ (mixed: native policy mutators; delegated diagnostics `DumpFloodCounters`/`DumpThrottledIPs`/`LoadPortScanner`) |
| Challenge redirect / DNAT | `internal/firewall/nftlib/challenge.go` | ✅ (native) |
| Wiring methods | `internal/firewall/nftlib/wiring.go` | ✅ |
| Wire `CFM_FIREWALL_ENGINE=nftlib` in `getBackend()` | `cmd/cfm/main.go` | ✅ |
| Phase 1.5: bounded semaphore (cap=4) for nft subprocess calls | `internal/firewall/nft/command_runner.go` | ✅ |
| Phase 1 cleanup: remove always-true `EnsureChallengeRedirect` type assertion | `internal/detectors/webdetector_register.go` | ✅ |
| Integration test: apply blocklist, verify nft list | `internal/firewall/nftlib/*_test.go` | ☐ |
| Native nftlib inspection (`ListBlocks`, `ListAllows`, `HasElem`, `ListSetElementsRaw`) | `internal/firewall/nftlib/inspect.go` | ✅ (`conn.GetSetElements`; CIDR pairs reconstructed via `keysToCIDR`) |
| Native nftlib feed management (`ApplyFeed`, `RebuildExternalUnions`, `PruneExternalFeeds`, `DropFeedSets`, `RemoveFeedByKey`) | `internal/firewall/nftlib/feeds.go` | ✅ (own `ReplaceSetFlushAdd`; set discovery via `conn.GetSets`) |

### Phase 2.5 — nftlib independence

| Task | File | Status |
|---|---|---|
| Fresh inventory scan (`2026-04-30`): `b.cli.` callsites in nftlib | `internal/firewall/nftlib/{inspect,policy,wiring}.go` | ✅ 10 callsites (2 inspect, 3 policy diagnostics, 5 wiring/reporting) |
| Fresh inventory scan (`2026-04-30`): `"cfm/internal/firewall/nft"` imports in nftlib | `internal/firewall/nftlib/{backend,feeds}.go` | ✅ 2 files |
| Method classification sweep (`2026-04-30`): every `firewall.Backend` method mapped to `native` / `delegated` / `mixed` with refs | `internal/firewall/nftlib/*.go` | ✅ (see checklist below) |

#### Backend method truth table (`internal/firewall/nftlib/*.go`, audited 2026-04-30)

- **native**
  - Lifecycle/set primitives: `EnsureBase`, `DropEverything`, `ResetTable`, `EnsureSetDynamic`, `DeleteSetIfExists`, `FlushSet`. (`lifecycle.go`)
  - Manual list mutations: `AddBlock`, `RemoveBlock`, `RemoveBlockBatch`, `AddAllow`, `RemoveAllow`, `AddIgnore`, `RemoveIgnore`, `AddChallenge`, `RemoveChallenge`, `AddBlockNet`, `RemoveBlockNet`, `AddAllowNet`, `RemoveAllowNet`, `AddIgnoreNet`, `RemoveIgnoreNet`. (`sets.go`)
  - Feed/bulk/set ops: `ApplyFeed`, `RebuildExternalUnions`, `PruneExternalFeeds`, `DropFeedSets`, `RemoveFeedByKey`, `AddElementsBulk`, `ReplaceSetFlushAdd`, `HasElem`, `ListSetElementsRaw`. (`feeds.go`, `bulk.go`, `inspect.go`)
  - Primary policy + DNAT paths: `ApplyFloodRules`, `ApplyHardeningRules`, `ApplyPortsPolicy`, `ApplyConnlimit`, `ApplyPortFlood`, `ApplySMTPBlock`, `ApplyOutboundObserve`, `SetChallengeRedirectEnabled`, `CleanupChallengeRedirect`, `EnsureChallengeRedirect`, `DNATStatus`, `DNATShow`, `DNATOn`, `DNATOff`. (`policy.go`, `challenge.go`)
  - JSON/state listing: `ListBlocks`, `ListAllows`, `ListTableJSON`, `ListSetJSON`. (`inspect.go`)

- **delegated**
  - Wiring/reporting-only pass-throughs to `b.cli`: `SetConfigDir`, `EnableEnrichment`, `GetEnricher`, `SetReporter`, `SetChallengeLogger`, `ReportBlock`. (`wiring.go`)
  - Text diagnostics pass-throughs: `ListTableTextNoDNS`, `ListChainText`. (`inspect.go`)
  - Policy diagnostics pass-throughs: `DumpFloodCounters`, `DumpThrottledIPs`, `LoadPortScanner`. (`policy.go`)

- **mixed**
  - File-level ownership: `inspect.go` (native + delegated), `policy.go` (native + delegated), `wiring.go` (delegated surface for shared services).

| Remove `cli *nft.Backend` field and `nft.New()` from `nftlib.New()` | `internal/firewall/nftlib/backend.go` | ☐ |
| Remove `cfm/internal/firewall/nft` import from all `nftlib/*.go` | `internal/firewall/nftlib/` | ☐ |
| Parity validation: run both engines on virgo, diff `nft list table inet cfm` output | virgo testlab | ☐ |

### Phase 3 — BSD backend (firewall TBD)

| Task | File | Status |
|---|---|---|
| **Decision:** choose pf, ipfw, or ipf (see §7c — recommendation is pf) | — | ☐ |
| Create `<fw>/backend.go` with struct + `New()` + compile assertion | `internal/firewall/<fw>/backend.go` | ☐ |
| Implement table ops (`AddBlock`, `AddAllow`, `AddIgnore`, `AddChallenge`, CIDR variants, bulk) | `internal/firewall/<fw>/sets.go` | ☐ |
| Implement policy rules (`ApplyPortsPolicy`, `ApplyHardeningRules`, `ApplyConnlimit`, `ApplyPortFlood`, `ApplySMTPBlock`) | `internal/firewall/<fw>/policy.go` | ☐ |
| Implement challenge redirect (`EnsureChallengeRedirect`, `DNATOn`/`DNATOff`) | `internal/firewall/<fw>/challenge.go` | ☐ |
| Implement outbound observe (`ApplyOutboundObserve`) — pflog+bpf (pf) or divert (ipfw) | `internal/firewall/<fw>/outbound.go` | ☐ |
| Implement user-space TTL expiry manager (min-heap goroutine, fires `RemoveBlock` on expiry) | `internal/firewall/<fw>/expiry.go` | ☐ |
| Build tag: `//go:build freebsd` (ipfw) or `//go:build freebsd \|\| openbsd` (pf) | all `<fw>/` files | ☐ |
| Wire `CFM_FIREWALL_ENGINE=<fw>` in `getBackend()` | `cmd/cfm/main.go` | ☐ |

---

## 10. Portability audit — Linux-specific features in current nft.Backend

This section documents every Linux/nftables-specific mechanism currently used in
`internal/firewall/nft/` and grades its portability to alternative backends
(BSD/pf/ipfw, future eBPF, hypothetical next-generation systems). Used as a reference
when implementing Phase 3 and beyond. For the BSD firewall selection rationale see §7.

**Grades:**
- ✅ **Ports cleanly** — concept exists, syntax differs, direct translation
- ⚠️ **Ports with work** — concept exists but mechanism is significantly different
- ❌ **No direct equivalent** — requires redesign or user-space workaround

---

### 10a. Feature inventory

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

### 10b. Summary table

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

### 10c. What this means for the interface

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
