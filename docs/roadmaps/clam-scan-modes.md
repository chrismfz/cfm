# CFM — ClamAV Scan Scope & Mode Roadmap

**Status:** Design — deferred from the ClamAV per-vhost work (PR-A/B/C). Not started.
**Scope:** Two independent knobs layered on the existing async upload scanner —
(1) `CLAM_SCAN_SCOPE` (what file types are worth scanning) and
(2) `CLAM_SCAN_MODE` (notify-only vs block-on-infection). Touch the scan data
path (`configs/lua/cfm_clamav.lua`, `internal/clam`), config, and the ClamAV
insights page.
**Goal:** Make fleet-wide upload scanning viable on busy shared servers
(scope), and offer real inline blocking where an operator wants it (mode) —
without regressing the safe, months-proven async default.

---

## Table of Contents

1. [Context — what already exists](#1-context--what-already-exists)
2. [The two axes are independent](#2-the-two-axes-are-independent)
3. [Item 1 — `CLAM_SCAN_SCOPE` (archives-only default)](#3-item-1--clam_scan_scope-archives-only-default)
4. [Item 2 — `CLAM_SCAN_MODE` (async vs inline)](#4-item-2--clam_scan_mode-async-vs-inline)
5. [Config surface](#5-config-surface)
6. [UI / insights](#6-ui--insights)
7. [Phase plan](#7-phase-plan)
8. [Open questions](#8-open-questions)
9. [Out of scope](#9-out-of-scope)

---

## 1. Context — what already exists

Shipped in the ClamAV per-vhost work:

- **Async, notify-only scanner** (`internal/clam`): the edge hook
  (`cfm_clamav.lua`) spools a multipart upload's file part and POSTs it to the
  nginx bridge, which enqueues a `clam.Job`; 2 workers `SCAN <path>` against
  clamd and emit `CLAM/UPLOAD` / `CLAM/INFECTED`. **The request is never
  blocked** — the ack is bounded (~300ms) and the queue drops on overflow.
- **Per-vhost on/off + global default**: `scan(host) = CLAMD_ENABLED &&
  (CLAM_SCAN_DEFAULT XOR host-in-override)`. Default ON. Override flips a vhost.
- **Resilience** (PR-B): a circuit breaker + health prober; when clamd is down
  the workers fast-skip instead of blocking, and a `CLAM/DOWN` alert fires.
- **Insights** (PR-C): admin scanner-status card + scoped per-vhost coverage +
  scoped `clam_infected` history.

Both items below build on this; neither should change the async default.

## 2. The two axes are independent

There are **three** conceptual per-vhost states, expressed by two orthogonal
knobs plus the existing on/off:

| axis | question | knob | default |
|---|---|---|---|
| coverage | scan this vhost at all? | on/off (shipped) | on |
| **scope** | which files are worth scanning? | `CLAM_SCAN_SCOPE` | `archives` |
| **mode** | notify-only or block? | `CLAM_SCAN_MODE` | `async` |

Do **not** collapse scope/mode into the on/off XOR — each answers a different
question and each has a different blast radius. Keep async as the always-safe
fallback; inline is a deliberate opt-in.

## 3. Item 1 — `CLAM_SCAN_SCOPE` (archives-only default)

**Why.** Scanning every upload at fleet scale is unviable on shared hosting —
`png`/`jpg`/`gif`/`webp`/`pdf`/`mp4` are high-volume and low-value as clamd
targets ("θάνατος σε μαζική κλίμακα σε shared servers"). The scanner is a second
line *after* the WAF; the files the WAF genuinely can't inspect are **compressed
containers** (a PHP shell inside a `.zip`). So the high-value default is
archives only.

**Values.**
- `archives` (default): scan only container/archive types.
- `all`: scan every multipart file part (today's behaviour).

**Type detection — magic bytes, NOT extension.** We already learned extensions
are forgeable (the multi-digit `.phpNN` bypass). Gate on content magic:
- Archives to scan: ZIP (`PK\x03\x04`), RAR (`Rar!\x1a\x07`), GZIP (`\x1f\x8b`),
  7z (`7z\xbc\xaf\x27\x1c`), XZ (`\xfd7zXZ`), BZIP2 (`BZh`), TAR (ustar magic at
  offset 257). Note `.tar.gz` presents as GZIP magic — fine, scan the gz.
- Skip list (when `archives`): image/video/pdf magic (`\x89PNG`, `\xff\xd8\xff`
  JPEG, `GIF8`, `RIFF…WEBP`, `%PDF`, ISO-BMFF `ftyp`).

**Where to gate — the real decision.** Two options, with a trade-off:
- **Edge (`cfm_clamav.lua`), before spool/enqueue** — cheapest (no disk, no
  bridge round-trip for skipped files), but the magic bytes live at the *start*
  of the file part, which shares the F17 truncation risk (a file part padded
  past the 32KB WAF-body cap). Mitigate: read the file part's leading bytes
  directly from the spooled body / `get_body_data` rather than the capped WAF
  view.
- **Scanner (`internal/clam` `process()`), after enqueue** — read the first N
  bytes of the spooled temp file (reliable, post-reassembly) and skip the `SCAN`
  if not an archive. Costs the spool + enqueue but is simpler and truncation-
  proof.

Recommendation: gate at the **scanner** first (simple, correct), then optimise
with an edge pre-filter if spool cost shows up. Either way, count skipped-by-
scope in the `HealthSnapshot` (a new counter) so the insights page can show it.

**Interaction with the existing pipeline.** Scope is a filter *inside* an
already-scanned vhost — it does not change the on/off XOR. A vhost that is
`scan=on` + `scope=archives` scans only archives; `scan=off` scans nothing
regardless of scope.

## 4. Item 2 — `CLAM_SCAN_MODE` (async vs inline)

**Why.** Some operators want real prevention: reject the upload response when
clamd flags the file, not just log it. That is a genuinely new *enforcement*
capability with real blast radius — a slow/down clamd would now delay or block
legitimate uploads — so it ships behind an explicit opt-in and defaults OFF.

**Values.**
- `async` (default): today's behaviour — enqueue, return immediately, notify.
- `inline`: the edge **waits** for the verdict (bounded) and returns `403`
  (or a template) on infection; clean/unknown → allow.

**Data-path change (the hard part).** The current bridge is fire-and-forget
(enqueue + ~300ms ack). Inline needs a *synchronous* scan:
- `cfm_clamav.lua` POSTs the body to a new bridge endpoint and **blocks** for
  the verdict within a hard timeout (e.g. `CLAM_INLINE_TIMEOUT`, default ~2–3s).
- Prefer clamd **`INSTREAM`** (stream the body, get a verdict on the same
  connection) over `SCAN <path>` — no spool-to-disk round-trip on the blocking
  path. `internal/clam` currently only does `SCAN <path>`; add an INSTREAM
  client method.

**The critical safety property — fail OPEN.** Inline mode MUST allow the upload
when clamd is unavailable, the queue is saturated, or the scan exceeds the
timeout. Reuse the PR-B circuit breaker: **breaker open ⇒ inline degrades to
allow-and-log**, never block. A clamd outage must never take down uploads
fleet-wide. This is non-negotiable and should have its own test.

**Per-vhost.** Global `CLAM_SCAN_MODE` default `async`, with a per-vhost mode
override (a second override store, or extend the existing one to carry a mode).
So a vhost is: `off` / `on+async` / `on+inline`. Inline is opt-in per vhost and
gets its own burn-in.

**Burn-in.** Ship with a `DRY_RUN`-style guard: inline-dry-run scans
synchronously and logs what it *would* block, without blocking — so an operator
can measure latency and false-positive rate before arming real blocking on a
vhost. Mirror the `waf_security` DRY_RUN discipline.

## 5. Config surface

```
# scope: which file types are worth scanning (magic-bytes based)
CLAM_SCAN_SCOPE = archives      # archives | all   (default archives)

# mode: notify-only vs block-on-infection
CLAM_SCAN_MODE  = async         # async | inline   (default async)
CLAM_INLINE_TIMEOUT = 3s        # inline hard cap; on timeout → allow (fail-open)
CLAM_INLINE_DRY_RUN = 0         # 1 = scan+log inline, never block (burn-in)
```

Both render into `cfm_clamav_config.lua` alongside `enabled`/`scan_default`
(via `sslcollector.WriteClamavLuaConfig`) and mirror into the webdetector
package (like `SetClamScanPolicy`) so the insights page reports them. Per-vhost
mode override reuses the scoped `/api/v1/clam/override/*` + `scopeCheckHost`
pattern.

## 6. UI / insights

- Scanner-status card: show `scope` and `mode` (global) next to the scan
  default; add skipped-by-scope and inline-blocked counters to `HealthSnapshot`.
- Coverage table: a per-vhost `mode` column (async/inline) once the per-vhost
  mode override lands — reuse the vhost-controls grid pattern.
- Infections history already distinguishes nothing about mode; add
  `payload.mode` (`async`/`inline`/`inline_dryrun`) to the `clam_infected`
  event so the insights table can show whether a hit was blocked or only logged.

## 7. Phase plan

1. **Scope, scanner-side** — magic-byte gate in `process()`, `CLAM_SCAN_SCOPE`
   config, skipped-by-scope counter, insights display. Default `archives`
   (behaviour change: shrinks what's scanned — announce in CHANGELOG, offer
   `all` for parity). Its own PR + review.
2. **Scope, edge pre-filter** (optional optimisation) — leading-bytes check in
   `cfm_clamav.lua` to skip spool/enqueue for non-archives. Its own PR.
3. **Inline plumbing** — INSTREAM client, synchronous bridge endpoint, blocking
   edge path, `CLAM_INLINE_TIMEOUT`, fail-open on breaker/timeout, DRY_RUN.
   Global `CLAM_SCAN_MODE` only. Heavy review; test fail-open hard.
4. **Per-vhost mode** — mode override store + scoped API + UI column.

## 8. Open questions

- Scope: is TAR (offset-257 magic, no leading signature) worth the extra read,
  or scan only leading-signature archives in v1?
- Scope: do we ever want a per-vhost scope override, or is global enough?
- Inline: INSTREAM size cap — clamd `StreamMaxLength`; how to behave when the
  body exceeds it (allow-and-log? fall back to spooled `SCAN`?).
- Inline: what does the operator-facing block page look like, and does it need
  a WAF/challenge-style bypass carve-out for panel/transfer endpoints
  (`/acctxfer*`, WHM live-transfer) — same class of hang risk we hit before.
- Mode + scope interaction: inline should probably still honour scope (only
  block on archive types) — confirm.

## 9. Out of scope

- Rewriting the async pipeline — async stays the default and the fallback.
- Scanning inside archives ourselves (clamd already recurses archives).
- Content-disarm/reconstruction, sandbox detonation, or any non-clamd engine.
