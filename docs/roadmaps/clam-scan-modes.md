# CFM — ClamAV Scan Scope & Mode Roadmap

**Status:** Items 1 (scope, scanner-side), 2 (sig-ignore: config baseline +
global/per-vhost store + API/CLI/UI) and 3 (inline mode: INSTREAM client,
synchronous bridge endpoint, fail-open edge path, DRY_RUN burn-in, per-vhost
mode override + UI/CLI) **shipped 2026-07-21**. `CLAM_SCAN_MODE` defaults
async — inline is per-operator opt-in after burn-in. The only remaining item
is the optional edge pre-filter (phase 4).
**Scope:** Three independent knobs layered on the existing async upload scanner —
(1) `CLAM_SCAN_SCOPE` (what file types are worth scanning),
(2) `CLAM_SIG_IGNORE` (which signatures are trusted enough to act on), and
(3) `CLAM_SCAN_MODE` (notify-only vs block-on-infection). Touch the scan data
path (`configs/lua/cfm_clamav.lua`, `internal/clam`), config, and the ClamAV
insights page.
**Goal:** Make fleet-wide upload scanning viable on busy shared servers
(scope), tame FP-prone signatures (sig-ignore) so real inline blocking is
trustworthy where an operator wants it (mode) — without regressing the safe,
months-proven async default.

---

## Table of Contents

1. [Context — what already exists](#1-context--what-already-exists)
2. [The axes are independent](#2-the-axes-are-independent)
3. [Item 1 — `CLAM_SCAN_SCOPE` (archives-only default)](#3-item-1--clam_scan_scope-archives-only-default)
4. [Item 2 — signature excludes (`CLAM_SIG_IGNORE`) — prerequisite for inline](#4-item-2--signature-excludes-clam_sig_ignore--prerequisite-for-inline)
5. [Item 3 — `CLAM_SCAN_MODE` (async vs inline)](#5-item-3--clam_scan_mode-async-vs-inline)
6. [Config surface](#6-config-surface)
7. [UI / insights](#7-ui--insights)
8. [Phase plan](#8-phase-plan)
9. [Open questions](#9-open-questions)
10. [Out of scope](#10-out-of-scope)

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

## 2. The axes are independent

The per-vhost decision decomposes into orthogonal knobs layered on the existing
on/off:

| axis | question | knob | default |
|---|---|---|---|
| coverage | scan this vhost at all? | on/off (shipped) | on |
| **scope** | which files are worth scanning? | `CLAM_SCAN_SCOPE` | `archives` |
| **signatures** | which verdicts are trusted enough to act on? | `CLAM_SIG_IGNORE` | hunting-grade sigs ignored |
| **mode** | notify-only or block? | `CLAM_SCAN_MODE` | `async` |

Do **not** collapse any of these into the on/off XOR — each answers a different
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

**What scope does NOT fix — Office files.** `docx`/`xlsx`/`odt`/`jar`/`apk`
*are* ZIP containers (`PK` magic), so `archives` keeps scanning them — correctly
(they can carry macros/payloads). That means archive-scope does **not** reduce
Office-document false positives like the observed
`YARA.SIGNATURE_BASE_Brooxml_Hunting.UNOFFICIAL` hit on a legitimate `.docx`.
That class of FP is a *signature-trust* problem, which is Item 2's job.

## 4. Item 2 — signature excludes (`CLAM_SIG_IGNORE`) — prerequisite for inline

**Why.** Real-world FP, observed in production: a legitimate customer `.docx`
flagged as `YARA.SIGNATURE_BASE_Brooxml_Hunting.UNOFFICIAL`. Third-party
*hunting-grade* YARA rulesets (signature-base "Hunting" rules, most
`.UNOFFICIAL` sigs) are written for threat hunting, not enforcement — they are
FP-prone **by design**. In async mode such a hit costs a spurious email; in
inline mode it would 403 a legitimate upload. So a signature-trust layer is a
**prerequisite for Item 3** (inline), and useful today to silence known-FP
notifications without touching clamd's signature databases.

**Semantics.** A matched ignore pattern means **log-only**: the scan still runs
and the hit is still written to `cfm.clam.log` + the scoped history
(`payload.sig_ignored=true`), but no CLAM/INFECTED notification fires, the file
is not moved to the infected dir, and (later) inline mode does not block. The
verdict is *downgraded*, never deleted — the operator can still audit what a
hunting sig matched.

**Config + matching.**
- Global: `CLAM_SIG_IGNORE` — comma/newline-separated glob patterns matched
  against the signature name (e.g. `*_Hunting.UNOFFICIAL`,
  `YARA.SIGNATURE_BASE_Brooxml_*`). Ship a conservative default that ignores
  hunting-grade patterns; `CLAM_SIG_IGNORE =` (empty) restores act-on-everything.
- Per-vhost: a scoped store keyed `(host, pattern)` — same scoped-auth pattern
  as `/api/v1/clam/override/*` (`validateScopedExcludeWrite`, list reads
  scope-filtered), **plus the same audit logging** (`[clam_override]`-style line
  in `cfm.clam.log`) since a scoped token weakening detection must be
  reconstructable.
- Enforcement point: **Go side only** (`internal/clam` `process()` result
  handling / the notify path) — the edge never sees signature names, so no Lua
  change and no new edge surface.
- Count ignored hits in `HealthSnapshot` (`sig_ignored` counter) for the
  insights page.

**UI / CLI.**
- CLI: `cfm clam sigignore add|remove|list <pattern> [--host <vhost>]`.
- ClamAV page: the "Recent infections" table already shows
  vhost/IP/URI/file/signature — add a per-row **"Ignore this signature"**
  action (admin: global or per-vhost; scoped: own vhost only), so the operator
  can neutralise an FP right where they see it, without a whole-vhost opt-out.
  Ignored hits render greyed-out with a `sig-ignored` badge instead of
  disappearing.

## 5. Item 3 — `CLAM_SCAN_MODE` (async vs inline)

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
override in a **separate store** — do NOT extend the existing on/off override
store to carry a mode: that store's entries are XOR *flips* whose meaning
changes with `CLAM_SCAN_DEFAULT`, and overloading them with a second semantic
is exactly the kind of drift trap §5 of CLAUDE.md warns about. So a vhost is:
`off` / `on+async` / `on+inline`. Inline is opt-in per vhost and gets its own
burn-in.

**Prerequisite: Item 2 (sig-ignore).** Do not arm inline anywhere while
hunting-grade signatures can still block — the observed Brooxml-on-docx FP
would have been a 403 on a legitimate customer upload.

**OpenResty-only.** `cfm_clamav.lua` runs in the in-path edge proxy; in **DNAT
mode there is no in-path edge for the vhost**, so uploads are not intercepted
and inline blocking is meaningless there. The mode knob must be a documented
no-op (and the UI column hidden/greyed) for DNAT-mode deployments — same
both-modes discipline as the challenge carve-outs (§6 CLAUDE.md).

**Burn-in.** Ship with a `DRY_RUN`-style guard: inline-dry-run scans
synchronously and logs what it *would* block, without blocking — so an operator
can measure latency and false-positive rate before arming real blocking on a
vhost. Mirror the `waf_security` DRY_RUN discipline.

## 6. Config surface

```
# scope: which file types are worth scanning (magic-bytes based)
CLAM_SCAN_SCOPE = archives      # archives | all   (default archives)

# signatures: verdicts to downgrade to log-only (glob on signature name)
CLAM_SIG_IGNORE = *_Hunting.UNOFFICIAL   # conservative default; empty = act on all

# mode: notify-only vs block-on-infection
CLAM_SCAN_MODE  = async         # async | inline   (default async)
CLAM_INLINE_TIMEOUT = 3s        # inline hard cap; on timeout → allow (fail-open)
CLAM_INLINE_DRY_RUN = 0         # 1 = scan+log inline, never block (burn-in)
```

Scope and mode render into `cfm_clamav_config.lua` alongside
`enabled`/`scan_default` (via `sslcollector.WriteClamavLuaConfig`) and mirror
into the webdetector package (like `SetClamScanPolicy`) so the insights page
reports them; `CLAM_SIG_IGNORE` is Go-side only (the edge never sees signature
names). Per-vhost mode/sig-ignore overrides reuse the scoped
`/api/v1/clam/override/*` + `scopeCheckHost` pattern **including its audit
logging**.

## 7. UI / insights

- Scanner-status card: show `scope` and `mode` (global) next to the scan
  default; add skipped-by-scope, sig-ignored and inline-blocked counters to
  `HealthSnapshot`.
- Coverage table: a per-vhost `mode` column (async/inline) once the per-vhost
  mode override lands — reuse the vhost-controls grid pattern.
- Infections table: per-row **"Ignore this signature"** action (Item 2) —
  global or per-vhost for admins, own-vhost for scoped users; ignored hits stay
  visible, greyed with a `sig-ignored` badge.
- Infections history already distinguishes nothing about mode; add
  `payload.mode` (`async`/`inline`/`inline_dryrun`) to the `clam_infected`
  event so the insights table can show whether a hit was blocked or only logged.

## 8. Phase plan

1. **Scope, scanner-side** — magic-byte gate in `process()`, `CLAM_SCAN_SCOPE`
   config, skipped-by-scope counter, insights display. Default `archives`
   (behaviour change: shrinks what's scanned — announce in CHANGELOG, offer
   `all` for parity). Its own PR + review.
2. **Sig-ignore, global** — `CLAM_SIG_IGNORE` glob match in the scan-result
   path, log-only downgrade, `sig_ignored` counter + history payload flag.
   Its own PR.
3. **Sig-ignore, per-vhost + UI** — scoped store/API (with audit logging), CLI,
   and the per-row "Ignore this signature" action on the ClamAV page.
4. **Scope, edge pre-filter** (optional optimisation) — leading-bytes check in
   `cfm_clamav.lua` to skip spool/enqueue for non-archives. Its own PR.
5. **Inline plumbing** — INSTREAM client, synchronous bridge endpoint, blocking
   edge path, `CLAM_INLINE_TIMEOUT`, fail-open on breaker/timeout, DRY_RUN.
   Global `CLAM_SCAN_MODE` only. Requires phases 2–3 shipped. Heavy review;
   test fail-open hard.
6. **Per-vhost mode** — separate mode-override store + scoped API + UI column.

## 9. Open questions (with current leanings)

- Scope: TAR has no leading signature (ustar magic at offset 257). **Leaning:
  leading-signature archives only in v1** — zip/gz/rar/7z/xz/bz2 cover the real
  browser-upload threat; plain `.tar` uploads are rare and the extra read
  complicates the gate.
- Scope: do we ever want a per-vhost scope override, or is global enough?
- Inline: body exceeds clamd `StreamMaxLength` — **leaning: allow the request
  (fail-open) and fall back to the async spooled `SCAN`** so the file is still
  scanned/notified, rather than a plain allow that drops coverage silently.
- Inline: what does the operator-facing block page look like, and does it need
  a WAF/challenge-style bypass carve-out for panel/transfer endpoints
  (`/acctxfer*`, WHM live-transfer) — same class of hang risk we hit before.
- Mode + scope interaction: inline should probably still honour scope (only
  block on archive types) — confirm.

## 10. Out of scope

- Rewriting the async pipeline — async stays the default and the fallback.
- Scanning inside archives ourselves (clamd already recurses archives).
- Content-disarm/reconstruction, sandbox detonation, or any non-clamd engine.
