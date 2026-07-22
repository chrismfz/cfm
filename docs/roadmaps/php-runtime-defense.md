# CFM — PHP Runtime Defense (Snuffleupagus) Roadmap

**Status:** Design — not started. Facts below verified against the upstream docs
(https://snuffleupagus.readthedocs.io/) on 2026-07-22; re-verify before building.
**Scope:** Deploy and *manage* the Snuffleupagus (SP) PHP extension as CFM's
PHP-runtime layer: CFM-rendered rules, monitor/enforce modes, per-vhost
excludes, a JSON event log + detector, and a cfm-admin page — mirroring the
ClamAV/vhost-controls patterns.
**Goal:** Close the "Proactive Defense" gap in the Imunify360-replacement
picture with a maintained open-source engine we orchestrate — instead of
writing our own PHP extension — with a simulation-first rollout that never
takes down customer PHP.

---

## Table of Contents

1. [Positioning — what layer this is](#1-positioning--what-layer-this-is)
2. [How SP actually works (verified)](#2-how-sp-actually-works-verified)
3. [Deployment model — global load, CFM-rendered rules](#3-deployment-model--global-load-cfm-rendered-rules)
4. [Modes — monitor / enforce, global + per-rule](#4-modes--monitor--enforce-global--per-rule)
5. [Per-vhost model](#5-per-vhost-model)
6. [Logging, alerts & the FP loop](#6-logging-alerts--the-fp-loop)
7. [Ruleset — what we ship, in tiers](#7-ruleset--what-we-ship-in-tiers)
8. [The failure mode that matters: a broken rules file](#8-the-failure-mode-that-matters-a-broken-rules-file)
9. [Packaging — the per-PHP-version build matrix](#9-packaging--the-per-php-version-build-matrix)
10. [Synergies with existing CFM layers](#10-synergies-with-existing-cfm-layers)
11. [Control plane & UI](#11-control-plane--ui)
12. [Phase plan](#12-phase-plan)
13. [Open questions](#13-open-questions)
14. [Out of scope](#14-out-of-scope)

---

## 1. Positioning — what layer this is

| Layer | Sees | Owns |
|---|---|---|
| CFM WAF (edge) | the HTTP request, pre-PHP | web-triggered exploits, uploads |
| ClamAV | file bytes (upload/at-rest) | known malware on disk |
| **SP (this)** | **code inside the PHP VM, post-deobfuscation** | malicious PHP *behaviour*, web + CLI/cron |
| cfm-lsm | syscalls / kernel LSM hooks | post-exploitation acts (exec, writes, connect-out) |

SP is the analogue of Imunify360's Proactive Defense, with a difference in
philosophy: PD is signature-based malware *detection* (hash lists), SP is
behaviour/policy *enforcement* (rules + virtual patching). It will not match
PD hash-for-hash; it kills the same bug classes (command injection, eval
chains, wrapper abuse, malicious includes) at the same layer, and it pairs
with cfm-lsm underneath (in-PHP attacks SP; anything that escapes to the OS,
the LSM).

## 2. How SP actually works (verified)

- **A PHP extension** (`snuffleupagus.so`), loaded via ini; config via
  `sp.configuration_file`, which supports **comma-separated files and glob
  patterns** (`/etc/.../*.rules`) — so a rules *directory* is natively
  supported.
- **Rules DSL**, e.g.
  `sp.disable_function.function("system").param("cmd").value_r("[$|;&\x60\n]").drop();`
  Filters: `.filename()`/`.filename_r()`, `.param()`/`.param_r()`,
  `.value()`/`.value_r()`, `.function()`/`.function_r()`, `.cidr()`, call-trace
  (`.function("a>b")`). Actions: `.drop()` / `.allow()`; `.dump(dir)` captures
  forensics for matched requests.
- **Evaluation is first-match-wins** — an `.allow()` placed *before* a
  `.drop()` whitelists that case. This is the mechanism our per-vhost excludes
  build on.
- **Simulation** exists **per feature and per rule** (`.simulation()`):
  logs what *would* block, blocks nothing. This is exactly our `logonly`.
- **Logging**: `sp.log_media("php"|"syslog"|"file:/path")` — we can point SP
  at a dedicated file and tail it.
- **Broken config**: by default an invalid rules file breaks PHP startup.
  `sp.allow_broken_configuration` exists but upstream recommends against it —
  see §8 for our gate instead.

## 3. Deployment model — global load, CFM-rendered rules

Load **globally per PHP version** (cPanel EA4 `ea-phpXX`, DA equivalents, and
CloudLinux `alt-php` where present): one ini drop-in per version pointing at a
CFM-owned rules directory:

```
; /opt/cpanel/ea-php82/root/etc/php.d/zz-cfm-sp.ini
extension=snuffleupagus.so
sp.configuration_file=/var/lib/cfm/sp/rules/*.rules
```

The rules directory is **generated** by cfm (like the rendered Lua configs):
reference material under `configs/sp/` → rendered, validated output under
`/var/lib/cfm/sp/rules/` (root:cfm, 0640 discipline). Operators never
hand-edit the rendered dir; overrides flow through the CFM control plane.

Per-vhost *loading* (per-FPM-pool ini) is deliberately **not** the v1
mechanism — pool templates differ per panel and fight with panel upgrades.
Path-scoped rules (§5) give per-vhost behaviour inside one global config.

## 4. Modes — monitor / enforce, global + per-rule

Two knobs, mirroring the WAF's `logonly → block` discipline:

- **Global mode** `SP_MODE = monitor | enforce` (default **monitor**).
  In monitor, the renderer appends `.simulation()` to every blocking rule.
  Fleet-deploys are burn-ins by default; nothing can break customer code on
  day one.
- **Per-rule state** `RULE_<id> = enforce | monitor | off` — every CFM-shipped
  rule carries a stable CFM rule id (comment-tagged in the rendered file and
  keyed in config). Promotion is per-rule, after its measured FP rate is
  clean (§6), exactly like promoting a WAF rule from logonly.

`enforce` global mode still honours per-rule `monitor`/`off` holds — arming a
newly added rule is always a deliberate per-rule decision (the
`waf_security`/WAF_CVE lesson: never let a default silently arm).

## 5. Per-vhost model

Same operator model as WAF/Challenge/Clam, different mechanics underneath:

- **Per-vhost disable (exclude)**: rendered as `.allow()` rules scoped by
  `.filename_r("^/home[0-9]*/USER/")` placed **before** the matching `.drop()`
  rules (first-match-wins makes this a whitelist). Granularity: whole-SP for a
  vhost, or per-rule for a vhost — both flow from one override store, reusing
  the `excludeStore` + scoped-API pattern (`RequireScopedOrAdmin` +
  `validateScopedExcludeWrite`; scoped tokens: host-type only, own vhost only).
- **Docroot → regex mapping** comes from the same vhost discovery the
  webdetector already does (cPanel userdata); rendered, never hand-written.
- Optional later: per-vhost *enforce* while global is monitor (the inverse),
  for early-adopter vhosts — the renderer supports it naturally (scoped
  non-simulation rule before the global simulation one).

## 6. Logging, alerts & the FP loop

SP's own log lines are plain text; CFM normalizes them:

- Point SP at a dedicated file: `sp.log_media("file:/var/log/cfm/sp.raw.log")`.
- A new **detector** (`internal/detectors/sp/`, log-driven — our bread and
  butter) tails it, parses rule id / vhost (from path) / client IP / function /
  filename, and:
  - writes **`/var/log/cfm/cfm.sp.log` as JSON** (schema like `cfm.waf.log`:
    ts, mode=`sim|drop`, cfm_rule_id, vhost, ip, function, script, evidence);
  - emits notifier events (`SP/SIM` info, `SP/DROP` warning|critical);
  - feeds **per-rule hit-rate counters** (the `waf hit-rates` pattern) — this
    is the promotion evidence: a rule with N days of zero/known-bad-only sim
    hits gets promoted; a noisy rule gets tuned or held.
- **FP handling order** (cheapest first): per-vhost per-rule allow → per-vhost
  whole-SP allow → per-rule global `monitor`/`off`. Never loosen global mode
  because one vhost's app trips one rule.
- IP-based autoblock from SP hits is **explicitly deferred**: killing a script
  is per-request enforcement; nft-banning the source needs the same care as
  `waf_security` Phase 1 (drop-tier only, family analysis) and its own design
  pass. CLI/cron hits have `cidr`/IP semantics that don't map to a remote
  attacker at all.

## 7. Ruleset — what we ship, in tiers

Curated from upstream's `default.rules`/`default_php8.rules` plus our own;
every rule gets a CFM id, a tier, and a default state:

**Tier 1 — enforce-candidates (start in monitor, promote first):**
- `system()`/`exec()`/`passthru()` argument injection (shell metachars in
  tainted params) — upstream's flagship rule.
- `mail()` `additional_parameters` injection (the `-X` file-write RCE class).
- Stream-wrapper abuse in includes: `data://`, `php://input`, `phar://` in
  include/require context.
- `curl` SSL-verify disable (`CURLOPT_SSL_VERIFYPEER/HOST = 0`).
- `chmod 0777`-class hardening.
- Recon probes: `ini_get`/`is_callable` chains on dangerous functions.

**Tier 2 — valuable but FP-prone (monitor long, promote per-vhost or never):**
- `eval()` blacklist (page builders/cache layers eval legitimately —
  measure per-vhost before dreaming of enforce).
- Include-extension whitelist (AFI hardening).
- `readonly_exec` (blocks PHP files writable by the PHP user — kills webshell
  persistence, but shared-hosting file ownership makes this loud; also SP's
  writable-exec block and cPanel file perms interact — measure).

**Tier 3 — DO NOT ship in v1 (documented-breaking on shared hosting):**
- Cookie encryption (invalidates sessions on key change; per-app breakage).
- `unserialize` HMAC (breaks existing serialized DB data — upstream says
  simulation-migrate first; per-app, not fleet, decision).
- Global strict mode / sloppy-comparison rewrite (type-juggling fixes that
  legacy CMS code trips constantly).
- Blanket stream-wrapper whitelist (breaks legit remote-file features).

**CVE virtual patches** (the SP side of WAF_CVE): per-CVE `sp.disable_function`
rules with exact signatures. Same iron rule as WAF_CVE: **never write a CVE
signature from memory** — PoC/patch/NVD/operator captures only; per-rule hold
(`monitor`) for lower-confidence rules; Lua↔Go-style id parity between the
rendered rules and the Go rule registry, enforced by a test.

## 8. The failure mode that matters: a broken rules file

An invalid rules file **breaks PHP startup fleet-wide** — every vhost, every
request. This is the SP equivalent of shipping a Lua file that fails to load,
and it gets the same treatment (a hard gate, not hope):

1. **Render** to a staging path.
2. **Validate** against *every installed PHP version*:
   `ea-phpXX/root/usr/bin/php -d extension=snuffleupagus.so -d sp.configuration_file=<staging>/*.rules -v`
   must exit 0 for each — a rule can be valid on 8.2 and break 7.4.
3. **Atomically swap** staging → live only when all pass; keep the previous
   rules dir as `last-good`.
4. **Reload FPM pools** (SP reads config at startup) — panel-appropriate
   reload, batched.
5. On any validation failure: keep serving last-good, alert loudly
   (`SP/CONFIG_INVALID`), never deploy.
6. `sp.allow_broken_configuration` stays **off** — it converts a loud failure
   into silent non-enforcement.

A `scripts/tests/check_sp_rules.sh` CI guardrail (syntax-validate reference
rules with whatever PHP is on the runner) mirrors `make lua`.

## 9. Packaging — the per-PHP-version build matrix

The single biggest operational cost. `snuffleupagus.so` must be built **per
PHP version** (`phpize` per `ea-phpXX` / DA php-mode / `alt-php`), and rebuilt
when panels roll minor PHP updates.

- v1: a build script iterating installed PHP SDKs on the host (or a CFM repo
  package per EA4 version, like CloudLinux does for its modules), triggered
  from `make release` tooling.
- `cfm sp status` must show, per PHP version: extension built? loaded? rules
  file hash? — drift here (a new ea-php installed without SP) silently opens a
  gap, so the detector should also flag "PHP version present without SP".
- CloudLinux `alt-php` multiplies the matrix; DirectAdmin's custombuild has
  its own hook points. Scope v1 to the panel/PHP set our fleet actually runs.

## 10. Synergies with existing CFM layers

- **`sp.upload_validation`** runs an external script per upload; non-zero exit
  blocks the file. `CLAM_SCAN_MODE=inline` already ships at the edge (see
  `docs/roadmaps/clam-scan-modes.md`), so this is **not** needed for inline
  upload blocking on OpenResty/Angie fleets — consider it only as a fallback
  for deployments where the edge proxy is not in path (pure-DNAT hosts), and
  only with the same fail-open rule: clamd down/timeout ⇒ exit 0.
- **`mail()` X-header injection** (SP adds a header identifying the sending
  script) → feeds the exim detector for spam-source tracing, an
  Imunify-feature-for-free.
- **`.dump()` forensics** on drop-tier rules → evidence directory in the style
  of the clam infected/ quarantine, surfaced on the insights page.
- **cfm-lsm** stays the layer below: SP kills in-PHP abuse; LSM catches what
  escapes to syscalls. Expect the same "signal, then noise" tuning curve the
  LSM had — budget for it.

## 11. Control plane & UI

Mirror the ClamAV work end-to-end (same shapes, same auth):

- **Config** (`cfm.conf`): `SP_ENABLED` (infra), `SP_MODE = monitor|enforce`,
  per-rule `SP_RULE_<id>` states; rendered like the clam lua config, mirrored
  into the daemon (à la `SetClamScanPolicy`) so UI == enforced reality.
- **CLI**: `cfm sp status` (per-PHP-version load state, mode, rule counts,
  last render/validate), `cfm sp mode monitor|enforce`,
  `cfm sp rule list|monitor|enforce|off <id>`,
  `cfm sp exclude add|remove|list <host> [--rule N]` (scoped semantics
  identical to `cfm clam override`).
- **API**: `/api/v1/sp/health` (admin: per-version load matrix, mode, config
  hash, last validation), `/api/v1/sp/exclude/*` (scoped, host-type only),
  events via the history store (`sp_sim`/`sp_drop` event types) queryable
  through the existing scoped history endpoint — the PR-C.2 pattern verbatim.
- **UI**: an "SP" page (status card + per-rule hit table + recent events,
  scoped like the ClamAV page) and later an SP column in vhost-controls.
- **Docs**: endpoint_scope_inventory.md entries land in the same change as the
  handlers (house rule).

## 12. Phase plan

Each phase is its own PR(s) + review; later phases only start after the
previous one has fleet burn-in.

1. **P0 — packaging spike**: build `snuffleupagus.so` for the fleet's PHP
   matrix; `cfm sp status` detection only. No rules, nothing loaded.
2. **P1 — monitor-only fleet deploy**: ini drop-ins + rendered Tier-1 ruleset,
   all `.simulation()`; the render→validate→swap→reload pipeline (§8) and the
   CI guardrail; SP detector → `cfm.sp.log` JSON + notifier + per-rule
   hit-rates. *No enforcement anywhere.*
3. **P2 — control plane**: modes + per-rule states + scoped per-vhost
   excludes + `/api/v1/sp/*` + the SP admin page.
4. **P3 — first promotions**: Tier-1 rules with clean burn-in to `enforce`,
   one by one; `.dump()` forensics on the promoted set.
5. **P4 — CVE virtual patching**: per-CVE rules under the WAF_CVE discipline.

## 13. Open questions

- Which PHP versions/panels does the fleet actually run (bounds the P0 build
  matrix — EA4 only? alt-php? DA)?
- CLI/cron PHP invocations don't read FPM ini the same way — confirm the ini
  drop-in covers CLI SAPI too, and decide whether cron-side enforcement is
  wanted at all in v1 (Imunify PD covers it; it's where its `/tmp/...` catches
  came from).
- Rule-id scheme: numeric bands like the WAF (1xx hardening / 9xx CVE), and
  where the id↔rule parity test lives.
- Does `sp.log_media("file:")` handle log rotation sanely, or do we need
  copytruncate care in the tailer?
- Per-vhost docroot regexes: `/home[0-9]*/user/` covers cPanel; DA paths
  differ — render per-panel.
- Opcache/FPM interaction: any need to clear opcache on rules swap? (Rules are
  ini-level, read at startup — FPM reload should suffice; verify.)

## 14. Out of scope

- Writing our own PHP extension (SP *is* the engine; we orchestrate).
- Hash-based PHP malware signature feeds (that's ClamAV's + the scanner
  roadmap's job; SP is behaviour/policy).
- IP autoblock from SP events (deferred — needs its own `waf_security`-style
  design pass).
- Tier-3 features (cookie encryption, unserialize HMAC, strict mode) — revisit
  only per-app, never fleet-default.
