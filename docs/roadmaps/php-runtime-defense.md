# CFM — PHP Runtime Defense (Snuffleupagus) Roadmap

**Status:** Design — not started. **Revised 2026-07-22** to lead with a
panel-agnostic PHP *inventory* and a **manager / adapter split**, because the
fleet runs a heterogeneous PHP matrix (cPanel EA4, CloudLinux alt-php,
DirectAdmin CustomBuild, LiteSpeed lsphp, custom). SP facts verified against
the upstream docs (https://snuffleupagus.readthedocs.io/); re-verify before
building.
**Scope:** *Manage* the Snuffleupagus (SP) PHP extension as CFM's PHP-runtime
layer — CFM-rendered rules, monitor/enforce modes, per-vhost excludes, a JSON
event log + detector, and a cfm-admin page — with the platform-specific
build/load/reload mess isolated behind a thin per-target adapter.
**Goal:** Close the "Proactive Defense" gap in the Imunify360-replacement
picture with a maintained open-source engine we orchestrate — never writing our
own PHP extension — with a simulation-first rollout that never takes down
customer PHP, and an inventory-first approach that never guesses the matrix.

---

## Table of Contents

1. [Positioning — what layer this is](#1-positioning--what-layer-this-is)
2. [How SP actually works (verified)](#2-how-sp-actually-works-verified)
3. [The fleet reality — manager vs adapter](#3-the-fleet-reality--manager-vs-adapter)
4. [PHP-platform adapters — the target matrix](#4-php-platform-adapters--the-target-matrix)
5. [Deployment model — global load, CFM-rendered rules](#5-deployment-model--global-load-cfm-rendered-rules)
6. [Modes — monitor / enforce, global + per-rule](#6-modes--monitor--enforce-global--per-rule)
7. [Per-vhost model](#7-per-vhost-model)
8. [Logging, alerts & the FP loop](#8-logging-alerts--the-fp-loop)
9. [Ruleset — what we ship, in tiers](#9-ruleset--what-we-ship-in-tiers)
10. [The failure mode that matters: a broken rules file](#10-the-failure-mode-that-matters-a-broken-rules-file)
11. [Coexistence with Imunify Proactive Defense & cutover](#11-coexistence-with-imunify-proactive-defense--cutover)
12. [Synergies with existing CFM layers](#12-synergies-with-existing-cfm-layers)
13. [Control plane & UI](#13-control-plane--ui)
14. [Phase plan](#14-phase-plan)
15. [Open questions](#15-open-questions)
16. [Out of scope](#16-out-of-scope)

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
  see §10 for our gate instead.

## 3. The fleet reality — manager vs adapter

The fleet is a heterogeneous PHP matrix: LiteSpeed + lsphp, lsphp behind
nginx/apache, plain php-fpm; some cPanel, some DirectAdmin, some custom. The
temptation is to see chaos and stall. The discipline is: **the chaos lives in
exactly one layer — isolate it there.**

| Layer | What it does | Platform-specific? | Share of the value |
|---|---|---|---|
| **Manager** | render rules, monitor/enforce modes, per-vhost excludes, log → `cfm.sp.log` JSON, detector, notifier, UI | **none** | ~80% |
| **Adapter** | build / install / load / reload SP for one PHP flavour | **all of it** | ~20% |

The manager operates on **rendered `.rules` files + the SP log** — both
identical on every platform. So it is written **once** and works anywhere SP is
loadable. Everything panel-specific (compile per PHP version, extension dir,
ini drop-in path, reload command, CageFS visibility) hides behind a small
adapter interface (§4), one implementation per target.

**The decisive principle: manager, not builder (in v1).** Architect the manager
to be *agnostic to how SP got installed*. Installation/build is a pluggable
adapter step that **starts with one target** and grows target-by-target. This
means the valuable 80% ships without waiting on the full build matrix, and a
new platform is a new small adapter — never a manager rewrite.

**Corollary: inventory before anything (§14 P0).** You cannot scope the build
matrix, or even decide which targets exist, without first *measuring* the
fleet. A read-only inventory is therefore the true first step — safe to deploy
everywhere, useful on its own, and the foundation the manager needs anyway.

## 4. PHP-platform adapters — the target matrix

One adapter per PHP flavour, behind an interface roughly:

```
// conceptual — one implementation per target
type PHPTarget interface {
    Enumerate() []PHPBuild   // version, SAPI, NTS/ZTS, extension_dir, ini scan dir, devel headers?
    Build(b PHPBuild) error  // phpize+compile, OR "already packaged / bring-your-own"
    Install(b, soPath)       // place snuffleupagus.so in the build's extension_dir
    IniDropIn(b) (path, body)// how this build loads the .so + points at the rules dir
    RulesVisible(b, dir) bool// e.g. CageFS: is the rendered rules dir inside the user's virt FS?
    Reload(b) error          // FPM pool reload / lsws restart / no-op for CGI
}
```

Honest difficulty ranking (drives the phase order). **The big finding
(verified on a live cPanel+CloudLinux host, 2026-07-23): whether a maintained
vendor package exists dominates the difficulty** — building the `.so` is the
expensive part, and CloudLinux already does it for alt-php:

| Target | PHP flavour | Get the `.so` | Load | Reload | Difficulty | v1? |
|---|---|---|---|---|---|---|
| **CloudLinux alt-php** | `alt-phpXX` | **`yum install alt-phpXX-snuffleupagus`** (vendor-maintained, all of 7.0–8.5) | `php.d/` + **CageFS skeleton** | FPM reload | **lowest — no build** | **beachhead where the fleet uses PHP Selector** |
| **cPanel EA4** | `ea-phpXX` (fpm/cgi/lsphp) | **build it** — no maintained vendor pkg (see below); `phpize` + `ea-phpXX-devel` headers present in the tree | `php.d/` drop-in | FPM pool reload | **medium — we own the build** | **beachhead where the fleet uses MultiPHP** |
| DirectAdmin | CustomBuild `phpXX` | build (custombuild) | `php.conf.d/` | FPM reload | medium — custombuild paths/hooks | later |
| **Standalone LiteSpeed** | `lsws/lsphpXX` | build against LiteSpeed's PHP | lsphp `php.ini` | `lswsctrl restart` | **high** | last / "unsupported v1" |
| custom | anything | ? | ? | ? | unknown — inventory decides | case-by-case |

**The alt-php vendor package reshapes the plan — but "installed" ≠ "loaded".**
On the (common) cPanel+CloudLinux fleet, the lowest-friction path to real SP is
**alt-php via PHP Selector + `yum install alt-phpXX-snuffleupagus`** — zero
compilation, vendor patches it. **BUT verified on a live host (2026-07-23):
after installing `alt-php83-snuffleupagus-0.13.0`, `php -m` still shows no
`snuffleupagus`** — the RPM only *places* the `.so`; loading it is a **CloudLinux
PHP-Selector operation (very likely per-user), not a global `php.d` auto-load**.
So the alt-php adapter is "install RPM → **enable via the selector** → render
rules into CageFS", and its load model is **per-user/selector**, unlike ea-php's
global `php.d` drop-in. Still no *build*, but not a one-liner. Two hard
consequences:
- **Inventory can't detect alt-php SP via CLI `php -m`** (it isn't loaded in the
  default context). Detect by RPM/`.so` presence + selector state instead — a
  P0b task; today's `cfm php-inventory` will under-report SP on alt-php.
- **The manager's "global load" assumption is ea-php-only.** The alt-php adapter
  owns a different enable/load model; keep that behind the adapter so the
  manager stays load-model-agnostic.

Where the fleet serves via cPanel MultiPHP (`ea-php`), we build. P0b's per-vhost
handler map tells us which stack actually serves each vhost, i.e. which adapter
matters where.

**Why EA4 is a build (the "did cPanel remove it?" answer).** cPanel never
shipped a *maintained* ea-php snuffleupagus package — only the **experimental,
release-less `CpanelInc/ea-scl-snuffleupagus`** repo, which stalled. So EA4's
intended path for a non-bundled extension applies: build with `phpize` against
`ea-phpXX-devel` (the full `…/ea-phpXX/root/usr/include/php` header tree +
`phpize`/`php-config` are present in the tree). The abandoned `ea-scl-*` spec is
still a useful **starting recipe** for the EA4 adapter's build step — crib it,
don't depend on it.

**LiteSpeed on cPanel is not the hard case.** On a cPanel+LSWS host the handler
is **ea-php's own `lsphp`** (`…/ea-phpXX/root/usr/bin/lsphp`, present in the
tree), sharing the ea-php `php.d/` — so it folds into the **EA4 adapter** (same
`.so`, same ini dir; reload differs: restart LSWS, not FPM). Only *standalone*
LiteSpeed (`/usr/local/lsws/lsphpXX/`, non-cPanel) is the separate high target.

Verified real paths (cPanel ea-php83, for the adapter):
- binaries: `…/ea-php83/root/usr/bin/{php,lsphp,php-cgi}`, FPM at
  `…/root/usr/sbin/php-fpm`, `phpize`/`php-config` in `…/usr/bin/`.
- ini scan dir: `…/ea-php83/root/etc/php.d/` (drop-in target).
- extension dir: `…/ea-php83/root/usr/lib64/php/modules/` (`.so` install target).
- **Imunify's PHP module is `i360`** (`i360.so` in modules, `i360.ini` in
  php.d) — that's what coexistence detection keys on, not "imunify"/"proactive".
- **CageFS is live** (`php.ini.cagefs`, `lsphp.cagefs` variants present) — the
  CageFS skeleton landmine is real on this fleet, not hypothetical.

Per-target landmines to bake into each adapter:

- **CloudLinux CageFS**: the `.so` *and* the rendered rules dir must live inside
  the CageFS skeleton, or the user's virtualized PHP can't see them. A rules
  swap must update the skeleton, not just the host path. (The vendor alt-php
  package already handles the `.so` side; we still render rules into the
  skeleton.)
- **Standalone LiteSpeed lsphp**: `.so` compiled against LiteSpeed's PHP; reload
  is `lswsctrl`-level. The one target we may ship "detected but unsupported".
- **CGI / suPHP / suEXEC**: fresh PHP process per request → **no reload needed**
  (rules take effect immediately, including monitor→enforce flips) but worst
  perf. The upside: the reload-window class of bug doesn't exist here.
- **Build drift**: within a PHP minor the extension ABI is usually stable, but
  a panel bumping the *minor* (`ea-php82` 8.2.x → an ABI-affecting rebuild) can
  silently unload a self-built SP. The inventory/status **must flag "PHP build
  present without a matching SP"** so drift is visible, never silent. (alt-php's
  vendor package sidesteps this — yum rebuilds track the PHP package.)
- **`ext/` vs Zend extension load order**: SP is a normal extension; keep the
  drop-in prefix (`zz-…`) so it loads after anything it must observe.

Whether CFM **installs a vendor package**, **builds the `.so`**, or **requires
it present** is a per-adapter choice: alt-php `yum install`s the vendor RPM; EA4
builds via `phpize`; a "bring-your-own" adapter just installs+loads+manages a
`.so` the operator supplies. All satisfy the same interface — the manager
doesn't care.

## 5. Deployment model — global load, CFM-rendered rules

Load **globally per PHP build** via the adapter's ini drop-in, pointing every
build at one CFM-owned rules directory. Illustrative (EA4):

```
; /opt/cpanel/ea-php82/root/etc/php.d/zz-cfm-sp.ini   (path is adapter-specific)
extension=snuffleupagus.so
sp.configuration_file=/var/lib/cfm/sp/rules/*.rules
```

The rules directory is **generated** by cfm (like the rendered Lua configs):
reference material under `configs/sp/` → rendered, validated output under
`/var/lib/cfm/sp/rules/` (root:cfm, 0640 discipline; adapters relocate/mirror
it where the platform needs, e.g. CageFS). Operators never hand-edit the
rendered dir; overrides flow through the CFM control plane.

Per-vhost *loading* (per-FPM-pool ini) is deliberately **not** the v1
mechanism — pool templates differ per panel and fight with panel upgrades.
Path-scoped rules (§7) give per-vhost behaviour inside one global config.

## 6. Modes — monitor / enforce, global + per-rule

Two knobs, mirroring the WAF's `logonly → block` discipline:

- **Global mode** `SP_MODE = monitor | enforce` (default **monitor**).
  In monitor, the renderer appends `.simulation()` to every blocking rule.
  Fleet-deploys are burn-ins by default; nothing can break customer code on
  day one.
- **Per-rule state** `RULE_<id> = enforce | monitor | off` — every CFM-shipped
  rule carries a stable CFM rule id (comment-tagged in the rendered file and
  keyed in config). Promotion is per-rule, after its measured FP rate is
  clean (§8), exactly like promoting a WAF rule from logonly.

`enforce` global mode still honours per-rule `monitor`/`off` holds — arming a
newly added rule is always a deliberate per-rule decision (the
`waf_security`/WAF_CVE lesson: never let a default silently arm).

## 7. Per-vhost model

Same operator model as WAF/Challenge/Clam, different mechanics underneath:

- **Per-vhost disable (exclude)**: rendered as `.allow()` rules scoped by
  `.filename_r("^/home[0-9]*/USER/")` placed **before** the matching `.drop()`
  rules (first-match-wins makes this a whitelist). Granularity: whole-SP for a
  vhost, or per-rule for a vhost — both flow from one override store, reusing
  the `excludeStore` + scoped-API pattern (`RequireScopedOrAdmin` +
  `validateScopedExcludeWrite`; scoped tokens: host-type only, own vhost only).
- **Docroot → regex mapping** comes from the same vhost discovery the
  webdetector already does (cPanel userdata / the inventory §14 P0); rendered,
  never hand-written. DA/LiteSpeed docroots differ — render per-panel.
- Optional later: per-vhost *enforce* while global is monitor (the inverse),
  for early-adopter vhosts — the renderer supports it naturally (scoped
  non-simulation rule before the global simulation one).

## 8. Logging, alerts & the FP loop

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

## 9. Ruleset — what we ship, in tiers

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

## 10. The failure mode that matters: a broken rules file

An invalid rules file **breaks PHP startup fleet-wide** — every vhost, every
request. This is the SP equivalent of shipping a Lua file that fails to load,
and it gets the same treatment (a hard gate, not hope):

1. **Render** to a staging path.
2. **Validate against every installed PHP build** (the adapter enumerates
   them): `<php-bin> -d extension=snuffleupagus.so -d sp.configuration_file=<staging>/*.rules -v`
   must exit 0 for each — a rule can be valid on 8.2 and break 7.4, or on
   ea-php but not lsphp.
3. **Atomically swap** staging → live only when all pass; keep the previous
   rules dir as `last-good`.
4. **Reload** via each adapter's `Reload` (SP reads config at startup) — batched.
5. On any validation failure: keep serving last-good, alert loudly
   (`SP/CONFIG_INVALID`), never deploy.
6. `sp.allow_broken_configuration` stays **off** — it converts a loud failure
   into silent non-enforcement.

A `scripts/tests/check_sp_rules.sh` CI guardrail (syntax-validate reference
rules with whatever PHP is on the runner) mirrors `make lua`.

## 11. Coexistence with Imunify Proactive Defense & cutover

The point of SP is to *replace* Imunify's PD — but you **cannot comfortably run
SP-enforce and Imunify PD at the same time**: both hook PHP execution, so
running both means double per-request overhead and possible conflicts.

Safe cutover, per server:

1. **SP in monitor, alongside PD still enforcing.** The SP detector logs what
   SP *would* catch; PD keeps protecting. Zero risk to customers.
2. **Compare coverage** over a burn-in window: does SP-sim catch what PD
   catches (and vice-versa)? Feed the gap analysis back into the ruleset.
3. **Cut over**: disable Imunify PD, flip SP the burned-in Tier-1 rules to
   `enforce` (per-rule). SP is now the PHP-runtime layer.

**Prerequisite test (before deploying anywhere):** verify SP loaded +
`.simulation()` **coexists peacefully with `i360` (Imunify) loaded in the same
PHP**. If the two extensions conflict even in monitor, stage SP first on
non-Imunify / non-PD servers and treat PD-servers as cutover-only (remove PD,
then install SP). The **inventory (§14 P0) must detect `i360` (Imunify)** and
surface the coexistence status per build.

## 12. Synergies with existing CFM layers

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

## 13. Control plane & UI

Mirror the ClamAV work end-to-end (same shapes, same auth):

- **Inventory** (P0): `cfm php-inventory` (CLI) + `/api/v1/sp/inventory` (admin)
  — per-server PHP builds/SAPIs, per-vhost handler, SP present?, `i360` (Imunify)
  present?, build-without-SP drift.
- **Config** (`cfm.conf`): `SP_ENABLED` (infra), `SP_MODE = monitor|enforce`,
  per-rule `SP_RULE_<id>` states; rendered like the clam lua config, mirrored
  into the daemon (à la `SetClamScanPolicy`) so UI == enforced reality.
- **CLI**: `cfm php-inventory`, `cfm sp status` (per-build load state, mode,
  rule counts, last render/validate), `cfm sp mode monitor|enforce`,
  `cfm sp rule list|monitor|enforce|off <id>`,
  `cfm sp exclude add|remove|list <host> [--rule N]` (scoped semantics
  identical to `cfm clam override`).
- **API**: `/api/v1/sp/inventory` + `/api/v1/sp/health` (admin: per-build load
  matrix, mode, config hash, last validation), `/api/v1/sp/exclude/*` (scoped,
  host-type only), events via the history store (`sp_sim`/`sp_drop` event
  types) queryable through the existing scoped history endpoint — the PR-C.2
  pattern verbatim.
- **UI**: an "SP" page (inventory/status card + per-rule hit table + recent
  events, scoped like the ClamAV page) and later an SP column in vhost-controls.
- **Docs**: endpoint_scope_inventory.md entries land in the same change as the
  handlers (house rule).

## 14. Phase plan

Each phase is its own PR(s) + review; later phases only start after the
previous one has fleet burn-in. Once the manager core (P1) exists, new
**adapters** (P3) and rule **promotions** (P4) can proceed in parallel.

0. **P0 — Inventory (all platforms, read-only).**
   - **P0a — build discovery `cfm php-inventory` — DONE (2026-07-22).**
     `internal/phpinventory` + the CLI: per-build flavour / version / ZTS /
     module count / Snuffleupagus-loaded / Imunify-`i360`-loaded, plus the
     SP+Imunify coexistence-conflict warning. `--json`. Read-only, no config
     touched. (Imunify keys on the `i360` module — confirm the exact `php -m`
     name on a live host; see open questions.)
   - **P0b — next, and DECISIVE:** per-vhost PHP handler mapping — which stack
     actually serves each vhost, **alt-php (PHP Selector) vs ea-php (MultiPHP)**.
     This split determines the build burden fleet-wide: alt-php vhosts get SP via
     the vendor RPM (no build), ea-php vhosts need a CFM-built `.so`. Also
     extension_dir / ini-scan-dir per build (adapter prep) and the admin
     `/api/v1/sp/inventory` + inventory card. **Do P0b before choosing which
     adapter to build first** — if the fleet is mostly alt-php, P1's beachhead
     should be the alt-php (yum) adapter, not EA4.
1. **P1 — Manager core + beachhead adapter (monitor-only, one server).**
   Beachhead adapter chosen by P0b — **alt-php (yum-install the vendor RPM) if
   the fleet skews PHP-Selector, else EA4 (phpize build)**.
   Platform-independent manager: render Tier-1 `.simulation()` rules, the
   render→validate→swap→reload gate (§10) + CI guardrail, SP detector →
   `cfm.sp.log` JSON + notifier + per-rule hit-rates. Plus the **one beachhead
   adapter** (alt-php: install RPM + render rules into the CageFS skeleton +
   reload; or EA4: build `.so` + drop-in + FPM reload). Prove the full loop on
   one test server. *No enforcement anywhere.*
2. **P2 — Control plane + UI**: `SP_MODE` + per-rule states + scoped per-vhost
   excludes + `/api/v1/sp/*` + the SP admin page. Still monitor by default.
3. **P3 — The other adapters**, gated on inventory data + real need: whichever
   of {alt-php, EA4} wasn't the beachhead, then DirectAdmin. **Standalone
   LiteSpeed lsphp last, or "detected-unsupported"** (cPanel+LSWS lsphp already
   rides the EA4 adapter).
4. **P4 — First promotions + Imunify cutover**: Tier-1 rules with clean burn-in
   → `enforce` per-rule; `.dump()` forensics on the promoted set; the §11
   PD→SP cutover on burned-in servers.
5. **P5 — CVE virtual patching**: per-CVE rules under the WAF_CVE discipline.

## 15. Open questions

- Inventory output first: which PHP versions / SAPIs / panels does the fleet
  *actually* run, and how many servers per target? (P0 answers this and bounds
  everything downstream.)
- **alt-php enable mechanism (blocking for the alt-php adapter):** installing
  `alt-phpXX-snuffleupagus` does NOT load it (`php -m` empty). How does
  CloudLinux enable it — `selectorctl`/`cloudlinux-selector`, a per-user ini
  overlay, an admin "force extension" toggle? Confirm with
  `rpm -ql alt-php83-snuffleupagus` (what/where it placed) + the CloudLinux
  Selector docs. This decides whether alt-php SP is global or per-user, and how
  the inventory detects it (not via CLI `php -m`).
- Confirmed (2026-07-23): Imunify's module is `i360` on ea-php 8.1/8.2/8.3;
  upstream SP registers as `snuffleupagus` (unverified on alt-php only because
  it wasn't loaded — see above).
- Does SP + `.simulation()` coexist with Imunify `i360` in the same PHP
  without conflict? (§11 prerequisite — decides whether PD-servers are
  stage-first or cutover-only.)
- CLI/cron PHP doesn't read FPM ini the same way — confirm the ini drop-in
  covers the CLI SAPI too, and decide whether cron-side enforcement is wanted
  in v1 (Imunify PD covers it; it's where its `/tmp/...` catches came from).
- lsphp: is building `snuffleupagus.so` against LiteSpeed's PHP even viable on
  our LSWS versions, or is that target permanently "bring-your-own / DNAT-only"?
- Rule-id scheme: numeric bands like the WAF (1xx hardening / 9xx CVE), and
  where the id↔rule parity test lives.
- Does `sp.log_media("file:")` handle log rotation sanely, or do we need
  copytruncate care in the tailer?
- Build drift detection cadence: how often does the inventory re-scan for a
  new PHP build that landed without SP?

## 16. Out of scope

- Writing our own PHP extension (SP *is* the engine; we orchestrate).
- Hash-based PHP malware signature feeds (that's ClamAV's + the scanner
  roadmap's job; SP is behaviour/policy).
- IP autoblock from SP events (deferred — needs its own `waf_security`-style
  design pass).
- Tier-3 features (cookie encryption, unserialize HMAC, strict mode) — revisit
  only per-app, never fleet-default.
- Full lsphp support in v1 (detected in inventory; adapter deferred).
