# CFM Roadmap

A single index of **where CFM is going**: what is open, in priority order
within each area. This file is a map, not a spec. Each item points at the doc
or PR that owns the detail, so this page never becomes a second copy that
drifts (CLAUDE.md §5). **When an item lands, delete it here** (the CHANGELOG
records it). Done items are not kept "for the record".

Tags: **[next]** queued and scoped · **[track]** larger effort, not yet broken
into PRs · **[idea]** not committed to · **[decided]** a standing "no", kept so
it is not reopened without new evidence. Discipline for everything here:
build → adversarial review until clean → PR → merge → next (small
single-concern PRs).

Last full review: 2026-11-18.

---

## 1. WAF tuning & coverage

Behaviour + FP runbooks: **`docs/waf.md`**, `docs/challenge-waf-release-checklist.md`.
WAF→autoblock: `docs/waf-autoblock-design.md`. CVE rules: **`WAF_CVE.md`**
(backlog: `WAF_CVE_PLAN.md`). Pre-merge numbers: `make waf-corpus` (BlazeHTTP).

- **WAF false-positive tuning** — [track, never "done"]. Against real apps
  (Joomla K2/elFinder, `/.well-known/`, WP migration/backup imports). Promote
  `logonly` → `challenge` → `block`; operator-side rule-scoped excludes over
  code carve-outs.
- **WAF CVE detectors (`WAF_CVE`)** — [track]. Per-CVE rules in the `10000+`
  band. Never write a signature from memory.
- **libinjection SQLi / XSS tokenizer** — [next]. LuaJIT FFI binding
  (`lua-resty-libinjection`-style) as a new detector beside 301 / 302,
  shipping `logonly`. Measured with `make waf-corpus` before merge and with
  `cfm webtop waf hit-rates` on the fleet before any promotion.
- **Decoding / normalization transforms** — [next]. `cmdLine`-style
  normalization for the RCE rules, unicode / fullwidth folding and
  `normalizePath` in `cfm_waf_util.lua` (today: `url_decode_once` × 2 + lower,
  no unicode normalization). Scope each to the variables it belongs to: the
  strict UTF-8 walker applied to the whole args+body buffer flagged legacy
  ISO-8859-7 Greek forms (`docs/waf.md`).
- **Login brute-force signals in the web detector** — [next]. The edge counts
  login *submissions* (rule 501: 8 per IP in 20 s), so a slow or distributed
  attack never trips it (vol2.gr, 2026-11-04: 2 787 failed `wp-login.php`
  posts from 1 121 IPs, none over 5 in 20 s). Phase 0 is built (the `auth`
  column, `auth_corpus` MCP tool); next the detector counts FAILED logins per
  IP across vhosts, per vhost, per /24, and flags a success from an IP that
  failed elsewhere. Design + fleet numbers: `docs/webdetector-signals-v2.md`.
- **cfm-admin WAF / ban UX** — [idea].
  - Hit-rates view: `/api/v1/waf/hit-rates` and its promotion hint
    (`ok_to_promote` / `silent` / `review` / `noisy`) are CLI/API only today.
  - Per-vhost protection presets (low / medium / high) that only WRITE the
    existing knobs (WAF modes, challenge tier, rate rules), never a second
    copy of the settings.
  - Ban evidence: every ban, not only `waf_security`'s, carries the requests
    that caused it in `detection_history`, shown beside the ban.
- **No Coraza / OWASP CRS in-path** — [decided 2026-11-18]. Its anomaly score
  has nothing to bind to (per-rule modes, autoblock families, scoped excludes,
  edge ban), it brings a second exclusion system and CRS's FP load on
  WordPress / Joomla / cPanel, and cPanel origins often run ModSecurity behind
  the edge already (the `modsec` detector reads it). UUSEC WAF, SafeLine and
  BunkerWeb were reviewed the same day: closed engines or CRS itself, so no
  rules to borrow; their usable ideas are the items above.
- **Edge Lua residuals** — [idea, low]. `cfm_purge.lua` `purge_ip` scans the
  whole `cfm_decisions` dict under lock on a force-unblock (perf); `[...]`
  bracket-class globs in excludes match literally in Lua but as a class in Go
  (narrower in-path, so protective).

## 2. Panel enforcement (edge unification follow-up)

Edge unification is done (as-built: `docs/edge-unification-plan.md`): panel
WAF + bridge decision enforce by default (`PANEL_WAF_MODE` /
`PANEL_DECISION_MODE`), the blanket panel challenge is kept on purpose.

- **Watch default-enforce on authenticated panel traffic** — [track,
  operator]. The burn-in behind it was scanner-dominated; per node, drop to
  `logonly` on a false positive.
- **Per-Content-Type body inspection on the panel ports** — [idea].

## 3. MCP telemetry surface

As-built: **`MCP.md`** (node tools) and the cfm-web fleet connector. Node MCP
stays read-only; writes live in cfm-web (blocklist, blackhole, notify) behind
per-ability tokens.

- **`ip_forensics` → rotated logs** — [next]. Reach rotated log segments, not
  just the live file.
- **`challenge_ip_status`** — [idea]. Per-IP challenge state drilldown.

## 4. Mail Monitor

- **MTA-agnostic mail tools** — [next]. Serve mail summaries from a
  detector-published snapshot instead of a per-request exec, so the tools work
  across exim/postfix without shelling out each call.

## 5. Health / observability correctness

- **Wire or drop the remaining `cfm_metrics`** — [next]. `active_blocks` /
  `challenge_queue` / `outbound_alerts` are still structural zeros
  (`internal/healthmodel/collector.go`). Populate them from the firewall block
  list / challenge engine / mail anomaly, or drop them.
- Watch item: any NEW consumer of edge-engine state must use
  `runtime.edge_service`.
- **CPU steal% in the `cpu_throttle` verdict** — [idea]. So the VM case gets a
  concrete answer, not just a pointer.
- **DirectAdmin host→owner in `panelmap`** — [idea]. `/etc/virtual/domainowners`,
  so `db_web_pressure` attribution works off cPanel too.

## 6. Control plane & operator housekeeping

- **Roll `ADMIN_TOKEN_IP_BINDING = enforce` per node** — [next, operator].
  Shipped default `off`; design + rollout note:
  `docs/security/admin-token-source-ip-binding.md`.
- **Rotate `MCP_TOKEN` + remove `MCPGODEBUG`** — [next, operator].
  Post-rollout hygiene on the live nodes.
- **Retire `internal/apiserver/auth_autoblock.go`** — [next]. Still started
  in `apiserver.go`; the `cfm_endpoints` detector is meant to replace it.
  Remove only after showing the detector bans the same login brute force
  (keep the login throttle / account lock).
- **Pre-auth challenge in front of the direct admin login** — [idea]. Design:
  `docs/security/challenge-login-gate-design.md` (test both edge and DNAT
  mode).
- **Fleet `detectors.conf` fixes** — [next, operator]. Quote typos, missing
  panel `CHALLENGE_VHOST` patterns, `permanent` leniency, dead keys:
  `docs/detectors-config-unification.md` §7.

## 7. Detectors config unification

Design: `docs/detectors-config-unification.md`. Shipped: `srcresolve` (auto
source detection) and `detectors.d` overlays (`detconf` layering).

- **Global `[leniency]` fallback + persisted auto-tokens** — [next] (doc §9 PR 6).
- **Stock `detectors.conf` converged defaults** — [next] (doc §9 PR 7). A
  behaviour change on hosts that inherit defaults: ships alone.
- **Fleet migration** — [track, operator]. Move each node's deltas to an
  overlay; `config_drift` reports a clean base.

## 8. Traffic classifier / abuse defense

**Plan of record: `docs/abuse-defense-master-plan.md`** (the one roadmap +
decision log for challenge / classifier / fingerprint reputation, both repos;
its §5 is the only live to-do list). Progress journal:
`docs/abuse-defense-progress.md`. Design: `docs/traffic-classifier.md`,
`docs/challenge-score.md`, `docs/under-attack-mode.md`,
`cfm-web:docs/fingerprint-reputation.md`. This section is only an index.

## 9. Webshell-drop safety net (cfm-lsm → ClamAV → edge attribution)

Design: `docs/lsm-php-drop-detection.md` (after the 2026-11-12 dmkomotinis.gr
compromise). `CFML-FS-009` watches the PHP tier write a PHP-executable file
under a docroot; the daemon scans that file with ClamAV and ties it to the
edge request so the IP can be banned.

- **P0 count-only** — [next, after the operator answers the doc's §11].
  `panelmap.Docroots()`, the BPF policy (own ringbuf, monitor-only) and the
  `php_drops` MCP aggregates. A fleet count gates every later phase; kernel
  deny is not planned.

## 10. PHP runtime defense (CFM-managed Snuffleupagus)

Design: `docs/roadmaps/php-runtime-defense.md`. CFM renders Snuffleupagus
rules, monitor/enforce modes and per-vhost excludes, and never writes its own
PHP extension (decided 2026-11-18: one engine for one purpose). Pairs with §9
at the kernel boundary. `cfm php-inventory` is shipped.

- **P0b per-vhost PHP handler mapping (alt-php vs ea-php)** — [next]. It picks
  the beachhead adapter for P1 (monitor-only, one server).

---

_Design docs live under `docs/`; this roadmap only indexes them. See
`CLAUDE.md` §6–§7 for the "where we historically lost the ball" areas and the
per-topic doc pointers._
