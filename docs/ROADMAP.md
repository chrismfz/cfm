# CFM Roadmap

A single index of **where CFM is going**: work in flight, the near-term
backlog, and longer tracks. This file is a map, not a spec — each item points
at the authoritative doc/PR that owns the detail, so this page never becomes a
second copy that drifts (CLAUDE.md §5). When an item lands, move it to
`CHANGELOG.md` and delete it here.

Conventions: **[in flight]** has an open PR or branch · **[next]** is queued and
scoped · **[track]** is a larger effort not yet broken into PRs · **[idea]** is
not yet committed to. Discipline for everything here: build → adversarial
review-until-clean → PR → merge → next (many small single-concern PRs).

---

## 1. Edge unification (one enforcement path, one clearance model)

Full design + phase log: **`docs/edge-unification-plan.md`**. Retire the legacy
per-IP challenge-DNAT path; unify web + panel on the edge cookie-clearance model.

- **Phase 2 — DONE** (2026-08-12). Panel unification LOGONLY landed (2a/2b/2d/2e
  + `cfm_selfip` parity); the last open item, the cPanel-plugin iframe cross-port
  clearance flow, was verified live (no loop). Burn-in FP gate clean on both
  engines (see `docs/edge-unification-plan.md` Status).
- **Phase 3 — burn-in + fleet + dead-code removal** — [in flight]. Burn-in done
  (orion+titan). `OPENRESTY_MODE` reference key removed (behavioural collapse was
  already in 1a; runtime deprecation warning kept). **Remaining:** the
  **cookie-net cleanup** (inert `cfm_ok`, legacy shared-cookie-name fallback, and
  — with Phase 4 — the panel loop-breaker) as its **own sign-off-gated PR** after
  a longer burn-in, since it touches the incident clearance path.
- **Phase 4 — panel enforcement graduation** — [track]. Also owns deleting
  `cfm_panel.lua`'s superseded local policy (can't remove the live enforcer
  before the bridge decision enforces). **Both** the panel
  challenge/decision (2d) **and** the panel WAF (2e) graduate from LOGONLY to
  enforce after logging confirms low false-positive rates — each its own opt-in
  PR after its own burn-in. Prereqs: ~~full self-origin parity~~ (DONE — shared
  `cfm_selfip` module gives the panel WAF the web edge's self-IP + `IGNORE_NETS`
  skip; wire it into the panel decision path when that enforces), a
  per-Content-Type body-inspection decision for panel, and preserved fail-open +
  kill-switch discipline so an admin can never be locked out of WHM/cPanel.

## 2. WAF tuning & coverage

Behaviour + FP runbooks: **`docs/waf.md`**, `docs/waf-analysis-2026-05-08.md`,
`docs/challenge-waf-release-checklist.md`. WAF→autoblock: `docs/waf-autoblock-design.md`.

- **WAF false-positive tuning** — [track, never "done"]. Continuous, against
  real apps (Joomla K2/elFinder, `/.well-known/`, WP migration/backup imports).
  Prefer `logonly` → `challenge` → `block` promotion; operator-side rule-scoped
  excludes over code carve-outs.
- **WAF CVE detectors (`WAF_CVE`)** — [track]. Per-CVE in-path rules in the
  `10000+` band. As-built + "CVE hunting" recipe: **`WAF_CVE.md`**; design +
  candidate backlog: `WAF_CVE_PLAN.md`. Never write a signature from memory.
- **Gap analysis follow-ups** — [idea]. See `docs/waf-gap-analysis-ninjafirewall.md`.

## 3. MCP telemetry surface

As-built + roadmap: **`MCP.md`**. Read-only telemetry across the fleet
(orion/titan). Everything here is READ-ONLY unless the write-layer track lands.

- **`whats_wrong` triage synthesis** — [in flight]. Ranked "what's wrong right
  now" entry point.
- **Logs group** — DONE. `cfm_log_tail` (CFM's own `/var/log/cfm/*`, curated
  keys) + `journal_tail` (allow-listed systemd units) landed via `internal/cfmlog`
  (edge `edge_error_tail` already landed).
- **Firewall/WAF drilldowns** — [next]. `nft_counters`, `waf_rule_detail`,
  `challenge_ip_status` (`waf_fp_hunt` landed — panel-logonly burn-in aggregator).
- **`ip_forensics` → rotated logs** — [next]. Optionally reach rotated log
  segments, not just the live file.
- **Minor read wins** — [next]. `notifier_status`, `clam_status`, `http3_status`.
- **MCP write/actions layer** — [track]. `mysql_kill` first, then `block_ip` —
  behind explicit auth; today the MCP surface is read-only by design.
- **Mail-log reader tool** — [next]. MCP + CLI reader for dovecot/exim/postfix
  (see §5).
- **Fleet MCP gateway in Laravel `cfm-web`** — [track]. Aggregate per-node MCP
  behind the fleet controller.
- **Laravel-embedded agent w/ DB session history** — [track, Ekdosi-style].

## 4. MySQL / resource pressure & governor

- **Correlation: MySQL pressure vs vhost hits** — DONE (MCP). `internal/dbwebcorr`
  join + the `db_web_pressure` MCP tool (composes governor `cpu`/`top` + webdet
  `top-short`, host→owner via `internal/panelmap`) surface "few hits, high DB
  pressure" tenants. Follow-ups (optional): a CLI/web-UI surface, and DirectAdmin
  host→owner support in `panelmap` (`/etc/virtual/domainowners`) so attribution
  works off cPanel too.
- **CPU thermal/throttle signal** — DONE. `internal/cputhrottle` (pure,
  load-gated classifier) + `GET /api/v1/system/cpu-throttle` + MCP `cpu_throttle`
  turn "high load" into a root cause: thermal throttling vs frequency cap
  (governor/policy) vs genuine demand vs idle downclock vs no-cpufreq (VM → check
  host steal). Follow-up idea: fold CPU steal% (from the health snapshot) into the
  verdict so the VM case gets a concrete answer, not just a pointer.
- **LVE per-tenant CPU signal (CloudLinux)** — DONE. Data plane:
  `internal/lvestat` (pure parser + cores/%-of-limit, unit calibrated to ns) →
  `internal/lvecpu` collector → `/api/v1/system/lve-cpu` + MCP `lve_cpu`.
  Presentation: `cfm lve` CLI + the Health-page "LVE per-tenant CPU" table.
- **Guard governor perf/userstat capability flags** — DONE (data race fixed;
  atomic.Bool + -race regression test).

## 5. Mail Monitor

Subsystem overview: staged NGM-style (`internal/mailmeter`). Traffic,
deliverability, per-domain, DNS, spam largely landed (see CHANGELOG).

- **MTA-agnostic mail tools** — [next]. Serve mail summaries from a
  detector-published snapshot instead of a per-request exec, so the tools work
  across exim/postfix/etc. without shelling out each call.
- **Mail-log reader** — [next]. Shared with §3.

## 6. Health / observability correctness

- **Wire the remaining `cfm_metrics`** — [next]. `waf_events_1h` now reads the
  real last-hour count (reconciled with `waf_last_hour`), but its siblings
  `active_blocks` / `challenge_queue` / `outbound_alerts` are still structural
  zeros (no production producer). Populate them from their real sources
  (firewall block list / challenge engine / mail anomaly), or drop them.
- ("which engine is the edge" family — resolved across whats_wrong #1230,
  edge_error_tail #1231/#1232, health-CLI #1233. Kept here as a watch item: any
  NEW consumer of edge-engine state must use `runtime.edge_service`.)

## 7. Operator / security housekeeping

Not code — operator actions tracked so they aren't forgotten.

- **Rotate `MCP_TOKEN` + remove `MCPGODEBUG`** — [next, operator]. Post-rollout
  hygiene on the live nodes.
- **Fleet detectors.conf immediate fixes** — [next, operator]. The quote-typo
  (`SESSION_ALL_FAILED"`) on 5 nodes, 3deers' missing panel `CHALLENGE_VHOST`
  patterns, speedhost's `permanent` leniency, dead `.leniency` threshold keys.
  List: `docs/detectors-config-unification.md` §7.
- **Neutralize a leaked admin `AUTH_TOKEN`** — two-part, so a leaked token (e.g.
  from a cfm-web DB leak) is useless without credentials:
  **(A) SHIPPED (default off).** `ADMIN_TOKEN_IP_BINDING = off|logonly|enforce`
  gates the `token_admin` branch to {loopback, selfIPs, `cfm.allow`/`cfm.dyndns`,
  the API_URL host} — closes direct-API use and SSO-code minting from any other IP
  (browser SSO/scoped/session/MCP untouched; fail-safe, independent of the
  firewall). **Operator action:** roll `enforce` per-node (see the doc's rollout
  note). **(B) still [design, code]:** decouple the embed cookie signing key from
  `AUTH_TOKEN` (per-node secret, or a stateful admin session — recommended, reuses
  `authstore`/`auth.db`), else a leaked token forges a `cfm-embed-admin` cookie and
  walks in from any IP, bypassing (A). **Also residual:** `/mcp` accepts the admin
  token (read-only telemetry) from any IP — close with a dedicated `MCP_TOKEN` so
  `auth_token` stops being an MCP credential. Live evidence 2026-08-27: token presented
  only from cfm-web `84.54.49.4` (= `cfm.myip.gr`) and loopback; `:6060`/`:6061`
  Internet-bound with no nft gate. Full design (traces, cookie-forgery gap,
  caveats): `docs/security/admin-token-source-ip-binding.md`.

## 8. Detectors config unification

Design: `docs/detectors-config-unification.md` (2026-08-25 10-server audit).
Auto-detected sources (`srcresolve`), `/etc/cfm/detectors.d/` overlays so the
base conffile stays package-updateable (no more `.rpmnew`), global
`[leniency]`, persisted auto-tokens, fleet-converged defaults.

- **PR sequence** — [next]. §9 of the doc: srcresolve → ssh/dovecot →
  exim/postfix+docker → webdetector edge source → detconf layering (WebUI
  editor writes overlays) → global leniency + tokens → converged stock values.

## 9. Traffic classifier (distributed-scraper / challenge-defeat defense)

Mechanism-agnostic per-client + per-vhost classification for scrapers that evade
UA detection (headless browsers, AI crawlers, faceted-URL floods, solver farms).
Design: `docs/traffic-classifier.md` (master plan, two tracks → one ladder),
`docs/challenge-score.md` (Track-2 per-client), `docs/challenge-score-b2.md`
(B2 as-built). All signals ship **shadow/log-only** first; `logonly → challenge/
harden → deny`, never straight to deny; never an adverse decision on country/ASN
alone; NAT-aware.

- **Track-1 vhost-anomaly fusion** — DONE (shadow). Robust-z baseline + fused
  facet/cost/dc score → `cfm.abuse_shadow.log`; surfaced by `abuse_shadow` MCP +
  per-vhost webtop pills.
- **Track-2 Stage 1a — per-IP challenge-abuse score** — DONE (shadow). Daemon-side
  `challenge_score` from the solve stream (fast/UA-lie/farm tells; NAT-safe).
- **Track-2 Stage 1b/B1 — Sec-Fetch headless tell** — DONE (shadow). WAF rule 612
  `WAF_FETCH_METADATA` (logonly); visible in the cfm-admin WAF analytics.
- **Track-2 Stage 1b/B2 — post-clearance nav-cadence** — DONE (shadow). `cfm_pcw`
  at `cfm.lua` Step 2b; `[cfm_pcw]` edge-log; config toggle
  `[webdetector] POST_CLEARANCE_CADENCE`.
- **Burn-in** — [in flight]. Deploy 1a+B1+B2; watch `abuse_shadow` /
  `waf_activity rule=WAF_FETCH_METADATA` / `edge_error_tail [cfm_pcw]`; tune the
  fused-score weights before B3.
- **Track-2 Stage 1b/B3 — three-grain, fingerprint-anchored seed** — [in flight,
  shadow]. Grounded 2026-09-11 (fleet read: the fingerprint grain is the hottest /
  highest-confidence signal, grain-A `rate_outlier`-dominant, grain-B thin), the
  seed is **anchored on the per-fingerprint reputation** (spine), with per-vhost
  `abuse_shadow` (posture) and per-IP `challenge_score`/`cookie_discard` (soft)
  corroborating. Design: `docs/traffic-classifier.md` § "Third grain".
  **Slice 1 — DONE (shadow):** the daemon marks the CONVICTING fingerprint (twin of
  the vhost farm mark) and the per-IP `challenge_score` opens on it as the dominant
  spine tell (`farmfp=` in `cfm.abuse_shadow.log`) — a coarse TLS bucket will light
  up some legit shared-bucket solvers, which is exactly what shadow measures before
  any enforcement keys on a fingerprint. Next: the edge seed-map fusing the daemon
  seed with the B1/B2 edge tells; weights tuned from burn-in.
- **Track-2 — solver-farm fingerprint-concentration (low-and-slow)** — [shipped,
  burn-in]. Burn-in surfaced a live challenge-defeating farm (`c28caa00` on
  `techking.gr`, 2026-09-08): ~50 residential-proxy IPs across ~40 countries under
  **one** TLS fingerprint, all SOLVING the PoW at ~8/min — under the existing
  `challenge_solver_farm` subnet-spread bar (`MIN_SUBNETS` 40/60s, calibrated for
  a ~110/min farm). Phase-1 added a fingerprint-**concentration** track (group-by
  fp, never a signature; country-spread as the FP-guard) for the per-vhost low-rate
  regime — shipped default-on/log-only, catching `techking.gr` + 3 more vhosts
  across 2 nodes ~12 h post-deploy, zero observed collateral. Feeds the
  `solver_farm` seed B3 budgets. `docs/solver-farm-fingerprint-concentration.md`.
- **Track-2 — solver-farm cross-host fingerprint aggregation (Phase 2)** — [shipped,
  burn-in]. Catches the *second* farm fingerprint (`95070673`) spread too thin per
  vhost for the Phase-1 60 s country guard (per-host country-peak ≤ 6) yet obvious
  per node (~23 vhosts / 44 countries). Per-node, per-fingerprint aggregation over
  `XH_WINDOW` (30m) with a per-vhost dominance pre-gate (`MIN_XH_HOST_SHARE_PCT`,
  the primary guard); `solves_per_ip` is **evidence only** (the weekday burn-in
  proved it does not separate farm from legit — dropped as a gate). Shipped
  default-on, **log-only through its own burn-in**; marks every farmed vhost.
  `docs/solver-farm-cross-host-phase2.md`.
- **Solver-farm convictions → `detection_history`** — [shipped]. Every emitted
  `challenge_solver_farm` finding now persists as `event_type=solver_farm` with
  fingerprint-scoped evidence (`countries ≤ subnets ≤ ips`), the node-side prereq
  that feeds the fleet fingerprint-reputation ingest below.
- **Fleet fingerprint reputation & observability (cfm-web)** — [A+B shipped, C
  deferred]. A central `fingerprints` store in `cfm-web` that remembers *convicted*
  client fingerprints (TLS `c28caa00`/`95070673` + later JA4H) with hard evidence.
  **Phase A** (ingest + MCP): `SolverFarmIngestor` PULLs the `solver_farm` source
  via `fleet_ingest_cursors` into durable `fingerprints` + `fingerprint_events`
  tables; read-only `fingerprints` MCP tool. **Phase B** (dashboard + policy,
  shadow): Filament reputation table + per-fp drilldown (`ExplainFingerprint`),
  arm/disarm/action/duration `fingerprint_policies` (durable record + re-armable
  policy — disarm ≠ delete), and a farming-fingerprints dashboard widget.
  **Phase C** (edge enforce) — deferred behind an **entry gate**: needs weeks of
  accumulated shadow data proving the verdict/share gates separate real farms from
  legit near-FPs, then a cfm-web policy-fetch endpoint + node `X-CFM-TLS` match
  with match-time re-validation, ≥K-node corroboration before `deny`, and a
  dedicated arm permission. `challenge` (self-targeting) not `block`; `ALLOW_FPS`
  override. Design + Phase-C plan: `cfm-web:docs/fingerprint-reputation.md`;
  cfm-side: `docs/fleet-fingerprint-reputation.md`.
- **Webtop visibility for the per-IP / edge-log shadow signals** — [post-burn-in].
  `challenge_score` (per-IP) and `cfm_pcw` (edge error log) don't map to the
  existing per-vhost webtop pills or the WAF-history analytics, so they're
  currently MCP-only (`abuse_shadow` / `edge_error_tail`). Once burn-in confirms
  the signals are worth keeping, add a webtop pane (per-IP would_harden/would_deny
  from the shadow log; `cfm_pcw` aggregates). Deferred deliberately — don't build
  UI for a signal that may be retuned or dropped.
- **Fingerprint in `suspicious_hosts` / cfm-admin** — [idea]. Surface the
  convicting fingerprint(s) on the suspicious-vhost rows (and the cfm-admin webtop),
  so an operator sees "this vhost is being hammered by fingerprint X", not just a
  vhost + score. The fingerprint marks (B3 slice 1) + the solve stream's `tls_fp`
  make the SOLVER case ready now; the WAF/scanner case (e.g. the live greek-sites.gr
  SQLi — one IP, 30+ spoofed UAs, one tool) needs the `tls_fp`-on-WAF **attribution**
  first (`cfm-web:docs/fingerprint-reputation.md §10`, roadmap #1 there). A natural
  B3 follow-on.
- **Durable node-side scoring memory (sqlite)** — [idea]. The per-IP
  `challenge_score`, fingerprint convictions and abuse-shadow marks are all
  in-memory today, so a daemon restart/reload resets a farm's accumulated score.
  A small node-local sqlite store would let the node's OWN live scoring survive a
  restart. Note the architectural boundary: the *durable reputation* memory lives
  centrally in cfm-web BY DESIGN (node detects, cfm-web remembers) — this is not a
  second reputation store, only restart-survival for the node's live scoring state.
- **Stage E actuation ladder** — [track]. Shared per-client + per-vhost actuator:
  PoW-harden / ChallengeV2 puzzle / 403 / tarpit / drop, edge-local (the cleared
  path skips the in-path decision). Only after burn-in shows a clean would-act set.

---

_Larger design docs live under `docs/`; this roadmap only indexes them. See
`CLAUDE.md` §6–§7 for the "where we historically lost the ball" areas and the
per-topic doc pointers._
