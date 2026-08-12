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
- **Logs group** — [next]. `journal_tail` / `cfm_log_tail` (edge `edge_error_tail`
  landed).
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

---

_Larger design docs live under `docs/`; this roadmap only indexes them. See
`CLAUDE.md` §6–§7 for the "where we historically lost the ball" areas and the
per-topic doc pointers._
