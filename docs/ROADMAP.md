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

- **Phase 2f — cleanup after burn-in** — [next]. Drop the panel loop-breaker,
  the legacy shared-cookie-name fallback, and the inert `cfm_ok` marker once the
  per-scope cookie scheme (2a) has burned in.
- **Phase 3 — burn-in + fleet** — [next]. orion first, one release of burn-in
  for Phase 1+2, then fleet. Delete `cfm_panel.lua`'s superseded local policy
  and the deprecated `OPENRESTY_MODE` key.
- **Phase 4 — panel enforcement graduation** — [track]. **Both** the panel
  challenge/decision (2d) **and** the panel WAF (2e) graduate from LOGONLY to
  enforce after logging confirms low false-positive rates — each its own opt-in
  PR after its own burn-in. Prereqs: full self-origin parity (self-IP set +
  `IGNORE_NETS`, ideally a shared module so web/panel can't drift), a
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
  `challenge_ip_status`, `waf_fp_hunt`.
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

- **Correlation: MySQL pressure vs vhost hits** — [next]. Surface "few hits,
  high DB pressure" tenants.
- **CPU thermal/throttle signal** — [next]. Turn "high load" into a root-cause
  flag (thermal/throttle vs genuine demand).
- **LVE per-tenant CPU signal (CloudLinux)** — [track]. Real per-tenant CPU
  source.
- **Guard governor perf/userstat capability flags** — [next]. Fix the
  pre-existing data race on the capability flags.

## 5. Mail Monitor

Subsystem overview: staged NGM-style (`internal/mailmeter`). Traffic,
deliverability, per-domain, DNS, spam largely landed (see CHANGELOG).

- **MTA-agnostic mail tools** — [next]. Serve mail summaries from a
  detector-published snapshot instead of a per-request exec, so the tools work
  across exim/postfix/etc. without shelling out each call.
- **Mail-log reader** — [next]. Shared with §3.

## 6. Health / observability correctness

- **`cfm_metrics.waf_events_1h` vs `waf_last_hour` mismatch** — [next]. Health
  snapshot reports two different WAF-hit counts; reconcile the source.
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
