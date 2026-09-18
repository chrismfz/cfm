# Abuse defense — MASTER PLAN (challenge · traffic classification · fingerprint reputation)

> **⭐ PLAN OF RECORD.** This is the ONE roadmap and decision log for the whole
> challenge / traffic-classifier / fingerprint-reputation effort, across BOTH
> repos (cfm node side + cfm-web central side). Every other doc in this area is
> a *design/as-built reference* — their embedded phase checklists are **frozen**
> and defer to this file (see §6 doc map). If this file and a reference doc
> disagree on *what happens next*, this file wins; on *how a shipped thing
> works*, the code wins.
>
> Owner: operator + challenge/webdetector. Created 2026-09-18 (consolidation of
> six drifting roadmaps). Keep it short: when a step ships, mark it DONE in one
> line and move detail to the relevant as-built doc.

---

## 1. The goal, restated once

CFM should notice, via edge signals, when a vhost is under pressure from mass
bots and (a) **deny (403)** when guilt is certain, (b) **escalate to a harder
challenge (ChallengeV2)** when bots defeat the PoW challenge and certainty is
lower, and (c) feed the evidence (IPs, subnets, ASNs, countries, fingerprints)
to **cfm-web** so the operator can stop campaigns fleet-wide. That goal is
unchanged since day one; this plan exists because we kept building sensors for
it without ever wiring the actuators.

## 2. Where we actually are (2026-09-18)

**The evidence pipeline WORKS and has already paid off.** The central ledger
(cfm-web `fingerprints`, 3 shadow sources ingesting every 5 min) holds, live:

- `c28caa00` — verdict **farm**, convicted by all three sources: 1,619
  solver-farm findings across 124 vhosts, peak 806 IPs / 73 countries in one
  window, 229 `would_deny` challenge-score rows, 5,867 attributed WAF blocks,
  **36,184 captured member IPs** (4,094 datacenter = block-safe, 30,616
  residential, 13 critical-infra). Its WAF traffic wears ~176 spoofed
  AI-crawler UAs (MistralAI/ClaudeBot/Perplexity/…) with **zero**
  FCrDNS-verified members.
- `95070673` — farm (98 vhosts, peak 399 IPs / 72 countries); `ba6b4aad` —
  farm + generic-tool bucket; ~108 more `observed` fingerprints with WAF
  attribution.

**What is missing is exclusively the action channel.** As of this writing:
`fingerprint_policies` can be armed in cfm-web but **no node ever pulls them**
(no fetch endpoint exists); ChallengeV2 is a decision record with zero code;
the only live enforcement born from this effort is `cookie_discard`'s
`BLOCK=24h` and the operator's manual per-IP "Block" button on Explain
Fingerprint. Roughly 15 shadow signals run; zero have been promoted.

**The failure mode to stop repeating:** "shadow-first" became shadow-forever
because burn-ins have no exit criteria, and each burn-in review spawned a new
signal + a new doc instead of a promote/retire decision. Hence §4-D3/D4.

## 3. Signal inventory & verdicts

Status is factual; verdicts marked **(proposed)** need operator ratification —
ratify by flipping the tag to a date, retire by deleting the code in a normal
reviewed PR.

| # | Signal | Code | Status today | Burn-in showed | Verdict |
|---|---|---|---|---|---|
| 1 | `solver_farm` (subnet-spread + fp-concentration + cross-host) | `internal/detectors/solverfarm` | alert/notify + feeds ledger | 3 farm convictions, clean guards | **KEEP — proven.** The ledger spine. |
| 2 | WAF-hit fp attribution (`waf_hit`, handshake `cfm_tlsfp`) | `cfm.lua` + `RecordWAFTrigger` | shadow evidence → ledger | 5.8k blocks attributed on one fp; exposed the fake-AI-UA corpus | **KEEP — proven.** Feeds E2. |
| 3 | `challenge_score` (Stage 1a + farm-fp spine) + durable `would_deny` | `challenge_score*.go` | shadow → ledger source #2 | thin alone; strong once fp-anchored | **KEEP as evidence**; per-IP promotion rides E3, not standalone. |
| 4 | `cookie_discard` re-solve | `internal/detectors/cookiediscard` | **ENFORCING** (operator `BLOCK=24h`) | works | **KEEP.** Already the ≥99 rung. |
| 5 | `abuse_shadow` rate_outlier (Signal C) | `abuse_shadow.go` | shadow | populated, dominant grain-A signal | **KEEP as evidence** (Track-1 fusion input). |
| 6 | `abuse_shadow` facet / cost / dc_fraction / fused | `abuse_shadow_{facet,cost,dcfrac,fused}.go` | shadow | thin; no Class-2 flood observed since built | **KEEP-FROZEN**: no new sub-signals, no weight-tuning PRs until the next real Class-2 flood provides data. Review then, with §4-D3 criteria. |
| 7 | WAF rule 612 `WAF_FETCH_METADATA` (Sec-Fetch tell) | `cfm_waf.lua` | logonly | fires as designed | **KEEP logonly**; E3 seed input. Not promoted alone. |
| 8 | `cfm_pcw` post-clearance nav cadence (B2) | `configs/lua/cfm_pcw.lua` | log-only | documented structural blind spot (fetch()-based scrapers invisible); fed no decision in its lifetime | **RETIRE (proposed).** Remove the Lua + toggle; `rate_outlier` already sees cleared traffic in the access log. |
| 9 | `under_attack` I1 state machine + notify | `under_attack.go` | detect-only (DRYRUN) | alarm value real ("challenge defeated" as an alert) | **KEEP as the alarm.** I1b read-surfaces optional. |
| 10 | `under_attack` campaign fingerprinter I2 | `under_attack_fingerprint.go` | shadow | no consumer; I3–I5 never built | **FREEZE (proposed).** E1–E3 supersede its enforcement path; revisit only if the draft-rule idea (I3) is ever picked up. |
| 11 | `ua_family=` solve-log corpus | `challenge_server.go` | log-first | builds the fp↔UA corpus | **KEEP.** Feeds E2 and the future JA4↔UA coherence tell. |
| 12 | Humanity scorer / would_v2 Rung-1 (`HUMANITY_MIN_OBS`, `MINORITY_PCT`) | **not built** | keys exist ONLY in live `/etc/cfm/detectors.conf` on the fleet — no code reads them | n/a | **Build inside E3** (with teeth, §5). Operator: delete the orphan keys from live configs until then. |

Fleet-config cleanup that falls out of the table: remove the orphan
`HUMANITY_*`/`MINORITY_PCT` keys (row 12); leave `UNDER_ATTACK*`,
`ABUSE_SHADOW*`, `[challenge_solver_farm]`, `[challenge_cookie_discard]` as
they are.

## 4. Standing decisions (the FP doctrine)

These unblock enforcement. D1/D2 were settled by the operator on 2026-09-18;
D3/D4 are the process fix.

- **D1 — A fingerprint is a population; residential members are NEVER
  auto-banned.** The captured member set of a coarse TLS bucket (`c28caa00`)
  provably contains innocent bystanders — e.g. Greek OTEnet/Vodafone customers
  who simply solved a challenge while sharing the bucket. Any per-IP ban keyed
  on fingerprint membership is therefore restricted to `kind=datacenter`
  members (`block_safe`), always TTL'd, `good_bot` exempt, critical-infra
  refused, whitelist never downgraded. **The residential path is ChallengeV2,
  not a ban** — self-targeting, no ISP-reassignment collateral, per-device on
  CGNAT.
- **D2 — Deny (403) on a bare fingerprint only when farm-UNIQUE** (ideally
  JA4H-corroborated later). A coarse bucket gets ChallengeV2 (floor), never a
  blanket deny. Unchanged from the hubs; recorded here as the standing gate.
- **D3 — Every shadow signal gets an exit contract or gets retired.** A
  burn-in is opened with: what it must show, the review date (≤ 4 weeks out),
  and who decides. At review the only outcomes are promote / keep-as-evidence
  / retire — "extend with a new sub-signal" is not an outcome. Signals #6 are
  grandfathered under "review at next Class-2 flood".
- **D4 — Sensor freeze.** No new shadow signals and no new design docs in
  this area until E1–E3 (§5) have shipped and been measured. The next PR here
  is an actuator.

## 5. Enforcement roadmap — the only live checklist

Ordered by cost→payoff. Each step is small-PR-sized per repo, follows the
house rules (adversarial self-review; edge changes through
`docs/challenge-waf-release-checklist.md`), and closes a loop the sensors
already opened.

- [ ] **E1 — Datacenter-member TTL ban for farm-verdict fingerprints**
      *(cfm-web; smallest, immediate payoff).* A bulk "Block all block-safe"
      action on Explain Fingerprint driving the existing `FingerprintIpBlocker`
      guards (datacenter-only per D1, TTL'd via the fleet blacklist, good_bot
      exempt, critical-infra refused, never-downgrade). Ships operator-clicked
      first; a scheduled auto-run for `verdict=farm` is a separate opt-in PR
      after the click flow proves clean. **What E1 buys, honestly:** the
      datacenter members are only ~11% of the captured footprint (~4,100 of
      ~36,200 on `c28caa00`) — but they are the *stable, reused* part of the
      farm's supply (EGIHOSTING/HostRoyale/Datacamp exits recur; the WAF side
      shows repeat use), so a TTL ban there is durable damage. The rotating
      residential ~85% is unbannable *by nature*, not just by policy
      (`solves_per_ip = 1`: each exit is burned once and discarded — a ban
      lands after the farm has already moved on). That majority is E3's job:
      the per-request fingerprint match + ChallengeV2 catches every fresh
      residential exit on first contact with no standing ban and no
      reassignment collateral.
- [ ] **E2 — Fake-crawler autoblock** *(cfm daemon-side).* A UA claiming a
      known crawler family (Googlebot/Bingbot/Applebot/ClaudeBot/GPTBot/
      Perplexity/Meta/…) whose IP fails FCrDNS verification is a
      near-zero-FP conviction — exactly what the `c28caa00` WAF corpus wears.
      Log-driven (FCrDNS is daemon-side, not in-path), reusing
      `verifiedGoodBot` + the detector-sink autoblock rails; `logonly → block`
      promotion per house rule, with the partner allowlist (Skroutz/BestPrice/
      ahrefs/…) honoured before anything counts.
- [ ] **E3 — Phase C minimal + ChallengeV2 Rung 1 with teeth** *(both repos;
      the keystone).*
      - cfm-web: `/fingerprint-policies/fetch` (mirror `/blocklist/fetch`),
        the dedicated arm permission, match-time verdict re-validation
        (checklist already written: `cfm-web:docs/fingerprint-reputation.md` §7).
      - cfm node: pull armed policies on the blocklist cadence; edge matches
        the handshake fp; actions `challenge` (floor), `challenge_v2` (floor,
        per the 2026-09-12 rung decision), `deny` (farm-unique only, D2).
      - ChallengeV2 Rung 1 (passive humanity probe): build it (the config keys
        already live on the fleet ahead of the code — row 12), and give it
        teeth from day one **for convicted fingerprints only**: convicted fp +
        failed passive check ⇒ no clearance issued (re-challenge / deny per
        score). For everyone else it stays invisible/shadow. This is what
        finally makes "the farm solves the PoW" a dead end for the farm.
- [ ] **E4 — Measure and publish the result** (one page appended here): bans
      issued, farm solve-rate before/after, FP reports. This is the exit
      review that D3 demands for the whole arc.

**Deliberately BACKLOG (not next, do not start):** surface-throttle +
gate-before-origin (Track-1 Phase 2), PoW-difficulty knob, JA4/JA4H edge
module, crawler rate-lane, geo-plausibility actions, Signal B/D enumeration,
Rung-2 visible puzzle (only if Rung 1 is beaten), under_attack I3–I5.

## 6. Doc map (after the 2026-09-18 consolidation)

| Role | Doc |
|---|---|
| **Plan of record (this file)** | `docs/abuse-defense-master-plan.md` |
| Node-side design detail (grains, ladder, ChallengeV2 rungs) — roadmap sections frozen | `docs/traffic-classifier.md` |
| Central ledger as-built (schema, ingestors, Phase C checklist) | `cfm-web:docs/fingerprint-reputation.md` |
| Track-2 per-IP score design detail — plan section frozen | `docs/challenge-score.md` |
| B2 decision record (as-built `cfm_pcw`; retire-candidate per §3) | `docs/challenge-score-b2.md` |
| Under-attack state machine design — increments frozen | `docs/under-attack-mode.md` |
| Historical context for the abuse_shadow signals | `docs/webdetector-refactor.md` |
| Archived (superseded, kept for archaeology) | `docs/archive/solver-farm-fingerprint-concentration.md` · `docs/archive/solver-farm-cross-host-phase2.md` · `docs/archive/fleet-fingerprint-reputation.md` |

`docs/ROADMAP.md` §9 is an index pointer to this file — per the CLAUDE.md
rule, never a second copy of this checklist.
