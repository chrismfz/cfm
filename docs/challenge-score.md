# Challenge-abuse score (per-client) — design notes

> **Status:** WORKING NOTES (design, pre-code). The per-client half of the
> traffic-classifier convergence — **Track 2**. Targets the *challenge-defeat*
> problem (headless browsers that SOLVE the challenge), which is structurally
> invisible to the daemon. Read `docs/traffic-classifier.md` first (the master
> plan and Track 1). Owner: challenge/webdetector. Last updated: 2026-08-27.

---

## 1. The problem this scores

The pain is not "a vhost is under a flood" (that is **Track 1**, the vhost
anomaly fusion over facet/cost/dc). The pain here is: **the challenge was issued,
the client solved it, and it kept abusing** — a headless/solver-farm pipeline
(Playwright / lightpanda / a hosted PoW solver) that answers the proof-of-work
and then re-solves per request or per short window.

Each per-IP tell is individually **below** its own threshold; together they are
categorical:

| Tell | What it means | Who sees it today |
|---|---|---|
| **re-solve ≤45 m** (canonical host collapsed) | headless keeps no cookie → asks for a fresh challenge | daemon — `cookie_discard` |
| **issuance cadence** > K/h | same IP pulls many fresh challenges | **edge only** |
| **solve-time < human floor** for the PoW difficulty | native/GPU solver answers faster than a real browser | daemon — challenge-solved history (`solve_ms`) |
| **cleared, then high nav cadence** (page after page) | a solver-farm keeps pulling pages after clearing; the in-path decision path can't see it (Step 2b skips the RPC) | **edge only** (post-clearance) — `cfm_pcw`, B2. (The original "no follow-up asset" framing was retired: assets bypass `cfm.lua`; see `docs/challenge-score-b2.md`.) |
| **claims-browser, no `Sec-Fetch-*` / `Accept-Language`** on a `text/html` nav | automation stack (lightpanda ships almost no modern headers) | **edge only** |
| **farm subnet-spread** | this IP is a member of a many-`/24` solving swarm | daemon — `solver_farm` mark (vhost-level) |

No current actuator **sums** these. `cookie_discard` sees only the first,
`solver_farm` only the spread (vhost-level), `under_attack` needs sustained
pressure on top. The gap the traffic-classifier doc names: **there is no
per-client score in the challenge domain.**

## 2. Why the daemon can't own this alone (the linchpin constraint)

`cfm.lua` Step 2b: when the clearance cookie is valid AND the WAF passed, the
`/nginx/decision` RPC is **skipped entirely** — a solved client is waved through
for the cookie lifetime (~45 m). So **issuance cadence, post-clearance silence,
and the Sec-Fetch tell are only observable at the EDGE**, and any actuation for a
post-clearance abuser must also be **edge-local** (the daemon decision path never
runs for that request). See `docs/traffic-classifier.md` § "clearance
short-circuits the decision".

## 3. Architecture — hybrid (recommended), not pure edge-Lua

The original sketch (chat, "Option A") put the whole score in edge-Lua. We
recommend a **hybrid** split instead, so the scoring logic stays testable in Go
and the edge does only what it *must* do locally:

```
 daemon (Go, testable)                         edge (cfm.lua, ngx.shared)
 ─────────────────────                         ──────────────────────────
 cookie_discard re-solve  ─┐                    issuance cadence   ─┐
 solve_ms anomaly          ├─► SEED map ──────► post-clearance     ├─► per-IP
 solver_farm membership   ─┘   (edge-read,      Sec-Fetch tell     ─┘   decayed
                                like the token   (edge-only tells)       SCORE
                                Lua files)                                │
                                                        T1/T2 ladder ◄────┘
                                                     (harden / 403, edge-local)
```

- **Daemon side** computes the signals it already holds best (it owns the
  challenge-solve event stream via `RecordChallengeSolved`, the `cookie_discard`
  detector, and the `solver_farm` marks) and publishes a **seed weight per IP**
  into an edge-consumed map — the same proven pattern as the generated Lua token
  files (`root:cfm 0640`) and the proposed edge-deny channel.
- **Edge side** keeps only the tells it alone can see in an `ngx.shared` dict
  with time-decay, adds the daemon seed, and applies the ladder **locally** so it
  survives valid clearance.
- **Alternative (flagged, not chosen):** pure edge-Lua score (all tells in Lua).
  Rejected as the default because it moves scoring logic into an untestable layer
  and duplicates signals the daemon already computes; kept as a fallback if the
  seed-map latency proves too coarse.

Any change to `cfm.lua` / `cfm_waf.lua` here goes through
`docs/challenge-waf-release-checklist.md` — shipping a Lua file that fails to load
takes the challenge/WAF layer down.

## 4. Score skeleton (indicative weights — tune in shadow)

Per-IP, decay **30 m half-life**, per-signal caps, `ALLOW_NETS` / `IGNORE_IPS`
bypass, NAT-aware. Weights are config knobs.

| Signal | Weight | Source | Note |
|---|---|---|---|
| re-solve ≤45 m (canonical host collapsed) | +40 | daemon seed | the `cookie_discard` signal |
| issuance cadence > K/h | +10 / hit | edge | absorbs the "issuance throttle" idea as a contributor |
| solve-time < human floor for PoW `n` | +15 | daemon seed | native/GPU solvers answer too fast |
| cleared + high nav cadence (≥30–60 navs/60 s) | +25 | edge | post-clearance cadence (`cfm_pcw`, B2) — replaces the unobservable "no-asset silence" |
| claims-browser + no fetch-metadata on `text/html` nav | +20 | edge | the Sec-Fetch tell as a score component, not a standalone deny |
| farm subnet-spread (member this window) | +5 / solve | daemon seed | bridge from `solver_farm`; spreads guilt to the swarm's solving IPs |

**De-correlation (carry the Track-1 guardrail):** re-solve / issuance / solve-time
partly measure the same "re-solve rate" — **group them under one capped weight**,
don't triple-count. Never feed the *consequence* of our own challenge
(challenge → re-solve) back as if it were independent evidence.

## 5. The ladder (shadow → T1 → T2), mirroring BAD_UA's score philosophy

| Band | Action | Notes |
|---|---|---|
| **shadow** (burn-in) | log only — `[cfm_challenge_score]` would-lines | measure would-act vs baseline before any enforcement |
| **≥ T1 (soft)** | **harden the NEXT challenge** for this IP | PoW `n`↑ **or** a harder interactive challenge (see §6) |
| **≥ T2 (hard)** | **403 deny** (edge) | 403, not nft — HTTP-layer, per-vhost, residential-FP-friendlier |
| **≥ 99 (reserved)** | deterministic jump | confirmed repeat-solver with canonical-host collapse — the job `cookie_discard` does today |

**Shadow-first is mandatory** (like `abuse_shadow` / the fingerprinter): a
`[cfm_challenge_score]` shadow log with `verdict=would_harden` / `would_deny`,
compared to baseline, before T1/T2 are ever armed. `logonly → challenge/harden →
deny` promotion, never straight to deny.

## 6. Actuator menu (Stage E — the last decision, shared with Track 1)

This score chooses *who*; the **actuator is a separate, later decision** and is
shared with the vhost lane:

- **Soft rung — harden.** PoW difficulty `n` 16→20 (`pow.go PowConfig.Difficulty`,
  today hardcoded 16; the knob is Phase A groundwork). ⚠️ `n=20` already loses
  ~⅓ of mobile clients to **expiry** — so the challenge expiry window MUST scale
  with `n` in the same change, or we self-DoS.
  - **ChallengeV2 (interactive: drag-image / puzzle)** is the stronger soft rung
    *specifically against headless*: PoW is pure CPU (a farm solves it trivially),
    while a drag/puzzle needs real interaction/rendering. Prefer ChallengeV2 over
    PoW-harden for the solver-farm class; keep PoW-harden for cost-based hardening.
- **Hard rung — deny.** 403 static (leaning this, residential-proxy mercy — the
  innocent sees *something* and can refresh) **/** tarpit (delayed-empty 200,
  steals attacker concurrency, hides detection) **/** nft drop (silent, but
  reveals nothing and is harsher on FPs). Deny-shape = master-plan Open Question #1.
- **Manual challenge** stays an operator tool throughout.

## 7. Guardrails

- **Shadow-first**, `logonly → harden → deny`, never straight to deny.
- **Never** an adverse decision on country/ASN alone (house rule).
- `ALLOW_NETS` / `IGNORE_IPS` bypass + **NAT awareness** — a shared corporate/NAT
  egress must not be locked out by one member's solver.
- Respect existing challenge/WAF **excludes & bypass** (e.g. `/acctxfer*`,
  `/.well-known/`) so we never gate transfers or ACME.
- Edge-Lua changes follow `docs/challenge-waf-release-checklist.md`.
- **Absorbs, doesn't duplicate:** long-term this score subsumes `cookie_discard`
  as a *contributor*; keep the `cookie_discard` / `solver_farm` alerts running as
  dual signals during burn-in, retire once the score leads.

## 8. Wiring anchors (grounded, from the 2026-08-27 code map)

- Clearance short-circuit: `cfm.lua` Step 2b (the reason the edge must own it).
- Challenge-solve event stream: `RecordChallengeSolved` → history store
  (`solve_ms`, `ua_impossible` already persisted).
- `cookie_discard` detector: `internal/detectors/cookiediscard` +
  `challenge_cookie_discard_register.go` (`BLOCK` is operator config).
- `solver_farm` marks: `IsSolverFarm(host)` (`solverfarm_marks.go`).
- PoW difficulty: `internal/webdetector/pow.go` — `PowConfig.Difficulty`,
  `defaultPowDifficulty = 16`; the `n=20 → ⅓ mobile expiry` note lives here.
- Edge-consumed map precedent: the generated Lua token files (`root:cfm`, `0640`).

## 9. Open questions (resolve before T-band code)

1. **Deny shape**: 403 vs tarpit vs nft drop (shared with the master plan).
2. **Client subject**: pure IP (simplest) vs `(IP, vhost)` (fairer multi-tenant)
   vs `/24` rollup (solver farms). Lean **IP-primary + a `/24` density feature**.
3. **Aggregation site**: the hybrid seed-map (recommended) vs pure edge-Lua.
4. **Burn-in log**: a new `[cfm_challenge_score]` shadow log (like `abuse_shadow`)
   vs folding into an existing surface. Lean **new dedicated log** (the daemon
   emits the seed side; the edge emits the edge-tell side — two writers, one
   schema), surfaced by an MCP tool like `abuse_shadow`.
5. **Dual signals**: retire `cookie_discard` / `solver_farm` alerts once the score
   leads, or keep as belt-and-suspenders?

## 10. Phased plan

- **Stage 0 — zero-code (operator):** `BLOCK = 6h` on `cookie_discard` +
  `UNDER_ATTACK_FINGERPRINT` / `FP_*` keys (data collection). Covers ~80% of the
  re-solver case today with no code.
- **Stage 1 — shadow scorer + aggregation view.** Split daemon-first (a code check
  found most signals are already recorded daemon-side, so the risky edge-Lua is not
  needed to start collecting):
  - **Stage 1a — DONE (daemon-side, Go, log-only).** `internal/webdetector/
    challenge_score.go`: a decaying per-IP score (30-min half-life) fed from the
    existing `SubscribeChallengeSolveEvents` stream. It scores only the
    *discriminating* per-solve tells — UA-lie (`UAImpossible`) and solver-farm vhost
    (`IsSolverFarm`) OPEN a score; implausibly-fast solve (`SolveLatencyMS`) is a
    corroborating AMPLIFIER only — emitting
    `signal=challenge_score … verdict=would_harden|would_deny` via `LogfABUSESHADOW`
    (into `cfm.abuse_shadow.log`, no new log/logrotate). **NAT/CGNAT-safe by
    construction** (honouring the §7 guardrail): raw solve VOLUME is not scored (no
    flat per-solve weight); the fast tell can't convict alone — ~15-23% of *honest*
    browser solves are "fast" at the default PoW difficulty (`pow.go`: median 1.3 s,
    exponentially distributed), so fast alone would light up a busy egress, hence it
    only adds weight to a solve that already carries a strong tell; and `IGNORE_IPS`/
    `IGNORE_NETS` IPs are skipped. So a benign shared egress (many users each solving
    once, fast or not) can't accumulate to a false farm. Rides
    `ABUSE_SHADOW`, no new config; weights/thresholds are in-code burn-in constants.
    Surfaced by the `abuse_shadow` MCP tool's by-signal/by-verdict counts (no
    dedicated reader needed yet). Deferred to a **daemon seed** (not proxied by
    counting solves here): the `cookie_discard` re-solve-cadence signal (§4 table
    row, +40, canonical-host collapsed) and edge issuance cadence — the only
    volume-shaped tells that genuinely discriminate a re-solving headless from a
    busy NAT.
  - **Stage 1a+ — DONE (fingerprint-anchored spine, shadow).** B3's first slice
    (`docs/traffic-classifier.md` § "Third grain"): the solver-farm detector now
    marks the CONVICTING fingerprint (`MarkSolverFarmFingerprint`, the fingerprint
    twin of the vhost farm mark), and `challenge_score` opens on
    `IsSolverFarmFingerprint(solve.TLSFP)` as the **dominant spine tell**
    (`chalScoreWFarmFP` = 40, weighted above the vhost-farm and UA-lie tells) — so
    a client repeatedly solving with a convicted fingerprint climbs to `would_deny`.
    The fingerprint tell ALONE (40) is under T1 (50), so a lone convicted-fp solve
    with no other tell does not reach `would_harden`; a second solve — or a
    corroborating tell on the same solve, e.g. the vhost-farm mark that co-fires on
    the same detector pass (40+15=55) or a fast solve (40+10=50) — crosses it.
    `farmfp=` in the shadow log. This is where
    the score stops being purely per-IP and becomes fingerprint-anchored — and where
    the shadow will show whether a coarse TLS bucket (`c28caa00`) lights up legit
    shared-bucket solvers, the exact signal that decides whether a fingerprint may
    be enforced bare or only with JA4H corroboration / an interactive challenge.
  - **Stage 1b — edge-Lua tells.** The two signals only the edge sees —
    post-clearance silence (tripwire) + Sec-Fetch — plus the hybrid seed map, per
    the architecture in §3. Follows the challenge-waf-release-checklist. Sliced:
    - **B1 — DONE (Sec-Fetch headless tell, logonly WAF rule).** Rule 612
      (`WAF_FETCH_METADATA`) in `cfm_waf.lua` + `cfm_waf_detectors.lua`
      (`detect_fetch_metadata_missing`), Go-parity in `waf_rule_ids.go`. Fires when
      a UA claims a Sec-Fetch-capable browser (Chrome ≥ 76 / Firefox ≥ 90) but a
      `text/html` `GET`|`HEAD` nav carries no `Sec-Fetch-*` AND no `Accept-Language`;
      honest CLI clients, self-declared crawlers (named tokens, incl. SleepBot and
      GeedoShopProductFinder) and infra paths (`/robots.txt`, `/.well-known/*`)
      never match; in-app browsers of social apps (named tokens,
      `IN_APP_UA_TOKENS` — TikTok's `musical_ly`; a real person, header-poor by
      the app's stack) are the known real-browser exception and get their own
      tag `NO_FETCH_META_IN_APP` (recorded, separable, weighted on its own,
      clamped to logonly in `cfm_waf.lua` whatever the rule's mode — not
      suppressed, so the spoofable token buys no silent skip); Safari excluded
      (16.4+ only). logonly SHADOW — surfaced by `waf_activity` (filter
      `rule=WAF_FETCH_METADATA`; `waf_fp_hunt` is panel-WAF-only), un-armed in
      `waf_security` (no edge-block rule), placed LAST so it never masks a stronger
      reason. Stateless, no `ngx.shared`. Feeds the score later via the seed map.
    - **B2 — DONE (post-clearance nav-cadence shadow, `cfm_pcw`).** `cfm.lua` Step 2b
      calls `cfm_pcw.observe` for each CLEARED request: it counts a cleared
      identity's **top-level** navigations (GET|HEAD document loads —
      `Sec-Fetch-Dest: document`, else `Accept: text/html`; iframes and prefetch
      excluded) per fixed 60s window, keyed `(ip, host, scope)` (the clearance
      grain), and logs `[cfm_pcw] post_clearance_burst … verdict=would_harden|would_deny`
      (≥30/min / ≥60/min) to the edge error log, read via `edge_error_tail`. **The
      design's "no-asset silence" tell was retired** — static assets bypass `cfm.lua`
      entirely, so asset fetches aren't observable here, and browser caching would
      break it (see `docs/challenge-score-b2.md`); nav cadence is cache-immune. It is
      **per-IP-per-host, not per-browser** (the cookie is `HMAC(ip,host,scope)`), so a
      shared egress (CGNAT/NAT) where many real users are cleared for the same host
      pools — a known FP class B3 must handle NAT-aware before enforcement. Edge-local
      (fills the Step-2b decision-skip blind spot), log-only, `pcall`-guarded,
      dedicated bounded `cfm_pcw` dict, config toggle
      (`detectors.conf [webdetector] POST_CLEARANCE_CADENCE = 0`, published to the
      edge on the 10s bridge TTL, no proxy reload). Feeds the seed map.
    - **B3 — hybrid seed map (last).** Daemon publishes the Stage-1a score +
      `cookie_discard`/`solver_farm` as a per-IP seed the edge reads (the
      `root:cfm 0640` token-file pattern); edge fuses seed + edge tells into one
      decayed per-IP score. The convergence piece.
- **Stage 2 — T1 harden:** wire the soft rung (POWN knob **Phase A manual** first
  — `CHALLENGE_POWN` + per-vhost + expiry scaling + cfm-admin button; then
  **Phase B auto governor** from `IsSolverFarm` / challenged / suspicious), and/or
  ChallengeV2.
- **Stage 3 — T2 deny:** the edge-deny (403) channel, after burn-in shows a clean
  would-deny set.

**Standalone building blocks (value on their own, feed this score):**
- **POWN difficulty knob** (Phase A manual) — also the I3 "harden" groundwork.
- **Sec-Fetch headless-tell WAF rule — DONE (Stage 1b/B1, rule 612).** `logonly`
  first (watch `waf_fp_hunt`), then promote; only ever fires when the UA *claims* a
  browser, so honest `curl`/`wget`/`Python-requests` never match. A stacked
  weak-signal rule (claims-browser AND missing `Sec-Fetch-*` AND missing
  `Accept-Language` AND `text/html` nav), not a single-header deny.
