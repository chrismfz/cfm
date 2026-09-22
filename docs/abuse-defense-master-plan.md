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
- **D5 — Humanity checks must not be authoritarian (operator, 2026-09-19;
  governs ChallengeV2 Rung 1 and any successor).** Four locks, all hard
  requirements: **(a) scope** — passive humanity scoring gets TEETH only for
  fingerprints an operator explicitly armed (`challenge_v2`), TTL'd and
  disarmable; for everyone else it is shadow/log-only. **(b) absence never
  convicts** — a solve fails only on POSITIVE headless evidence (e.g.
  `navigator.webdriver=true`, software-renderer + impossible-screen combos);
  missing signals (keyboard-only users, privacy browsers blocking canvas,
  partial JS) can never fail a solve on their own. **(c) failure is
  retry-able, never a silent wall** — a failed passive check re-serves the
  challenge (and, once Rung 2 exists, escalates to a VISIBLE interactive
  check with an accessibility fallback); a no-recourse deny stays reserved
  for farm-unique fingerprints per D2. **(d) full observability** — every
  scored solve logs `hs=` + `tells=` so the operator can see exactly why any
  client passed or failed, with a shadow burn-in + measured FP rate (D3 exit
  contract) before teeth are trusted.

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
      after the click flow proves clean.
      - [x] Drill-down control slice — **DONE 2026-09-20** (cfm-web, operator
        decision: "more manual control BEFORE any risky automation"). The IP
        section's Top networks / Top countries chips (and row Network cells)
        are toggle filters (country AND asn combine, URL-shareable,
        server-sanitized; `country` is the full GeoLite2 name), and ONE
        `ipQuery()` feeds the table and the filtered counts. Bulk blocks act
        on the CONFIRMED scope (filter+count baked into the click; a
        mid-flight toggle can't widen the set; drift aborts) — kind gates
        unchanged. Per-country/ASN *challenge* buttons deliberately
        NOT faked here — they arrive with the policy-kinds item below. **What E1 buys, honestly:** the
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
      - [x] cfm-web slice 1 — **DONE 2026-09-18**: `GET /api/fingerprint-policies/fetch`
        (token-authed; serve-time re-validation — `deny` withheld below a farm
        verdict, `observe` never served), the dedicated `Arm:FingerprintPolicy`
        permission, `challenge_v2` in the arm vocabulary. As-built:
        `cfm-web:docs/fingerprint-reputation.md` §7.
      - [x] cfm node slice — **DONE 2026-09-19**: agent-channel pull (~60s,
        stale-ok) → package-level store → `GET /nginx/fppolicy` bridge lookup
        (tuple→id stays single-sourced in `internal/tlsfp`) → edge
        `cfm_fppolicy.lua` cache + `cfm.lua` Step 0c: `deny` 403s BEFORE the
        clearance fast-path; challenge/challenge_v2 are a floor for uncleared
        clients (v2 behaves as v1 until Rung 1 ships). Knobs `FP_POLICY` /
        `FP_POLICY_ALLOW_FPS`; expires honoured at lookup. **Web path only** —
        the panel-port gate (`cfm_panel.lua`) does not consult the policy yet.
      - [x] Panel-port fp-policy consult — **DONE 2026-09-22**
        (`cfm_panel.lua` step 2f): the same operator-armed policy the web
        edge enforces at Step 0c now covers `:2083/:2087/:2096`. As-built:
        ONLY `deny` acts, under the panel mode ladder
        (`PANEL_FP_POLICY_MODE` off|logonly|enforce, default enforce like
        its panel siblings; env `CFM_PANEL_FP_POLICY`; published via the
        bridge config so flips land in ~10s) — `logonly` records
        `[cfm_panel_fppolicy] logonly=would_deny`. Challenge/challenge_v2
        fingerprints stay OBSERVE-ONLY on panel ports (logged, never
        enforced: the panel has no per-request challenge serve — the 2e
        loop rationale — so the floor remains a web-path concept). The
        global `FP_POLICY=0` kills the consult too; self/IGNORE_NETS never
        reach the lookup; the tuple comes from the panel port's own
        handshake ($ssl_*); the lookup reuses the shared cfm_fppolicy
        cache dict + the panel's bridge client; everything pcall'd +
        fail-open (a fault can never lock the panel).
      - [x] ChallengeV2 Rung 1 — **DONE 2026-09-19** (`challenge_v2.go` +
        the challenge-page passive collectors): every solve is scored on
        positive headless evidence only (webdriver / HeadlessChrome UA fail
        alone at 100; SwiftShader-class renderer 60, touch-lie 50, outer-zero
        40 each PASS alone; no-input is an amplifier that never opens — D5b),
        logged as `hs=`/`tells=` on the solve line. Armed `challenge_v2` fp +
        failing score ⇒ `result=v2_reject`, 403, no clearance — the page
        reloads into a fresh challenge (D5c). Everyone else: shadow
        `signal=humanity verdict=would_v2` (rides ABUSE_SHADOW). Knobs
        `CHALLENGE_V2_PASSIVE` / `_FAIL_SCORE` / `_DEBUG` (X-CFM-HS header).
        Solving the PoW stops paying for an armed fingerprint: the solve no
        longer earns clearance. **Honest limits (documented in
        `challenge_v2.go`):** the report is client-authored, so a
        signal-aware farm can fabricate a clean one — Rung 1 catches standard
        automation stacks and raises per-exit cost (a stripped body shows as
        `hs=-`, so evasion is visible); the escalation if beaten is Rung 2.
        Teeth are web/edge-path-only (DNAT clients author their own
        `X-CFM-TLS`), the same limitation family as the slice-2 edge match.
        (Operator row-12 cleanup stands: delete the orphan `HUMANITY_*` keys
        from live configs — the built rung uses `CHALLENGE_V2_*`, not those.)
      - [x] **Policy kinds: country / asn — DONE 2026-09-20** (operator
        decision 2026-09-19; both repos). The policy channel's `kind`
        generalised to `country` (ISO-2) and `asn` rows — same arm
        permission, feed, pull and TTL machinery. **Challenge tiers only:
        `deny` per country/ASN is excluded by doctrine** (D1-adjacent: a
        whole country in 403 with no recourse is the authoritarian failure
        mode), enforced THREE times: arm-time refusal (cfm-web
        `armGeo`), serve-time withhold (`deny_unsupported_kind`), and the
        node store drops a geo deny on ingest. The house rule stays intact:
        "never an adverse decision on country/ASN alone" binds AUTOMATIC
        signals; the manual, TTL'd operator arm is the sanctioned exception.
        As-built: arm from Explain Fingerprint's active country/ASN filter
        (country target resolved to the ISO code via a sample member IP —
        the ledger stores display names); feed rows carry
        `policy_kind` + target; the node enforces daemon-side as a challenge
        FLOOR on the per-IP decision path (country from the edge-passed/
        enrich ISO, ASN via the local mmdb, lazy) — solved-ok clears it,
        verified good bots and Challenge Access exemptions still apply, and
        `challenge_v2` bites at verify via the geo resolver (same D5 gate as
        the fingerprint grain). Old nodes ignore geo rows harmlessly.
        `FP_POLICY=0` kills all kinds. Web/edge decision path only (same
        residual family as the fp grain). Known residuals: the M2M endpoint
        carve-out clears a geo-floor-only challenge (payment webhooks from an
        armed country keep working — review finding, fixed in-slice); the
        panel ports consult the same decision so an armed country adds
        `would_enforce` logonly WARN noise there (no enforcement — the panel
        probe is block-tier only); country hit wins over ASN hit at lookup;
        cold IPs (enrich cache miss) fail open for up to the 90s edge
        decision-cache window.
      - [ ] **ChallengeV2 arm surfaces (operator ask 2026-09-20): v2 as an
        on-demand tier from WAF rules / vhost control / traffic rules /
        scoped customers.** Insight that makes this cheap: challenge_v2 is
        a VERIFY-time distinction, not a serve-time one — so "arm v2 from
        X" only needs verify to know the challenge came from a v2-tier
        source. Foundation: a small per-(ip, host) **rung mark** TTL store
        in webdetector, written as a side effect wherever a challenge is
        already issued daemon-side (as built: handleDecision for v2-tier
        traffic rules, handleIPPush for v2-tier WAF pushes), OR'd into
        the verify gate next to the fp/geo checks. D5 carries over verbatim
        (an explicit rule mode / vhost toggle IS an operator arm; fails stay
        retry-able; hs=- keeps evasion visible); consider a dedicated
        CHALLENGE_V2_ENFORCE kill switch since v2 teeth stop being
        fp-policy-only. Slices, in order:
        - [x] **A — per-vhost v2 mode + verify OR — DONE 2026-09-22.** The
          MANUAL vhost challenge carries a `rung` ("" plain / "v2"), stored
          in the engine's manual store (persisted with the challenge,
          apex→www covering) — NOT in bridge vhState: the tier is a
          verify-time distinction, so the verify gate ORs a wired
          `challengeV2HostArmed(host)` next to the fp/geo checks. Verify
          is edge-only (localhost listener; the per-IP challenge-DNAT is
          retired — operator catch 2026-09-22), and the edge verify blocks
          re-stamp XFH, so the gate inputs are edge-authoritative on
          current confs (HONEST LIMITS in challenge_v2.go). Wildcard hosts
          fail closed for v2; a rung-less re-add preserves an existing v2
          arm, and the cfm-admin buttons send a tier ONLY from the card
          that shows the Tier picker. Surfaces:
          cfm-admin "Tier" picker next to the Challenge TTL, API
          `rung=v1|v2` on `challenge/vhost/add` (scoped tokens included —
          challenge-tier by construction, so slice D's self-arm largely
          exists already via the existing vhost scope checks), CLI
          `cfm webtop challenge add <host> --rung v2`; `rung` in the
          status API. Design note: the generic per-(ip,host) rung-mark
          store originally sketched here was NOT needed for the vhost
          grain and is deferred to slices B/C, where a transient
          per-request source (rules / WAF hits) genuinely requires it.
        - [x] **B — traffic-rules action `challenge_v2` — DONE 2026-09-22**
          (rules-model.js + traffic_rules.go same PR — Simulate IS
          enforcement; rules-builder option with the same band as
          challenge). Per-vhost-per-condition v2. As-built: the rule stores
          and simulates as `challenge_v2`; the BRIDGE maps it to plain
          "challenge" on the wire (the edge vocabulary stays
          block/challenge/throttle — old and new edges work unchanged) and
          records the v2 intent in the per-(ip,host) RUNG-MARK store
          (challenge_v2.go: TTL 15m, cap 8192, fail-open to plain v1 on
          pressure), which the verify gate ORs in as the FOURTH arm grain.
          The mark exists because a rule matches one request's attributes
          at decision time and verify cannot re-evaluate it later. Slice C
          (WAF tier) reuses this store. Accepted residuals (review verdicts):
          within the 15m TTL a mark can be consumed by a challenge a
          DIFFERENT (v1) source caused on the same (ip,host) — acceptable:
          the arm is operator-authored for exactly that pair, bounded, and
          D5b/D5c still hold; marks are WEB-scope only (a panel decision
          probe never writes one — v2 stays web-path until the panel consult
          ships); and sustained new-pair pressure (~9/s) can pin the store
          at its cap so NEW marks degrade to plain v1 (fail-open by design) —
          roadmap note: an eviction-of-soonest-expiry + a status counter
          would remove that disarm lever if it ever shows up live.
        - [x] **C — WAF rule tier `challenge_v2` — DONE 2026-09-22.** The
          missing rung in the promotion ladder `logonly → challenge →
          challenge_v2 → block`, set per rule via `cfm_waf_config.lua`.
          One default ships at the new tier: `rule_xss` (302) promoted
          challenge→challenge_v2 in the same change (operator decision —
          XSS probes like `?q=<script>alert('XSS')</script>` are a scanner
          smoke test, so their solvers face the humanity gate; revert per
          fleet with `rule_xss = "challenge"`).
          As-built: cfm_waf.lua accepts the mode (rule_mode/set_rule),
          severity challenge(2) < challenge_v2(3) < block(4) — only block
          short-circuits; the edge serves the SAME challenge page (cfm.lua's
          challenge-tier else-branch) and, per review, presents plain
          "challenge" to the client on both rungs (X-CFM-Action shows the
          rung only under CFM_DEBUG_HEADERS — echoing it would hand a
          signal-aware farm the exact solves under v2 scrutiny); the
          ip_push carries the verbatim tier; handleIPPush (+ the events
          batch) stores a plain "challenge" decision (edge wire vocabulary)
          and writes the slice-B per-(ip,host) rung mark, which the verify
          gate already ORs in — no verify change needed. Doctrine held:
          challenge tier does NOT arm waf_security autoblock (wafsec feeds
          on action=block pushes only, and should_push keys the v2 tier
          separately so a v1 window never masks the mark-writing push);
          post-clearance converts v2 exactly like challenge (no re-challenge
          loop); the panel gate stays block-tier (a v2 rule is observe-only
          on panel ports). Review catch folded in the same PR: the
          challenge-resume redirect (challenged POST) used to return BEFORE
          the ip_push — a body-carried v2 hit would never write its mark
          (and a resumed challenge left no cfm.waf.log/history at any tier);
          the push+log now runs on every route out of the action branch,
          resume path included. Version-skew hazard documented in
          docs/waf.md: an OLDER edge maps the unknown mode to `disabled` —
          upgrade before setting the tier.
        - [x] **D — scoped customer self-arm — DONE 2026-09-22** (cPanel
          "panic button"). The scoped WRITE path itself predated this
          slice (slice A: `challenge/vhost/add|remove` take scoped tokens,
          `vhostAllowed` fail-closed, challenge tiers only by
          construction; generic per-identity rate limit 120 writes/60s).
          Slice D added what was missing:
          (1) **TTL cap** — a scoped arm is clamped to
          `scopedMaxChallengeTTL` (24h), clamp-and-report
          (`ttl_capped: true` + effective expiry in the response), admin
          uncapped;
          (2) **audit** — `challenge_vhost_manual_on/off` history events
          now carry `payload.rung` (explicit "v1"; absent key = pre-D
          event) and `payload.actor` ("admin"|"scoped" from the request
          scope; `ManualChallengeVhostAs`/`ClearManualChallengeVhostAs`),
          and the CHALLENGES log line gained `actor=` — "who armed v2"
          no longer needs a cfm.api.log timestamp join;
          (3) **the surface** — an "Emergency challenge" card on
          `/cfm-admin/webdetector/controls/` (the page the cPanel plugin
          iframe lands on, which had NO arm control): vhost picker,
          Standard/Strict(v2) mode, 1h/6h/24h duration, arm/disarm,
          status from the one scoped-readable
          `challenge/vhost/status` (single request, no per-row fan-out);
          single-vhost scopes preselect their host. Copy explicitly
          distinguishes it from the adjacent Challenge ON/OFF engine
          toggle (recon flagged the naming trap). The slice's dedicated
          SECURITY REVIEW ran (verdict FIX-FIRST → fixed in the same PR):
          I1 the free-text `reason` could forge the flat audit logs — now
          control-char-stripped + capped at the input boundary
          (`sanitizeAuditReason`) and `%q`-quoted at every log site; I3
          the `vhost/attack` override left no audit trail — now emits a
          `challenge_vhost_attack_override` history event + CHALLENGES
          line with the actor; I2 the scoped embed-bootstrap cookie
          (SameSite=None) was exempt from the CSRF Origin check while
          every arm endpoint accepts query-param POSTs — the CSRF
          middleware now covers embed-cookie auth too (same-origin iframe
          XHRs pass; a cross-site form 403s). Accepted residuals
          (review-verified, all own-vhost/self-inflicted or same-tenant):
          no per-vhost flap throttle beyond the generic 120/60s write
          bucket; re-arming resets the 24h window, so a scoped cron can
          maintain a standing challenge on its own vhost (soft arms/day
          counter is the future lever); the bridge's apex→www expansion
          installs the www twin past the exact-match scope check
          (same-account ServerAlias in cPanel practice); a scoped re-arm
          may replace/downgrade an admin arm on the customer's own vhost
          (owner self-service — an owner-immutable challenge belongs in
          config-time CHALLENGE_VHOST); ~~the scoped `vhost/attack`
          override stays un-TTL'd~~ RESOLVED 2026-09-22 (operator
          decision): a scoped `on=1` override is TTL-bound to the same
          24h ceiling as the panic arm — expiry returns the vhost to
          AUTO control via the tick (st.on stays true, so the vhost
          leaves by the normal exit rules, not mid-attack) and the read
          paths honour it immediately; admin overrides stay unbounded.
          The SAME re-arm residual as the panic arm applies and is
          accepted: a scoped on=1 every <24h keeps the override standing
          (own vhost, audited per re-arm);
          the scoped Tier picker on the
          WebDetector overview page pre-existed via slice A under the
          same server-side scope checks.
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
