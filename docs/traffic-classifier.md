# Traffic classifier — living design notes

> **Status:** WORKING NOTES (not a frozen spec). Accumulating the Phase-0 audit
> and a grounded design before we commit to weights/actions. Authorised to live
> on `main` while we converge. Owner: challenge/webdetector.
> Last updated: 2026-08-25.

## Why this exists

The web classifier started as a set of independent per-signal detectors, each
with its own threshold and its own actuator:

- **suspicious engine** (per-vhost score: err%, path/UA diversity, uniqIP, bot%, …)
- **cookie_discard** (per-IP re-solve count → alert / optional nft)
- **solver_farm** (per-vhost subnet-spread → observe/badge only)
- **under_attack** (per-vhost state machine → detect-only, DRYRUN)
- **abuse_shadow** (per-(vhost,IP) rate outlier → log only)
- **WAF BAD_UA** (per-request UA score, `≥99` deterministic deny)

The problem we keep hitting (e-athlos.com, techking.gr, …) is a **distributed,
UA-invisible, cost-driven** abuse of expensive dynamic surfaces. It changes
platform daily — WooCommerce facet filters one day, OpenCart pagination or phpBB
`viewtopic`/`search` the next — so **per-site or per-CMS rules do not
generalise.** We need a mechanism-agnostic classifier, and we need the existing
signals to *cooperate* rather than each firing (or not) on its own threshold.

**Design thesis:** stop adding detectors that each own a threshold AND an
actuator. Every signal becomes a **contributor** to one of two scoreboards that
already exist, and there is ONE actuator ladder. Decisions fork on a small,
explainable set of features — never a black box.

---

## Phase-0 audit (fleet, 2026-08-25)

Read-only MCP telemetry across the 7 web-facing nodes (earth, mars, orion,
rigel, server.speedhost, titan, virgo). Full drill-downs on a balanced sample of
attack-labelled vs normal-labelled vhosts.

### Finding 1 — there are THREE traffic classes, not one

| Class | Live example | Who | Surface | Verdict |
|---|---|---|---|---|
| **1. Verified-crawler over-crawl** | techking.gr (0.81, challenged), shopzy.gr (0.74) | **Verified Googlebot** (rDNS `crawl-*.googlebot.com`, AS15169), **Meta** `meta-externalagent` (AS32934), Bing, ByteDance, TikTok | unbounded facet/pagination (`?route=product/category&path=…&page=1062`; YITH `filter_χρώμα=…,…`) | **cost/SEO problem, NOT malice.** Never deny. Rate/crawl-budget only. |
| **2. Malicious flood** | e-athlos.com (Aug 21–22) | **544,492 residential IPs**, rotating *realistic* Chrome/FF/Edge, **no declared bot** | WooCommerce `filter_*` combinatorics | **security threat.** 861k req, 93.5% to filters, **256k× HTTP 500**, origin collapse. |
| **3. Single-source scraper/scanner** | dev.socialpower.gr (uIP 1, err 100%), gastenis.gr | one aggressive host | anything | handled by the **existing per-IP score** already. |

**The reframe:** day-to-day, what trips the suspicious engine fleet-wide is
mostly **Class 1** — legitimate search/AI crawlers stuck in infinite facet URL
spaces. The engine scores them like attackers (`bot_ratio 0.96` + `high_err` +
`scanner_like_path_diversity` → 0.81 → challenge). **Challenging verified
Googlebot/Meta is a latent SEO/social FP.** Class 2 (the real threat) is the
intermittent tail and is currently *below* the score threshold at rest.

### Finding 2 — the separator is a FORK, not a single scalar

Real numbers from the sample:

| Feature | Normal (moto-empire, queerdoc) | Class 1 verified-crawler (techking, shopzy) | Class 2 malicious flood (e-athlos Aug / mathematica) |
|---|---|---|---|
| Top-IP ASNs | residential ISP (Orange Mali/Guinée, Cox) | **verified** Google/Meta | **unverified** datacenter/residential-proxy (AWS/GCP/DO/HostRoyale/code200) |
| Verified crawler (rDNS) | none / incidental | **dominant** | none |
| UA coherence | real, coherent | honest declared bot | **spoofed** (impossible `chrome/150`, `chrome/151`) |
| bot_ratio | 0–0.47 | 0.9+ | low (claims human) |
| Referrers | real (Google Ads `gclid`, article URLs) | `(direct)` | `(direct)` |
| Cost / errors | low | high (facet enum) | high → 500 collapse |
| datacenter-ASN frac | ≈ 0 | high (but verified) | high (unverified) |

The **primary fork** that cleanly separates all three:

```
1. Verified crawler (rDNS/ASN: Google 15169, Bing, Meta 32934, Apple)?
     → Class 1 → crawl-budget / rate on expensive surface. NEVER deny.
2. Not verified, but datacenter/proxy ASN + spoofed-UA + facet-cost + spread?
     → Class 2 → security response (surface-throttle → gate → deny).
3. Residential + coherent UA + real referrers?
     → normal → leave alone.
```

**`datacenter-ASN-fraction` alone is dangerous** — it fires on Google/Meta too.
It only becomes safe *gated by verified-crawler classification*, which is
currently **absent** from scoring. Verified-crawler classification is the
linchpin of the whole design.

### Finding 3 — two concrete blind spots / dead code

- **`path_diversity` collapses the query string.** e-athlos sent **805,746
  distinct filter URLs**; the engine saw `unique_paths = 2`,
  `path_diversity = 0.058` → reads **benign**. The combinatorial-cost signature
  is invisible to the vhost score today. (Raw query IS retained in the access
  ring — `redactQuery` only strips secret params — so the signal is derivable,
  just not computed.)
- **`solver_farm` is quiet, but correctly so (corrected).** `solver_farm: false`
  on every flagged host during the audit — NOT because it is mis-tuned, but
  because **no many-subnet flood was live**. `MinSubnets=40` is deliberately
  calibrated (`solverfarm/detector.go:17-28`): on the 23h capture the farm vhost
  showed **median 73 distinct /24 per 60s window** (p01 49, max 122) while every
  other vhost maxed at 27 — so 40 flags 2758/2761 farm windows and 0/3212 legit,
  a 1.5× margin. That is the **e-athlos residential-proxy flood** shape (544k IPs
  → thousands of /24s). The Meta /24 (`57.141.20.0/24`) is a **single** subnet →
  correctly NOT a "farm"; it is the CHALLENGE_SUBNET path (+ good-bot exemption),
  a complementary detector. **Do not lower solver_farm thresholds** — it will
  fire when a real many-subnet flood is live.

### Finding 4 — a live false positive to fix regardless

The log-driven engine repeatedly issues `CHALLENGE_ERR_RATIO` to a **real
Googlebot IP** (`66.249.74.226`). Any cost/ASN signal we add MUST verify
crawlers (rDNS) or we amplify this.

### Not yet measured (needs a burst)

- **query-cardinality / URL-repeat-ratio** live during an active flood: no host
  was in burst during the audit (`5xx ≈ 0` fleet-wide). To be captured via raw
  `edge_access_tail` the next time a Class-2 flood is live, to fix the weight.

---

## What we already have (grounded wiring inventory)

The two-tier scoreboard we want **already physically exists**; convergence is
mostly wiring the detectors into it, not new machinery.

### Two scores, two actuators, one chokepoint

- **Per-client score** — `IPSignals.Score` (`engine.go`), mapped by
  `IP_SCORE_RULES = block:0.90,challenge:0.75` (`webdetector_config.go`) in
  `proposeIPActions` → `emitIPBlocks`: `challenge` → `nginxBridge.ChallengeIP`
  (writes `ipState`); `block` → `core.Alert` → section sink → `fw.AddBlock`
  (nft). **Fed only by the web-detector's own traffic counters today** — NOT by
  cookie_discard / solver_farm / abuse_shadow / BAD_UA / solve-latency.
- **Per-vhost score** — `SuspiciousRow.Score` (`scoring.go`, `longwin.go`),
  evaluated in `challenge_rules.go` → `ChallengeVhostWithReason` (writes
  `vhState`, action = `"challenge"` only).
- **Chokepoint** — `handleDecision` (`/nginx/decision`, `nginx_bridge.go`)
  returns `map{ip_action, vhost_action, rule_action, rule_id, throttle_profile}`
  and is consulted per uncached request. Edge enforces in `cfm.lua` Step 3.

### Detector → enforcement path (the section sink)

`sectionSink.Publish` (`autoblock_sink.go`) turns a `core.Alert` into:
challenge (`nginxBridge.ChallengeIP` → ipState) / nft block (`fw.AddBlock` via
`BLOCK` policy) / leniency temp-ban / API+email. Controlled by `Extra` keys:
`ip`, `ip_scope=host` (fail-closed, no IP adopted), `action=challenge`,
`enforcement=observe|dryrun`, `ttl`, `block_ttl`. solver_farm deliberately lands
in the **observe** branch (alert only); wafsec emits `core.Alert` only and lets
the sink enforce. **This is exactly the seam a converged score plugs into.**

### Verified-crawler + datacenter classification ALREADY EXIST (reuse, don't rebuild)

Both features the design leans on are already implemented and battle-tested —
they are simply not wired into the vhost score:

- **FCrDNS verified-crawler** — `verifiedGoodBot(ptr, ip)` +
  `goodBotPTRSuffixes` (`abuse_shadow.go:222-258`): forward-confirmed reverse DNS
  over the `internal/enrich` PTR subsystem. Registry today: **googlebot, google,
  bingbot, yahoo, applebot, yandex, meta (`.fbsv.net`)**. A spoofed PTR fails
  forward-confirm → earns nothing. Used in exactly TWO places: abuse_shadow
  (`ABUSE_SHADOW_GOODBOT_EXEMPT`, default on) and the subnet-challenge exemption
  (`subnetVerifiedGoodBot`, `CHALLENGE_SUBNET_GOODBOT_EXEMPT`, default on,
  30-min posTTL cache, DNS-budgeted per tick).
- **Datacenter-ASN classifier** — `DatacenterClass(asn, name)` / `IsDatacenter`
  (`asnclass.go`): curated `knownCloudASNs` (AWS/GCP/Azure/DO/Hetzner/OVH/M247/
  Datacamp/Leaseweb/…) + strong org-keyword fallback. Header documents the exact
  guardrail we adopted: **datacenter ≠ malicious, additive-only, good-bot
  exemption runs first, ASN flag alone is never a trigger.**

**Consequence / the gap:** the good-bot exemption guards only the SUBNET signal,
NOT the vhost suspicious score. That is why techking/shopzy (verified
Google/Meta) are still **vhost-challenged** (score 0.81/0.74 from
`bot%`+`err`+`path_div`). So "verified-crawler first" is **wiring an existing
verifier into the vhost/decision path** — small — not building rDNS from scratch.
Likewise `datacenter-ASN-frac` reuses `DatacenterClass`; only
**query-cardinality/URL-repeat/cost** is genuinely new substrate.

### Throttle is already a solved primitive (matters for Class 2)

- **Action + edge enforcement exist:** `rule_action="throttle"` +
  `throttle_profile` (traffic-rules plane) → `cfm.lua:1465` → `cfm_rules` →
  `X-CFM-Action: throttle` + `Retry-After` + `ngx.exit(429)`.
- **Edge-local lock-free counters exist and ship:** `cfm_rules throttle_hit`
  (key `tr|profile|host|window|ip`), WAF `auth|cnt|…` / `xmlrpc|cnt|…` bursts,
  `cfm_ua_emergency` — all `SH:incr` fixed-window in `cfm_decisions` (64m) /
  `cfm_ua_throttle` (4m), no daemon round-trip.
- **Missing for surface-throttle:** (a) a **URI/endpoint-pattern dimension** in
  the counter key (every counter is keyed on IP/UA + host + a *hardcoded* tag);
  (b) an operator **config surface** for `(vhost, path-pattern) → rate`; (c) an
  **IP-independent aggregate** cap (≤N/s to an endpoint class across all IPs —
  the exact weapon for a 544k-IP flood).

### PoW hardening is daemon-only

The edge never sees or passes a difficulty value; PoW generation/verification is
purely daemon-side (`127.0.0.1:9098`). `PowConfig{Difficulty}` exists but is
unwired (hardcoded 16). So a per-vhost/under-attack "harden PoW" rung is a clean
**daemon-only** change — no edge work.

### One subtlety: clearance short-circuits the decision

`cfm.lua` Step 2b: when the clearance cookie is valid AND the WAF passed, the
`/nginx/decision` RPC is **skipped entirely**. So a client that *solved* the
challenge is waved through for the cookie lifetime (~45m). The only signal that
catches a solver post-clearance is **cookie_discard** (re-solve). Implication:
for the solver-farm / headless-solver class, the per-client score must act
through a path that survives valid clearance (shorten/condition clearance, or
re-challenge on re-solve), not the normal decision RPC.

---

## Design (draft — pending Phase-0 weights)

### Two-tier scoreboard + a verified-crawler fork

```
                    ┌───────────── verified crawler? (rDNS/ASN) ─────────────┐
                    │ yes → CRAWLER lane                    no → CLIENT lane  │
   per-request ──►  │ crawl-budget / rate on expensive     per-client score  │
   signals          │ surface; never deny                  (ipState)         │
                    └───────────────────────────────────────────────────────┘
   per-vhost signals ──►  per-vhost posture (vhState + under_attack state)
                          modulates the client-lane thresholds & actions
```

### Signal → subject → contributes-to

| Signal | Subject | Per-vhost score | Per-client score |
|---|---|---|---|
| err%, path/UA div, uniqIP, post%, bot%, rps | vhost | ✔ (existing) | — |
| **query-cardinality / URL-repeat / cost** (NEW) | (vhost, base-path) | ✔ | — |
| **datacenter-ASN frac** (NEW, gated by verified-crawler) | vhost + IP | ✔ | ✔ |
| solver_farm subnet-spread | vhost / /24 | ✔ (mark→weight) | ✔ (/24 rollup) |
| cookie_discard re-solve | IP | ✔ (aggregate rate) | ✔ |
| abuse_shadow rate-outlier | (vhost, IP) | ✔ (outlier count) | ✔ |
| BAD_UA score, solve-latency, **header-coherence** (NEW) | IP/request | — | ✔ |

Same event often feeds both tiers at different aggregation (e.g. cookie_discard:
this IP re-solves → client; aggregate re-solve rate → "challenge defeated here"
→ vhost).

### Self-baseline, not iForest

- Subject for anomaly = **(vhost, window)**, never per-IP: the Class-2 attack is
  *distributional* (no individual IP is an outlier), so point-anomaly detectors
  (iForest/HBOS over IPs) structurally miss it.
- Method: **robust per-feature deviation** (median/MAD → robust-z vs the vhost's
  own decayed baseline) summed into an anomaly score. Explainable per feature
  (the reason string writes itself), cheap, online, decays. The
  fingerprinter's `fpBaseline` (30m half-life) is the substrate.
- Graduate to **HBOS/eHBOS** only if a feature proves multimodal. **iForest:
  no** (opaque, needs rebuild, no graceful online decay).
- **Feature engineering ≫ model choice.** The verified-crawler fork +
  query-cost + datacenter-frac matter far more than the algorithm.

### Decision matrix (vhost posture × client score → action)

| vhost ↓ / client → | low | mid | **under_attack** |
|---|---|---|---|
| normal | — | alert | vhost-wide challenge |
| suspicious | alert | targeted challenge | **deny 403** (client) |
| high | targeted challenge | deny 403 | deny + nft |
| *Class-2 flood (client-anonymous)* | — | **surface-throttle** | **surface-throttle + gate before origin** |

Action → subject rules: **deny = client only** (deny a whole vhost = outage);
**under_attack = vhost state only**; **surface-throttle = (vhost, endpoint-class)**,
the only lever for the client-anonymous flood; **alert = anywhere**. Crawler lane
never reaches deny — only rate/budget.

### Guardrails carried from the audit

- **Never** key an adverse decision on country/ASN alone (house rule).
  datacenter-frac is a corroborating FEATURE, always gated by verified-crawler.
- **logonly → challenge → block/deny** promotion, never straight to deny.
- **Shadow first** (like abuse_shadow / fingerprint): measure would-act vs
  baseline before any enforcement. Adding signals recalibrates the existing
  `raw/6, ON 0.70` score — shadow protects current arm behaviour.
- **De-correlate contributors:** cookie_discard / abuse_shadow / solve-latency
  partly measure the same "rate/re-solve" — group them under one capped weight,
  don't triple-count. Don't feed the *consequence* of our own challenge
  (challenge → re-solve) back into the score.

---

## Plan (measure-first, mechanism-agnostic)

### Phase 0 — audit + zero-code (operator config; in progress)

Decisions locked (2026-08-25): **Meta → rate-limit** (Phase 2 surface-throttle;
until then leave it challenge-exempt, never hard-challenge — challenging a
crawler is pointless/harmful). **AI crawlers (GPTBot/ClaudeBot/bytespider/
tiktokspider) → free for a start** (no special handling). Google/Bing → keep,
crawl-budget on expensive surfaces later. **verified-crawler is the first CODE
task** (Phase 1 lead).

Zero-code = live `/etc/cfm/detectors.conf` on the 7 web nodes (operator-applied;
MCP is read-only). Verified live state on titan via `config_drift`:
`solver_farm` is **already** operator-tuned to `MIN_SUBNETS=30 / MIN_SOLVES=30`,
`ACTION=logonly` (leave it — harmless at logonly; still targets the many-subnet
flood). The `UNDER_ATTACK_FINGERPRINT` / `FP_*` keys are **missing** live, and
the code defaults are `UNDER_ATTACK=false`, `ABUSE_SHADOW*=false` — so the
shadow surfaces are OFF and must be set explicitly. Target block for **data
collection** (all detect/log-only, no enforcement):

```ini
[webdetector]
UNDER_ATTACK               = 1   ; master (default OFF) — needed for the fingerprinter; detect-only, ships DRYRUN=1
UNDER_ATTACK_DRYRUN        = 1   ; keep dry (no enforcement) during burn-in
UNDER_ATTACK_FINGERPRINT   = 1   ; missing live → add (shadow "would-arm" lines)
ABUSE_SHADOW               = 1   ; default OFF — turn the shadow log ON
ABUSE_SHADOW_RATE_OUTLIER  = 1   ; per-IP rate outlier vs vhost median
ABUSE_SHADOW_DATACENTER    = 1   ; log the DatacenterClass tag (additive)
; ABUSE_SHADOW_GOODBOT_EXEMPT / CHALLENGE_SUBNET_GOODBOT_EXEMPT default ON — no action
```

Reload after editing; verify with `config_drift` / the Detectors page. Then let
it accumulate `cfm.abuse_shadow.log` + fingerprint would-arm lines through a real
Class-2 burst.

- [x] Fleet audit → three-class model + separation table (this doc).
- [x] Confirm verified-crawler + datacenter substrate exists (reuse path found).
- [ ] Operator: apply the shadow config block above on the 7 web nodes.
- [ ] Capture query-cardinality/repeat live during the next Class-2 burst
      (`edge_access_tail`) to fix that weight.

### Phase 1 — converge into the two scores, SHADOW-only
- [x] **DONE — wire `verifiedGoodBot` into the challenge decision.** Branch
      `claude/verified-crawler-vhost-exempt`: a per-IP good-bot exemption at
      `handleDecision` downgrades a would-be challenge (per-IP OR vhost-wide) to
      allow for an FCrDNS-verified crawler (Google/Bing/Meta/Apple/Yandex),
      reusing the existing verifier. Cache-only on the hot path (lazy PTR + async
      forward-confirm), fail-closed, never softens a `block`. Fixes the live
      Googlebot `CHALLENGE_ERR_RATIO` FP and stops hard-challenging Meta on
      techking/shopzy. Knob `CHALLENGE_GOODBOT_EXEMPT` (default on, like the
      subnet exemption — provably safe, so not gated behind shadow). Adversarial
      review folded in (RWMutex fast path, single-sourced matcher, log-once).
- [x] **DONE (query-cardinality half) — abuse_shadow facet signal (Signal F).**
      Branch `claude/webdet-query-cardinality-shadow`: per-vhost distinct-full-URL
      count (`bucket.fullURIs`, a capped hash-set filled only when enabled, static
      assets excluded) vs distinct base paths, flagged when
      `distinct_URLs ≥ MIN_URLS(300)` AND `distinct_URLs/distinct_paths ≥
      MIN_EXPANSION(20)` — exactly the `path_diversity` blind spot (§ "805,746
      distinct query strings → path_diversity 0.058"). Log-only: a per-vhost
      `query_cardinality` badge (webtop/suspicious/challenge rows, `facet` pill in
      cfm-admin, `facet=N` in `cfm webtop challenge`) + a `signal=facet_expansion`
      line in `cfm.abuse_shadow.log`. Own mark store + TTL, mirroring the
      rate-outlier mark. Default-ON under `ABUSE_SHADOW` (no per-node edit to start
      collecting); knobs `ABUSE_SHADOW_FACET[_MIN_URLS|_MIN_EXPANSION|_CAP]`. NO
      score contribution, NO enforcement. `URL-repeat-ratio` is logged as
      corroboration on the same line but not yet a gate. Numerator, denominator
      and total share ONE universe (dynamic, static-excluded) so the ratio is
      comparable across vhosts — the fix from the adversarial review, which had
      flagged `distinctPaths` (from `b.paths`, static-inclusive) as diluting the
      per-vhost threshold. **Expected burn-in noise:** the signal deliberately
      also badges *legit* single-endpoint high-cardinality shapes — analytics
      pixels (`/collect?v=UUID`), plain-permalink WordPress (`/?p=N`), calendars
      (`/cal?date=…`) — because they are the exact facet shape at the metric level.
      That is why it is log-only: the `facet` badge means "high query cardinality
      here", not "malicious". Multi-path catalogues (a news site's 4000 distinct
      article paths) correctly stay clear (ratio ≈ 1). The would-be discriminator
      for the malicious case is the enforcement-time context (verified-crawler
      fork, cost/5xx, repeat ≈ 1), added later — never the badge alone.
- [x] **DONE (cost/5xx half) — abuse_shadow cost-pressure signal (Signal G).**
      Branch `claude/webdet-cost-pressure-shadow`: per-vhost 5xx-pressure, flagged
      when `5xx/total ≥ MIN_FRAC(0.15)` AND `reqs ≥ MIN_REQ(50)` AND
      `5xx_rps ≥ MIN_RPS5XX(1.0)` — the *symptom* of the flood (origin collapse),
      complementing facet's *cause*. Reuses the per-bucket 5xx counters (no ingest
      cost). Log-only: a `cost_pressure` badge (5xx percent — `cost N%` pill /
      `cost=N%` CLI flag) + a `signal=cost_pressure` line (with avg RT as a second,
      non-gating cost dimension) in `cfm.abuse_shadow.log`. Own mark store + TTL.
      Default-ON under `ABUSE_SHADOW`; knobs `ABUSE_SHADOW_COST[_MIN_FRAC|_MIN_REQ|
      _MIN_RPS5XX]`. NO score contribution, NO enforcement. **Known tuning caveat**
      (adversarial review): `5xx/total` is over the whole response mix (static/
      cached 200s included, per the engine's `ErrRatio` convention), so a
      cache-heavy vhost shows a diluted fraction — a full origin collapse behind
      mostly-cached traffic can sit under `MIN_FRAC`. Safe direction (false-negative,
      never false-positive); the `RPS5XX` floor is the partial backstop. **Before
      this graduates to any enforcement**, switch to a dynamic-only 5xx denominator
      (needs a per-bucket dynamic counter, like facet's `facetTotal`).
- [x] **DONE — abuse_shadow datacenter-fraction signal (Signal H, verified-gated).**
      Branch `claude/webdet-dcfrac-shadow`: per-vhost fraction of requests from
      datacenter/cloud ASNs that are NOT FCrDNS-verified good bots, flagged when
      `dc_reqs/total ≥ MIN_FRAC(0.5)` over `≥ MIN_IPS(5)` distinct datacenter IPs
      and `≥ MIN_REQ(50)` requests. Verified crawlers excluded via FCrDNS (else a
      crawled shop reads ~100% datacenter — the techking/shopzy trap). **Origin is
      never innocence**: datacenter-ASN alone drives NO decision — corroborating
      feature only. Cost-bounded (CLAUDE.md §6): cheap mmdb ASN class for all IPs,
      capped FCrDNS only for datacenter+good-bot-PTR candidates, per-tick IP budget
      with a logged deferral (no silent cap); every budget edge errs toward not
      flagging. Log-only: `dc_fraction` badge (`dc N%` pill / `dc=N%` CLI) +
      `signal=dc_fraction` line. Own mark store + TTL. Default-ON under
      `ABUSE_SHADOW`; knobs `ABUSE_SHADOW_DCFRAC[_MIN_FRAC|_MIN_REQ|_MIN_IPS]`. NO
      score contribution, NO enforcement.
- [ ] Add missing per-client features: header-coherence, solve-latency; route
      cookie_discard / solver_farm / abuse_shadow as contributors into
      `IPSignals.Score` / `SuspiciousRow.Score` (they stop being independent
      actuators; alerts stay during burn-in).
- [ ] Self-baseline (robust-z) on the vhost feature vector.
- [ ] Emit `verdict=would_*` shadow lines; compare vs baseline.

### Phase 2 — actuation ladder (under_attack I3)
- [ ] **Surface-throttle**: add a URI-pattern-keyed counter (mirror
      `cfm_rules`/`cfm_ua_emergency` `SH:incr`) + config `(vhost,endpoint)→rate`
      + an IP-independent aggregate cap. Emit from vhost posture — needs a new
      `vhost_action`/field in the decision map + `cfm.lua` branch (mirror the
      proven `rule_action=throttle` path).
- [ ] **Gate expensive surface before origin** when a vhost is under_attack:
      un-cleared clients hitting the endpoint class get challenge/403 at the
      edge, protecting PHP.
- [ ] **Harden-PoW rung** (daemon-only): wire `PowConfig.Difficulty` per-vhost /
      under-attack; scale challenge expiry with difficulty (mobile cost).
- [ ] **Crawler lane**: verified crawlers get rate/crawl-budget on expensive
      surfaces, never deny.

---

## Open questions (to resolve before Phase 2 code)

1. **Deny shape**: clean `403` vs tarpit (delayed-empty, steals attacker
   concurrency, hides detection)? Leaning `403` for residential-proxy FP mercy.
2. **Client subject**: pure IP vs `(IP, vhost)` vs `/24` rollup? Data says IP
   for residential floods, `/24` for solver farms — support both, IP-primary
   with a `/24` density feature.
3. **Burn-in log**: new `[cfm_challenge_score]` shadow log (like abuse_shadow),
   or fold into the existing shadow surfaces?
4. **Dual signals**: keep cookie_discard / solver_farm / abuse_shadow alerts
   during burn-in, retire once the score leads?
5. **Crawler lane policy**: is aggressive Meta/AI crawl "abuse" for these
   tenants (rate it) or desired (leave it)? This is a per-operator policy knob,
   not a security default.
