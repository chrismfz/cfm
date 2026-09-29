# Traffic classifier — living design notes

> **▶ PLAN OF RECORD: `docs/abuse-defense-master-plan.md`** (2026-09-18). The
> phase/plan checklists embedded below ("Plan (measure-first)", Phase 0–2) are
> **FROZEN** — kept as design context, no longer the to-do list. What happens
> next lives only in the master plan (§5 — E4's measurement, then its ordered
> candidates; the frozen and dropped lists after the 2026-09-29 operator
> review — and the standing decisions D1–D5).
>
> **⭐ SINGLE SOURCE OF TRUTH (node side).** Canonical node-side entry point for
> the Traffic Classifier / Fingerprint Reputation work: the fingerprint evidence
> ledger (node grains: `solver_farm`, `challenge_score`, WAF-hit fp attribution),
> the actuator ladder, and the **ChallengeV2 rung**. The central store + policy
> live in **cfm-web (`cfm-web:docs/fingerprint-reputation.md`)**. Per-IP score
> deep-dive: `docs/challenge-score.md`. The SIGNALS here are **shadow** — the
> node emits evidence only, and no signal keys enforcement on a fingerprint
> AUTOMATICALLY. Since 2026-09-19 (master plan E3 node slice) the one
> enforcement path is the OPERATOR-armed per-fingerprint policy pulled from
> cfm-web (`internal/webdetector/fppolicy.go` + `configs/lua/cfm_fppolicy.lua`).
> Superseded design notes folded into this hub: `docs/archive/solver-farm-cross-host-phase2.md`,
> `docs/archive/solver-farm-fingerprint-concentration.md`, `docs/archive/fleet-fingerprint-reputation.md`.

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
  (the reason string writes itself), cheap, online, decays. **CORRECTION
  (2026-08-27, see "Two tracks → one ladder" below):** `fpBaseline` is a
  categorical path/UA histogram, NOT a median/MAD substrate — robust-z is net-new
  and reuses only `fpState`'s *pattern* (per-vhost keying + 30 m decay + prune),
  not its data.
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

## Two tracks → one ladder (2026-08-27 reconciliation)

The convergence has **two independent tracks** that feed **one shared actuation
ladder**. They answer different problems and live in different layers; keeping
them separate (but pointed at the same actuators) is the plan of record.

| | **Track 1 — vhost anomaly fusion** | **Track 2 — per-client challenge-abuse score** |
|---|---|---|
| Problem | Class-2 **distributed flood** (facet/cost/dc) | **headless solver-farm** — "the challenge was defeated" |
| Layer | **Go**, log-driven, per-vhost | **edge-Lua (hybrid: daemon-seeded)**, per-IP |
| Why separate | the engine *sees* the flood | the engine is **blind post-clearance** (`/nginx/decision` skipped for cleared clients, § above) → those tells are edge-only |
| Feeds | `SuspiciousRow.Score` (shadow-parallel) | a per-IP score with the T1/T2/≥99 ladder |
| Design doc | this file | **`docs/challenge-score.md`** |

**Shared Stage E (actuation ladder / deny-shape) — the LAST decision**, after the
scores say *who*: soft rung = **harden PoW** (16→20 + expiry scaling) *or* a
**harder interactive challenge (ChallengeV2 drag/puzzle**, which beats headless
better than PoW — PoW is pure CPU a farm solves trivially); hard rung = **403 /
tarpit / nft drop** (Open Question #1, leaning 403 for residential mercy); vhost
lane = surface-throttle / gate-before-origin / crawler-rate. Manual challenge
stays an operator tool throughout. *(Status 2026-09-29, master plan §5: the
harden rung is frozen behind a faster in-page solver; the drag/puzzle and the
crawler-rate lane are dropped; surface-throttle / gate-before-origin are
frozen until a Class-2 flood; the deny shape is E3's `403`.)*

### Track-1 shadow fusion — the concrete build (grounded 2026-08-27)

Shadow-only: a **parallel** fused score, never mutating the live arm.
`fused = clamp01(base_score + Δ)`, where `Δ` is a capped, de-correlated sum of
weighted **robust-z** deviations of facet/cost/dc against each vhost's own decayed
baseline. Emit `signal=fused_score … verdict=would_arm|would_relax` when `fused`
crosses the arm line but `base` did not (net-new catch) or vice-versa (FP-relax
candidate). `facet` contributes **only** when `paths ≥ 2` **and** corroborated
(the `planetgym.gr` 402-URLs-on-1-path benign-single-endpoint guard), `dc` stays
verified-crawler-gated, and cost/dc/facet/shadow share **one capped group weight**
(don't triple-count the same rate/cost shape). Reads the shadow magnitudes at
score time via the package accessors (`FacetShadowCardinality(host)` etc.),
emitting from a new `emitAbuseShadowFusedScore(now)` in the existing per-tick
`if e.cfg.AbuseShadow` block (`challenge_rules.go`, after the dc-frac emitter).

### Three corrections the code forced (supersede earlier prose in this doc)

1. **`fpBaseline` is NOT a robust-z / median-MAD substrate** — it is an
   EWMA-decayed **categorical path/UA histogram** for the fingerprinter
   (`under_attack_fingerprint.go`). No median/MAD/robust-z code exists in the repo.
   The robust-z substrate and the per-vhost per-feature scalar baseline are
   **net-new** (a new sibling store modeled on `fpState`'s *pattern* — per-vhost
   keying, 30 m half-life decay, cap/prune, copy-under-lock — not an extension of
   `fpBaseline`). This corrects the "Self-baseline" note above.
2. **Arm thresholds are 0.70 arm / 0.60 disarm (hysteresis)** — not "0.72".
   `ChallengeSuspiciousScoreOn = 0.70`, `…ScoreOff = 0.60`
   (`webdetector_config.go`); a per-node config may override on_threshold.
3. **The `/6.0` divisor is a bare constant** (`scoring.go`), unrelated to the sum
   of weights — so adding *any* positive term into `Score()` silently rescales
   **every** vhost across the 0.70 line. ⟹ the fused term MUST be a separate
   parallel computation expressed as a normalized score-delta, **never** an added
   term inside `heuristicScorer.Score`. (This is exactly the "shadow protects the
   existing raw/6, ON 0.70 arm" guardrail — now with the mechanism named.)

> The Phase-1 checklist item below — "add per-client features … route
> cookie_discard / solver_farm / abuse_shadow into `IPSignals.Score`" — is **Track
> 2**, and belongs in `docs/challenge-score.md` (edge-Lua hybrid), NOT a direct
> `IPSignals.Score` edit, precisely because of the post-clearance blindness above.

## Third grain — fingerprint reputation, fingerprint-anchored (2026-09-11)

The two tracks above are per-vhost (Track 1) and per-IP (Track 2). A **third
grain** now exists: the **per-fingerprint reputation store** — cfm-web's
`fingerprints`, fed by the node `solver_farm` finding and now carrying each
fingerprint's own captured client IPs, enriched and classified
(`cfm-web:docs/fingerprint-reputation.md`; node capture/scope in
`internal/detectors/solverfarm/`). The **B3 three-grain seed fuses all three,
anchored on the fingerprint grain** — the decision below (fingerprint = the
strongest, most reliable "guilty").

### Why fingerprint-anchored (grounded — 2026-09-11 fleet read)

A live read of titan/mars/earth/orion/rigel/virgo:

- **Fingerprint grain is the hottest, highest-confidence signal.** On titan,
  near-every `challenge_solved` carries `tls_fp=c28caa00`, solving continuously
  across ≥4 vhosts from a wide rotating pool (dozens of countries; ASNs mixing
  residential Etisalat/VNPT/Vodafone AND datacenter Datacamp/Leaseweb/HUAWEI),
  **1 solve per IP**, fresh UA each. Store: `c28caa00` at 191 IPs / 48 countries
  (verdict *farm*). A convicted farm fingerprint is the strongest guilt the fleet
  produces.
- **Grain A (Track-1 `abuse_shadow`) is populated, `rate_outlier`-dominant**
  (titan 71, mars 58, earth 36; `dc_fraction` secondary; facet/cost tiny).
- **Grain B (Track-2 `challenge_score`/`cookie_discard`) is THIN** —
  `challenge_score`/`fused_score` barely surface (orion 2/1). The live per-IP tell
  is the challenge *lifecycle* (issued → `expired_unsolved`, the non-solving
  scanner), not the score.

**The decisive insight: a solver farm SOLVES the PoW** (`c28caa00` at diff=16,
300 ms–56 s). Challenging a fingerprint that *solves* is futile. So the fingerprint
grain does not route to "harden PoW"; it routes to the **hard rung** — and the
right hard action depends on two orthogonal axes that must not be conflated.

### Two axes, two actions (this is the correction that shapes B3)

Blocking is TWO different actuators with TWO different collateral models. Keep
them separate:

1. **Persistent IP-ban (nft, the shipped Phase-2 fleet block).** Collateral =
   **ISP reassignment**: a residential IP is a DHCP lease, so a week-long ban
   outlives the abuser's tenancy and later lands on whoever the ISP hands that
   address to — collateral that is real *even when today's occupant is a
   compromised botnet/IoT node* (the malware is cleaned or the lease rotates, the
   ban remains). Datacenter IPs don't churn like that and are usually
   single-tenant VMs (the whole IP *is* the abuser). ⟹ **the datacenter-vs-
   residential gate belongs to THIS action only**: bulk-ban datacenter members,
   never bulk-ban residential ones.
2. **Fingerprint DENY (403) at the edge (Phase-C `X-CFM-TLS` match).** Self-
   targeting *in time* — it acts per request, not as a standing ban — so it has
   **no reassignment collateral**: when a residential IP is later reassigned to an
   innocent customer, they present *their own* browser's fingerprint, never the
   farm's, and are untouched; a compromised device is denied exactly while it
   speaks the farm's fingerprint. It is also **per-device surgical on a shared
   IP**: other devices behind the same router/CGNAT present their own fingerprints
   and are never seen by the rule (an IP-ban takes the whole household down;
   fingerprint-deny does not). ⟹ residential-vs-datacenter is **NOT** the gate for
   this action.

**The real gate for fingerprint-DENY is how SHARED the fingerprint is**, because a
TLS fp is a *bucket*, not an identity (GREASE-normalised — see §7 "coarseness" in
the cfm-web doc). `c28caa00` is a coarse Chrome bucket that legit shoppers also
collapse onto, so a blanket 403 on it hits innocents — collateral from the same
*browser build*, not the same IP (the only case where a different device on the
farm's IP is NOT fine is when it runs that exact build). So:

- **Fingerprint unique-enough to the farm** (seen only in farm-shaped traffic,
  ideally corroborated by **JA4H** as a second axis — *dropped 2026-09-29
  with the edge module*) → **deny (403) outright**, residential or datacenter.
  It is the guilty unit.
- **Shared browser bucket** (`c28caa00`) → do NOT blanket-deny. Use a **harder
  *interactive* challenge** (ChallengeV2 drag/puzzle — beats the headless farm the
  PoW couldn't, and self-targets legit shared-bucket users), and/or narrow the
  deny to `(fp × JA4H)` or `(fp × farm-context)`, and/or IP-ban only the
  *datacenter* members while harder-challenging the rest. *(As built: the
  harder challenge is the passive ChallengeV2 Rung 1; the drag/puzzle and
  `(fp × JA4H)` were dropped 2026-09-29.)*

### The fingerprint-anchored seed

- **Spine — fingerprint conviction → its member IPs + the fingerprint itself.** A
  `farm`/`suspect` fingerprint maps its conviction onto each captured address's
  per-client score, pre-weighted by `kind` for the IP-ban sub-action (datacenter
  → ban-eligible; residential/unknown → not banned) AND onto the fingerprint-DENY
  path per the uniqueness gate above. Dominant term.
- **Mid — grain A (`rate_outlier` + `dc_fraction`, goodbot-exempt)** — the built
  Track-1 fused score, corroborates per-vhost.
- **Soft — grain B (`challenge_score`/`cookie_discard`, `challenge_expired_unsolved`)
  + Sec-Fetch/WAF** — low weight (thin in the data); corroboration only, can raise
  an IP alone only at higher combined weight.
- **Fusion rule:** fingerprint-implicated clients start high; grains A/B add
  capped, de-correlated deltas (same discipline as Track-1's fused score — never
  triple-count one rate shape). **Shadow-first** (`would_*` lines), tuned against
  the live magnitudes (rate_outlier carries weight; challenge_score cannot alone).

### B3 open items

*(B3 was dropped 2026-09-29, superseded by E3 — master plan §5. The items
below are kept as design context.)*

- The fingerprint→IP mapping is only as complete as the captured sample (bounded,
  accumulates), so a farm's long residential tail is never fully enumerated — the
  seed must **degrade gracefully**: fingerprint-DENY/interactive-challenge for
  un-captured IPs sharing the fp, IP-ban for captured *datacenter* members.
- **JA4H as the uniqueness corroborator** is what makes "deny the bucket" safe —
  prioritise it for any fingerprint-DENY of a coarse TLS bucket. *(Dropped
  2026-09-29 with the JA4/JA4H edge module, master plan §5; D2's
  farm-unique bar stands without it.)*
- Thickening the spine with more conviction sources (WAF-block, abuse_shadow →
  fingerprint) needs the **attribution prerequisite**: the 2026-09-11 read caught a
  WAF scanner (Google Cloud, `WAF_TRAVERSAL`/`WAF_SQLI`/`WAF_PHP_WRAPPER` across
  spoofed bot UAs) whose `waf_*` events carry **no `tls_fp`** — carrying the
  edge-stamped `X-CFM-TLS` onto WAF findings is the first task there. See
  `cfm-web:docs/fingerprint-reputation.md §10`. *(Done: WAF hits carry the
  handshake-derived `cfm_tlsfp`, master plan §3 row 2.)*

## Fingerprint evidence ledger — node → UI + cfm-web (2026-09-11)

*(Status 2026-09-29: the node-side per-fingerprint rollup and its
cfm-admin/TUI view below were never built and are dropped — cfm-web's central
ledger does this job; master plan §5.)*

The signals today are scattered: `abuse_shadow` per vhost, `challenge_score` /
`cookie_discard` per IP, `solver_farm` per fingerprint, WAF hits per request — on
the node, over MCP, and in the cfm-admin UI, and only `solver_farm` reaches
cfm-web. To decide "guilty" you cross-reference all of them by hand. Make the
**fingerprint the correlation key** and fold every *per-client* signal into one
per-fingerprint **evidence ledger**, surfaced locally and published to cfm-web.

**The distinction that makes this work — not every signal keys on a fingerprint:**

- **Per-CLIENT signals** (are evidence *of* a fingerprint — things one client
  does): `solver_farm` (fp), the `challenge_score` tells (UA-lie, fast-solve, and
  the fp-conviction spine), `cookie_discard` (re-solve cadence), WAF-block hits
  (once `tls_fp` is stamped on them — the attribution prereq above), challenge
  FAIL / `expired_unsolved`.
- **Per-VHOST signals** (are *context*, not client evidence): `dc_fraction`,
  `facet_expansion`, `cost_pressure`, the `suspicious` score, vhost-aggregate rate.
  `dc_fraction` = "this **site's** traffic is 86% datacenter" — it can't be pinned
  on one fingerprint; it is the *environment* the fingerprint was seen in. These
  attach to the ledger as "the vhosts this fp touched, and their posture" (already
  what `fingerprint_events.host` + the finding carry), never as fp evidence.

**The ledger is a rollup on a store that already exists.** The node's webdetector
already runs a **sqlite `detection_history`** (where `solver_farm` is persisted).
The ledger is a per-fingerprint rollup on top of it: `fingerprint → {farm?,
challenge_score, cookie_discard, waf_hits, verdict}, vhosts[], ips[], counts,
first/last seen`. That single row is the whole guilt picture (*"farm=yes,
challenge_score=high, cookie_discard=8, WAF_SQLI×30, 12 vhosts, 191 IPs (48 dc /
143 residential)"*) — the multi-source corroboration of
`cfm-web:docs/fingerprint-reputation.md §10`, made visible.

```
node per-client signals ─► node sqlite fingerprint ledger ─┬─► cfm-admin UI / TUI: "weird" fingerprints + their evidence,
   (solver_farm, chal_score,   (rollup on the existing      │      clickable to investigate (next to the signals)
    cookie_discard, WAF, …)      detection_history sqlite;   └─► cfm-web: PULL the per-fp SUMMARY (not raw events),
                                 survives restart)                  fleet-wide decide (same cursor pattern as solver_farm)
```

Three properties fall out: it **survives a daemon restart** (today marks/scores
are ephemeral in-memory); it is the **UI/TUI surface** for "which fingerprints are
weird, and why"; and it is the **compact thing cfm-web pulls** — a per-fingerprint
*summary*, because `solver_farm` is rare but `challenge_score` / `cookie_discard` /
WAF fire constantly (you aggregate on the node and publish the rollup; you never
stream the raw firehose to cfm-web). Same PULL-cursor mechanism as `solver_farm`,
just a richer payload with more `source`s.

**Caveat (unchanged):** the ledger makes guilt easier to SEE and DECIDE; it does
not change the ENFORCEMENT safety rules. A fingerprint is still a population, so
the uniqueness gate (§ "Two axes, two actions") still governs whether a verdict
becomes bare-deny, ChallengeV2, or an IP-ban.

## The ChallengeV2 rung — the keystone that lets Deny mean "100% guilty"

Every wall this design keeps hitting is the same one: **Challenge (PoW) is SOLVED
by the farm** (the live data: `c28caa00` at diff 16, 300 ms–56 s), and **Deny is
dangerous for a coarse bucket** (a shared Chrome TLS id hits legit shoppers). That
leaves a gap with no good action for the large "probably guilty but shared/unsure"
middle. **ChallengeV2 — an *interactive* challenge (genuine pointer/touch/scroll +
render, optionally a puzzle) — is that missing middle rung.** Already named as the
intended soft rung here (Stage E) and in `docs/challenge-score.md` §6; promote it
to a first-class, **armable action**.

It is both:
- **self-targeting** (like a challenge) — a real human sharing the fingerprint does
  the interaction once and passes; and
- **effective against headless** (unlike PoW) — a headless solver has no real
  pointer/render, so it fails the exact thing PoW (pure CPU) can never catch.

What it buys:
1. **Closes the coarse-bucket gap** — for an uncertain shared bucket, arm
   ChallengeV2 *instead of* deny: legit users pass, the farm fails, **zero outage
   risk**. Removes the scariest part of Phase C.
2. **Pushes Deny to the edge of the ladder** — Deny then arms only on **100%
   guilty**: a farm-UNIQUE fingerprint, or a confirmed datacenter IP. Everything
   uncertain-but-suspect routes to ChallengeV2; Deny stops being the tool for
   uncertainty.
3. **Breaks the farm's economics** — real interaction/render per client costs far
   more than the free CPU of PoW.

```
observe → Challenge (PoW) → ChallengeV2 (interactive) → Deny
  log      cheap, 1st line     the teeth vs headless      last resort,
           (the farm solves it)  self-targeting, safe       100%-guilty only
```

**Arming surfaces** (same model as Challenge today): per-vhost **auto-arm** on an
"unsure" posture (a stronger tier than the current auto-challenge) or operator
**force**; per-fingerprint **`challenge_v2`** policy action in cfm-web
(`fingerprint_policies` gains it alongside observe/challenge/deny); per-IP at the
`challenge_score` T1 rung *(dropped 2026-09-29, master plan §5)*.

**The honest hard part is the front-end, not the logic** — and it must be staged:
- **V2a — invisible interaction proof** (first): require genuine pointer/touch/
  scroll entropy + render/timing before clearance. A headless client emitting no
  pointer events fails silently; a real user never notices. Cheap, **accessible**,
  and it catches *today's* farm.
- **V2b — visible puzzle** (only if V2a is beaten): a rendered drag/rotate puzzle
  **with an accessible fallback** (keyboard/screen-reader — a pure drag-puzzle
  locks out disabled users: wrong, and a legal risk). Reserved for the hardest tier.
  *(Dropped 2026-09-29, master plan §5: CAPTCHA farms solve puzzles cheaply,
  and the real-browser farms it would target are `cfm_pcw`'s job. What stays a
  candidate is the Rung-2 CONFIRM fallback for a Rung-1 reject.)*

Self-hosted (CFM's ethos — no third-party CAPTCHA), edge-local like the PoW
challenge (the cleared path skips the daemon decision), so it goes through
`docs/challenge-waf-release-checklist.md`. Sequence it **after** the evidence
ledger (which says *who* to arm it on) and the B3 burn-in.

### Decision record (2026-09-12) — v2 is a RUNG, not a second on/off axis; Rung-1 (passive) ships first

Settles the recurring "how do we not create a config panic" question (operator,
2026-09-12). The worry: if `challenge_v2` becomes a *parallel armable action*
(off/auto/exclude per vhost AND per fingerprint, next to v1), the state space
explodes — "v1 off but v2 on?", "auto-challenge → v1 or v2?", "who arms which?".

**Decision.** There is ONE challenge control (off / auto / force + excludes), per
vhost and per fingerprint — unchanged. The *difficulty* (invisible PoW → passive
check → interactive) is a **rung the engine climbs from the request's
score/evidence at serve time**, NOT a second operator knob. Therefore:

- `challenge` off → nothing is served; there is no separate v2 to be "on". The
  "v1 off / v2 on" state **cannot exist by construction**.
- A vhost on auto-challenge (or a fingerprint armed to challenge) serves *the*
  challenge; the engine picks the rung. There is no fork to configure.
- `fingerprint_policies.action = challenge_v2` (the "armable action" named above)
  means **"this fingerprint's challenge starts no lower than the v2 rung"** — a
  *floor* on the single control, not an independent second control. Disarm the
  fingerprint's challenge and nothing is served.

This **refines** the "first-class armable action alongside observe/challenge/deny"
wording earlier in this section: `challenge_v2` is a rung-floor selector, not a
parallel axis.

**Rung-1 (passive) ships BEFORE any puzzle, shadow-first.** The stronger insight
(operator): against a *solver farm* an interactive puzzle is not obviously
stronger than passive detection — the farm's business IS solving challenges (it
already solves the PoW), and a puzzle a human can solve is exactly what its
human-solver tier is paid for. Passive humanity/environment signals are harder to
farm because they are invisible (the farm doesn't know what is measured) and must
be produced by the real client stack, per request, on every rotating exit.

- **Rung 0** — v1 invisible PoW + clearance cookie (shipped).
- **Rung 1 (v2a) — passive**: the same invisible page also measures the signals
  below, scores them (`hs=`), runs **shadow** (log-only, feeds the ledger as a new
  per-client tell). No user-visible change. **Go here first.**
- **Rung 2 (v2b) — interactive**: a genuine pointer/drag/touch gesture (accessible
  fallback, never a pure drag-puzzle), only for the tail Rung-1 scores
  likely-headless AND high-risk. *(2026-09-29: only the confirm fallback for a
  Rung-1 reject remains a candidate; the puzzle is dropped.)*
- **deny** — farm-UNIQUE fingerprint / confirmed datacenter only (unchanged).

#### Rung-1 signals → which headless-tell each catches

Ordered by spoof-resistance (= weight). **None is a gate; the *combination*
convicts.** Some are **positive-only** (fire → suspect; absent → proves nothing).

| Layer | Signal | Headless-tell it catches | Weight | Trips legit (FP) |
|---|---|---|---|---|
| **Transport** (server-observed, unspoofable from JS; already stamped) | **JA4 (TLS) ↔ UA** | UA claims Chrome N but the ClientHello JA4 isn't that browser's (curl-impersonate, Go/Node, old Chrome) | ★★★★★ | measured 2026-09-23: NOT rare — front proxies (33% of human solves), AV/corporate inspection, iOS in-app browsers; not adopted, see "UA ↔ TLS coherence tell" below |
| | **JA4H (HTTP/2)** — roadmap 2nd axis | h2 SETTINGS / header + pseudo-header order don't match the claimed browser | ★★★★★ | ~0; dropped 2026-09-29 (needs an edge module we don't build) |
| **Environment / render** (JS probe; costly to fake per-request at scale) | **WebGL UNMASKED_RENDERER** | SwiftShader / llvmpipe / Mesa software renderer = headless/VM | ★★★★ | RDP/VDI/GPU-blocklisted reals → confidence, not gate |
| | **Canvas / audio hash** | software-render buckets; also session stability | ★★★ | Brave/Tor randomize → reals; dropped 2026-09-29 (fingerprinting the tenants' visitors: a consent question) |
| | **Screen / viewport coherence** | mobile UA + desktop DPR/screen; `outerHeight=0` | ★★★ | unusual-but-real setups |
| | **hardwareConcurrency / deviceMemory / languages / plugins / fonts / timezone** | headless defaults; mobile UA + 32 cores; empty `languages`; tz vs Accept-Language mismatch | ★★ | locale-quirky reals; corroboration only. hc is in (the hardware tells), deviceMemory measured and not adopted; only tz ↔ Accept-Language stays a candidate, after E4 |
| **Behavioral** (passive; noisy → score only) | **Touch ↔ UA** | mobile UA but `pointerType=mouse` / no touch / constant pressure | ★★★★ | low |
| | **Pointer entropy** | no motion before solve, or scripted linear / identical-`dt` vs human jitter | ★★★ | keyboard-only / touch users → absence ≠ bot; its crude form (`ptr`/`mv`) is the real-input rescue since 2026-09-29, and the input a Rung-2 confirm fallback would read |
| | **deviceorientation / devicemotion** | "phone" UA but zero/static sensor events | ★★★ | meaningful only when UA claims mobile (iOS needs a permission gesture); dropped 2026-09-29 |
| | **rAF cadence / interaction latency** | cadence far from a real refresh; solve with zero input events / robotic timing | ★★ | throttled tabs; fast users |
| **Positive-only** | **`navigator.webdriver` / CDP artifacts** | `true`; missing `window.chrome`; headless UA leaks | (positive) | `false` proves nothing (trivially spoofed) |

Weighting rule: server-observed (JA4/JA4H) ≫ hard-to-fake render
(WebGL/canvas/audio) > behavioral entropy > trivially-spoofable JS flags.

#### Rung-1 hardware tells (2026-09-23) — written from the corpus, not from memory

The retained `sig=` readings were collected exactly so a tell could be
measured before it scores. The first measurement showed the passive rung was
nearly toothless against the farms actually solving at volume: at the default
`FAIL_SCORE = 100` only **0.1%** of farm solves would have been rejected — they
sit just under the bar (`sw_renderer,no_input` = 90) or are fully clean.

**Corpus.** 13 299 `challenge_solved` rows carrying `sig` (7 nodes, ~24 h,
2026-09-22 20:00 → 09-23 19:00 UTC, pulled with `detection_history`). Labels
built INDEPENDENTLY of any tell:

- **H — likely human (2 031, 195 vhosts):** GR/CY source, consumer ISP (not a
  datacenter ASN), UA not self-declared bot.
- **F — farm (6 734):** non-GR/CY source, a convicted fingerprint
  (`c28caa00` / `95070673` / `ba6b4aad`), on a farm-shaped vhost (≥30 solves,
  ≥10 countries, ~1 solve per IP, <20% GR). A fingerprint alone is NOT the
  label — `c28caa00` and `ba6b4aad` also carry Greek humans.

**Adopted** — device-claim contradictions (the `touch_lie` class, so
positive evidence under D5b; an ABSENT reading never fires). A core count
counts only where it is IMPOSSIBLE for the claimed device:

| Tell | Rule | H | F | Weight |
|---|---|---|---|---|
| `mobile_hw_lie` | phone/tablet UA **and** `hardwareConcurrency ≥ 16` (human mobiles report 4-10) | 0 / 1 217 mobile | 42.3% | 50 |
| `mac_hw_lie` | Mac UA **and** `hardwareConcurrency ≥ 64` (human Macs in H topped out at 16) | 0 / 37 Mac | 15% | 50 |

**The device-claim group.** `touch_lie`, `mobile_hw_lie`, `mac_hw_lie` and,
since 2026-09-29, the UA-borne `ua_lie` (see "ua_lie" below) all say "this is
not the device the UA claims", and one spoof trips several at once: DevTools phone emulation or a UA switcher on a 16-thread desktop fires
both `touch_lie` and `mobile_hw_lie`. Summed, ONE exotic setup would reject,
which D5b forbids. So each member that fires is LISTED in `tells=`, but the
group adds only its strongest weight to `hs`, once. All of them weigh 50, so
Google-Read-Aloud still scores exactly 140. A rejection needs independent
evidence from outside the group; in the corpus every farm solve caught
through it also carried `sw_renderer`.

**No core-count tell for Windows/Linux UAs, however high** (second
adversarial-review finding). A human on an RDS/VDI session host, the very
user D5b's "sw_renderer alone passes" rule protects, reports the server's
64+ logical processors together with a software renderer. That is identical
to a farm box, so no weight could separate them. An earlier `hc_extreme`
(any UA, ≥ 64) was dropped for this. It cost 2.6 points of farm catch and the
whole CN-farm catch (Windows, hc 64), which is exactly that profile.

**Result**, simulated with the exact scorer (it reproduces the stored `hs` of
all 13 299 rows):

- farm fail rate **0.1% → 46.0%**; gastronom.hk 97%, kialasiatrika.gr 99.6%,
  vitolighting.com 60%, tzampalampa.gr 100%;
- humans **0% → 0%**;
- unlabelled solves 9.2% → 26.0%, the newly failing ones farm-shaped
  (1.01 solves/IP, 85% convicted fingerprints, foreign sources on Greek shops).

**Kill switch:** `[webdetector] CHALLENGE_V2_HW_TELLS` (default 1), read in the
same settings snapshot as the other v2 knobs.

**Measured, not adopted: `webkit_lie`** (an iPhone/iPad UA reporting
`deviceMemory`, a Blink-only API). It fired on 0 of 321 human iOS solves and
on 21% of farm solves, but only ever co-fired with `mobile_hw_lie`, so it
added no catch. Under the EU DMA a non-WebKit iOS browser may also
legitimately report it.

**Rejected** — each fired on real humans in H:

- mobile UA + `dpr = 1` — cheap Android tablets (Lenovo TB-X306) really are dpr 1;
- `hardwareConcurrency ≥ 32` — real 32-48-thread workstations on OTE/Vodafone
  (and any Windows/Linux core count at all — the RDS/VDI host, above);
- Mac UA + `dpr = 1` — old Intel Macs / external monitors;
- Chrome major lagging (≤ 151 when 153 was current) — 14% of humans;
- `raf` ≈ 16.7 ms (a perfect 60 Hz) — 84% of one farm, but 17% of humans;
- lowering `FAIL_SCORE` to 90 — clean on H, but H holds no RDP/VDI users, the
  very population D5b's `sw_renderer`-alone rule protects.

**Residuals (honest limits).**

- **Over-bound `hc` is dropped, not clamped.** A client reporting more than
  1 000 000 threads escapes both tells. Clamping would write a value the
  browser never sent into `sig=`, which the corpus must keep AS REPORTED, and
  it would close nothing: a non-integer `hc` fails the whole payload parse
  (`hs=-`), and a farm can simply report a plausible count. It is the same
  client-authored residual as the next point.
- **One farm is untouched:** techking.gr, 3 235 solves on `c28caa00`, 0.4% after
  the change. It has a real GPU and plausible hardware (hc 12, dm 16). What
  differs is either shared with humans (dpr 1, lagging Chrome, 60 Hz rAF) or
  an ABSENCE (0% pointer movement vs 30% of humans), which D5b forbids from
  convicting. No Rung-1 lever reaches it, and not a fingerprint policy,
  because `c28caa00` carries humans too; `cfm_pcw` did not see this shape
  either (master plan E4 read, 2026-09-29).
- **Client-authored:** a farm can fix these values once they bite, the
  standing D5b cost-lever residual.
- **Where they bite:** only under a v2 arm (D5a), but that already includes
  every WAF challenge-tier rule, which is `challenge_v2` by default. Those
  WAF marks (per IP since 2026-09-29) are strict (no good-bot waiver), so the tells take
  effect fleet-wide on upgrade. H was not sampled from WAF-mark traffic
  specifically. Elsewhere the tells show on the `would_v2` line; re-run this
  measurement on the `would_v2` / `src=` data before arming v2 anywhere new.

#### `ua_lie` — a legacy Edge token on a modern Chrome (2026-09-29) — adopted

**What it is.** EdgeHTML, the Edge before Chromium (majors 12-18), sent an
`Edge/<major>` token beside a Chrome/ compatibility token frozen in its own
era: Chrome/42 on Edge 12 up to Chrome/70 on Edge 18. Chromium Edge writes
`Edg/`. So `Edge/12`-`Edge/18` beside Chrome/80+ is neither browser. It is a
`uaplausible` rule (`legacy_edge_on_modern_chrome`). The scorer reads the same
matcher (`LegacyEdgeOnModernChrome`) as the device-claim member `ua_lie`
(50, the group's max once). It is UA-borne, so it is scored even without a
payload.

**Why.** The post-deploy review of the WAF `challenge_v2` sweep found one
scanner solving v2-armed challenges and passing. Its UA is
`… Chrome/125.0.6422.60 Safari/537.36 Edge/12.246`. It comes from four Google
Cloud IPs (104.197.69.115, 34.72.176.129, 34.122.147.229, 34.123.170.104) and
probes bare server IPs (rule 602) and `webmail.` / `cpanel.` logins. It passed
at three scores:
- hs 90: `sw_renderer,no_input`;
- hs 70: `outer_zero,no_input`;
- hs 0: a clean report (hc 16, dm 32, zero input).

**Corpus** (2026-09-29, 7 nodes):
- **Every challenge-log line carrying an `Edge/1` token, ~10 days (~590 000
  lines scanned).** Each one was that scanner. No other client, human or bot,
  solved with such a token.
- **WAF hits with an `Edge/1` token, 240 h (1 491 events, 207 sampled).**
  - 156 were the scanner string.
  - The real EdgeHTML pairings were present and are **not** flagged: 17
    Chrome/42 + Edge/12, 2 Chrome/58 + Edge/16, and 3 Chrome/70 + Edge/18.
    These are stale browsers, not impossible ones, the `uaplausible` line.
  - 29 were a separate fake shape, `… Edge/119|120.x` with no Chrome/ token.
    It was measured separately and not adopted (see "`Edge/1xx` with no
    Chrome/ token" below).

**Effect.** With the tell, the two corroborated variants fail — where a v2
arm covers the solve (D5a; elsewhere they show as `would_v2`):
- `ua_lie` + `sw_renderer` + `no_input` = 140;
- `ua_lie` + `outer_zero` + `no_input` = 120.

The clean-report variant scores 50 + 30 = 80 and still passes. This is
deliberate: D5b forbids rejecting on one fact, and a UA switcher set to this
string is one fact. That variant is a documented residual. The bound is
Chrome/80, not 71: margin over the last real pairing, at no cost. It is not
under `CHALLENGE_V2_HW_TELLS` (that switch gates the core-count tells), and it
has no switch of its own: it cannot fail a solve alone, and in ~590 000
challenge-log lines it fired on nothing but that scanner. The weight is set so
that `ua_lie` + `outer_zero` alone (90) still passes; `ua_lie` +
`sw_renderer` (110) is the same two-fact rejection `mac_hw_lie` +
`sw_renderer` already makes. Tests:
`internal/uaplausible` (`TestLegacyEdgeOnModernChrome`) and
`challenge_v2_ualie_test.go` (the three logged variants).

#### `deviceMemory` tells (2026-09-29) — measured, NOT adopted

Prompted by the `ua_lie` scanner's clean-report variant: it reports `dm:32`,
and Chrome was believed to cap `navigator.deviceMemory` at 8. If that held, a
Chrome UA above 8 would catch the one variant `ua_lie` leaves passing.

**Corpus.** The challenge logs of the 7 edge nodes (live + rotated), every
line with a `dm:` reading: 11 125 lines (10 884 solves, 241 `v2_reject`),
the newest ≤ 2 000 per node, ~1-7 days deep depending on the node.
**H** (likely human) is labelled as for the hardware tells: GR/CY source,
consumer ISP, no bot token. H holds 1 932 solves from 1 364 IPs on 203 vhosts.
Everything else (9 193) is **not** a farm label, just "not H".

**The premise is false for desktop Chrome.** Current desktop Chrome reports
above 8. 823 of 1 387 human desktop-Chrome solves (59%) reported 16 or 32:
569 × 16 and 219 × 32 on Windows. So `dm:32` does not set the scanner apart.
Human Android Chrome never exceeded 8 (544 solves: 8 / 4 / 2).

**Narrower shapes that were 0 in H, and why none was adopted:**

| Shape | H | not-H | Would newly fail |
|---|---|---|---|
| phone/tablet UA with `dm ≥ 16` | 0 / 545 mobile | 2 352 | 7 |
| Firefox UA reporting `dm` at all (a Blink-only API) | 0 | 88 | 0 |
| Windows UA with `dm ≤ 1` | 0 | 612 | 0 |
| `dm` not a power of two (6, 12, 20, 24) | 0 | 49 | 17 |

"Would newly fail" counts a 50-point member of the device-claim group, as
`ua_lie` is.
- **Mobile `dm ≥ 16` duplicates `mobile_hw_lie`.** 2 342 of the 2 352 already
  score ≥ 100 (`mobile_hw_lie` + `sw_renderer`), the same population and the
  same outcome as `webkit_lie` above.
- **The Firefox and Windows-`dm ≤ 1` hits are single facts.**
  - Firefox: 86 of the 88 score 0. They are one fingerprint (`95070673`) on
    87 residential IPs.
  - Windows `dm ≤ 1`: all 612 score 0. 611 are one UA (`Chrome/118.0.0.0`) on
    `19877aeb`, across 606 residential IPs.
  - Under D5b a single fact never rejects, so a tell changes nothing for
    either. Their lever is a fingerprint policy, not a Rung-1 tell.
- **An iOS UA reporting `dm` hit a human.** The one H match of "non-Blink UA
  reporting `dm`" was the Google app on an iPhone (`GSA/435`, OTEnet). That
  rules out the iOS part, like `webkit_lie`.

So at best ~24 of 9 193 non-H solves (0.26%) would newly fail, for a new
member that a browser change could turn against humans. Not worth it. Revisit
only if a farm that solves at volume carries one of these shapes **together
with** evidence from outside the group.

#### `Edge/1xx` with no Chrome/ token (2026-09-29) — measured, NOT adopted

The second fake shape from the `ua_lie` corpus: a Chromium-era `Edge/<major>`
token (`Edge/100`, `117`, `120`) with no Chrome/ token. Real Chromium Edge
writes `Edg/` beside a Chrome/ token. The UA contradicts itself, so it is a
`uaplausible` candidate.

**It never reaches a challenge.**
- **Challenge logs (7 nodes, all rotations, ~10 days):** every `Edge/1`
  token was the Chrome/125 + `Edge/12.246` scanner. No challenge line
  carried the no-Chrome shape.
- **WAF log (same reach):** 387 events carried an `Edge/1` token. 23 were
  this shape:
  - 12 × `… Edge/120.0.2210.91` (Windows), 4 × `… Edge/100.0.0.0`
    (Mac/Linux) and 1 × `Edge/117.0`;
  - 23 distinct IPs;
  - 22 were rule 512 (`xmlrpc.php` burst, **block**, `WAF_AUTH_BURST` is
    autoblock-armed) and 1 was rule 410 on `/adminer.php`.

`uaplausible.Check` is read only at challenge verify (the solve's
`ua_impossible` label on its line and history row, and the +30 shadow
`challenge_score`). A rule for a
shape that is already blocked at the edge and never solves would change
nothing. Revisit if it starts solving challenges.

#### UA ↔ TLS coherence tell (2026-09-23) — measured, NOT adopted

The "JA4 ↔ UA" row of the signal table above, and the "future JA4↔UA
coherence tell" of the master plan (§3, row 11). Prompted by 1 334 solves on
`c28caa00` (a Chrome-ordered cipher list) whose UA claims Chrome on iOS
(`CriOS`), which must use Apple's TLS. No human in the corpus showed that pair.
The question was what such a tell would catch **beyond** the tells already
shipped. The answer is nothing, so it was not built. Don't re-open it without
new data (see "when to revisit" below).

**Corpus.** 13 720 `challenge_solved` rows with `sig` from the same 7 nodes,
2026-09-22 19:10 → 09-23 20:22 UTC. Same independent labels as the hardware
tells above: **H** 2 135 (197 vhosts), **F** 7 878 (10 farm-shaped vhosts),
**U** 3 707. The simulator reproduces the stored `hs` and `tells` of all 13 720
rows (the nodes did not run `mobile_hw_lie`/`mac_hw_lie` yet; those were then
simulated on top). Baseline with them: H 0%, F 41.0% fail.

**Stack classes come from the data, keyed on the cipher list, not the id.**
The 8-hex id also hashes the curve list, and edge OpenSSL builds name the
post-quantum curve differently (`X25519MLKEM768` vs `0x11ec`). So one Chrome
stack is `c28caa00` on some nodes and `95070673` on others. The
GREASE-stripped cipher ORDER, read
from the `first_seen` lines, is stable across nodes. Every human plain iOS
Safari/CriOS and Mac Safari solve on a client stack used one of two Apple
lists (TLS 1.3 AES-256 first and 3DES last, or AES-128 first with the same
tail). 94% of human Chromium solves on a client stack were on one Chromium
list (the rest were ChaCha-first variants and the middleboxes below). Human
Firefox was on its own lists.

**Results** (extra = solves that would newly fail, weight 50 in the
device-claim group; as an independent opener it was also 0 for every F row):

| Candidate | H | F | U | extra F | extra U |
|---|---|---|---|---|---|
| iOS UA on the Chromium list | **3** | 1 471 | 158 | 0 | 0 |
| plain iOS Safari/CriOS UA (nothing appended) on the Chromium list | 0 | 1 471 | 157 | **0** | **0** |
| plain iOS UA on any non-Apple list | 0 | 1 471 | 157 | 0 | 0 |
| Firefox UA on the Chromium list | 0 | 1 | 2 | 0 | 2 |
| Chrome UA on an Apple list / Android UA on an Apple list / Mac Safari on Chromium | 0 | 0 | 0 | 0 | 0 |
| Chrome UA on a list human Firefox showed | **1** (a CCM middlebox list, below) | 0 | 0 | 0 | 0 |

**Why nothing extra:**

- **`mobile_hw_lie` already covers the whole population.** All 1 628
  plain-iOS-on-Chromium solves (F and U) already fire `mobile_hw_lie`: the
  farm claims an iPhone from desktop hardware (hc ≥ 16). As a device-claim
  contradiction the new tell would have to join that group (max, once), so
  it adds 0 while both fire.
- **The farm solves that still pass are COHERENT.** Of the 4 651 F solves
  that pass with the hardware tells, 4 637 (99.7%) send a Chrome UA over the
  Chromium list. No UA ↔ TLS rule can see them. The remaining 14: 11 with
  the UA `pc`, 2 self-declared bots and 1 Firefox UA.

**Why the broader rules are unsafe** (each hit H, or would have):

- **iOS in-app browsers bring their own TLS.** Three human solves on ancho.gr
  come from TikTok's in-app browser on iOS (UA ends in `musical_ly_46.x`): an
  iPhone Safari UA over a Chromium-ordered list with no PQ curve
  (`19877aeb`). One more human app webview (no `Safari/` token) used a third
  stack. So "iOS UA ⇒ Apple TLS" is false for in-app browsers. The rule is
  0-in-H only when narrowed to UAs with nothing appended after `Safari/…`,
  and that narrowing is exactly what a farm can copy.
- **A front proxy replaces the client's handshake for a whole vhost.**
  `ba6b4aad` (and `fd4fd84d`, the same cipher list on speedhost) is
  shown by every UA family: Android and desktop Chrome, iOS Safari and apps,
  Firefox. It appears on only 10 vhosts. That shape is a CDN or reverse proxy
  that re-originates TLS to the edge, so `X-CFM-TLS` describes the proxy and
  not the client. It carried **700 of the 2 135 human solves (33%)**. The
  same shape explains why `ba6b4aad` has a farm verdict and still "carries
  Greek humans": every visitor to those vhosts shares it. **Arming a
  fingerprint policy on `ba6b4aad` would hit every visitor of those vhosts.**
  The vhosts resolve to Cloudflare, and the edge trusts Cloudflare's ranges for
  the client IP (`trusted_proxies.conf`). **Fixed 2026-09-23:** `cfm_tlsfp.value()`
  returns no fingerprint when the TLS peer is a trusted proxy (`$realip_remote_addr`
  ≠ `$remote_addr`, the same unforgeable test the confs use for
  `X-Forwarded-Proto`). So the verify stamp, the fingerprint-policy lookups and
  the WAF-hit attribution all treat such a request as "no fingerprint" instead
  of charging the proxy's handshake to the client (live check on mars: a
  `ba6b4aad` solve on toolpoint.gr logged `peer=` a Cloudflare address and
  `xfp_trust=1`, the same test). The cfm-web records for `ba6b4aad` and
  `fd4fd84d` (the same Cloudflare handshake, curves named differently) stay.
  **Trade-off:** on a Cloudflare-fronted vhost the solver-farm detector's two
  fingerprint tracks (per-host concentration, cross-host) now see only the
  solves that reach the origin directly. Those are a small, already suspicious
  residual, and they now make up the whole cross-host share denominator for
  that vhost instead of being diluted by the proxy's fingerprint (the spread
  floors still gate a finding). The subnet-spread track still covers the vhost,
  and so do the Rung-1 tells, which read the page's own report. A policy can no
  longer be armed on a Cloudflare egress fingerprint, which was never a
  client's anyway. Anyone who relays through Cloudflare now carries no
  fingerprint; before, they carried Cloudflare's, never their own.
- **TLS-inspecting middleboxes are not rare.** Human Chrome and Firefox UAs
  (improv.gr, fcs.com.gr, webmail.deyadoxatou.gr) arrive over OpenSSL-shaped
  lists with CCM, ARIA or DHE suites that no browser offers: antivirus or
  corporate HTTPS inspection. So the table's "~0 FP, rare proxy/AV" guess was
  wrong. A "browser UA on an unknown stack" rule hits humans. An allow-list of
  browser stacks would also need a new entry for every browser and OpenSSL
  release.

**The one population it would newly catch is a fingerprint, not a
contradiction.** `d9d37bc0` (www.smart-tech.gr on earth: 1 995 solves, 1 992
IPs, 83% CN, `sw_renderer,no_input` = 90) sends Windows Chrome UAs over a
list with TLS 1.2 suites first and TLS 1.3 last. No human showed that list. A
rule naming it would be an automatic decision keyed on one fingerprint, which
the shadow-first invariant forbids (CLAUDE.md §6). The lever for it already
exists: an operator-armed fingerprint policy. Note that `challenge_v2` there
would still pass these solves (90 < 100). Only `deny` would stop them, and in
cfm-web `d9d37bc0` is a WAF-hit fingerprint with rotating UAs, not a
convicted solver farm.

**When to revisit.** Only if the farms stop claiming iPhones from desktop
hardware but keep the iOS UA over Chrome TLS (so `mobile_hw_lie` stops firing
while this pair stays). Re-run this measurement then, before writing any code.
Build the stack classes from the data by cipher list, restrict to UAs with
nothing appended, exclude vhost-bound (front-proxy) lists, and keep it in the
device-claim group.

#### Auto-v2 — automatic vhost challenges at the v2 tier (2026-09-29)

Until now the vhost grain was armed only by a MANUAL arm at `rung=v2`. Since
2026-09-29 an **automatic** vhost challenge runs at v2 too, when its source
is in `[webdetector] CHALLENGE_V2_AUTO_VHOST` (default
`suspicious_vhost,uniqpaths_short,under_attack`; `vhost_config` is opt-in,
`off` arms none). Code: `challenge_v2_auto.go`.

**Measured first (D3 exit contract).** The week after the hardware tells
shipped (2026-09-23 → 09-29, 7 nodes, `src=` on every solve) sized the arm
from the solves it would have covered:

| `src=` | solves | would fail | likely humans (fail) | convicted-farm (fail) |
|---|---|---|---|---|
| `vhost:suspicious_vhost` | 28 524 | 8 207 | 3 395 (4) | 21 054 (7 625, 36%) |
| `vhost:vhost_config` | 1 650 | 523 | 780 (0) | 394 (388) |
| `vhost:uniqpaths_short` | 126 | 64 | 33 (0) | 31 (18) |

Of the 4 human-labelled fails, 2 carry `webdriver` (automation on a Greek
line); the other 2 are `sw_renderer,outer_zero` on real input (`mv` 729 /
341) — software-rendered machines, the known RDP/VDI residual. ~0.06%. Since
2026-09-29 real pointer input rescues those two (`v2_rescued=input`, "Who the
deterministic-FP residual is" below); what remains is a human on such a
machine who does not move a pointer (keyboard, touch). For them the false
reject is deterministic per device (a retry fails the same way), so
what bounds it is the automatic challenge's LIFETIME — while the scorer keeps
the vhost suspicious (plus holddown) or Under-Attack holds. That is not a
fixed TTL: a vhost suspicious for days is at v2 for days, and the v1 pin is
the per-vhost way out. The config list (permanent by nature) is therefore
opt-in, and the fingerprint/geo policies stay explicit operator arms.

**One resolver** (`challengeV2VhostTier`) answers "what tier is this vhost
at", for the verify gate AND every surface (vhost list/status, controls
rows, CLI):

1. a manual arm at v2 → v2;
2. no automatic source covering the host → the manual arm's v1, or no tier;
3. a **tier pin** on the host (or its apex, for `www.`) → the pinned tier;
4. the knob: v2 iff the covering source is armed.

A manual arm at v1 never DOWNGRADES what 3/4 give: a tier-less "Challenge"
click or a tenant's panic-button arm must not switch off an auto-v2,
Under-Attack or operator-pinned-v2 vhost (a review finding: it was a scoped
bypass of an operator's v2 pin). The way down is a v1 pin.

The automatic source needs a live bridge vhost entry — the SAME entry and
matcher `src=vhost:<reason>` reads (`vhostEntryLocked`). The entry's single
sticky reason can't name it (a manual arm and a `CHALLENGE_VHOST` list match
both relabel it, and it can outlive the source that wrote it), so it is never
read for arming. Instead the tick NOTES each active automatic source on the
entry (`NoteVhostAutoSource`: `under_attack` — the state as the tick
evaluates it, operator `attack on` included — `suspicious_vhost`,
`uniqpaths_short`, `vhost_config`), re-noting it EVERY cycle it is active
with a short TTL (10 ticks, 2–10 min — a tick slowed by a flood's log
backlog must not drop the tier between re-notes) and dropping it the cycle it turns
off. A cycle that never reaches the host (an exclude/ignore `continue`, a
host that left the candidate set, a stalled tick) just stops re-noting, and
the source lapses: no missed transition can leave a stale v2 — an
unevaluated source is never kept alive, including while the uniqpaths
branch skips the scorer and Under-Attack (uniqpaths_short, armed by
default, carries the tier then). An operator `attack off` drops the
under_attack note at once.
Notes are keyed on the host that wrote them and read www→apex, so a `www.`
host's own cycle can never erase what its apex noted — but a `www.` host
inherits only while the apex itself has a live challenge. A host suppressed
from automatic challenges (host bypass, a Challenge exclude, the ignore
list) has no automatic tier at all — own or inherited — asked at READ time
(`hostAutoSuppressed`), so it holds however quiet the host is; a manual arm
on it keeps its own tier. Notes die with
their entry, so a forced `attack on` on a host nothing challenges arms
nothing. The first ARMED noted source wins (strongest first: under_attack,
suspicious_vhost, uniqpaths_short, vhost_config). One bridge RLock at
verify — no scorer or Under-Attack lock. The UNDER_ATTACK transition line
carries `tier=` so the log says whether entering the state armed v2.

**What armed it — `v2_via=`.** `src=` can't say (it reads the entry's
sticky reason), so every `v2=vhost` solve and reject line — and the
`challenge_solved` / `challenge_v2_reject` rows (`payload.v2_via`) — carries
`v2_via=manual|pin|auto:<source>` (right after `v2=` on the solve line,
after `src=` on the reject line). The FP-hunting query
for the auto arm is `detection_history type=challenge_v2_reject` filtered on
`v2_via` starting `auto:`. The grain stays `v2=vhost`, so the
good-bot waiver applies exactly as for a manual v2 arm, and `src=` says
which vhost source covered the solve.

**Tier pins** (`POST /api/v1/challenge/vhost/tier`, `cfm webtop challenge
tier <vhost> v1|v2|auto`, the cfm-admin "→ v1 (pin)" / "↺ auto" buttons):
`v1` is the emergency drop-back, `v2` arms a source the knob leaves at v1,
`auto` hands the tier back to the knob. A pin never creates or extends a
challenge and does nothing while no automatic challenge covers the host.
Persisted (`webdetector_challenge_tier_pins.json`), because every config
reload restarts the daemon and a lost v1 pin would silently re-arm the host;
and one store per state file is shared across Engine rebuilds, so a pin
written in a reload's window lands where the new Engine's gate reads. In the
same window the gate answers through the previous Engine until the new one's
first tick has noted its sources (its bridge starts empty), so a config
reload never drops an auto-v2 host to v1. A host whose automatic challenge
the store never records (`uniqpaths_short`) still reads `auto_active` on the
status read, so its pin control is there when it is needed.
Scoped tokens may pin their own vhosts, TTL-capped at 24h, and may not
replace, clear or shadow a pin the operator set (the status read carries
`rung_pin_locked` so their page hides controls that would 403). Audited as
`challenge_vhost_tier_pin` (`from`/`rung`/`actor`, a no-op writes nothing).

**Under-Attack's first consequence.** I1 stays detect-only for its action
ladder; the v2 tier is the one thing UNDER_ATTACK now changes. Caveat from
the same week: `vhost_under_attack_on` never fired fleet-wide (still none on
2026-09-29), although
farms solved ~25 000 challenges — entry leg 3 needs the origin to be
erroring (≥50%), and a farm that doesn't break the site never trips it. So
`under_attack` is the rare, strong trigger; `suspicious_vhost` is the one
that carries the volume.

**Not solved by this.** ~52% of convicted-farm solves score `hs=0` (the
95070673 hc=8 pool, c28caa00 on real GPUs): no Rung-1 arm catches them.
Their lever is the operator fingerprint / geo policy; `cfm_pcw` did not see
them (they solve once per IP), and the Rung-2 step below acts only on a
reject, which an `hs=0` solve never is. The deterministic-FP residual above
(the 2 rejected humans moved the mouse; 0 of 9 954 failing farm solves did)
is the real-input rescue's since 2026-09-29. The Rung-2 "confirm you're
human" step is for the humans left after it, who did not move a pointer —
with the honest limit that a CDP click is trusted and the accessible
keyboard path has no trajectory, so it is an escape hatch for humans, not a
wall.

**Who the deterministic-FP residual is (first read, 2026-09-29, before the
release).** In a week of `would_v2` lines the likely-human would-rejects under
the automatic sources are Windows **Chrome/109** — the last Chrome for Windows
7/8.1 — on 2-4 cores with a software renderer AND no window size, exactly
`hs=100`, with real pointer input (a Serres school, a Nova line, one in
Bulgaria). The farm half of that bucket is Linux Chrome/154 at hc 640 with no
movement. Real input (≥ 5 pointer events, ≥ 100 px) marked 1 of 2 861 failing
solves in the `sig` corpus — the human — and no farm solve. The operator's
mitigation (master plan E4, READ 2026-09-29): **real input rescues**. A failing
score with those readings (≥ 5 events, ≥ 100 px) and no certain tell
(webdriver, headless UA) takes the solved path under every grain, marked
`v2_rescued=input` (`challengeV2InputRescue`; kill switch
`CHALLENGE_V2_INPUT_RESCUE`). Trajectory readings followed, log-only (and the
page now counts trusted events only), then the confirm fallback for the
humans who did not move a pointer. The honest limit: the counts are
client-authored — a bot can post any numbers, and a CDP-dispatched pointer
event is a trusted one.

#### Observability contract (shadow-first; reuses existing logs — no new log, per CLAUDE.md §5)

Rung-1 writes the SAME surfaces `challenge_score` uses (open-question #4
resolution — `docs/challenge-score.md` §8), so it is fully MCP-observable for
burn-in and FP triage with no new plumbing and no logrotate change:

- **`cfm.challenges.log`** (per solve; already logs `ua=`, `solve_ms=`,
  `ua_impossible=`): add `hs=<humanity_score>`, `tells=<fired,comma,list>`,
  `fp=<tlsfp>` — the raw grep surface for "which solve, and why" — plus
  `v2=<grain>` naming the arm that covered the solve (`fp` / `geo` / `vhost` /
  `mark`), absent when unarmed, and for `v2=vhost` also `v2_via=manual|pin|auto:<source>`
  (what put the vhost at v2 — "Auto-v2" above). The grain is what separates "the tier is live
  and this solve passed it" from "the tier never fired": without it a clean
  armed solve reads exactly like a plain v1 one. `grep 'v2='` is the burn-in
  question "is my newly-armed tier actually covering traffic?"; `grep
  v2_reject` is "did it bite"; `grep v2_waived=` is "which failing solves did
  it let through as an FCrDNS-verified good bot" (`CHALLENGE_GOODBOT_EXEMPT`;
  e.g. Google-Read-Aloud, hs=140 from rotating first-seen Google IPs — the
  gate forward-confirms a crawler-looking PTR inline, bounded, on the reject
  path only). Only under a geo or vhost arm, the grains the decision-time
  exemption already softens; a fingerprint policy or a traffic-rule/WAF mark
  stays strict. The history row carries it as `v2_waived`. The mirror image
  on a `result=v2_reject` line is `v2_waiver_miss=<why not>`, after the geo
  fields and only when the client's PTR claims a crawler: `grain` (the arm is a
  fingerprint policy or a mark — never waived), `mark` (a geo/vhost arm, but
  a mark covers the client too), `off` (`CHALLENGE_GOODBOT_EXEMPT = 0`),
  `spoofed` (the forward-confirm didn't match), `timeout` (no verify slot in
  time) or `transient` (resolver failure). Without it a Read-Aloud the gate
  couldn't confirm reads exactly like an impostor; the `challenge_v2_reject`
  row carries it as `v2_waiver_miss`. A reject with no `ptr=` has no reason
  either — the PTR wasn't known at verify — and that is NOT evidence the
  client isn't a crawler. `grep v2_rescued=` (since 2026-09-29) is "which
  failing solves did real pointer input let through": under ANY grain, a
  failing score with no certain tell and `sig=` reporting ≥ 5 pointer events
  covering ≥ 100 px (`mv` as `sig=` shows it; "Who the deterministic-FP
  residual is" above). It rides only an armed solve's line, after `v2=` /
  `v2_waived=`, with the failing `hs=`/`tells=` intact, and the history row
  carries `v2_rescued`. An unarmed failing solve had nothing to be let
  through: its would-be rescue rides the `would_v2` shadow line instead, so
  `abuse_shadow`'s `humanity.rescued` says how many of a would-be arm's
  rejects it would clear. Finally `sig=` carries the report AS REPORTED —
  `ptr`/`tch`/`key` (event counts), `mv` (accumulated pointer movement, px),
  `hc`, `dm`, `dpr`, `raf`, then (since 2026-09-29) the trajectory readings
  `ut`/`co`/`st`/`dj`/`mj`/`pd` — in that fixed order, omitting any signal the
  browser did not report. `dm`/`dpr`/`raf` and the trajectory readings are
  scored by nothing; `hc` feeds
  `mobile_hw_lie`/`mac_hw_lie` ("Rung-1 hardware tells" above);
  `ptr`/`tch`/`key` are also the `no_input` amplifier's inputs, and
  `ptr`+`mv` decide the real-input rescue (which only ever clears), so logging
  them makes both auditable. The trajectory readings describe the pointer
  path behind `ptr`/`mv`, so the rescue can be tightened from measured
  distributions (master plan E4, step 2):
  - `ut`: untrusted (script-dispatched) pointer-move events. They are
    excluded from `ptr`/`mv` and every other reading, and untrusted keys and
    touches are not counted in `key`/`tch` either, so the rescue and
    `no_input` see trusted input only;
  - `co`: coalesced samples behind the delivered events (absent where the
    browser lacks `getCoalescedEvents`);
  - `st`: straightness, net `clientX/Y` displacement over path length (1 =
    one straight line; needs a path);
  - `dj`: inter-event timing jitter, the coefficient of variation of the gaps
    (needs 3 gaps);
  - `mj`: the largest single-event `|movementX|+|movementY|` (the same basis
    as `mv`), px;
  - `pd`: ms from the first pointer-move event to the last (needs 2 events).

  The page sends them raw and the daemon rounds them (`sigRound`), so a tiny
  real value is never posted as 0. A CDP-dispatched event is trusted, and
  how it coalesces, how straight and how regular it is are exactly what the
  corpus has to show, so none of these is a tell yet. The path mixes every
  pointer (no `pointerId` split), so a pinch or a pen lands in one path.
  `result=v2_reject` lines carry `sig=` too.
  A rejected solve is never published as a solved event (it cleared nothing);
  since 2026-09-22 it writes its own `challenge_v2_reject` history row instead,
  built by the same payload builder as `challenge_solved`, so the two
  populations compare field for field — `detection_history
  type=challenge_v2_reject node="all"` is the fleet FP-hunting query. Every
  solve and reject line also carries `cc=`/`asn=`/`asn_name=`/`ptr=` — after
  the fields older parsers read: on the reject line followed by
  `v2_waiver_miss=`, `src=`, `v2_via=` and `scope=`, on the fallback solved
  line by `src=` and `scope=`, and on the hook-written solved line by `src=`,
  `scope=` and the legacy ` - (AS…, Country)` tail, which stays last for
  tooling that reads it. That is the client's network
  identity, resolved ONCE at verify without ever blocking it: country/ASN from
  a live mmdb read (the enricher's cached record can be up to a day stale),
  PTR from the cached-or-async path. Each key is absent when unresolved — and
  `ptr` also when the address has none. The verify-side **geo arm check reads
  the same live database** (its own lookup, same source), so the line and the
  gate agree. It used to match the enricher's cached record, which lagged an
  mmdb update by up to 24h (or was empty if cached before the mmdb loaded), so
  a `v2=geo` line whose `cc=`/`asn=` sat outside the armed set was the gate
  acting on a stale record. Seen now, that is a bug to report. The history rows
  carry the same as `country`/`country_iso`/`asn`/`asn_name`/`ptr`. Mind the
  name clash: top-level `ptr=` is reverse DNS; `sig=ptr:` is a pointer-event
  count. Log/corpus only — nothing scores on network identity. This is the corpus half of the table above: the
  signals listed there as ★★/★★★ candidates are measured and logged long
  before any of them is allowed to score, so a weight is set from real
  distributions rather than written from memory. `sig=` absent means nothing was
  RETAINED, which is a SUPERSET of "no payload arrived": a client that posts
  `{}`, or a body whose every reading fails the bounds, parses fine and shows
  `hs=0` with no `sig=` — that is not an `hs=-` case. Isolate the
  body-stripping population with `hs=-` (or the row's `hs_nopayload`); `sig=`
  absence alone does not identify it.
- **`cfm.abuse_shadow.log`**: `signal=humanity verdict=would_v2 …` when the score
  *would* escalate — shadow, nothing served. Since 2026-09-23 the line also
  carries who the client is and what challenged it, space-free for the
  abuse-shadow parser: `cc=` `asn=` `provider=` `ptr=` `ua_family=` `ua_bot=1`
  (the UA self-declares a bot — unverified) and `src=`. The `abuse_shadow` MCP
  tool aggregates them in its `humanity` section (`by_src_kind`, `by_src`,
  `by_fp`, `by_provider`, `by_ptr_domain`, `by_scope`, …). Since 2026-09-29
  `scope=` rides last (see below), and `v2_rescued=input` (before `src=`)
  marks a line an arm would have let through after all — real pointer input,
  no certain tell — counted as `humanity.rescued`. Lines minus rescued is an
  upper bound on what an arm would reject (the geo/vhost good-bot waiver
  clears verified crawlers too).
- **`src=` — challenge provenance** (`challenge_src.go`, 2026-09-23): a
  snapshot, taken at verify, of every source covering (ip, host) then —
  `waf:<rule id>`, `ip:<detector rule>`, `vhost:<manual|vhost_config|suspicious_vhost|uniqpaths_short>`,
  `rule:<traffic rule id>`, `fp`, `geo`; `src=-` = none covered (an entry that
  expired between serve and verify); absent = not resolved. On the solve
  line, the reject line, the would_v2 line and the `challenge_solved` /
  `challenge_v2_reject` rows (`payload.src`, stripped for scoped callers). It
  is a snapshot, not the one decision that served the page: several sources
  can be listed. LOG-ONLY — `v2=` stays the one answer to "did the teeth
  cover this solve". It exists to size a new v2 arm (e.g. auto vhost
  challenge at v2) from real would-rejects before turning it on — which is
  how the auto-v2 default above was sized.
- **`scope=` — the verify surface** (2026-09-29): `web`, or `panel:<port>`
  for a panel port's human-entry challenge (`clearanceScope`, resolved once at
  verify). It is last on the reject and would_v2 lines, and after `src=` on the
  solve line (before only the hook line's legacy free-text tail). It is also
  `payload.scope` on both rows, stripped for scoped callers (a `panel:2087`
  on a tenant's row would name a WHM user: operator data). It matters
  because the rung marks count only on a web-scope verify (`v2=mark` can never
  appear beside `scope=panel:…`), and only a web-scope solve releases the IP's
  bridge decision, so without it a panel solve reads exactly like a web one.
  Absent = a line or row from a daemon that predates it. The `abuse_shadow`
  `humanity` section counts it as `by_scope`. LOG-ONLY.
- **`detection_history`** (durable, fleet-pullable): fingerprint-anchored, rolls
  into cfm-web's `fingerprints` ledger as another per-client tell. The
  `challenge_solved` row carries `hs`, `tells`, `v2` (the arm grain),
  `hs_nopayload` and `sig` (the readings as a JSON
  object, same numbers and rounding as the log's `sig=`), so the burn-in
  readout does not require shell access to every node. `hs_nopayload` is the
  MORE precise of the two surfaces, not a rename of the log's `hs=-`: the log
  collapses to `hs=-` only when the score is also 0, so a HeadlessChrome UA
  that strips the body logs `hs=100 tells=headless_ua` while the row carries
  `hs:100` AND `hs_nopayload:true` (likewise `hs=50 tells=ua_lie` for the
  legacy-Edge UA since 2026-09-29). Grepping `hs=-` and querying
  `hs_nopayload` therefore return different populations — use the row.
  `payload.sig` is admin-only (stripped for scoped callers,
  `docs/endpoint_scope_inventory.md`), and so, since 2026-09-29, is the
  whole `v2` / `v2_*` family: `v2=fp` / `v2=geo` name operator policy, as
  `src` does, and each other member narrows the grain. The rest of the
  payload is unchanged.
  `challenge_solved` is the highest-volume row type, so these keys add ~50-80
  bytes each and the history DB grows accordingly at unchanged retention (it
  is bounded by row count, not bytes) — see the CHANGELOG storage note.
  Every humanity key is gated on the scorer having actually run, so an
  unscored solve carries none of them rather than a default-looking `hs:0`. Every humanity key is omitted
  entirely when the rung is off: there is no `-1` sentinel to look for, so the
  ABSENCE of `hs` — not a magic value — is what says "never scored".

MCP surfaces: `abuse_shadow` (per-node signal/verdict counts), `detection_history`
(durable; `node="all"` for the fleet), `challenge_events`; suspected-FP drilldown
via `ip_forensics` / `edge_access_tail`; cross-signal per fingerprint via cfm-web
`fingerprints`.

**FP workflow.** A false positive = a real client that scored high but (shadow)
was not acted on. Find it in `cfm.challenges.log` (`hs=` high + `tells=`) →
understand the cause (e.g. RDP SwiftShader, keyboard-only) → downweight that tell
/ `ALLOW_FPS` / `ALLOW_NETS` / raise threshold. A tell only graduates to actually
gating Rung-2 after its FP population is understood — the same FP-cleanliness
readout discipline as the `challenge_score` B-slice burn-in.

**Slice 1 — shipped 2026-09-12 (log-first).** Challenge solves now log `ua_family=`
(uaplausible's browser family) next to the existing `tls_fp=`/`ua=` on the
`cfm.challenges.log` solve line, so the fingerprint↔UA-family corpus is derivable
from real traffic. Two honest caveats
that reshape the signal table above: the server-side fp is **JA3-grade** (nginx exposes
ciphers/curves/ALPN/proto, **not** the extension list a true JA4 hashes) — a real JA4
needs an edge module and was **deferred**, and is now dropped (2026-09-29, master plan §5); and the JA4↔UA *coherence tell* is
**not** same-day wiring — it waits on a derivation pass over this corpus (Step 2), never
a hand-written per-UA fp table (the codebase forbids that by convention:
`internal/tlsfp`, `internal/uaplausible`). Slice 1 adds no new log/event and no
enforcement.

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
      *(2026-09-29: done on 6 — `cfm.abuse_shadow.log` is live there;
      `server.speedhost.gr`'s is empty — its `[webdetector]` has no
      `ABUSE_SHADOW` (default off), so set `ABUSE_SHADOW = 1` there; until
      then its shadow lines, `would_v2` included, are missing from every
      fleet readout.)*
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
      feature only. Cost-bounded (CLAUDE.md §6): cheap mmdb ASN class for all IPs
      under a per-tick IP budget (logged deferral, no silent cap; a single
      over-budget vhost is processed anyway so the biggest floods stay visible);
      the good-bot exclusion runs through a shared FCrDNS **verdict cache**
      (`dcFracGoodBot`, the same non-blocking cached machinery as the verified-
      crawler exemption) — a verified crawler is a DNS-free cache hit, only a miss
      kicks a bounded/deduped/async confirm, so a stable crawler is confirmed once
      per TTL not every tick and the verdict survives geo-cache eviction. **Two
      adversarial-review MAJORs fixed** in the same PR: (1) the original synchronous
      per-tick FCrDNS was a per-tick DNS storm on crawled shops — replaced by the
      verdict cache; (2) a vhost with more distinct IPs than the whole per-tick
      budget was deferred forever — now processed. **Residual, pre-enforcement:**
      a cold good-bot verdict (chiefly the first ticks after a restart) counts the
      IP as datacenter until the async confirm lands (~2–3 ticks) — deliberate
      (excluding the unknown would blind the signal to generic/absent-PTR floods),
      but "count-on-unknown / exclude-on-verified" must be closed before this
      feeds any decision. Log-only: `dc_fraction` badge (`dc N%` pill / `dc=N%`
      CLI) + `signal=dc_fraction` line. Own mark store + TTL. Default-ON under
      `ABUSE_SHADOW`; knobs `ABUSE_SHADOW_DCFRAC[_MIN_FRAC|_MIN_REQ|_MIN_IPS]`. NO
      score contribution, NO enforcement.
- [ ] Add missing per-client features: header-coherence, solve-latency; route
      cookie_discard / solver_farm / abuse_shadow as contributors into
      `IPSignals.Score` / `SuspiciousRow.Score` (they stop being independent
      actuators; alerts stay during burn-in). *(Superseded by E3, dropped
      2026-09-29 — master plan §5.)*
- [x] **DONE (PR #1377) — self-baseline (robust-z) primitive.**
      `internal/webdetector/vhost_baseline.go`: a bounded per-`(vhost,feature)`
      recency ring → modified robust-z (median/MAD, so the spike we hunt does not
      poison its own baseline), per-feature `madFloor`, cold-start guard, non-finite
      guard, `MaxHosts` LRU + `Prune`. Pure/unwired; two adversarial reviews folded.
- [x] **DONE — fused shadow score + `verdict=would_*` lines.**
      `internal/webdetector/abuse_shadow_fused.go`: `fused = clamp01(base + Δ)`,
      Δ = capped Σ weighted robust-z of facet/cost/dc/shadow against each vhost's
      own baseline, emitted from the shadow block (throttled to ~1 pass/2 min so
      baseline samples stay independent). **Corroboration is over the vhost-level
      shapes {facet, cost, dc}** — ≥2 must co-fire (rate-outlier feeds Δ but not the
      gate, since one aggressive IP trips both facet and rate-outlier) → the
      planetgym facet-alone / dc-alone guard; the would-arm also inherits the live
      uniqIP floor. **Baseline-frozen while corroborated** (an active flood never
      trains itself in; frozen hosts are Touch()'d so a sustained flood isn't
      pruned). Logs `signal=fused_score … verdict=would_arm|confirm` only; the live
      `raw/6, ON 0.70` arm is never read from the fused value. Rides `ABUSE_SHADOW`,
      no new config; weights are in-code burn-in constants.

### Phase 2 — actuation ladder (under_attack I3)

*(Status 2026-09-29, master plan §5: surface-throttle and gate-before-origin
are FROZEN until the next real Class-2 flood; the harden-PoW rung is FROZEN
until a faster in-page solver lands; the crawler lane is DROPPED — traffic
rules with rate limits do it.)*
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

*(Status 2026-09-29: 1 answered by E3 — a clean `403`; 3 answered — the
`challenge_score` lines ride `cfm.abuse_shadow.log`; 5 moot — the crawler lane
is dropped; 4 moot — the `IPSignals` routing it asks about is dropped. Only 2
stays open.)*

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
