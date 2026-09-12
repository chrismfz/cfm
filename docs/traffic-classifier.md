# Traffic classifier — living design notes

> **⭐ SINGLE SOURCE OF TRUTH (node side).** Canonical node-side entry point for
> the Traffic Classifier / Fingerprint Reputation work: the fingerprint evidence
> ledger (node grains: `solver_farm`, `challenge_score`, WAF-hit fp attribution),
> the actuator ladder, and the **ChallengeV2 rung**. The central store + policy
> live in **cfm-web (`cfm-web:docs/fingerprint-reputation.md`)**. Per-IP score
> deep-dive: `docs/challenge-score.md`. Everything here is **shadow** — the node
> emits evidence only; nothing on the node keys enforcement on a fingerprint.
> Superseded design notes folded into this hub: `docs/solver-farm-cross-host-phase2.md`,
> `docs/solver-farm-fingerprint-concentration.md`, `docs/fleet-fingerprint-reputation.md`.

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
stays an operator tool throughout.

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
  ideally corroborated by **JA4H** as a second axis) → **deny (403) outright**,
  residential or datacenter. It is the guilty unit.
- **Shared browser bucket** (`c28caa00`) → do NOT blanket-deny. Use a **harder
  *interactive* challenge** (ChallengeV2 drag/puzzle — beats the headless farm the
  PoW couldn't, and self-targets legit shared-bucket users), and/or narrow the
  deny to `(fp × JA4H)` or `(fp × farm-context)`, and/or IP-ban only the
  *datacenter* members while harder-challenging the rest.

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

- The fingerprint→IP mapping is only as complete as the captured sample (bounded,
  accumulates), so a farm's long residential tail is never fully enumerated — the
  seed must **degrade gracefully**: fingerprint-DENY/interactive-challenge for
  un-captured IPs sharing the fp, IP-ban for captured *datacenter* members.
- **JA4H as the uniqueness corroborator** is what makes "deny the bucket" safe —
  prioritise it for any fingerprint-DENY of a coarse TLS bucket.
- Thickening the spine with more conviction sources (WAF-block, abuse_shadow →
  fingerprint) needs the **attribution prerequisite**: the 2026-09-11 read caught a
  WAF scanner (Google Cloud, `WAF_TRAVERSAL`/`WAF_SQLI`/`WAF_PHP_WRAPPER` across
  spoofed bot UAs) whose `waf_*` events carry **no `tls_fp`** — carrying the
  edge-stamped `X-CFM-TLS` onto WAF findings is the first task there. See
  `cfm-web:docs/fingerprint-reputation.md §10`.

## Fingerprint evidence ledger — node → UI + cfm-web (2026-09-11)

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
`challenge_score` T1 rung.

**The honest hard part is the front-end, not the logic** — and it must be staged:
- **V2a — invisible interaction proof** (first): require genuine pointer/touch/
  scroll entropy + render/timing before clearance. A headless client emitting no
  pointer events fails silently; a real user never notices. Cheap, **accessible**,
  and it catches *today's* farm.
- **V2b — visible puzzle** (only if V2a is beaten): a rendered drag/rotate puzzle
  **with an accessible fallback** (keyboard/screen-reader — a pure drag-puzzle
  locks out disabled users: wrong, and a legal risk). Reserved for the hardest tier.

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
  likely-headless AND high-risk.
- **deny** — farm-UNIQUE fingerprint / confirmed datacenter only (unchanged).

#### Rung-1 signals → which headless-tell each catches

Ordered by spoof-resistance (= weight). **None is a gate; the *combination*
convicts.** Some are **positive-only** (fire → suspect; absent → proves nothing).

| Layer | Signal | Headless-tell it catches | Weight | Trips legit (FP) |
|---|---|---|---|---|
| **Transport** (server-observed, unspoofable from JS; already stamped) | **JA4 (TLS) ↔ UA** | UA claims Chrome N but the ClientHello JA4 isn't that browser's (curl-impersonate, Go/Node, old Chrome) | ★★★★★ | ~0 (rare TLS-terminating proxy/AV) |
| | **JA4H (HTTP/2)** — roadmap 2nd axis | h2 SETTINGS / header + pseudo-header order don't match the claimed browser | ★★★★★ | ~0 |
| **Environment / render** (JS probe; costly to fake per-request at scale) | **WebGL UNMASKED_RENDERER** | SwiftShader / llvmpipe / Mesa software renderer = headless/VM | ★★★★ | RDP/VDI/GPU-blocklisted reals → confidence, not gate |
| | **Canvas / audio hash** | software-render buckets; also session stability | ★★★ | Brave/Tor randomize → reals |
| | **Screen / viewport coherence** | mobile UA + desktop DPR/screen; `outerHeight=0` | ★★★ | unusual-but-real setups |
| | **hardwareConcurrency / deviceMemory / languages / plugins / fonts / timezone** | headless defaults; mobile UA + 32 cores; empty `languages`; tz vs Accept-Language mismatch | ★★ | locale-quirky reals; corroboration only |
| **Behavioral** (passive; noisy → score only) | **Touch ↔ UA** | mobile UA but `pointerType=mouse` / no touch / constant pressure | ★★★★ | low |
| | **Pointer entropy** | no motion before solve, or scripted linear / identical-`dt` vs human jitter | ★★★ | keyboard-only / touch users → absence ≠ bot |
| | **deviceorientation / devicemotion** | "phone" UA but zero/static sensor events | ★★★ | meaningful only when UA claims mobile (iOS needs a permission gesture) |
| | **rAF cadence / interaction latency** | cadence far from a real refresh; solve with zero input events / robotic timing | ★★ | throttled tabs; fast users |
| **Positive-only** | **`navigator.webdriver` / CDP artifacts** | `true`; missing `window.chrome`; headless UA leaks | (positive) | `false` proves nothing (trivially spoofed) |

Weighting rule: server-observed (JA4/JA4H) ≫ hard-to-fake render
(WebGL/canvas/audio) > behavioral entropy > trivially-spoofable JS flags.

#### Observability contract (shadow-first; reuses existing logs — no new log, per CLAUDE.md §5)

Rung-1 writes the SAME surfaces `challenge_score` uses (open-question #4
resolution — `docs/challenge-score.md` §8), so it is fully MCP-observable for
burn-in and FP triage with no new plumbing and no logrotate change:

- **`cfm.challenges.log`** (per solve; already logs `ua=`, `solve_ms=`,
  `ua_impossible=`): add `hs=<humanity_score>`, `tells=<fired,comma,list>`,
  `fp=<tlsfp>` — the raw grep surface for "which solve, and why".
- **`cfm.abuse_shadow.log`**: `signal=humanity verdict=would_v2 …` when the score
  *would* escalate — shadow, nothing served.
- **`detection_history`** (durable, fleet-pullable): fingerprint-anchored, rolls
  into cfm-web's `fingerprints` ledger as another per-client tell.

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
      actuators; alerts stay during burn-in).
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
