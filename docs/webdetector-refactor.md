# Web-detector refactor — smarter, targeted abuse detection

**Status: LIVING HANDOFF DOC.** This is the anchor for a multi-PR effort to make
CFM's challenge engine catch abuse it currently misses, and to challenge the
*abuser* rather than the *whole vhost*. It captures the why, the how, what we
already do (and why it isn't enough), the false-positive minefield, the
telemetry contract, and a running FP + progress log — so we can stop, collect
data for days, and resume without re-deriving anything.

Everything here ships **log-only first** (shadow evaluation, no enforcement),
and every shadow signal is designed to be **readable over MCP** so we can watch
it accumulate from the fleet gateway rather than SSHing into logs.

---

## 1. Why (the problem)

Today's auto-challenge decides at the **vhost aggregate** granularity, scored on
ratio features (`internal/webdetector/scoring.go`). Two failure modes fall out
of that, and the operator named both:

1. **Abuse passes "αβέρτα" below the score.** Aggregate features **dilute** the
   abuser into the legit traffic (95% good + 5% abuse → a calm vhost number).
   Clean scrapers that avoid errors, and low-and-slow distributed crawlers,
   never move the ratio score. So real bots/scrapers/attacks get a free pass.
2. **When it does fire, it's collateral.** A vhost-wide challenge hits every
   legit user of that site, not just the abuser.

Goal: **(A)** challenge the abusing *entity* (IP / subnet / ASN) directly,
leaving legit traffic untouched; and **(B)** arm a full-vhost challenge on
*smarter, concentration-aware* criteria when abuse genuinely dominates.

## 2. What already exists — and why it isn't enough

Grounded in the code (so we don't rebuild what's there):

- **Per-IP challenge — EXISTS, largely dormant.** `challenge_rules.go` §0/§2
  drive per-IP challenges from a rich set of per-IP thresholds
  (`ChallengeIPRPSMin`, `…4xxRPSMin`, `…5xxRPSMin`, `…ErrRatioMin`,
  `…PostRatioMin`, `…NoUAMin`, `…HTTP10Min`, `…MalformedMin`, `…UniqUAMin`,
  `ChallengeIPUniqPaths*`). All default **0 = off**. So the *targeting machinery
  already exists* — option (A) is a signals problem, not an enforcement-plumbing
  problem.
- **Per-subnet challenge — EXISTS.** `ChallengeSubnetEnabled` +
  `emitSubnetChallenges` aggregate by subnet (`subnetHostReqs`/`subnetIPs`/
  `subnetUniqPaths`).
- **Vhost-aggregate auto — the noisy part.** `tripReason` arms on
  `score ≥ ScoreOn && uniqIP ≥ MinUniqIP`, or on uniqIP thresholds. Live fleet
  data (2026-08-21) showed most real arms come via the **uniqIP path at very low
  rps** (e.g. `mathematica.gr` 179 IPs @ 0.27 rps; `himaira.gr` 163 @ 0.40) —
  i.e. distributed shapes — while benign low-traffic sites cluster at score
  0.3–0.6 on ratio noise but are saved from arming by the uniqIP floors.
- **ASN — resolved, but display-only.** `internal/enrich` (MaxMind
  GeoLite2-ASN) gives `Result{ASN uint, ASNName string}` inline (µs, no DNS) via
  `e.enr.Lookup(ip)` / `LookupGeoFast` / `LookupCachedOrAsync`. The **challenge
  decision never uses it.** PTR/FCrDNS is available for good-bot verification.

### Known score weaknesses (documented, being addressed separately)
- **Volume dead at vhost scale.** `scoring.go` refs are *server*-scale
  (`refRPSTotal=1000`, `refUniqueIPs=300`), so per-vhost RPS barely moves the
  score → the **volume floor** (score-path, log-only) landed in PR #1305
  (`CHALLENGE_SUSPICIOUS_VHOST_MIN_RPS`).
- **`err_ratio` counts 499, not 3xx.** `engine.go:1787`
  `ErrRatio = (c4+c5+c499)/tot`. 3xx is already excluded; **499 (client-closed)**
  is the benign inflator (slow clients, bot aborts, redirect-then-close) that
  pumps `high_error_ratio` even on 2-IP sites. Candidate: drop/deweight 499.
- **Ratios are windowed MAX** (`BotRatioMax`/`PathDivMax`/`UADivMax` in
  `longwin.go`) → a single bad 5s bucket pins them at 1.0.
- **`ua_diversity` ref=0.05 saturates** for nearly every vhost → a ~constant
  +0.5 offset with no discriminative power.

(These four are tracked in the backlog; #62. This doc's new work is the
entity-level signals below.)

## 3. The plan — three entity-level shadow signals, log-only → targeted

All three are **score-independent** (they don't depend on the diluted aggregate)
and feed the *existing* per-IP / per-subnet challenge once burned in. Each ships
log-only, is measured against real fleet traffic + an FP register (§8), then
promoted.

**REPRIORITISED after the 2026-08-20 evidence (see §4a).** The fleet's real
abuse is **residential**, so the ASN-agnostic signals lead:

- **Signal C — per-entity rate/behaviour outlier vs the vhost's own baseline**
  (an IP/subnet whose rate is a large multiple of the vhost `median_per_ip_rps`;
  `ip_skew` already exists). ASN-agnostic → catches residential AND cloud.
  **Counts DYNAMIC requests only** (`bucketSW.ipsDyn`, `isStaticAssetPath`
  excluded): a single human page view pulls 40–60 static assets on an
  asset-heavy theme, so counting them made a normal shopper read as a 300–900×
  outlier (the 2026-08 Greek-residential FP class). The enforced `uniqIP` path
  still counts all requests. Each shadow line also carries `cc=<ISO-2>`; the
  `abuse_shadow` tool surfaces a `by_country` split so a domestic-residential
  burst (likely FP) is obvious.
  Solves dilution directly. **← candidate first signal.**
- **Signal B — behavioural enumeration** (one IP walking many distinct
  product/category paths in order, low repeat — catalog scraping). ASN-agnostic.
  Reuses the per-IP uniq-paths metering + path entropy.
- **Signal A — datacenter/hosting-ASN origin — DEMOTED to a supplementary,
  logged-only *feature*, not a primary trigger** (§4/§4a). Narrow: it hints at
  cloud *scraping*, misses residential attacks entirely, and must never trust
  consumer traffic.

The **full-vhost fallback (B-side of the goal)** then arms on *concentration*
(ip_skew, ASN-concentration) rather than raw ratios.

## 4. Signal A: datacenter-ASN — and its false-positive minefield

**"Datacenter" ≠ "malicious."** This is the whole point of log-only-first. A
large amount of *legitimate* traffic originates from cloud/hosting ASNs, and we
must not challenge it blind:

- **Verified search bots:** Googlebot/AdsBot (AS15169, the *same* ASN as Google
  Cloud), Bingbot (Microsoft AS8075 / AS8068, same as Azure), Applebot,
  YandexBot.
- **LLM / AI crawlers:** GPTBot, ClaudeBot, PerplexityBot, Google-Extended,
  CCBot — mostly from cloud ranges.
- **SEO / monitoring:** AhrefsBot, SemrushBot, uptime monitors (UptimeRobot,
  Pingdom, StatusCake), security scanners the operator runs.
- **Ecommerce integrations:** XML/CSV **import/export** feeds, price/stock
  syncers, marketplace connectors, payment webhooks, headless-CMS build hooks —
  these legitimately hit a shop from AWS/Azure/GCP.

So the ASN flag alone is **not** an action signal — it's *one feature*.
Safeguards baked into the design:

1. **Good-bot exemption via FCrDNS (forward-confirmed reverse DNS)** — verify
   Googlebot/Bingbot/etc by PTR → forward A/AAAA match, NOT the spoofable UA.
   The enricher already provides PTR. Exempt verified good bots *before* any
   would-challenge verdict.
2. **Allowlists** — operator-maintained: UA substrings (AhrefsBot, GPTBot, …),
   ASN allowlist, and per-vhost integration allowlists (a shop that pulls a
   cloud feed service allowlists that source). Reuse existing IGNORE/exclude
   plumbing where possible.
3. **Log-only + FP register** — measure catch vs collateral for days before
   promoting; every observed FP goes in §8 with its (asn, ua, host) so the
   allowlist/keyword set is data-driven.
4. **Content-vhost scoping** — the signal is meaningful for consumer-facing
   sites (a shopper is never on Hetzner); it is NOT for API vhosts that expect
   machine clients. Per-vhost opt-in/opt-out.

### Classifier (this PR)
`internal/webdetector/asnclass.go` — pure, testable:
`DatacenterClass(asn uint, asnName string) string` returns a provider tag
(e.g. `"amazon-aws"`, `"hetzner"`) or `""`. **Curated ASN map is authoritative**;
a conservative org-name keyword fallback catches the long tail. It only answers
"is this hosting infrastructure?" — the good-bot exemption and burn-in are what
make it safe to act on. The curated list is intentionally non-exhaustive and
grows from observed data (§9).

## 4a. Reality check — abuse is RESIDENTIAL; datacenter-ASN is not the lens

**Evidence (2026-08-20, fleet WAF_SQLI autoblock alerts).** The overwhelming
majority of real attacks the fleet sees are SQLi/UNION-SELECT injection from
**Greek consumer ISPs** — AS3329 Vodafone, AS6799 OTEnet, AS25472/AS1241 Nova,
AS14593 Starlink, AS51505 ΔΕΗ — e.g. `89.44.94.244` (AS3329, PTR
`ppp089044094244.access.hol.gr`, a residential DSL line) hitting
`stereotiki.gr /store4/index.php?dispatch=1'%20AND%201=1%20UNION%20SELECT…`.
These are already caught by the WAF (`WAF_SQLI` → autoblock), independent of ASN.

Two consequences that reshape this whole effort:

1. **A datacenter-ASN signal would MISS the fleet's actual threat.** Residential
   attackers (botnets, compromised home machines, mobile NAT, VPS-free consumer
   lines) are the norm. Cloud-origin abuse is real but narrower (scraping). So
   datacenter-ASN is at best a supplementary *scraping* hint — never the primary
   abuse lens.

2. **THE HARD INVARIANT — additive-only, never trusting.** No signal here may
   ever treat "consumer ISP / Greek / OTE / Vodafone" as legitimate,
   safe, or a reason to lower suspicion. Origin is NOT innocence. Concretely:
   - `DatacenterClass()==""` means "no cloud-scraper-origin hint" — it must NEVER
     be read as "trusted", "normal", or "exempt". A residential IP gets exactly
     the same WAF + rate/behaviour scrutiny it always did.
   - The datacenter feature may only ADD a positive weight to a scraping-shaped
     request. It may never SUBTRACT from, or short-circuit, any other detector.
   - Any allowlist (§4) is keyed on **verified identity** (FCrDNS good-bot,
     explicit operator opt-in), NEVER on "it's a consumer/Greek ASN".

The detectors that actually catch residential abuse are ASN-agnostic and already
exist or are Signals B/C: the **WAF signatures** (SQLi/RCE/etc.), **per-entity
rate/behaviour outliers** (Signal C), and **enumeration** (Signal B). Those lead;
datacenter-ASN rides along as a logged feature we measure, nothing more.

## 4b. TWO abuse classes — edge-visible vs edge-invisible (backend cost)

**Evidence (2026-08-21, titan).** `evafeiadis` showed 15 lsphp workers @ ~70%
CPU on `/home/evafeiadis/public_html/index.php` + mariadbd @ 266%, and
`db_web_pressure` flagged it **#1 `few_hits_high_pressure`: 109,170 queries /
120s (~900 q/s) with web_hits=0, web_rps=0**. Yet the edge web-detector saw
`e-vafeiadis.gr` at **0.04 rps, 1 IP, 0 requests short-window**. The abuse is
real and severe, and **completely invisible to the edge** — it's backend-direct
(bypassing OpenResty/Angie) or expensive-per-request.

This splits the problem in two, and they need DIFFERENT detectors/enforcement:

- **Class 1 — edge-visible.** Requests flow through the edge access log.
  Detected by the WAF (signatures) + the challenge engine + **Signal C/B**
  (this doc). Enforceable at the edge (challenge/block).
- **Class 2 — edge-invisible (backend cost).** Little/no edge traffic but heavy
  CPU/DB. Detected by **`db_web_pressure` / `mysql_pressure` / `lve_cpu`**
  (already exist as READ tools; `few_hits_high_pressure` already flags it).
  NOT enforceable at the edge (the traffic isn't there) — enforcement is
  backend: alert, LVE throttle, kill runaway procs, IP-block from the account's
  own access log, or suspend.

Consequences for this effort:
- **Signal C (edge rate outlier) will NOT catch the evafeiadis class.** It is the
  right tool for Class 1 only. Don't over-claim it.
- The fleet's real, painful abuse in the observed cases is often **Class 2** —
  which CFM already *detects* but does **not auto-act on** (`db_web_pressure` is
  read-only; today it relies on CloudLinux LVE throttling + manual kill). The
  higher-value gap may be **turning `few_hits_high_pressure` into an
  alert/enforcement path**, parallel to the edge work here.
- **Open question — RESOLVED (2026-08-21):** it was the **`www` vhost**, not
  edge-bypass. The apex `e-vafeiadis.gr` was a red herring (0.04 rps);
  `www.e-vafeiadis.gr` is edge-visible at 2.74 rps and drives the backend. So
  this specific case is **Class 1** after all — Signal C catches it. (Lesson for
  the tooling: drill BOTH apex and www; consider folding www↔apex in the
  detector's host view.)

### Signal C — reference validation case (`www.e-vafeiadis.gr`, 2026-08-21)
The live shape Signal C must catch, and why it beats the vhost-aggregate score:
- Vhost aggregate: rps 2.74, 70 IPs, score **0.585 (< 0.72 on-threshold)** → the
  vhost-wide auto would NOT arm. Abuse hiding under the aggregate — exactly the
  "περνάει αβέρτα" case.
- But `ip_skew=11.56`, `median_per_ip_rps=0.008`, and TWO IPs
  (`37.6.1.149`, `109.242.116.126`, both AS25472 Nova / Greek **residential**,
  identical mobile UA) did **62 requests each in 120s ≈ 62× the vhost median**,
  hammering `/product_info.php` (osCommerce, DB-heavy) with a 4xx storm — which
  is the 109k-queries/900-qps backend pressure `db_web_pressure` flagged.
- **Signal C = per-IP rps ≫ vhost `median_per_ip_rps` (large ratio), gated by
  `ip_skew` and an absolute floor** flags exactly those two IPs, ASN-agnostically
  (they're residential), and challenges only them — leaving the legit Google-Ads
  shoppers (gclid referrers) and verified crawlers untouched. Candidate initial
  shadow rule: `per_ip_rps >= max(FLOOR, K × median_per_ip_rps)` with `ip_skew ≥
  S`; tune K/FLOOR/S from the shadow log.
- **Datacenter additive-only, validated:** the SAME vhost carries verified
  Googlebot (PTR `crawl-…googlebot.com`), Bingbot (`…search.msn.com`), Facebook
  meta-agent, AdsBot — several on cloud ASNs (AS15169, AS8075). A datacenter
  *trigger* would have hit these good bots; hence logged-only + FCrDNS exemption.

### Signal C is NOT a silver bullet — two SHAPES of edge-visible abuse

**Counter-example (2026-08-21, titan, `e-athlos.com`, live webtop).** score 0.37,
err 11.5%, **uniqIP 140**, bot 2%, ~5–8 rps. Top IPs are FLAT: #1=43 reqs, #2=37,
then a long slope to ~10 each; ASNs span South Africa, Brazil, Hong Kong,
Colombia, Nigeria, Pakistan, Ethiopia, Iraq, Jordan, Algeria, Spain… all hitting
`/shop/`, `/shop/page/2/`, `/product-category/`, product pages. A coordinated
DISTRIBUTED catalog scrape of a Greek bike shop.

- **Signal C would NOT catch this.** No per-IP outlier (top ≈ 4× median, not
  62×), **`ip_skew` is low**. Lowering K to reach the pack FPs legit bursty
  users; challenging the top 5 leaves 135 scraping. Wrong tool for this shape.
- **It's already handled** by the existing **uniqIP path** (140 uniqIP → the
  header shows `CHALLENGE auto` ON; `/__cfm_challenge` + `/__cfm_verify` are the
  top paths).

So edge-visible abuse has **two shapes**, needing different signals — Signal C is
only the first:

| shape | example | detector |
|---|---|---|
| **Concentrated** (few IPs, high per-IP rate) | e-vafeiadis (2 IPs @ 62× median) | **Signal C** (per-entity rate outlier) |
| **Distributed** (many IPs, low per-IP rate) | e-athlos (140 IPs @ ~10 each) | **uniqIP aggregate** (exists) + **Signal B** (collective enumeration across the catalog) + **origin-dispersion anomaly** (a local shop lit up from 20+ unrelated countries/ASNs is itself the signal) |

**Signal D idea (new, from e-athlos):** *origin-dispersion / audience anomaly* —
flag a vhost whose live traffic's country/ASN entropy is wildly inconsistent
with its baseline audience (a Greek shop does not normally get coordinated hits
from Ethio Telecom + Pakistan Telecom + Jordan Data). Per-vhost, distributed-shape
detector; complements the uniqIP path. Backlog.

**Takeaway for scope:** don't sell Signal C as "the" abuse detector. It targets
the concentrated shape. The distributed shape is (a) already partly covered by
uniqIP and (b) needs Signal B / Signal D. Build C first (it's the clean gap:
concentrated abuse under the aggregate score, like e-vafeiadis), measure, then B/D.

## 5. Telemetry contract — MCP-readable (hard requirement)

Shadow signals must be **queryable over MCP**, not just greppable, so we can
watch them accumulate from the gateway. Contract:

- Each shadow hit emits ONE structured line to a dedicated, logrotated file
  (proposed `/var/log/cfm/cfm.abuse_shadow.log`), throttled per entity:
  ```
  [abuse-shadow] signal=datacenter_ip host=<vhost> ip=<ip> asn=<n> asn_name="<org>"
      provider=<tag> good_bot=<none|googlebot|bingbot|…> ua="<ua>" rps=<f>
      uniq_paths=<n> verdict=<would_challenge|exempt_goodbot|exempt_allowlist>
      reason=<why>
  ```
- A future **MCP tool `abuse_shadow`** (node-level, read-only) aggregates that
  log the way `waf_fp_hunt` aggregates logonly WAF: counts by
  signal/provider/host, top would-challenge entities, and the `exempt_*` split
  (so FPs are visible as data). Add it under the CFM gateway too (`node="all"`)
  for a fleet view. **Any signal we add MUST land its shadow line in this format
  so the tool can read it without per-signal special-casing.**
- Nothing enforces during burn-in. Promotion = flip a per-signal `…_ENFORCE`
  and route the verdict into the existing per-IP/subnet challenge.

## 6. Config (all default OFF; good-bot exemption default ON)

- `ABUSE_SHADOW` — master log-only switch (default 0).
- `ABUSE_SHADOW_DATACENTER` — Signal A shadow (default 0).
- `ABUSE_SHADOW_GOODBOT_EXEMPT` — FCrDNS good-bot exemption (default 1).
- (later) `…_ENUMERATION`, `…_RATE_OUTLIER`, per-signal `…_ENFORCE`,
  allowlist keys.

## 7. Increments / status

- [x] **I0** — this design/handoff doc.
- [x] **I1** — datacenter ASN classifier (`asnclass.go`) + tests. *(pure, no
  behavior)*
- [x] **I2** — `ABUSE_SHADOW*` config + per-IP **Signal C** (rate outlier)
  shadow emission, log-only, with good-bot FCrDNS exemption + datacenter tag +
  the dedicated `/var/log/cfm/cfm.abuse_shadow.log` (glob-rotated). All off by
  default. *(Signal A/datacenter is a logged tag here, not the trigger — per §4a.)*
- [x] **I3** — `abuse_shadow` MCP tool + `/api/v1/system/abuse-shadow` endpoint
  (`internal/abuseshadow` tail+aggregate). Fleet-wide via the gateway
  `node_call node="all"` (no gateway change — passthrough). Admin-only, read-only.
- [ ] **I4** — Signal B (enumeration) shadow. **I5** — Signal C (rate outlier).
- [ ] **I6** — promote whatever the data justifies to per-IP/subnet challenge.
- [ ] **I7** — smarter vhost-wide arm on concentration signals.

### Deferred to the enforcement-promotion follow-up (from the I2 review)
- **Throttle-map reaper.** `vhostSuppressLoggedAt` gains a per-`(host,ip)` key
  and is never pruned → a slow accumulation over days when enabled. Fine for
  burn-in (tiny entries), but add a reaper before enforcement.
- **Cancellable DNS.** The good-bot reverse/forward lookups use
  `context.Background()`, so the run watchdog can't interrupt them. The per-tick
  cap (`maxShadowEnrichPerTick=50`) bounds the worst case for now; thread the run
  ctx into the lookups when promoting to enforcement.
- **IPv6 exemption compare** is now `net.IP.Equal`-based (fixed in I2), but the
  broader per-IP challenge path should be audited for the same when C promotes.

## 8. False-positive register (append as found)

Format: `date | host | ip | asn (name) | ua | why-it's-legit | action`.

- _(none yet — populate from the I2 burn-in)_

## 9. Progress log (append)

- **2026-08-21 (course correction)** — Operator flagged, with WAF_SQLI evidence
  (§4a), that the fleet's real abuse is RESIDENTIAL (consumer-ISP SQLi), so
  datacenter-ASN is the wrong primary lens and "consumer/Greek ISP" must never
  imply legit. Reprioritised: Signals C/B (ASN-agnostic) lead; datacenter-ASN
  demoted to a logged supplementary feature under a hard additive-only invariant
  (§3, §4a). Classifier header updated with the invariant. **Open decision: which
  ASN-agnostic signal (C rate-outlier vs B enumeration) becomes the first I2
  log-only shadow.**
- **2026-08-21** — I0 doc + I1 classifier landed. Curated cloud-ASN set seeded
  from the fleet's own top-blocked ASNs (orion `firewall_blocks`: AS8075
  Microsoft, AS63949 Akamai/Linode, AS9009 M247, AS212238/60068 Datacamp,
  AS14061 DigitalOcean, AS16509 Amazon, AS45102 Alibaba, AS396982 Google,
  AS23470 ReliableSite, AS51167 Contabo). Grow from I2 data.
