# Abuse defense — progress journal

> **Start here.** This file is the running record of what the fleet actually
> shows, one entry per read. It answers "where are we, on which version, and
> what did the data say". The PLAN and every DECISION live in
> `docs/abuse-defense-master-plan.md`; the design and the meaning of every log
> field live in `docs/traffic-classifier.md`. A read records numbers here; when
> a read leads to a decision, the decision goes into the master plan and the
> entry links to it. Newest entry first.

## 1. Where everything lives

| Question | Doc |
|---|---|
| What is planned, decided, frozen, dropped (D1–D5, §5 candidates, E4) | `docs/abuse-defense-master-plan.md` |
| What a tell / reading / log field means; ChallengeV2 Rung 1 design; the rescue; the trajectory readings | `docs/traffic-classifier.md` (Auto-v2; "Who the deterministic-FP residual is"; Observability contract) |
| The condensed hard-won rules for this area | `CLAUDE.md` §6 "Traffic classifier / fingerprint reputation" |
| Per-IP `challenge_score`; the PoW / solver roadmap | `docs/challenge-score.md` · `docs/roadmaps/challenge-engine.md` |
| The WAF `challenge_v2` tier (per-IP rung mark) | `docs/waf.md` "The `challenge_v2` tier" |
| Under-Attack Mode | `docs/under-attack-mode.md` |
| What a cPanel (scoped) user can see of all this | `docs/endpoint_scope_inventory.md` (history payload redaction) |
| The central fingerprint ledger and the operator policies | `cfm-web:docs/fingerprint-reputation.md` |
| The knobs and their defaults | `configs/detectors.conf` (`[webdetector]` `CHALLENGE_V2_*`, `ABUSE_SHADOW`, `FP_POLICY`, `UNDER_ATTACK_*`) |

## 2. Current picture (update on every read)

*As of 2026-10-20 (read 3, the last E4 read).*

- **Fleet version:** the 7 web nodes run `2026.10.19`, deployed
  2026-10-19 15:26. The 4 nodes without an edge serve no challenge:
  mymail, saf and watchdog run `2026.10.08`, and 3deers runs `2026.09.26`.
- **Live since release 2026.09.29** (deployed 2026-09-29/30):

  | PR | What |
  |---|---|
  | #1520 | **Auto-v2**: the automatic vhost challenges (`suspicious_vhost`, `uniqpaths_short`, `under_attack`) run at ChallengeV2; per-vhost tier pins |
  | #1521 | WAF rule 603 stops challenging WebDAV sync clients |
  | #1522 | A WAF rule's v2 rung follows its per-IP challenge; a panel solve can't lift it |
  | #1523 | `ua_lie` tell (legacy Edge token on Chrome/80+) |
  | #1525 | `scope=` on solve / reject / would_v2 lines and rows |
  | #1526 | `challenge_v2` WAF push dedup is host-agnostic |
  | #1528 | **Real-input rescue** (`v2_rescued=input`; kill switch `CHALLENGE_V2_INPUT_RESCUE`) |
  | #1529 | **Trajectory readings** (`ut co st dj mj pd` in `sig=`) and trusted-only input |
  | #1530 | The `v2` / `v2_*` history keys hidden from cPanel users |
  | #1531 | The `solver_farm` IP sample (`ips`, `good_bots`) hidden from cPanel users (a cross-host sample held other tenants' visitors) |

  Later releases (2026.09.30 to 2026.10.04) added, in this area: #1532 (a
  second open tab reaches its own page), #1537 (the challenge-exclude file's
  ua/asn rules apply at serve time) and #1539 (Twitterbot, Google-Read-Aloud
  and Meta's facebookcatalog exempted).

  Releases 2026.10.08 to 2026.10.11, deployed by 2026-10-11, added, in this
  area:
  - #1546: the challenge page sends exempt clients to `next`;
  - #1547: a `cfm_rt` is consumed only by its owner;
  - #1574: the fppolicy armed reserve;
  - #1582 and #1584: web bans at the edge;
  - #1587: a verified good bot is never IP-banned.

  Release 2026.10.19 added #1602 and #1603: the challenge page lives only
  at `/__cfm_challenge`, and a cleared client bounced back by a CDN cache
  gets one `cfm_nc` retry (`cdn_cached_challenge`, edge_health Check F).
- **What bites today:** operator-armed fingerprint / country-ASN policies
  from cfm-web (still no `v2=geo` line in read 3's week), the WAF challenge
  tier at `challenge_v2`, manual vhost v2 tiers, the automatic vhost
  challenges (auto-v2) and the rescue.
- **What the arm catches (first measured in read 3):** under an armed vhost
  the convicted farms passed 232 431 solves and were rejected 150 339 times
  on orion, titan and mars, so the arm stopped about 39 % of their solves.
  Their passes score `hs` 0, 60 or 90, under the fail score by design (D5b).
  Stopping the rest is the operator fingerprint policy's job (E3), not a
  harder score.
- **Under measurement:** the auto-v2 false-reject rate on humans, the
  rescue (`v2_rescued=input`), the trajectory readings (humans vs farms).
- **Watch items** (findings, not decisions; details in the newest entry):
  1. Farm solves with no payload (`hs=-`) pass an armed vhost, by design
     (D5b). This happened 658 times in read 3 (orion 386, titan 261), up from
     378 in read 2 and 227 in read 1. Still under 0.5 % of the farms'
     passes.
  2. *(Closed in read 2.)* Google-Read-Aloud and Meta were served the
     challenge through the challenge page's own URL. #1546 fixed this.
  3. The challenge page sends Meta to `next`, and the edge challenges it
     again.
     - Read 3 has 1 410 such loops on mars shopzy.gr (mostly
       `goodbot:meta`, the rest Meta exclude rules) and 15 on titan, where
       stereotiki dropped from 13 418 to 2.
     - shopzy.gr sits under an AUTOMATIC `suspicious_vhost` v2 challenge.
       Its reason is `scanner_like_path_diversity`, and the loopers are
       Meta's ad-preview fetches of its product URLs (`utm_source=fb`).
     - The edge's challenge source is still not proven. By the code, the
       decision and the page run the same cache-only good-bot verdict and
       the same exclude matcher. That leaves the Step-0c fingerprint floor,
       which only the edge sees.
     - No harm, since the breaker serves the page.
     - Since 2026-10-19 a CLEARED client's second bounce logs
       `cdn_cached_challenge`, not `next_redirect_loop`. So `why="cleared"`
       counts are not comparable with reads 1–2.
- **Open decisions** (master plan §5 / E4). Read 3 carries a proposal for
  each; none is decided until the operator says so:
  1. **The rescue.** Proposed: keep it, and cap it at the fail score
     (rescue only `hs ≤ 100`). In three weeks it never fired, so the cap
     costs no measured human. It would keep the device-claim farm families
     (`mobile_hw_lie` / `mac_hw_lie`, ~93 000 of read 3's 153 354 rejects)
     rejected even if they learn to post fake input.
  2. **α (the Rung-2 confirm fallback).** Proposed: do not build it now.
     One profile is walled off, 3 IPs this week: Windows Chrome/109, no
     input, `outer_zero` on every retry. First confirm whether those are
     minimized windows.
  3. **`cfm_pcw` exit review.** Proposed: keep it as log-only evidence. Do
     not promote it: there is no actuator, and 20 of its 28 episodes this
     week were humans. Do not retire it: D3a, it is alive and nothing else
     names its datacenter scrapers.
  4. Config decisions after E4: `vhost_config` in auto-v2; the shipped
     `solver_farm` defaults; the orphan `HUMANITY_*` keys.
- **Next read:** none scheduled. E4's three reads are done; a further read
  follows an operator decision (e.g. a week after the rescue cap ships).
- **Kill switches, if a read shows harm:** `CHALLENGE_V2_INPUT_RESCUE = 0`
  (rescue off) · `CHALLENGE_V2_AUTO_VHOST = off` (auto-v2 off) · per vhost
  `cfm webtop challenge tier <vhost> v1` · `CHALLENGE_V2_HW_TELLS = 0` ·
  `FP_POLICY = 0` (every operator policy) · `CHALLENGE_V2_PASSIVE = 0` (the
  whole rung, telemetry included).

## 3. Fleet state

| Node | Edge | Version | `ABUSE_SHADOW` | History kept | ChallengeV2 knobs |
|---|---|---|---|---|---|
| earth | openresty | 2026.10.19 | 1 | 30 d / 1M rows | defaults |
| mars | openresty | 2026.10.19 | 1 | 30 d / 1M rows | defaults |
| orion | angie | 2026.10.19 | 1 | 30 d / 1M rows | defaults |
| rigel | openresty | 2026.10.19 | 1 | 30 d / 1M rows | defaults |
| server.speedhost.gr | openresty | 2026.10.19 | 1 (since 2026-09-29) | **7 d** | defaults |
| titan | openresty | 2026.10.19 | 1 | 30 d / 1M rows | defaults |
| virgo | angie | 2026.10.19 | 1 | **7 d** | defaults |

`/var/log/cfm/*.log` (challenges, abuse_shadow) keeps 14 generations, daily
or at 200 MB, so a busy node may hold less than 14 days. **A read therefore
covers the last 7 days**: every source holds that much on every node. A
week missed is a week lost on virgo and speedhost.

## 4. Signals under measurement

| Signal | Where to read it | Since | What would change a decision |
|---|---|---|---|
| Auto-v2 rejects of humans | `detection_history type=challenge_v2_reject` with `v2=vhost`; humans = GR/CY consumer ISP ASNs, no bot UA | #1520 | Humans rejected with no pointer input → α; many → `vhost` sources or pins |
| Real-input rescue | `v2_rescued=input` on solve lines / `challenge_solved` rows; `abuse_shadow` `humanity.rescued` | #1528 | Any rescue on a **convicted farm fingerprint** → farms fake input → kill switch or tighten |
| Trajectory readings | `sig=` `ut co st dj mj pd`, humans vs convicted-farm solves | #1529 | A band humans never cross and farms do, stable across reads → a tightening rule |
| Would-reject sizing | `abuse_shadow` `humanity` (`lines`, `rescued`, `by_src_kind`) | #1525 / #1528 | Sizes any new v2 arm before it is turned on |
| Payload health | the `hs=-` share of scored solves | — | A jump after a release = the page payload broke (parse / 1 KB cap) |
| Payload stripping under an arm | `hs=-` solve lines that carry `v2=` (a pass: D5b never fails a missing payload) | read 1 | A rising share on a convicted fp = the farm bypasses the arm by stripping the body → a master-plan decision |
| Farm catch rate under an arm | farm-fp `result=solved` vs `result=v2_reject` lines carrying `v2=` (per node: `c28caa00`, `95070673`) | read 3 | Sizes how much of a farm the arm stops (read 3: ~39 %); a falling rate on a convicted fp = the farm scores under the fail score → the operator fingerprint policy (E3), not a harder score |

## 5. Entry template

```
### YYYY-MM-DD — read N (window: 7 days to YYYY-MM-DD)
- Fleet: versions per node; PRs live since the last read; knob changes;
  armed operator policies.
- Health: hs=- share; trajectory keys present.
- Arms: challenge_v2_reject by v2 / v2_via / src / scope; human-labelled
  rejects (UA, tells, sig).
- Rescue: v2_rescued=input count by grain; RED FLAG check on convicted fps.
- Trajectory: humans vs farms — median / p10 / p90 of ut, co/ptr, st, dj,
  mj, pd; farm solves at ptr>=5 and mv>=100.
- Since last read: what moved.
- Actions: none / what was done (link the master-plan decision if any).
```

**Method notes** (learned in read 1; they decide what a read can reach):

- Query `detection_history` one node at a time; `node="all"` drops the big
  nodes' rows. A single call returns at most ~10 MB through the relay:
  about 9 000–12 000 reject rows, which on titan and orion is only the
  newest ~3 days. Say so in the entry, with the span.
- For the human check on those nodes, grep the challenges log by ISP name
  (`asn_name="OTEnet`, `asn_name="Vodafone-panafon`, `asn_name="Nova
  Telecom`) with `rotated=14`. A `cc=GR` grep fills its 2 000-line limit in
  2–3 days there.
- `cfm_log_tail` reads at most ~200 000 rotated lines. That is the full week
  on most nodes, but only from ~10-01 on mars and orion. With a small
  `limit` it stops early, so `matched` is not a count; count from the lines.
- Log lines carry node-local time (Athens, UTC+3). History `ts_utc` is UTC.
- **Read 2 onwards: parse the nodes' own logs over SSH (read-only)** when
  the operator's SSH access is available. Use `cfm.challenges.log*`,
  `cfm.abuse_shadow.log*`, `challenge.access.log*` and the edge's
  `access.cfm.log*`, with a python script fed on stdin. Nothing is written
  on the node. This covers the full week on every node, with no relay cap.
  - Pool trajectory percentiles from per-node 5 % quantiles.
  - `would_v2` lives in the abuse_shadow log (`signal=humanity
    verdict=would_v2`), not in the challenges log.
  - `challenge.access.log` records only `/__cfm_verify` POSTs.
  - `access.cfm.log` records challenged and blocked requests, not passes.
  - `post_resume_applied` is logged at INFO, below the edge's error_log
    level, so a replay is not countable.
- Human label = GR/CY consumer ISP ASN **and** a GR/CY address, no bot UA.
  A Greek public-sector or school network (AS8248, PTR `…sch.gr`) also
  counts.
  Starlink (14593) and Vodafone IPs also carry farm exits; check the fp and
  `hc` before calling a reject human.

## 6. Entries

### 2026-10-20 — read 3 (window: 7 days to 2026-10-20 12:00 Athens)

The third and last E4 read. Same method as read 2: every node's own logs
parsed over SSH (read-only, python on stdin), full week on every node.
Section *Proposals* closes E4 with one proposal per open decision. None is
decided: the master plan records only what the operator decides.

- **Fleet:**
  - The 7 web nodes ran `2026.10.13` from ~10-13 21:00, then `2026.10.19`
    from 10-19 15:26 (same binary mtime on all 7). In this area 2026.10.19
    carries #1602 / #1603 (the challenge page only at `/__cfm_challenge`; the
    `cdn_cached_challenge` one-time retry). The edgeless nodes are unchanged.
  - Knobs: every web node's `detectors.conf` was rewritten on 10-15 at
    14:58, a fleet push. No ChallengeV2, `FP_POLICY` or
    `POST_CLEARANCE_CADENCE` key is set on any node. mars carries no
    `ABUSE_SHADOW` line, yet its abuse_shadow log keeps writing, so the
    key is set elsewhere (e.g. an overlay).
  - The convicted farm fingerprints are unchanged: `c28caa00`, `95070673`,
    `19877aeb`, `ba6b4aad` (cfm-web, `fingerprints min_verdict=farm`).
  - Operator policies: again **no `v2=geo` line** anywhere, and no reject
    under a fingerprint policy.
- **Health:**
  - 735 solves with no payload (`hs=-`) among 292 790 solves. 729 were on
    farm fingerprints, so no page break.
  - 658 of them were farm **passes under an arm** (orion 386, titan 261).
    Read 2 had 378 and read 1 had 227. That is watch item 1, still under
    0.5 % of the farms' passes.
  - The trajectory keys are present. `ut` was 0 on all 6 608 labelled
    lines with pointer input.
- **Arms:** `challenge_v2_reject` lines per node, all `scope=web`:

  | Node | Rejects | Main hosts |
  |---|---|---|
  | orion | 91 149 | www.mathematica.gr 82 980, mathematica.gr 3 447, www.vitolighting.com 3 200 |
  | titan | 42 985 | www.e-vafeiadis.gr 24 619, gastronom.hk 12 066, e-athlos.com 2 946 |
  | mars | 17 679 | happy-nest.gr 16 285, ksilokosmos.gr 507 |
  | earth | 925 | agrologio.gr 489, motopegasus.com 384 |
  | virgo | 474 | mygreecetours.org 464 |
  | rigel | 112 | karagilanis.gr 27, santorinitours.org 14 |
  | server.speedhost.gr | 30 | pittakistore.gr 15 |

  - Total 153 354: 3.8× read 2 (40 644), most of it the same farm-hit
    vhosts.
  - Under `v2=vhost`: 153 060.
    - `auto:suspicious_vhost` 142 252, `auto:uniqpaths_short` 10 808.
    - No `manual` or `pin` reject.
  - Under a mark: 294. These are mars rule `r_b13ec7fcf4d408fc` 199,
    virgo rule `r_1eccbeb26f4117cd` 10, and WAF 302 / 502 / 602 85.
  - By fingerprint: `95070673` 91 324, `c28caa00` 60 673, `19877aeb` 35,
    no fp 1 275 (mars 914), other 47.
  - Farm rejects by score and tells:
    - On orion, titan and mars, ~93 000 carry a device-claim tell
      (`sw_renderer,mobile_hw_lie,no_input` at 140 is the biggest family).
    - ~42 000 are `sw_renderer,outer_zero,no_input` at 130.
    - ~15 000 are `sw_renderer,outer_zero` at 100.
    - ~7 000 carry webdriver or a headless UA.
    - Nearly every farm reject has `no_input`.
  - **The farm catch rate, measured for the first time.** Farm solves
    under `v2=vhost`:

    | Node | Passed | Rejected | Caught |
    |---|---|---|---|
    | orion (`95070673`) | 191 812 | 90 833 | 32 % |
    | titan (`c28caa00`) | 39 810 | 42 926 | 52 % |
    | mars (`c28caa00`) | 809 | 16 580 | 95 % |

    - The passes scored `hs` 90 (orion 141 644), 60 (orion 40 264) and 0
      (titan 22 229, a clean real browser).
    - All of them are under the fail score by design: `sw_renderer` alone
      is a real person on RDP (D5b).
- **Human-labelled rejects: two profiles.**
  1. *Pointer-light Chrome/109, recovered on the retry (3 IPs).*
     - Who:
       - orion www.mathematica.gr, two Greek school networks (AS8248
         CTI Diophantus, `…sch.gr`), 10-16 and 10-19;
       - mars www.anastasiadi.gr, an OTEnet IPv6 visitor from a Google Ads
         click, 10-16.
     - The reject: Windows Chrome/109, fingerprint `260c7eae`, hs 100
       (`sw_renderer,outer_zero`), ptr 1–3 and mv 0–2, so the rescue could
       not apply.
     - All three passed 4–7 s later, once `outer_zero` was gone (hs 9, …, 60;
       anastasiadi's retry moved 27 events / 642 px). This is the same
       recovery as reads 1 and 2.
  2. *No input at all, never recovered (3 IPs, 18 rows), titan.*
     - Who: Nova residential lines (`…tellas.gr`). nlf.gr, one deep product
       URL, from two IPs on 10-18 and 10-19; www.e-vafeiadis.gr on 10-19.
     - The reject: Windows Chrome/109, `260c7eae`, hs 130
       (`sw_renderer,outer_zero,no_input`), ptr 0.
     - Each IP retried six times over ~2 minutes, every time with
       `outer_zero`, and never solved.
     - `260c7eae` also solved 18 times on titan this week with real input
       (ptr 21–58), so the bucket is a genuine browser population.
     - The persistent 0×0 outer window with no input fits a minimized
       window or a background tab (Chrome reports outerWidth/Height 0 for a
       minimized window). That is a hypothesis, not measured.
  - Not human: mars athensescorts.uk.com, an OTEnet IP with `webdriver` and
    16 cores (hs 190, 5 rows), is automation.
  - Google-Read-Aloud and Meta: 0 reject rows.
- **Rescue:**
  - No `v2_rescued=input` anywhere: solve, reject and would_v2 lines, all 7
    nodes. That makes three weeks with zero rescues.
  - **RED FLAG check: clear.**
  - Lines with real input (ptr ≥ 5, mv ≥ 100): humans 806 and farm fps 757.
    None was rejected; all passed on score.
- **Would-v2 sizing (unarmed, `abuse_shadow` humanity):**
  - 26 927 lines, 26 840 of them on farm fps. No human-labelled line and no
    rescued line.
  - The residue is still the two farm sources: `vhost:vhost_config` 16 931
    (orion mail.mathematica.gr) and the v1 rule `r_57e05719c3d78f21` 4 504
    (mars).
- **Trajectory:** humans vs farm fps, lines with pointer input only.
  Pooled from per-node 5 % quantiles, so values are interpolated.

  | Reading | Humans p10 / med / p90 (n 1 662) | Farm fps p10 / med / p90 (n 4 946) |
  |---|---|---|
  | ptr | 1 / 9 / 43 | 1 / 1 / 19 |
  | mv (px) | 3 / 156 / 1 310 | 0 / 0 / 531 |
  | co/ptr | 1.1 / 2.0 / 7.5 | 2.0 / 2.0 / 4.5 |
  | st | 0.36 / 0.96 / 1.0 | 0.57 / 0.98 / 1.0 |
  | dj | 0.30 / 0.94 / 3.0 | 0.32 / 0.75 / 1.81 |
  | mj (px) | 2 / 37 / 272 | 0 / 0 / 138 |
  | pd (ms) | 50 / 555 / 3 140 | 52 / 427 / 1 530 |

  - Where both sides really move (ptr ≥ 8, mv ≥ 200), `st ≥ 0.99` covers
    18 % of human lines (116 of 629) and 28 % of farm lines (158 of 556).
    Reads 1 and 2 had 20 / 34 % and 16 / 23 %.
  - Three reads agree: the ranges overlap, and no band separates the two.
    **No trajectory rule.**
- **Watch item 3 (Meta loops):**
  - Exempt-client `next_redirect_loop` lines: mars 1 416, titan 15, virgo
    18, earth 8, orion 6, rigel 2, speedhost 0.
  - Titan's www.stereotiki.gr: 2 (read 2: 13 418).
  - mars shopzy.gr: 1 410, all Meta (mostly `goodbot:meta`, the rest the
    AS32934 exclude rules), from `173.252.69.x` fetching ad product URLs
    (`utm_source=fb`).
  - shopzy.gr is under an **automatic `suspicious_vhost` v2 vhost
    challenge**, reason `scanner_like_path_diversity`. Meta's own ad-preview
    fan-out may be what scores it. The edge also 429s Meta there
    (`meta_host_rps`).
  - The edge line shows the content URL proxied to `cfm_challenge`, with no
    reason field.
  - Code read: the decision path and `challengePageExempt` run the same
    cache-only good-bot verdict (`goodBot.verified`) and the same exclude
    matcher (`ChalExcludeHot` with the inline mmdb ASN). So the mismatch
    is not in those two. The candidate stays the Step-0c fingerprint
    floor, which the page never sees.
  - To prove it, one request with the edge's debug headers on
    (`X-CFM-Dec-VH`, the `fp_floor=` route note): an operator action.
- **CDN-cache retry (since 10-19 15:26):** `cdn_cached_challenge` 7 lines,
  all on 10-20 (rigel amabilecreations.com 4, titan ioannidis-bros.gr 2,
  orion queerdoc.com 1). None reaches Check F's 3-client floor.
- **`cfm_pcw` (D3a check):**
  - `edge_error_tail grep=cfm_pcw node="all"`: 0 matches. But the live
    error logs hold only ~20 000 lines (hours).
  - The rotated edge error logs, read over SSH, hold 37 `[cfm_pcw]` lines
    in the week (mars 24, rigel 8, titan 3, orion 1, earth 1; virgo and
    speedhost 0). Orion's angie logs reach back to 09-21 with 7 more.
  - It is wired on all 7 nodes: the module, the `lua_shared_dict`, and the
    knob at its default.
  - 28 distinct (ip, host) episodes:

    | Shape | Episodes | Examples |
    |---|---|---|
    | GR residential on one shop's paginated tag pages | 14 | mars ksilokosmos.gr `/product-tag/…/page/2/`, Cosmote / Vodafone / Nova, Google Ads traffic |
    | Logged-in admin or webmail | 6 | `wp-admin/post.php`, `admin-ajax.php`, roundcube ×2, an OpenCart-style `flexboard` admin |
    | Datacenter IPs (3 IPs) | 5 | `91.99.217.205` (Hetzner) on 3 vhosts across rigel and orion, `78.47.142.243` (Hetzner), `34.216.175.253` (AWS) |
    | Unknown, Asian residential | 3 | rigel santorinitours.org |

  - None of the episodes came from the convicted farms.
- **Since last read:**
  - Rejects rose 3.8×, nearly all auto-v2 on farm-hit vhosts.
  - The arm stops ~39 % of farm solves; the rest pass under the fail
    score, as designed.
  - The no-input Chrome/109 profile is the first human class that does
    not recover on its retry: 3 IPs.
  - The rescue still has not fired, and the trajectory readings still do
    not separate humans from farms.
  - Meta's loops moved from titan to mars shopzy.gr, under an automatic
    vhost challenge.

#### Proposals (for the operator; nothing is implemented without a go)

**(a) The real-input rescue: keep it, and cap it at the fail score.**
- *The rule as shipped* (`challengeV2InputRescue`): a failing solve with
  ptr ≥ 5 AND mv ≥ 100 and no certain tell (webdriver, headless UA) is
  rescued at any score.
  - Without the 30-point `no_input`, which real input removes, the highest
    such score is 150 (`sw_renderer` 60 + `outer_zero` 40 + one device-claim
    tell 50).
- *Proposed:* rescue only when `hs ≤ CHALLENGE_V2_FAIL_SCORE` (100 by
  default): one comparison in `challengeV2InputRescue`.
- *Measured cost, three weeks:*
  - **Humans lost: 0.** The rescue fired 0 times at any score. The only
    measured class it exists for (Chrome/109 on a software renderer with no
    window size) scores exactly 100 and stays rescuable.
  - **Farm solves excluded from it:** today, also 0, since no farm faked
    input.
  - What the cap protects is the next step. Nearly every farm reject
    carries `no_input`, so a farm that learns to post ptr ≥ 5 / mv ≥ 100
    loses 30 points AND gets rescued.
  - With the cap, the ~93 000 device-claim rejects of this week
    (`mobile_hw_lie` / `mac_hw_lie` + `sw_renderer`, 110–150, a family the
    hardware-tells corpus measured on 0 humans) stay rejected even then.
  - The ~57 000 `sw_renderer,outer_zero` rejects (100, or 130 with no
    input) stay rescuable by faked input, cap or no cap. That bucket is
    shared with the human class, and it is the honest residual.
- *Alternative:* leave it as is. Equally free today, and one less change.
  - The argument for the cap: it costs nothing measured, and it closes the
    cheapest way past ~60 % of today's rejects before a farm finds it.

**(b) α, the Rung-2 confirm fallback: not needed now.**
- Three reads found human rejects without real pointer input:
  - reads 1 and 2: 1 each;
  - read 3: 3 that recovered and 3 that did not.
- Every one that recovered did so on the plain retry, within seconds
  (`outer_zero` goes away).
- The only class walled off is read 3's 3 IPs: Windows Chrome/109, no input
  at all, `outer_zero` on every retry.
  - If they are minimized or background windows, a confirm step would not
    reach them either: nobody is looking at the page.
  - If they are kiosk-style users who never touch the mouse, α is the fix.
- *Proposed:* do not build α. First tell those two cases apart. The
  cheapest way is a one-key page reading, `document.visibilityState` at
  solve time (a `vs` sig key, log-only, scored by nothing, under the D5
  rules). Then decide on the next read that carries it.
- Revisit α if a pointer-less human class shows up while the page was
  visible.

**(c) `cfm_pcw` exit review (master plan §5 candidate 2): keep, as log-only
evidence.**
- *D3a:*
  - It emits: 37 lines in 7 days on 5 nodes, all wired.
  - What it names is not obviously covered elsewhere: a solved client then
    pulling ≥ 30 pages a minute, three datacenter IPs among them, one of
    them on three vhosts across two nodes. A retire would first have to show `rate_outlier`
    (or another signal) holds those same IPs. That was not checked, so no
    retire.
- *No promote:*
  - There is no actuator: B3 is dropped, and the edge has no "harden" rung.
  - 20 of its 28 episodes this week were humans. These are 14 residential
    visitors on one shop's paginated pages, plus 6 logged-in admin or
    webmail sessions.
  - Its starting constants (T1 30 / T2 60 navs a minute) would deny real
    customers.
- *Proposed:* close the review as **keep-as-evidence**, with no new
  re-review date: it is re-opened only by a proposal that names an actuator.
  - One optional noise cut, if it is kept as a signal: skip admin and
    webmail paths (`/wp-admin/`, `/cpsess…/3rdparty/roundcube/`). They are
    6 of 28 episodes.
  - Side finding for the tenant: ksilokosmos.gr's tag pagination drives
    ordinary visitors to 30–60 page loads a minute. That looks like a page
    or redirect loop on the site, worth a look by its owner.

- **Actions:** none. Proposals only; nothing goes to the master plan until
  the operator decides.

### 2026-10-13 — read 2 (window: 7 days to 2026-10-13 12:00 Athens)

The second week with auto-v2 and the rescue live, and the first with #1546
and #1547. This read parsed every node's own logs over SSH (read-only), so
every count covers the full week: no relay cap, no sampling (method note
in §5).

- **Fleet:**
  - The 7 web nodes run `2026.10.11`. The edgeless nodes run `2026.10.08`
    (mymail, saf, watchdog) and `2026.09.26` (3deers).
  - Live since read 1, in this area:
    - #1546: the challenge page sends exempt clients to `next`.
    - #1547: a `cfm_rt` is consumed only by its owner.
    - #1574: the fppolicy armed reserve under a fingerprint flood.
    - #1582 and #1584: web bans enforced at the edge.
    - #1587: a verified good bot is never IP-banned.
    - #1550: `also_rule_ids` on WAF hits.

    Both #1546 and #1547 were deployed on 2026-10-06, per the operator.
  - No ChallengeV2 or `ABUSE_SHADOW` knob changed on any node. No node's
    `detectors.conf` was written after 2026-10-01.
  - Operator policies: **no `v2=geo` line anywhere this week**. Read 1 had
    43, and orion had ~500 a day on 09-29/30. The US country policy looks
    disarmed; cfm-web holds the record. No row came from a fingerprint
    policy.
- **Health:**
  - The trajectory keys are present. `ut` was 0 on all 3 419 labelled
    lines with pointer input.
  - `hs=-` (no payload) on 415 solves, 409 of them on convicted farm fps
    (orion 358, titan 41). No page break.
  - 378 of them were **passes under an arm**: 333 on orion, 36 on titan,
    9 on earth and mars together. 375 of the 378 were farm fps. Read 1 had
    227 on orion.
  - On orion that is ~2.2 % against its 14 912 farm rejects, up from
    ~1.2 % on read 1's busiest day. Watch item 1, still small.
- **Arms:** `challenge_v2_reject` lines per node, all `scope=web`:

  | Node | Rejects | Main hosts |
  |---|---|---|
  | orion | 15 488 | www.mathematica.gr 8 832, www.vitolighting.com 5 446 |
  | titan | 15 397 | www.e-vafeiadis.gr 6 262, gastronom.hk 4 882, techking.gr 2 754 |
  | mars | 6 631 | happy-nest.gr 4 527, sfragida.com.gr 1 079 |
  | earth | 3 013 | motopegasus.com 2 869 |
  | virgo | 63 | mygreecetours.org 58 |
  | server.speedhost.gr | 33 | pittakistore.gr 16 |
  | rigel | 19 | santorinitours.org 14 |

  - Total 40 644, the whole week on every node. Read 1 had ~25 000, with
    titan and orion capped at 3 days.
  - Under `v2=vhost`: 40 127.
    - `auto:suspicious_vhost` 38 384, `auto:uniqpaths_short` 1 743.
    - No `manual` or `pin` reject.
  - Under a mark: 517. These are `src=rule` 475 (mars, a `challenge_v2`
    traffic rule) and `src=waf` 42.
  - By fingerprint:
    - `c28caa00` 24 412 (titan, mars, earth, speedhost, rigel);
    - `95070673` 14 973 (orion, virgo);
    - `19877aeb` 16;
    - no fp 1 222 (mars 624 and orion 563, vhosts behind a trusted proxy);
    - other 21.
  - **Human-labelled rejects: 1, and the recourse worked again.**
    - orion, www.mathematica.gr, 10-13 07:16Z: a Greek school network
      (AS8248 CTI Diophantus, PTR `…sch.gr`), Windows Chrome/109.
    - hs 100 (`sw_renderer,outer_zero`), ptr 1 / mv 0, under
      `auto:uniqpaths_short`.
    - It passed 10 s later with hs 90, once `outer_zero` had gone. That is
      the same profile as read 1's only human.
    - The other GR/CY-addressed rejects were webdriver datacenter exits
      (Datacamp, PacketHub; `tells=webdriver`).
  - Google-Read-Aloud and Meta: **0 reject rows** this week. Read 1 had 3
    for Read-Aloud on rigel.
- **Rescue:**
  - No `v2_rescued=input` anywhere, on solve, reject or would_v2 lines.
  - **RED FLAG check: clear.**
  - Farm-fp lines with real input (ptr ≥ 5, mv ≥ 100): 507 of 2 031. Every
    one passed on score; none was rejected, so the rescue never came into
    play. Humans: 711 of 1 388.
- **Would-v2 sizing (unarmed, `abuse_shadow` humanity):**
  - 24 007 lines, 23 080 of them on farm fps.
  - No human-labelled line and no rescued line.
  - The residue is the same two farm sources as read 1:
    - `vhost:vhost_config`: orion 16 463 (mail.mathematica.gr, `95070673`),
      earth 187, titan 37.
    - The v1 traffic rule `r_57e05719c3d78f21` on mars: 3 979, `c28caa00`.
  - Orion also has `vhost:manual` (v1) 378 and its v1 rule
    `r_406f009fd2f281d5` 120.
- **Trajectory:** humans vs farm fps, lines with pointer input only.
  Pooled from per-node 5 % quantiles, so values are interpolated.

  | Reading | Humans p10 / med / p90 (n 1 388) | Farm fps p10 / med / p90 (n 2 031) |
  |---|---|---|
  | ptr | 1 / 8 / 41 | 1 / 1 / 17 |
  | mv (px) | 2 / 162 / 1 290 | 0 / 0 / 603 |
  | co/ptr | 1.0 / 2.0 / 6.5 | 1.6 / 2.0 / 4.6 |
  | st | 0.30 / 0.95 / 1.0 | 0.50 / 0.97 / 1.0 |
  | dj | 0.28 / 0.87 / 2.39 | 0.28 / 0.63 / 1.73 |
  | mj (px) | 1 / 38 / 264 | 0 / 0 / 172 |
  | pd (ms) | 51 / 493 / 2 580 | 50 / 351 / 1 460 |

  - The farms' typical input is still one synthetic event (ptr 1, mv 0,
    co 2).
  - Where both sides really move (ptr ≥ 8, mv ≥ 200), `st ≥ 0.99` covers
    16 % of human lines (90 of 555) and 23 % of farm lines (86 of 374).
    Read 1 had 20 % and 34 %.
  - `dj` and `pd` run lower for farms at the median and the p90, as in
    read 1, but the ranges overlap almost entirely.
- **#1546 / #1547 check (deployed 2026-10-06):**
  - **Meta and Read-Aloud.** On titan, Meta's `POST /__cfm_verify` (its
    failed solve attempts in `challenge.access.log`) per day:

    | Day | Attempts |
    |---|---|
    | 10-05 | 4 556 |
    | 10-06 (the deploy day) | 1 928 |
    | 10-07 to 10-12 | 435, 327, 257, 312, 108, 462 |

    - That is a drop of ~90 %.
    - Google IPs: 3–7 a day before, then 0 on five of the six days.
    - No Read-Aloud or Meta reject row anywhere.
    - What remains is Meta under a challenge the page cannot lift (below).
  - **`exempt_redirect` lines:** 15 856 in all.
    - These are throttled to one per host per minute, so they are a lower
      bound on redirects.
    - By node: titan 10 962 (Meta exclude rule 10 615, goodbot 345), mars
      2 461 (goodbot 1 436, exclude 1 025), orion 1 536 (access 689,
      exclude 668, goodbot 179), earth 743, virgo 103, rigel 32,
      speedhost 19.
    - The bridge counter `challenge_page_exempt_redirects` was not read; it
      resets on a reload.
  - **`next_redirect_loop` was NOT rare: ~14 900 lines.**
    - titan 13 418: 98 % Meta on www.stereotiki.gr, 8 072 on 10-07 alone,
      falling to 3 on 10-13.
    - mars 1 220: Meta on shopzy.gr, `goodbot:meta` and exclude.
    - orion 137, earth 109, virgo 16, speedhost 7, rigel 0.
    - The mechanism: the page judged Meta exempt and sent it to `next`, but
      the edge challenged it again. On titan, Meta's 302s to the challenge
      on 10-13 were stereotiki 1 191, program.bet-prognostika.com 870 and a
      long tail.
    - The breaker then served the page. Meta ends where it was before
      #1546, one hop later, so this is a measured mismatch, not harm.
    - The edge's source for that challenge is **not yet found**. It is not
      the vhost challenge: stereotiki is in `CHALLENGE_VHOST_IGNORE`. It is
      not a traffic rule, not a WAF hit and not a geo floor (no `v2=geo`).
    - The leading candidate is the Step-0c fingerprint-policy floor, which
      neither the decision exemptions nor `challengePageExempt` see. It is
      unconfirmed: the edge logs carry no action reason. Watch item 3.
  - **#1547 is not measurable from the logs.**
    - `post_resume_applied` is logged at INFO, below the edge's error_log
      level.
    - `access.cfm.log` records challenged requests, not passes.
    - On titan, 2–4 challenged POSTs a day stored a resume token. No
      failure was reported.
- **Since last read:**
  - Rejects now have full-week coverage: 40 644. They are almost all
    auto-v2 on farm-hit vhosts. They caught one human, a school PC, who
    passed on the retry.
  - The geo arm went quiet.
  - The rescue still has not fired.
  - #1546 cut Meta's challenge solves on titan by ~90 %, and Read-Aloud and
    Meta rejects to 0. It left a page/edge mismatch for Meta.
  - The trajectory readings still show no separating band. Both reads
    agree there is none, so **no candidate rule**.
- **Watch items:**
  1. `hs=-` passes under an arm: 378, up from 227. This is D5b by design;
     a rising share is the farm's way past the arm.
  2. (Read 1's Google-Read-Aloud item) **Closed.** #1546 ended Read-Aloud
     and Meta rejects. Its residual is item 3.
  3. **New.** The challenge page sends Meta to `next`, and the edge
     challenges it again (titan stereotiki / bet-prognostika, mars
     shopzy). Find the edge's challenge source for those requests: a debug
     header, or the `/nginx/decision` answer for one Meta IP. Then mirror
     it in `challengePageExempt`, or leave it.
- **Actions:** none. No decision, so nothing goes to the master plan.

### 2026-10-06 — read 1 (window: 7 days to 2026-10-06)

The first week with auto-v2 and the rescue live. Release 2026.09.29 went out
on 2026-09-29/30, and the nodes have run 2026.10.04 since 2026-10-04.

- **Fleet:** the 7 web nodes run `2026.10.04` and the 4 without an edge run
  `2026.09.26`.
  - Live since the baseline: #1520–#1531, then #1532, #1537 and #1539 (see
    §2), plus config and firewall work (#1533–#1536, #1538, #1540–#1544).
  - No ChallengeV2 knob was changed on any node. `ABUSE_SHADOW = 1` on all 7
    web nodes.
  - Operator policies: the US country policy is still armed (43 `v2=geo`
    rejects, on earth, mars and virgo). No row came from a fingerprint
    policy.
- **Health:**
  - The trajectory keys are present on every solve with pointer input. `ut`
    was 0 on all 2 712 such lines read (titan, orion, earth, mars, virgo),
    so no script-dispatched pointer events were seen.
  - `hs=-` (no payload): 315 solves, 308 of them on convicted farm fps
    (orion 242, all farm; titan 58 of 60). No page break.
  - 227 of orion's `hs=-` solves were **passes under `v2=vhost`**. A missing
    payload cannot fail a solve (D5b), so a farm that strips the body clears
    an armed vhost. On orion's busiest day, 10-04, that was 86 passes
    against 7 424 rejects of the same fp. Watch item 1.
- **Arms:** `challenge_v2_reject` rows per node:

  | Node | Rows | Coverage |
  |---|---|---|
  | earth | 2 801 | full week |
  | mars | 836 | full week |
  | virgo | 230 | full week |
  | server.speedhost.gr | 20 | full week |
  | rigel | 10 | full week |
  | titan | ≥ 12 101 | newest 3 days only (relay cap); about 3 000–4 500 a day |
  | orion | ≥ 9 000 | newest 3 days only (relay cap); 7 424 on 10-04 alone |

  - That is about 25 000 rows, against 1 361 in the baseline week.
  - Almost all are `v2=vhost v2_via=auto:suspicious_vhost`. 45 are
    `auto:uniqpaths_short` and 14 come under a mark (12 of them on virgo).
    All are `scope=web`.
  - The usual tells are `sw_renderer,mobile_hw_lie,no_input` (hs 140).
  - By fingerprint: `c28caa00` on earth, mars, rigel, speedhost and titan;
    `95070673` on orion and virgo. Mars has 588 rows with no fp, consistent
    with vhosts behind a trusted proxy (ligaapola.gr, anastasiadi.gr,
    toolpoint.gr).
  - Hot hosts: www.mathematica.gr (orion, 8 001), www.e-vafeiadis.gr (titan,
    7 985), motopegasus.com (earth, 2 721).
  - **Human-labelled rejects: 1.**
    - titan, newpageclothing.gr, 2026-10-02 17:39Z: Vodafone GR, Windows
      Chrome/109, hs 100 (`sw_renderer,outer_zero`), ptr 2 / mv 1. That is
      below the rescue bar.
    - The visitor retried 6 s later and passed with hs 90, because
      `outer_zero` was gone. The recourse worked.
    - A second GR-ISP reject (orion, a Vodafone IP, 10-01) came from fp
      `95070673` with a Mac UA claiming 168 cores. That is a farm exit, not
      a human.
  - Google-Read-Aloud on rigel (karol.gr): 3 rejects on 10-04, when the PTR
    was not yet known at verify. Each retry was then waived
    (`v2_waived=google`).
- **Rescue:**
  - No `v2_rescued=input` line anywhere: none in the challenges logs and
    none on would_v2 lines. The challenges logs cover the full week on
    earth, rigel, speedhost, titan and virgo, and mars and orion from
    ~10-01.
  - **RED FLAG check: clear.** There was no rescue at all, so none on a
    convicted fp.
  - Farm-fp solves with real input (ptr ≥ 5, mv ≥ 100): 78 of 766. Every
    one passed on score (no tell, or one worth ≤ 60), so the rescue never
    came into play. Humans: 855 of 1 723.
- **Would-v2 sizing (unarmed):** no human-labelled line and no rescued
  line. The unarmed residue comes from two farm sources:
  - `vhost:vhost_config`: 1 950 on orion in ~20 h (mail.mathematica.gr,
    `95070673`) and 243 on earth (mostly cpanel./webmail.fex.org.gr and
    365home.gr).
  - A v1 traffic rule on mars (`rule:r_57e05719c3d78f21`, kialasiatrika.gr):
    ~1 930 in 3 days, `c28caa00`.

  This feeds open decision 4 (`vhost_config` in auto-v2).
- **Trajectory:** humans vs farm fps, lines with pointer input only.

  | Reading | Humans p10 / med / p90 (n 1 723) | Farm fps p10 / med / p90 (n 766) |
  |---|---|---|
  | ptr | 1 / 7 / 35 | 1 / 1 / 7 |
  | mv (px) | 1 / 141 / 926 | 0 / 0 / 315 |
  | co/ptr | 1.0 / 2.1 / 6.0 | 2.0 / 2.0 / 3.0 |
  | st | 0.47 / 0.97 / 1.0 | 0.47 / 0.98 / 1.0 |
  | dj | 0.28 / 0.81 / 2.13 | 0.29 / 0.65 / 1.91 |
  | mj (px) | 1 / 37 / 231 | 0 / 0 / 86 |
  | pd (ms) | 46 / 409 / 1 759 | 80 / 396 / 1 324 |

  - The farms' typical input is a single synthetic event (ptr 1, mv 0,
    co 2).
  - Where both sides really move, no reading separates them yet. At ptr ≥ 8
    and mv ≥ 200, `st ≥ 0.99` covers 20 % of human lines and 34 % of farm
    lines.
  - One cluster to follow: 24 lines with an "iPhone OS 26_3_0" UA from
    datacenters (Datacamp, HostRoyale, M247; CA/US; fps `c28caa00` and
    `95070673`). They hit webmail., cpanel. and whm. hosts, and `st` was
    1.0 on 19 of 22.
- **Since last read:**
  - Auto-v2 and the rescue went live.
  - Rejects grew from 1 361 (geo) to about 25 000, from auto-v2 on vhosts
    the farms hit. They caught one human, who passed on the retry.
  - The rescue has not fired.
- **Watch items:**
  1. `hs=-` passes under an arm (227 on orion). This is D5b working as
     designed. If the share grows, it is the farm's way past the arm, and
     that becomes a master-plan decision.
  2. Google-Read-Aloud was still served the challenge on rigel after the
     #1539 rule loaded. The rule loaded at 10-04 20:22Z (14 rules). The
     challenge was then served on karol.gr and megashopgr.gr from 10-04
     20:33Z to 10-05 15:58Z. The serve-time lift (#1537, `nginx_bridge.go`
     `ChalExcludeHot`) did not apply. To investigate.
- **Actions:** none. No decision, so nothing goes to the master plan.

### 2026-09-29 — baseline (before the release; E4 first read)

Full text: master plan E4, "READ 2026-09-29". Fleet: the 7 web nodes on
2026.09.28; none of #1520–#1529 live.

- **Live rejects 2026-09-23..29: 1 361.** 1 350 under the armed US country
  policy (`v2=geo`), 11 under a mark. None human-labelled, none with pointer
  movement.
- **Auto-v2 sized from `would_v2`** (7 826 lines on 6 nodes; speedhost had
  `ABUSE_SHADOW` off): 5 on GR/CY consumer ISPs, 2 of them webdriver. The
  rest were Windows Chrome/109 PCs scoring exactly 100 (software renderer, no
  window size) with real pointer input (41 / 714 px, 7 / 729, 74 / 3 149).
  This is the class the rescue (#1528) now lets through.
- **`sig` corpus:** 11 125 lines; real input (≥ 5 events, ≥ 100 px) on 1 of
  2 861 failing solves, and on no farm solve.
- **`cfm_pcw`:** 3 episodes in the live edge-log windows, none from the
  `hs=0` farms.
- **Actions:** the rescue (#1528), the trajectory readings (#1529) and the
  scoped-v2 redaction were built; `ABUSE_SHADOW` enabled on speedhost; three
  weekly reads scheduled.
