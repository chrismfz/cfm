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

*As of 2026-10-13 (read 2).*

- **Fleet version:** the 7 web nodes run `2026.10.11`. The 4 nodes without
  an edge serve no challenge: mymail, saf and watchdog run `2026.10.08`, and
  3deers runs `2026.09.26`.
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
- **What bites today:** operator-armed fingerprint / country-ASN policies
  from cfm-web (no `v2=geo` line in read 2's week: the US country policy
  looks disarmed), the WAF challenge tier at
  `challenge_v2`, manual vhost v2 tiers, the automatic vhost challenges
  (auto-v2) and the rescue.
- **Under measurement:** the auto-v2 false-reject rate on humans, the
  rescue (`v2_rescued=input`), the trajectory readings (humans vs farms).
- **Watch items** (findings, not decisions; details in the newest entry):
  1. Farm solves with no payload (`hs=-`) pass an armed vhost, by design
     (D5b). This happened 378 times in read 2 (333 on orion), up from 227
     in read 1.
  2. *(Closed in read 2.)* Google-Read-Aloud and Meta were served the
     challenge through the challenge page's own URL. #1546 fixed this.
     Read 2: 0 Read-Aloud or Meta rejects, and Meta's solve attempts on
     titan down ~90 %.
  3. The challenge page sends Meta to `next`, and the edge challenges it
     again: ~14 900 `next_redirect_loop` lines, mostly titan
     www.stereotiki.gr and mars shopzy.gr. The edge's challenge source is
     not found yet; the leading candidate is the Step-0c fingerprint floor.
     No harm, since the breaker serves the page, but the mirror is
     incomplete. Since the CDN-cache fix (2026-10-19), a CLEARED client's
     second bounce logs `cdn_cached_challenge` (one cache-busting retry), not
     `next_redirect_loop`, so `why="cleared"` loop counts after it are not
     comparable with reads 1–2; exempt clients (this item) are unchanged.
- **Open decisions** (master plan §5 / E4):
  1. Tighten the rescue or leave it, including a score ceiling (it clears
     up to 150; the measured human class scored exactly 100).
  2. Whether α — the Rung-2 confirm fallback for humans who don't move a
     pointer — is needed.
  3. `cfm_pcw` exit review, due 2026-10-20.
  4. Config decisions after E4: `vhost_config` in auto-v2; the shipped
     `solver_farm` defaults; the orphan `HUMANITY_*` keys.
- **Next read:** Tuesday 2026-10-20, 12:00 Athens (scheduled check-in). It
  is read 3, and it brings the proposals for the open decisions.
- **Kill switches, if a read shows harm:** `CHALLENGE_V2_INPUT_RESCUE = 0`
  (rescue off) · `CHALLENGE_V2_AUTO_VHOST = off` (auto-v2 off) · per vhost
  `cfm webtop challenge tier <vhost> v1` · `CHALLENGE_V2_HW_TELLS = 0` ·
  `FP_POLICY = 0` (every operator policy) · `CHALLENGE_V2_PASSIVE = 0` (the
  whole rung, telemetry included).

## 3. Fleet state

| Node | Edge | Version | `ABUSE_SHADOW` | History kept | ChallengeV2 knobs |
|---|---|---|---|---|---|
| earth | openresty | 2026.10.11 | 1 | 30 d / 1M rows | defaults |
| mars | openresty | 2026.10.11 | 1 | 30 d / 1M rows | defaults |
| orion | angie | 2026.10.11 | 1 | 30 d / 1M rows | defaults |
| rigel | openresty | 2026.10.11 | 1 | 30 d / 1M rows | defaults |
| server.speedhost.gr | openresty | 2026.10.11 | 1 (since 2026-09-29) | **7 d** | defaults |
| titan | openresty | 2026.10.11 | 1 | 30 d / 1M rows | defaults |
| virgo | angie | 2026.10.11 | 1 | **7 d** | defaults |

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
