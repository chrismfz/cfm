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

*As of 2026-09-29, before the next release.*

- **Fleet version:** the 7 web nodes run `2026.09.28`; the 4 nodes without an
  edge (3deers, mymail, saf, watchdog) run `2026.09.26` and serve no
  challenge.
- **In `main`, not released yet** (all ride the next release together):

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
  | scoped-v2 PR | The `v2` / `v2_*` history keys hidden from cPanel users |

- **What bites today (2026.09.28):** operator-armed fingerprint / country-ASN
  policies from cfm-web (a US country policy is armed), the WAF challenge
  tier at `challenge_v2`, and manual vhost v2 tiers. **After the next
  release**, also the automatic vhost challenges (auto-v2) and the rescue.
- **Under measurement:** the auto-v2 false-reject rate on humans, the
  rescue (`v2_rescued=input`), the trajectory readings (humans vs farms).
- **Open decisions** (master plan §5 / E4):
  1. Tighten the rescue or leave it, including a score ceiling (it clears
     up to 150; the measured human class scored exactly 100).
  2. Whether α — the Rung-2 confirm fallback for humans who don't move a
     pointer — is needed.
  3. `cfm_pcw` exit review, due 2026-10-20.
  4. Config decisions after E4: `vhost_config` in auto-v2; the shipped
     `solver_farm` defaults; the orphan `HUMANITY_*` keys.
- **Next reads:** Tuesdays 2026-10-06, 10-13 and 10-20, 12:00 Athens
  (scheduled check-ins). The 10-20 read also brings the proposals for the
  open decisions.
- **Kill switches, if a read shows harm:** `CHALLENGE_V2_INPUT_RESCUE = 0`
  (rescue off) · `CHALLENGE_V2_AUTO_VHOST = off` (auto-v2 off) · per vhost
  `cfm webtop challenge tier <vhost> v1` · `CHALLENGE_V2_HW_TELLS = 0` ·
  `FP_POLICY = 0` (every operator policy) · `CHALLENGE_V2_PASSIVE = 0` (the
  whole rung, telemetry included).

## 3. Fleet state

| Node | Edge | Version | `ABUSE_SHADOW` | History kept | ChallengeV2 knobs |
|---|---|---|---|---|---|
| earth | openresty | 2026.09.28 | 1 | 30 d / 1M rows | defaults |
| mars | openresty | 2026.09.28 | 1 | 30 d / 1M rows | defaults |
| orion | angie | 2026.09.28 | 1 | 30 d / 1M rows | defaults |
| rigel | openresty | 2026.09.28 | 1 | 30 d / 1M rows | defaults |
| server.speedhost.gr | openresty | 2026.09.28 | 1 (since 2026-09-29) | **7 d** | defaults |
| titan | openresty | 2026.09.28 | 1 | 30 d / 1M rows | defaults |
| virgo | angie | 2026.09.28 | 1 | **7 d** | defaults |

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

## 6. Entries

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
