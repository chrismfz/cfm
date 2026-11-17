# Targeted challenges: the audience floor and the under-attack confirm step (design)

> **Status: design; S4 (the confirm step under a manual `attack on`) built 2026-11-17.** Written 2026-11-17 after E4 read 7, at the
> operator's request ("challenge what we believe is a farm and let the human
> through"). The plan of record is still `docs/abuse-defense-master-plan.md`.
> Its §5 holds the decision and the order. This note is the design both
> increments are built from. The measurements it rests on are read 7 in
> `docs/abuse-defense-progress.md`; read 8 measures what is still open.

## 1. Why: read 7

- **The score is a loop.** `linux_sw` (#1652) rejected ~166 000 farm solves,
  and the fleet catch rate went from 14 % to 52 %. Within a day, `c28caa00`
  moved its passes to Windows and Mac UAs with no software renderer.
  - They now score **0**: 59 795 Windows and 79 121 Mac passes after 11-11.
  - They come from residential proxies: 60 672 IPs on qualityweb, 43 518 on
    mars.
  - Each new tell buys about a day. At hs 0, D5b means no tell can reject
    alone.
- **WHO is challenged is where the humans can be spared.** Of the 192 390
  solves under an automatic vhost challenge:

  | Floor | Solves covered | GR/CY consumer-ISP solves it would still challenge |
  |---|---|---|
  | Not GR/CY | 87 % | **0** |
  | Convicted farm fingerprint | 93 % | 15 108 (the bucket's Greek audience) |
  | Datacenter ASN | 11 % | 0 |
  | No input | 90 % | 85 % of the Greek visitors on other fingerprints |

  - A farm fingerprint is a population, not a client (§4 D2).
  - No input is useless on its own: today's page asks for nothing.
- **The farm's hs-0 profile has no input.** On qualityweb, 74 417 of 78 388
  such solves have `ptr`, `tch` and `key` all 0; on mars, 44 460 of 44 530.
  A human who is asked for a click gives one. The farm must script one on
  every solve.

## 2. The ladder

Per vhost, per request. Nothing changes for a vhost with no challenge.

| Vhost state | Client in the vhost's audience | Outside the audience, or a datacenter ASN |
|---|---|---|
| No challenge | nothing | nothing |
| Automatic vhost challenge (`suspicious_vhost`, `uniqpaths_short`) | **no challenge** (§3) | the challenge as today: PoW + Rung-1 v2 |
| **UNDER_ATTACK** (§4) | no challenge | PoW + Rung-1 v2, and **a confirm step** when the solve carries no input |

Every other path is unchanged and still applies to the audience:
- the WAF, per-IP challenges and rule marks;
- manual vhost challenges and `vhost_config`;
- the operator's fingerprint and country / ASN policies;
- edge bans, rate limits and traffic rules.

The audience floor narrows ONE arm, the automatic vhost challenge. It is never
a trust grant.

## 3. Increment A: the audience floor

**What it decides:** whether an AUTOMATIC vhost challenge covers this client.

- **The audience set, per vhost:**
  - Default: GR/CY, the fleet's audience.
  - **Estimate:** the GR/CY share of the vhost's solves with real input
    (`ptr` ≥ 5 and `mv` ≥ 100, the rescue's bar) on a non-farm fingerprint,
    over a rolling window (proposed 7 days), with a minimum sample (proposed
    n ≥ 20). Below that it uses the default set or the pin. **Measured
    2026-11-17, not the access log** (§8): the access log cannot give an
    audience.
  - **Operator pin:** `audience=<cc,cc>` or `audience=all` per vhost. A
    foreign-audience site (gastronom.hk, mygreecetours.org,
    elitefirstclassmykonos.com, all farm targets in read 7) is pinned `all`,
    or falls back to `all` by itself when its estimate is under a floor
    (proposed: GR/CY < 70 %). `all` keeps today's vhost-wide challenge.
  - Read 8 measures the estimate's week-to-week stability before any number
    above is fixed.
- **In the audience:** the client's country (edge geo / enrich, the same
  resolver as E3's country floor) is in the set, AND
  `DatacenterClass(asn) == ""`.
  - A GR/CY datacenter address counts as outside (980 such solves in read 7).
  - This uses `DatacenterClass` additively: a datacenter hit ADDS the
    challenge, and "" is not read as trust. It honours the asnclass.go
    invariant, because the floor only narrows the one automatic arm and
    leaves every other scrutiny as it is.
- **Mirrors (CLAUDE.md §6, "Challenge excludes & scoping"):** this is a new
  client exemption from a vhost challenge, so it lands in all the places one
  must:
  - `handleDecision`;
  - `challengePageExempt` (a client sent to `/__cfm_challenge` is sent to
    `next`);
  - the uniqIP mirror (`vhostChallengeExemptClient`: an audience client is
    not counted toward arming a vhost challenge — decide in review whether
    it should be, since the farm's GR exits would then arm nothing).

  A vhost in LOCKDOWN withdraws it (`vhostLockedDown`), like every other
  exemption. A `next` that carries a `cfm_rt` keeps its challenge.
- **Shadow first (S1):** every automatic-challenge serve, solve and reject
  line gets `aud=in|out|dc`, and nothing is skipped. The next read counts:
  - the solves the floor would have spared (humans);
  - the rejects it would have let through. Read 7 found ~160 from GR/CY
    consumer ISPs, every one a `webdriver` / `headless_ua` bot. Without the
    automatic challenge on that vhost they still meet the WAF and the per-IP
    paths.
- **Live (S2):** the floor skips the automatic challenge for `aud=in`. Kill
  switch `[webdetector] CHALLENGE_AUDIENCE_FLOOR = 0`, per-vhost pin `all`.

## 4. Increment B: the under-attack confirm step

This is `docs/roadmaps/challenge-engine.md` §8 (the level-2 gate,
escalation-gated) with a checkbox where §8.4 had a puzzle. The puzzle was
dropped on 2026-09-29: CAPTCHA farms solve puzzles cheaply, and the cost lands
on every challenged human. It is master plan candidate 4 (the Rung-2 confirm
fallback), triggered by the under-attack state rather than only by a reject.

> **As built (S4, 2026-11-17, `internal/webdetector/challenge_confirm.go`):**
> - **Knobs** (`[webdetector]`):
>   - `CHALLENGE_V2_CONFIRM` = `manual` (default: only while an operator's
>     override holds the vhost UNDER_ATTACK), `auto` (the detector's automatic
>     entry too) or `off`;
>   - `CHALLENGE_V2_CONFIRM_AUDIENCE` = `GR,CY` (default; `none` = everyone).
>
>   A datacenter ASN (`DatacenterClass`) is outside the audience, and an
>   unresolved country never sees it.
> - **Flow:**
>   1. The verify of a qualifying solve answers 403 with `X-CFM-Confirm`, an
>      HMAC token bound to (ip, host, PoW token), and logs `result=v2_confirm`.
>   2. The page shows a native Continue button, once the tab is visible.
>   3. A trusted click re-posts the same solve with the token and `clk`
>      (the click; a new log-only `sig` reading). A re-post with the token
>      and still no trusted input (no `clk`, pointer, touch or key) is asked
>      again with the same token (a re-post never mints a new one, so one PoW
>      cannot be kept alive by re-posting). Its PoW is checked as of the token's issue time, so the PoW's
>      2-minute TTL never sends the visitor back. The token lives 5 minutes,
>      but the `cfm_chal` cookie the re-post needs expires 300 s after it was
>      set, so the window is up to 5 minutes and can be shorter (the page then
>      reloads into a fresh challenge).
>   4. The solve logs `v2_confirm=clicked v2_confirm_ms=<ms>` (history
>      payload keys of the same names, withheld from scoped callers as
>      `v2_*`).
>
>   A `v2_confirm` line with no later clicked solve from the same ip and host
>   is a visitor who did not click. The shown confirm is a log line only, not
>   a history row (it decides nothing, and under attack it is high volume);
>   reads count it from `cfm.challenges.log*`. A confirm-asked solve still
>   feeds the under-attack solve rate, so `auto` is not starved by a farm
>   that never clicks.
> - **Honest limits** (the header of `challenge_confirm.go`): a farm that
>   reads the 403 and posts `clk:1` with the token passes, and a CDP click is
>   trusted; a token is reusable from the same ip and host until it expires
>   (~7 minutes after the PoW was issued instead of 2).
> - **Where it applies:** web scope only. A `www.` host with no state of its
>   own follows its apex's (`attack off` on the `www.` host wins). An
>   FCrDNS-verified good bot is never asked (it cannot click): the Rung-1
>   waiver's verdict and rules (`CHALLENGE_GOODBOT_EXEMPT`; not under a rung
>   mark, not on a vhost in lockdown).
> - **The override is in memory:** a cPanel user can set it on their own vhost
>   (24 h max), and a config reload (a `detectors.conf` save, a tailed log's
>   rotation) clears it, so a test must re-arm it after one. Each visitor
>   outside the audience makes two verify POSTs, which count toward the
>   verify rate limit.
> - **The state challenges nobody by itself,** so a test needs a served
>   challenge: `cfm webtop challenge add <vhost>` + `cfm webtop attack on
>   <vhost>` (or the cfm-admin Under-Attack toggle).
> - **Differences from the text below:** the field names (`v2_confirm`, not
>   `confirm`, so the scoped strip covers them by prefix), and the kill switch
>   (`CHALLENGE_V2_CONFIRM = off`; `UNDER_ATTACK_CONFIRM_TICKS` already
>   existed).

- **The state:** UNDER_ATTACK (`internal/webdetector/under_attack.go`, master
  plan §3 row 9) with its hysteresis, holddown and auto-exit. I3–I5 (draft
  block rules, auto-apply, repeat-offender nft) stay frozen (§3 row 10). This
  gives the state a consumer; it does not build the old ladder.
- **Entry:**
  1. **Manual:** `cfm webtop attack on <vhost>`, which exists today.
  2. **Automatic, after its shadow (S3):** a `solver_farm` finding on that
     vhost whose humanity line says the solving cluster is outside the
     vhost's audience. Proposed: ≥ 80 % of its passed solves outside the
     audience set, at hs 0 or 60–99. Read 7's candidates:
     - joinjewels.com (mars): ~1 800 hs-0 solves per window, PK / AR / BD;
     - www.e-vafeiadis.gr (rigel);
     - www.ventus.com.gr and www.ekalogeropoulos.gr (qualityweb);
     - gastronom.hk (titan).

     It must never fire on the Greek-audience findings (www.mathematica.gr,
     gokids.gr: GR ×30–37 at hs 0). The audience test is exactly what
     excludes them.

     S3 logs `would_enter_under_attack host= reason=solver_farm out_aud=<pct>`
     and changes nothing.
  - Today's entry legs (≥ 50 % origin errors) stay. They have never fired.
- **Who sees the confirm:** inside UNDER_ATTACK, a client outside the
  audience (or `dc`) whose solve passed Rung 1 with `ptr`, `tch` and `key`
  all 0.
  - A solve with real input passes as today.
  - A certain tell (webdriver / headless UA) rejects as today.
- **The page:**
  - After the PoW, if there was no trusted input, the page shows one control
    ("Συνέχεια" / "Continue", a native button). There is no image, no text to
    read, and no timer before it appears.
  - If the page is hidden (the visitor is in another tab), it waits for
    `visibilitychange` and shows the control when the tab is visible again.
    This replaces today's `hid:1` post-while-hidden, for this case only.
  - Keyboard (Space / Enter) and screen readers work: a native, labelled
    button.
  - The click posts the verify with the page's existing trajectory readings
    (`ut co st dj mj pd`), now measured on an approach to a target.
- **The click passes** unless a certain tell. D5b holds: absence never
  convicts. The confirm IS the recourse D5c promised, so a person is never
  walled. What it buys:
  - **Cost:** the farm must script a click on every solve.
  - **A corpus:** a trajectory to a target, where today it has nothing to
    measure.

  Any rule that READS the click (time to click, path) is a later decision,
  after its own burn-in (§8.7 there: no threshold before its burn-in).
- **Shadow (S4):** behind `attack on` only (manual), the confirm is shown,
  with these logs:
  - `confirm=shown|clicked|abandoned`;
  - `confirm_ms`;
  - the click's trajectory readings;
  - `v2_via=auto:under_attack` or `manual`.

  `abandoned` is the human cost. Read it per country / ASN before the
  automatic entry goes live (S5).
- **Kill switches:** `[webdetector] CHALLENGE_V2_CONFIRM = off`, and `attack off`
  per vhost.

## 5. What this does not do

- No block rule, no 403, no nft (I3–I5 stay frozen; challenge-engine §4: a
  ban lands on a residential visitor, a UA rule is evaded by a header).
- No visible puzzle (dropped 2026-09-29).
- No new score tell. Read 7's Mac `dpr:1` measurement is recorded, not
  shipped.
- No change to the WAF, per-IP challenges, manual challenges, `vhost_config`,
  fingerprint / geo policies or edge bans.

## 6. Honest limits

- **A CDP click is a trusted click.** A farm running real Chrome through CDP
  will click. The win is cost and a corpus, not a wall (§8.5 there: it moves
  the cost curve).
- **The farm can rent GR/CY residential exits.** It already uses a few
  (read 7's reject lists). Against those, the floor gives up the automatic
  challenge on Greek-audience vhosts. They still meet the WAF, the per-IP
  paths, the fingerprint policy and, under attack, nothing new: the confirm
  is for clients outside the audience. If read 8 or later shows the farm
  moving to GR exits, the floor's value drops, and the pin (`all`) is the
  lever.
- **A Greek visitor abroad** gets the challenge, and under attack the
  confirm, as today.
- **The estimate needs solves.** Most vhosts have fewer than 20 real-input
  solves a week, and a vhost with no challenge has none. Those keep the
  default set (GR/CY) or their pin.
- **The farm posts real input on a few solves.** gastronom.hk had 7 of its 8
  real-input solves on a farm fingerprint, mygreecetours.org 8 of 9. So the
  estimate leaves out the convicted farm fingerprints.

## 7. D5 / D3

- **D5 amendment (proposed, for the operator's ratification with S2):**
  - (a) An automatic vhost arm may cover fewer clients than the whole vhost:
    the audience floor narrows an arm, it never widens one.
  - (c) The escalation it anticipates is the confirm step, which may also be
    shown, without a reject, to a no-input solve outside the audience while
    the vhost is UNDER_ATTACK. The click always passes absent a certain tell.
- **D3 exit contract:**
  - The floor is retired if the farm's share of GR/CY exits makes the floor
    spare more farm than humans for two reads.
  - The confirm step is retired if, over two reads under attack, the farm
    clicks at the human rate and `abandoned` humans exceed the farm solves it
    stopped.
  - Both are kill-switched and log-only until measured.

## 8. Increments and measurement

| Step | What | Live effect | Measured by |
|---|---|---|---|
| — | Read 8: the audience estimate per vhost and its stability; would-enter from the history DB's `solver_farm` humanity | none | read 8 |
| S1 | `aud=in\|out\|dc` on automatic-challenge lines | none | that the in-code classifier agrees with the offline count (the solve lines already carry `cc=` and `asn_name=`, so the sizing itself needs no code) |
| S2 | the audience floor live (kill switch, pins) | GR/CY audience skips the automatic challenge | spared solves, let-through rejects |
| S3 | `would_enter_under_attack` from `solver_farm` | none | how often, on which vhosts, never a Greek audience |
| S4 (**built** 2026-11-17) | the confirm page under manual `attack on` | the confirm is shown, the click passes | `v2_confirm` lines vs `v2_confirm=clicked` solves, the click corpus |
| S5 | the automatic entry | the confirm under automatic UNDER_ATTACK | as S4 |

Each step is its own small reviewed PR. Every edge-affecting step follows
`docs/challenge-waf-release-checklist.md`.

**The audience estimate: what was measured (2026-11-17, read-only, no code)**

- **The edge's `access.log` does NOT give an audience.** On qualityweb's 10
  automatically challenged vhosts (one day), GR/CY is 1–4 % of the distinct
  addresses. After removing non-browser and bot UAs, the convicted farm's
  addresses, static files and datacenter ASNs, it is still 0–18 %. The rest
  is residential addresses from SG, US, CN and BR: scraping that never meets
  a challenge. On a Greek shop, humans are a small minority of the
  addresses that reach it.
- **Real-input solves do.** The solves with `ptr` ≥ 5 and `mv` ≥ 100 in the
  week's `cfm.challenges.log*`, per vhost, on all 8 nodes:
  - The Greek shops read 95–100 % GR/CY:

    | vhost (node) | real-input solves | GR/CY |
    |---|---|---|
    | mathematica.gr (orion) | 405 | 96 % |
    | lpr.gr (qualityweb) | 273 | 100 % |
    | e-vafeiadis.gr (rigel) | 186 | 99 % |
    | somabed.gr (qualityweb) | 156 | 99 % |
    | ekalogeropoulos.gr (qualityweb) | 97 | 98 % |
    | ventus.com.gr (qualityweb) | 85 | 99 % |
    | gokids.gr (rigel) | 56 | 100 % |
    | techking.gr (titan) | 34 | 97 % |

  - The vhosts that are not Greek-audience stand out, though their counts are
    small and mostly farm:
    - gastronom.hk: 8, 12 % GR/CY, HK ×4;
    - mygreecetours.org: 9, 0 %;
    - vitolighting.com: 9, 0 %, SI and IT.
  - Most other vhosts have fewer than 20 a week, all GR/CY.
- **Consequence for the design:** the estimate is the real-input share (§3);
  the access log is dropped. A busy Greek-audience vhost estimates itself;
  the long tail uses the default or a pin. The would-be sizing (spared
  solves, let-through rejects) is computable from the solve and reject
  lines today, with no code.
- **Read 8 adds the stability:** the same share for this week vs read 7's
  week, per vhost with n ≥ 20.
