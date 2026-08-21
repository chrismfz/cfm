# Under-Attack Mode — per-vhost escalation state (design)

**Status: DESIGN — direction agreed 2026-08-21, nothing built yet.** Increment
I1 (detector + state + notify, log-only) goes first. Siblings:
`docs/webdetector-refactor.md` (entity signals), `docs/roadmaps/challenge-engine.md`
§4 (actuators: harden/throttle) + §8 (level-2 gate), `docs/waf-autoblock-design.md`
(the two-knob detect/persist split this reuses), `internal/webdetector/traffic_rules.go`
(the enforcement substrate).

---

## 1. Problem — automate the operator's eye

Live incident (e-athlos.com, 2026-08-20→21): the operator's workflow today is

1. glance at webtop → **2,540 unique IPs** on one small shop → "WTF";
2. drill down → IPs scattered across 30+ countries / hundreds of residential
   ASNs, ~25 rotating browser UAs in near-equal shares, `bot% ≈ 0`;
3. read the challenge log → **the challenge is armed and being SOLVED** at
   ~30 IPs/min (real headless browsers + one-solve-per-exit proxies), so the
   flood continues *through* it — 102 rps, err 100%, backend RT 11s;
4. start blocking things by hand, one at a time, and lose.

Two structural gaps make this manual:

- **Challenge efficacy is never measured.** The engine arms the challenge and
  considers the job done. Nobody closes the loop "did pressure actually drop?".
- **There is no state above CHALLENGED.** When the challenge is defeated, the
  engine has nothing stronger to escalate to, and no way to say so.

Under-Attack Mode is that missing state plus the feedback loop, with the same
discipline as everything else in CFM: log-only first, TTL'd actions, operator
override, good bots exempt before anything counts.

## 2. The state model (per vhost)

```
NORMAL ──► SUSPICIOUS ──► CHALLENGED (auto|manual) ──► UNDER_ATTACK
              (exists)        (exists)                    (new)
   ◄─────────── de-escalation with holddowns ────────────┘
```

UNDER_ATTACK is **only reachable from CHALLENGED**: it is by definition
"challenged AND the challenge is not working". It is never entered directly —
a vhost that was never challenged cannot be under attack in this model.

**Surfacing (all four surfaces, same field):**

- `cfm webtop challenge` — STAT column grows the value `attack` (alongside
  `active`); `cfm webtop <vhost>` header shows `state=UNDER_ATTACK since=…`.
- cfm-admin — badge next to the vhost (🔒 challenged → 🚨 under attack).
- API — `state` field on `/api/v1/challenge/vhosts` + `/vhost` rows
  (`normal|suspicious|challenged|under_attack`), additive, `omitempty`.
- MCP — `challenge_vhosts` / `host_drilldown` carry the same field, and
  entering/leaving the state emits a history + notify event
  (`WEB/VHOST_UNDER_ATTACK_ON|OFF`), so the operator learns from an alert,
  not from reading logs.

**Knobs (mirror the challenge knobs):**

```ini
UNDER_ATTACK          = 1     ; master (ships 1 but with DRYRUN=1: detect+notify only)
UNDER_ATTACK_DRYRUN   = 1     ; state + notifications, NO enforcement actions
UNDER_ATTACK_SOLVES_MIN     = 15    ; distinct solving IPs/min that count as "farm solving"
UNDER_ATTACK_CONFIRM_TICKS  = 3     ; consecutive ticks before entering
UNDER_ATTACK_HOLDDOWN       = 30m   ; min time in state; exit needs pressure below floor this long
UNDER_ATTACK_RULE_TTL       = 6h    ; TTL of any auto/draft traffic rule
```

Manual override, like manual challenge: `cfm webtop attack on|off <vhost>`
(on = force the state; off = leave + suppress re-entry for the holddown).

## 3. Entry criteria — challenge-efficacy feedback + corroboration

All of the following, for `CONFIRM_TICKS` consecutive ticks, computed **after**
good-bot exemption (§5):

1. **Challenge armed** on the vhost (auto or manual).
2. **The challenge is being defeated**: distinct solving IPs/min ≥
   `SOLVES_MIN` (from the existing `challenge_events` stream). Humans do not
   arrive as 30 fresh IPs/min from 30 countries; a solver farm does. A
   *working* challenge shows the opposite shape: issuance high, solves low,
   pressure falling.
3. **Pressure is sustained**: uniqIP still ≥ the arm threshold AND
   (err_ratio ≥ 0.5 OR backend RT ≥ 3× the vhost's baseline). The challenge
   was supposed to relieve this; it did not.
4. **The population claims to be human**: `bot_ratio ≈ 0` while uniqIP is
   exploding — the inversion tell. Thousands of "browsers" appearing at once
   is itself the signature; honest crawlers self-declare and are already out
   of the count via §5.

Exit: condition 3 false (pressure below floor) for `HOLDDOWN` → back to
CHALLENGED; normal challenge cool-down takes it the rest of the way.

## 4. Reference cases (live, titan, 2026-08-21) — the calibration contract

Any implementation MUST fire on the first and MUST NOT fire on the second.

| signal | **e-athlos.com** (MUST fire) | **www.stereotiki.gr** (MUST NOT fire) |
|---|---|---|
| unique IPs (window) | 2,540+ | 155 |
| population claims | browser UAs, `bot% ≈ 0.3` | self-declared crawlers, `bot% ≈ 90` |
| origin spread | 100s of residential ASNs, 30+ countries | one ASN (AS32934 Meta, one /24) + FCrDNS-verified googlebot + a few humans |
| err_ratio | ~100% | 0.8% |
| backend RT | ~11s (melting) | 224ms (fine) |
| paths | 3 paths hammered + challenge loop (`/shop/` ×5433, `__cfm_challenge` ×4599) | 437 distinct catalog pages (a real crawl) |
| static assets | ≈ none (favicon ×3 in 12,757 reqs) | js/css/png present in top paths |
| challenge efficacy | armed; solved ~30 IPs/min; pressure unchanged | vhost not challenge-armed; crawler backs off |

stereotiki fails every entry leg: not vhost-challenge-armed (leg 1), no solve
storm (leg 2), no pressure (leg 3), population self-declares bot (leg 4). It
can never reach the state — by construction, not by tuning.

**Live FP found while capturing this** (action item, independent of this
design): `CHALLENGE_SUBNET` is currently issuing per-IP challenges to Meta's
crawler /24 (`57.141.20.0/24`, 60+ IPs, `meta-externalagent` UA) on
stereotiki — the `SUBNET_MIN_IPS=60` heuristic caught a legitimate crawler
farm. The subnet-challenge path should run the same good-bot exemption before
firing, and `goodBotPTRSuffixes` (internal/webdetector/abuse_shadow.go) should
learn Meta (`.fbsv.net` PTRs, FCrDNS-confirmed) — plus the Greek comparison
crawlers (Skroutz/BestPrice/Shopflix) via UA+ASN allowlist. Tracked as I0.

## 5. Good-bot exemption — always first

Before anything is counted, fingerprinted, or acted on:

1. **Self-declared bot UAs** are out of the "claims-browser" population by
   definition (they claim bot, not browser).
2. **FCrDNS-verified** good bots (`verifiedGoodBot`: Google/Bing/Apple/
   Yandex — extend with Meta per §4) are exempt from every count and every
   action. A fake "Googlebot" from a residential proxy fails forward-confirm
   and gets no exemption.
3. **Operator allowlist** (UA-substring + ASN) for known partners the PTR
   scheme can't verify: Skroutz, BestPrice, ahrefs, semrush, GPTBot,
   ClaudeBot, meta-externalads…

Nothing in this design may key an *adverse* decision on country or ASN alone
(the standing invariant: origin is never innocence, and never guilt).

## 6. In-state actions (the ladder)

DRYRUN=1 stops after 6.0. Everything below is TTL'd and vhost-scoped.

- **6.0 Notify + record** (I1): history event + notification with the evidence
  one-liner ("challenge defeated: 31 solving IPs/min from 28 countries; RT 9.8s").
- **6.1 Harden** (the §4 actuator challenge-engine.md calls "the one worth
  building"): raise PoW difficulty for this vhost + throttle challenge
  issuance. Zero FP risk, immediately raises the farm's cost.
- **6.2 Campaign fingerprinting** (I2, shadow first): over the flagged window,
  compute the attacking population's common denominators — vector-agnostic:
  - base-path concentration (e-athlos: `/shop/` = 95%);
  - query-shape: param-key set + value cardinality (`filter_category` with
    ≥5 values — tomorrow it's `?search=` or id enumeration, same feature);
  - UA-pool uniformity (~25 UAs in near-equal shares; real audiences are
    power-law — synthetic uniformity is the tell);
  - dynamic-fraction ≈ 1.0 (no assets; `ipsDyn/ips`, already collected);
  - tls_fp cluster (already stamped per solve).
  Each candidate **deny predicate** is scored
  `coverage(attack) × (1 − collision(baseline))`, where collision is measured
  by replaying the predicate against the vhost's pre-attack traffic via the
  existing traffic-rules **simulate** endpoint. A predicate arms only above a
  coverage floor AND below a collision ceiling (proposed: ≥60% / ≤0.5%).
- **6.3 Draft + notify** (I3): the winning predicate becomes a **draft**
  vhost-scoped traffic rule (`action=block`, `RULE_TTL`), delivered in the
  notification with a one-liner to apply:
  `cfm webtop attack apply <vhost> <draft-id>`.
- **6.4 Auto-apply** (I4, after burn-in proves the collision gate): the rule
  applies itself, still TTL'd, still logged, still revocable.
- **6.5 Repeat-offender escalation** (I5): an IP that keeps hitting the armed
  predicate after being 403'd N times within a window is a persistent bot
  node → TTL'd nft ban via the existing detector-sink path (the
  `waf_security` accumulate model, reused not reimplemented).

## 7. 403 vs L3 block — the decision

**403-first, nft only for repeat offenders.** Rationale:

- This attack shape is *rotating* residential/CGNAT exits: median 2–4
  requests per IP, then gone. A per-IP L3 ban mostly bans an address that
  already left (the solver-farm postmortem measured 1.07 solves/address), and
  on CGNAT it takes real customers with it. The durable identity of the
  campaign is the **pattern**, not the address — so the primary weapon is the
  pattern-keyed 403 at the edge, which survives rotation by construction.
- The 403 is surgical: it denies the matching *requests* only; the same IP
  can still browse the rest of the site, so a rare human collision costs one
  odd URL, not the site.
- What the 403 does NOT fix is log flood and edge cost. Two answers: denied
  hits log **deduplicated** per (ip, rule) per cooldown (the `should_push`
  pattern the WAF already uses), and §6.5 promotes the persistent minority to
  nft where they cost nothing. The one-shot majority never earns an nft entry
  — and doesn't need one.

## 8. Guardrails

- Good-bot exemption before everything (§5); adverse keys never country/ASN-only.
- No predicate arms without passing the baseline-collision gate (§6.2).
- Every action TTL'd; every rule vhost-scoped; nothing server-wide.
- `UNDER_ATTACK_DRYRUN=1` ships first; burn-in on titan against §4's contract.
- `cfm webtop attack off <vhost>` always wins, immediately, with holddown.
- The state machine only *escalates* what the challenge layer already armed —
  it never challenges or blocks a vhost the existing paths left alone.

## 9. Increments

- **I0** — good-bot fixes from §4: Meta in `goodBotPTRSuffixes` (FCrDNS),
  good-bot exemption in the subnet-challenge path, seed the partner allowlist
  (Skroutz/BestPrice/…). Independent, ships first, fixes a live FP.
- **I1** — efficacy detector + state + surfacing + notify. Log-only
  (`DRYRUN=1`). The operator stops discovering "challenge defeated" from logs.
- **I2** — fingerprinter in the abuse-shadow harness: candidate predicates +
  coverage/collision logged, nothing enforced. Validate on e-athlos live.
- **I3** — draft rule + notification + `attack apply` command.
- **I4** — auto-apply + harden actuator.
- **I5** — repeat-offender nft escalation via the detector sink.

## 10. Open questions

- Threshold calibration for `SOLVES_MIN` (needs a week of `challenge_events`
  baselines across the fleet — what does a *working* challenge's solve rate
  look like on a busy legit vhost?).
- Multi-vhost campaigns: the same fingerprint appearing on several vhosts
  should become one campaign object (fleet-level, via cfm-web) rather than N
  independent states — out of scope for I1–I5, noted for the fleet layer.
- Whether 6.1 harden needs its own knob or rides `UNDER_ATTACK` (leaning:
  rides the state; it is the state's whole point).
