# WAF → autoblock via the detector framework — design

> **Status: PHASE 1 IMPLEMENTED.** The `waf_security` detector, the
> `SubscribeWAFHitEvents` hook (published from `Engine.RecordWAFTrigger`), and
> the `[waf_security]` + `[waf_security.leniency]` config all exist. Phase 1 is
> scoped to **edge-`block` hits only** — the subscribe callback drops any hit
> whose edge action isn't `block`, so only what the WAF already blocked feeds
> the counter ("block at WAF → nft candidate"). Among those, the opted-in
> families `SQLI`/`RCE`/`BACKDOOR`/`UPLOAD_EXPLOIT` are ON at threshold 1; all
> challenge-tier families ship at `0`. It ships enforcing a **soft TTL block**
> (`BLOCK = "6h"`, self-healing) rather than `permanent`; `DRY_RUN = 1` remains
> available for a pure watch-first burn-in, and GR/CY get a 15m lenient tier.
> Phase 2 (relax the action gate + turn on challenge-tier families from live
> data) and Phase 3 (per-/24 escalation) are still design-only, as is the
> Phase-2 edge-ban-dict retirement below.

## Motivation

Two things came together:

1. A 6-server `cfm.waf.log` review (2026-07) showed the SQLi families are
   **100% precise** (24/24 `WAF_SQLI` TP, 188/188 `WAF_SQLI_LEXICAL` TP, 0 FP),
   dominated by **distributed** campaigns (one error-based sqlmap sweep used
   ~180 rotating proxy IPs against a single host). Per-request `block` stops
   each request, but the same IPs keep coming — there is no persistent,
   L3/L4, cross-request ban.
2. The edge currently tracks bans in an **in-RAM shared-dict** that is hard to
   inspect ("is this customer IP blocked, and why?"). We want a **single
   source of truth**: the block lives in **nftables** (queryable via
   `cfm which <ip>` / `cfm search`), is logged to **`cfm.detectors.log`**,
   flows to the **cfm-web unblock API** (who/where/why/which-rule), and is
   **emailed** like every other detector block (filterable by country/ASN in
   the operator's inbox).

The insight: **this is not a new mechanism.** CFM already has a detector that
does exactly "subscribe to a webdetector event stream → score per IP → block
via the shared framework (with leniency, allow-lists, blocklist, API, email)":
`internal/detectors/api_abuse_register.go`. The WAF-block detector is the same
shape with a new signal source.

## Principle

> **The WAF *detects* (in-path, per-request). The detector framework
> *decides the persistent block* (cross-request, stateful, geo-aware).**

The Lua WAF is stateless per request and must not own ban-state, geo logic, or
leniency. Those already live in the detector framework. So we feed WAF hits
into a new detector and reuse everything downstream. This matches the layering
in `CLAUDE.md` (WAF detects in-path; web-detector does behavioural scoring →
block).

## Two orthogonal decisions (read this first)

There are **two independent knobs**, and conflating them is the easy mistake:

1. **Edge WAF action** — what happens to *this* request, right now (in Lua):
   `logonly` (log) / `challenge` (interstitial) / `block` (**403 now**).
2. **`[waf_security]` threshold** — how fast this **IP** accrues toward a
   **persistent nft block** (in the detector). This is fed by **every WAF hit
   whose family threshold is > 0**, *independent of the edge action*.

They are orthogonal, and often diverge:

| Family | Edge action (now) | `[waf_security]` | Result |
|---|---|---|---|
| `WAF_SQLI` | `block` = 403 now | `SQLI=1` | 403 now **+** instant nft ban |
| `WAF_BAD_UA` | `challenge` now | `BAD_UA=40` | challenge now **+** nft after 40 in WINDOW |
| `WAF_AUTH_BURST` | `challenge` now | `AUTH_BURST=0` | challenge now **+** NEVER nft |
| `WAF_SUPERGLOBAL` | `logonly` | `=0` | log only, nothing else |

The counter is **not** "only fed by `block` hits": a `challenge`-mode family
(`WAF_BAD_UA`) still accumulates toward nft — otherwise a forever-challenged
scanner flood would never get an L3/L4 ban. Once the nft ban lands, the IP is
dropped **before** it reaches the edge; during the ≤`EVERY` window before that,
the edge action (403 / challenge) covers the requests.

**Why feeding the counter from `challenge` hits is safe — clearance self-cleans
it.** A `challenge` isn't only a gate; passing it mints a **clearance** for a
TTL (~1h). During that window the WAF's challenge-tier rules don't re-fire for
that IP, so **a human who solves the challenge emits zero further challenge
events** and never approaches the threshold — while also getting a reassuring
"you're protected" interstitial and ~1h of frictionless browsing. The only IPs
that keep generating `challenge`-tier hits are the ones that *never clear it*,
i.e. bots ignoring the interstitial. So the nft counter, when fed by a
challenge-tier family, is effectively a **bot-persistence** counter: it rises
for clients that repeatedly trip the rule *without* proving human, and stays
flat for anyone who solved it once. That is the whole point of the split —
"show the challenge" and "count it as an nft candidate" are different acts, and
clearance is what keeps the second from ever touching a real customer.

## Flow

```
 Lua WAF rule fires (record())            configs/lua/cfm_waf.lua
        │  per-hit event
        ▼
 webdetector.SubscribeWAFHitEvents(...)   NEW hook (Phase 1)
        │  core.InputEvent
        ▼
 wafsec.Detector  (copy of apiabuse)      internal/detectors/wafsec/
        │  per-IP counters per reason-family, thresholds, allow-lists
        ▼  core.Alert{Kind:"WAF/SQLI", Key:ip, Extra:{rule_id,host,uri,…}}
 shared detector framework
        ├── leniency (GR/CY → temp ban, lenient blocklist)   [waf_security.leniency]
        ├── nftables block (permanent / TTL)                 cfm which / cfm search
        ├── cfm.detectors.log                                one line per block
        ├── cfm-web unblock API (who/where/why/rule)
        └── email notification                               filter by country/ASN
```

## Event → Alert contract

The existing `core.InputEvent` (in `internal/detectors/core/input_event.go`)
already carries everything we need — no struct change:

| `core.InputEvent` field | WAF value |
|---|---|
| `Source` | `"waf"` |
| `Reason` | reason family, e.g. `"WAF_SQLI"` (drives per-family thresholds) |
| `Signal` | the specific `rule_id`, e.g. `"301"` / `"309"` (drill-down attribution) |
| `Scope` | the vhost / `host` |
| `SrcIP` | client IP (the block/counter key) |
| `Path` | request URI · `Method` / `Status` / `UserAgent` from the request |
| `When` | hit timestamp |

Note: **country/ASN are NOT carried in the event** — the framework's leniency
layer geo-resolves the IP at block-decision time (that's how
`[exim_security.leniency] MATCH_COUNTRY` already works). One less thing for the
WAF to plumb.

The detector emits `core.Alert` (in `internal/detectors/core/types.go`),
mapping family → `Kind` and specifics → `Extra`:

```go
core.Alert{
    Kind: core.AlertKind("WAF/SQLI"),      // family: grouping, thresholds, inbox filter
    Key:  ev.SrcIP,                        // the IP
    Extra: map[string]string{
        "rule_id": ev.Signal,              // 301 / 309 — per-rule drill-down
        "reason":  ev.Reason,              // WAF_SQLI / WAF_SQLI_LEXICAL
        "host":    ev.Scope,               // where
        "uri":     ev.Path,                // where
        "action":  "block", "ttl": "...",  // set by the enforcement tier
    },
}
```

### Per-rule visibility (the "who is blocked, and by which rule" requirement)

Attribution lives at **two levels at once**, so both queries work:

- **By family** — `Kind = WAF/SQLI` vs `WAF/RCE` vs `WAF/UPLOAD`: grouping,
  per-family thresholds, and inbox rules by country/ASN.
- **By specific rule** — `Extra["rule_id"]`: e.g. `grep 'rule=309'
  cfm.detectors.log` shows exactly who was blocked by the lexical rule vs 301.

Example block line (log / email / API):

```
WAF/SQLI  ip=185.199.197.32  rule=301 reason=WAF_SQLI  host=alexandras.gr
          uri=/wp-admin/admin-ajax.php?action=ays_sccp…SLEEP(6)…
          action=block(permanent) count=1
```

`Kind` is a free string; if per-rule grouping is ever wanted at the top level,
it can be `WAF/SQLI/309`. Default recommendation: **family in `Kind`
(one counter/threshold per family), `rule_id` in `Extra`** (full per-hit
attribution) — the same split `cfm_endpoints` uses for its stages.

## Config schema — mirrors `exim_security`

```ini
[waf_security]
ENABLED = 1
EVERY   = "20s"          ; evaluation cadence
WINDOW  = "30m"          ; rolling per-IP counter window
SAMPLE_LIMIT = 10
COOLDOWN = "20m"

; Per-IP thresholds by WAF reason FAMILY (hits in WINDOW → block).
; Confirmed-malicious families = instant (1); noisy/probe = accumulate;
; 0 = never autoblock (family stays edge-only: logonly/challenge as configured).
; Defaults justified by the 6-server 2026-07 review (0 FP on the injection set).
;
; --- PHASE 1 (SHIPPED ON): only edge-`block` HITS feed the counter. ---
; AS IMPLEMENTED: the subscribe callback drops any hit whose edge action isn't
; `block`, and the config key for a family is its name minus WAF_ (so the
; grouped `UPLOAD_EXPLOIT` below is really two keys, UPLOAD_FNAME + UPLOAD_
; CONTENT). Because only edge-`block` hits feed, only families that HAVE a
; block-tier rule can ever fire in Phase 1 — as of 2026-09-05 (source: the Go
; registry, DefaultMode "block"): WAF_SQLI (301), WAF_SQLI_LEXICAL (309),
; WAF_RCE (320, 329), WAF_UPLOAD_FNAME (401, 414), WAF_UPLOAD_CONTENT (402),
; WAF_WEBSHELL (413, the proper-noun drop-path subset, added 2026-07-03),
; WAF_CVE (10001+), WAF_PHP_WRAPPER (305), WAF_AUTH_BURST (510-512) and
; WAF_TRAVERSAL (101, promoted 2026-09-05). All default to 1 except WAF_TRAVERSAL, held at 0 through its
; burn-in (volume: ~2 300 scanner IPs/week fleet-wide); its step runs after every
; armed block family in cfm_waf.lua so it cannot shadow their bans. WAF_WEBSHELL was HELD at 0 through burn-in — a webshell
; GET-probe (`/c99.php`) is also what benign scanners (Shodan/Censys/monitors)
; do — but as of 2026-07-18 the operator runs it armed fleet-wide and confirms it
; cleanly bans malicious scanners/scrapers/bots, so it now arms to 1 by default
; like the rest. BACKDOOR has no block rule yet (430-438 are logonly/challenge) so
; it is inert, but is armed to 1 so it fires the moment one (e.g. 438) is promoted.
; Every family is a knob and the full registry is covered automatically
; (TestWAFSecurityFamilyCoverage).
SQLI            = 1      ; WAF_SQLI (301, block). Separate key SQLI_LEXICAL (309)
                        ;   is challenge-tier → inert in Phase 1.
RCE             = 1      ; WAF_RCE (has block rule 320)
BACKDOOR        = 1      ; WAF_BACKDOOR (430-438) — armed; no block rule yet
UPLOAD_EXPLOIT  = 1      ; = UPLOAD_FNAME (401) + UPLOAD_CONTENT (402), both block
WEBSHELL        = 1      ; WAF_WEBSHELL (413, block) — armed by default (2026-07-18).
                        ;   Exempt a benign scanner with ALLOW_UA_CONTAINS/ALLOW_NETS
                        ;   or hold the rule with RULE_413 = 0 if needed.
;
; --- PHASE 2 (SHIP AT 0; raise per-family once live data confirms): ---
; edge-`challenge` families. They keep triaging humans vs bots at the edge; we
; only start feeding the persistent counter after observing real accrual rates.
; Intended (not-yet-active) values kept here as guidance:
XXE             = 0      ; (intended 2) WAF_XXE (307)
SSRF            = 0      ; (intended 2) WAF_SSRF (7xx)
BAD_UA          = 0      ; (intended 40) WAF_BAD_UA (201) — scanner floods
IP_HOST         = 0      ; (intended 25) WAF_IP_HOST (602) — bare-IP-Host scanners
;
; --- NEVER feed autoblock (stay 0 permanently): ---
; AUTH_BURST: a legitimate admin/dev doing bulk WordPress logins across many
; sites once tripped an auth-burst *block* (real incident). It stays
; edge-`challenge` (rule 501, a human solves it in the browser); it must never
; become a persistent nft ban here.
AUTH_BURST      = 0      ; WAF_AUTH_BURST (501/502/510-512) — edge-challenge only
SUPERGLOBAL     = 0      ; WAF_SUPERGLOBAL (318, logonly) — observe-only
BAD_UTF8        = 0      ; WAF_BAD_UTF8 (611, logonly) — observe-only

; Per-RULE overrides (by numeric rule id) win over the family default above.
; For rules that behave differently from their family — tighten the ones that
; are almost-always-attack, loosen the noisy ones — same idea as
; exim_security's core-rule + per-signal "specials".
;RULE_511 = 2           ; xmlrpc pingback: near-always attack → strict
;RULE_501 = 25          ; generic auth-burst: extra-lenient (bulk-admin devs)
;RULE_411 = 1           ; webshell-ping fingerprint: instant

; False-positive escape hatch (same keys cfm_endpoints uses). For a KNOWN legit
; source (e.g. that bulk-update developer's box) this is the sharpest tool —
; allow the IP and skip scoring entirely.
ALLOW_IPS  = ""         ; never block these IPs (+ the GLOBAL NET/IP ignore list)
ALLOW_NETS = ""

BLOCK = permanent
BLOCK_COOLDOWN = 30m

[waf_security.leniency]
; Trusted geographies: a GR/CY IP sending SQLi is likelier a compromised local
; machine / legit customer scan / rare FP → soft tier + surface for review,
; not a permanent farm-wide ban.
MATCH_COUNTRY  = "GR,CY"
;MATCH_ASN     = "..."          ; the big GR/CY ISP ASNs, if desired
BLOCK          = "15m"          ; temp ban, not permanent
BLOCK_COOLDOWN = "15m"
SEND_TO_API       = YES         ; report → support/unblock lookup
SEND_TO_BLOCKLIST = lenient     ; local-only, NEVER served to the farm
```

### Challenge is the human/bot filter — leniency only ever meets block-tier hits

An important consequence of the *two orthogonal decisions* above: **challenge
already does the "is this a human or a bot?" triage at the edge**, per request,
for free. A leniency tier only has to worry about hits that would feed a
persistent nft ban — i.e. families with a threshold `> 0` — and in practice
those are the unambiguous block-tier ones (`SQLI`/`RCE`/`BACKDOOR`/…), not the
ambiguous challenge-tier ones.

This is not a hypothesis; it is what the fleet actually does. Re-scanning the
six production `cfm.waf.log` files (85,797 WAF events, 2026-06/07):

| bucket | count | families seen |
|---|---|---|
| **GR — block** | **0** | — |
| **CY — block** | **0** | — |
| GR — challenge | 129 | `BAD_UA` (108), `AUTH_BURST` (11), `IP_HOST` (8), `XSS` (2) |
| CY — challenge | 19 | `BAD_UA` (19) |
| GR — logonly | 108 | `BAD_UTF8` (108) |

**Not one GR or CY IP hit a block-tier rule.** Every GR/CY hit landed in a
challenge- or logonly-tier family, and every one, on inspection, is either
benign infra (`IP_HOST` = someone reaching a farm box by bare IP; `AUTH_BURST`
= a farm-local host and Jetpack/pingback hammering `xmlrpc.php`) or the exact
"human-or-bot?" grey zone (`BAD_UA`, `XSS`-looking crawler URLs) where the
challenge is the correct discriminator — a human solves it, a bot doesn't.

So the leniency design lands as:

1. **Challenge-tier families never feed the nft counter for GR/CY** anyway,
   because the challenge already exonerated the humans among them. (They accrue
   for *other* countries via their family threshold; for GR/CY the family
   threshold path simply doesn't get exercised, because those hits stay at
   challenge and never escalate.) Nothing special to code — it falls out of
   "challenge is edge-only unless the family threshold is crossed", and GR/CY
   traffic doesn't cross it.
2. **Only a block-tier hit from GR/CY reaches the leniency tier at all** — and
   that population is empirically *empty*, so the conservative
   `15m + API + lenient-blocklist` tier costs us nothing on real Greek
   customers while still catching the rare compromised-.gr-host case.
3. Leniency is **geo-only, and must stay conservative**, because GeoIP is
   game-able: `148.135.200.x` in the sample geolocates to Greece but is a cheap
   reseller VPS range brute-forcing `xmlrpc.php`. A permanent-skip for "GR" would
   hand attackers a bypass by renting GR-geolocated space; a temp-ban + surface
   does not.

`meta.Register(... LeniencySupported: true)` (as `cfm_endpoints` does) is what
activates the `[waf_security.leniency]` section — no extra code.

## What already exists vs. what to build

**Reused, no new code:** leniency (`[.leniency]`), `ALLOW_IPS`/`ALLOW_NETS` +
global ignore, nft block, `cfm.detectors.log`, cfm-web unblock API + "where &
why" findings, email notifications, per-IP counters/windows, the periodic
`RunOnce → core.Alert` pipeline.

**Phase 1 (new) — block-tier only, the conservative first slice.** The hook and
detector are built once and handle every family, but the *shipped default
config* only turns on the edge-`block` (0-FP) families; every challenge-tier
family ships at `0` (edge-only, exactly as today). So Phase 1 changes behaviour
for `SQLI`/`RCE`/`BACKDOOR`/`UPLOAD_EXPLOIT` and nothing else — no risk to the
challenge-tier FP-prone families (auth-burst, bad-UA) until we have live data.
1. `webdetector.SubscribeWAFHitEvents(func(WAFHitEvent))` — the WAF engine
   already calls `record()` on every hit; emit a per-hit event carrying
   `ip / reason / rule_id / host / uri / method / status / ua`. (Today only
   per-host hit-rate *counters* cross to Go; this adds the per-IP event.)
   The hook emits all hits; the *detector* is what discards families whose
   threshold is `0`, so Phase 2 is pure config — no change to the emit path.
2. `internal/detectors/wafsec/` — a near-copy of `internal/detectors/apiabuse`
   (per-IP counters keyed by reason-family, thresholds, allow-lists,
   `RunOnce → core.Alert`).
3. `internal/detectors/waf_security_register.go` — a near-copy of
   `api_abuse_register.go` (`meta.Register` + `Register("waf_security", …)` +
   `SubscribeWAFHitEvents`).
4. `[waf_security]` + `[waf_security.leniency]` in `configs/detectors.conf`,
   with challenge-tier families at `0` (see the config schema above).

**Phase 2:** turn on challenge-tier families one at a time (`BAD_UA`, `IP_HOST`,
…) by raising their threshold above `0`, tuned from live `cfm.detectors.log`
data (e.g. does `BAD_UA=40` over `WINDOW=30m` block real scanners without
catching a busy legit crawler?). Pure config — no code change. **Also here:**
retire the edge in-RAM ban shared-dict for block-state (keep it for hit-rate
counting) once the nft path is trusted; until then the two coexist harmlessly
(edge 403 *and* nft ban is redundant defence, no coverage gap).

**Phase 3:** distributed-campaign escalation — per-`/24` or per-ASN counters,
so a rotating swarm (the lexima.de pattern: ~180 IPs, each 1-2 hits) escalates
to a range/ASN block instead of whack-a-mole per IP. Per-IP instant block
already handles each swarm IP on its first hit; this is an optimisation.

## Open questions (decide before Phase 1)

- **Detector name:** `waf_security` (sibling of `exim_security`,
  `postfix_security`) vs folding into `[webdetector]`. Proposal: standalone
  `waf_security` — clean per-family config + it is a distinct signal source.
- **Counter key granularity:** per-IP-per-family thresholds (`SQLI`, `BAD_UA`, …)
  with **per-rule (`RULE_<id>`) overrides** on top — resolved. Per-family keeps
  config simple; the ID override handles rules that behave unlike their family
  (a real driver: an admin doing bulk WP logins tripped an auth-burst *block*
  once, hence `AUTH_BURST = 0` here — it stays edge-challenge and never feeds a
  persistent ban). Known legit sources are handled even more sharply by
  `ALLOW_IPS` / the global ignore list.
- **`Kind` granularity:** `WAF/<family>` (proposed) vs `WAF/<family>/<rule_id>`.
- **Leniency for unambiguous SQLi (GR/CY):** *resolved — temp-ban + API,* on the
  data. A re-scan of the six production logs (85,797 events) found **zero** GR/CY
  hits at any block-tier family; every GR/CY hit was challenge/logonly-tier and
  benign or challenge-triageable (see "Challenge is the human/bot filter" above).
  So `15m + API + lenient-blocklist` for GR/CY costs nothing on real customers
  yet still surfaces the rare compromised-.gr-host, and — because GeoIP is
  game-able (a GR-geolocated VPS was brute-forcing xmlrpc in the sample) —
  leniency must stay a *temp-ban*, never a skip.
