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
; WAF_TRAVERSAL (101, promoted 2026-09-05; 103, raw-path, added 2026-09-22). All default to 1 except WAF_TRAVERSAL, held at 0 through its
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
SUPERGLOBAL     = 0      ; WAF_SUPERGLOBAL (318, challenge_v2) — edge-challenge only
BAD_UTF8        = 0      ; WAF_BAD_UTF8 (611, disabled) — off (FP-only, 2026-09-23)

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

## Decision record — held block families and evaluation order (2026-09-05)

`record()` gives the headline to the FIRST block-tier hit and `goto done` ends
evaluation; `cfm.lua` pushes only that headline, so the family `wafsec` sees on
a request that trips two block families is whichever ran first. That was
harmless while every block family was armed. Rule 101 (`WAF_TRAVERSAL`) is the
first block family HELD at 0, and a held family evaluated first would have
shadowed `WAF_RCE` / `WAF_PHP_WRAPPER` / … on wrapper-LFI and LFI→RCE requests
and cost them their ban. The fix is ORDER: the traversal step runs after every
armed block family in `cfm_waf.lua` (pinned by `cfm_waf_traversal_test.lua`
and severity test 15b).

**"Push every block-tier hit" was considered and deliberately rejected**
(2026-09-05). It would require removing the block short-circuit (86 `goto
done` sites), i.e. running the heavy body/upload/base64 scanners on every
request that is already blocked at a cheap step — the short-circuit is the
cheap-rules-first design of the pipeline, and the requests it saves are
exactly the scanner floods. Plus a new `ip_push` field, a Go ingest change and
four tests changing semantics, all for a case that does not occur: the only
held family runs last, and the "mirror image" (an operator arms `TRAVERSAL`
and un-arms an earlier family) is a misconfiguration, documented in CLAUDE.md
§6. Known cost of the order fix: a traversal-only scanner request runs the
remaining detectors before blocking (~11.5k such requests/week fleet-wide, a
few string scans each).

**Revisit only if a second held family appears** — two held families cannot
both run last. Even then the cheap fix is not to drop the short-circuit but to
let `record()` keep evaluating only when the block hit belongs to a held
family (a small Lua-side set mirroring `heldAutoblockFamilies`), so armed
families still short-circuit as today.

**Rule 201's block joins the late group (2026-10-09).** `WAF_BAD_UA` has no
block-tier rule (its default is `challenge_v2`), so it is not armed, yet a
score >= 99 scanner identity (sqlmap, nikto, nuclei, zgrab, the fake legacy
MSIE / Windows UAs) or an operator `block` mode blocks. Recorded at step 1 it
was the first block hit on every such request: sqlmap's own SQLi payload, a
nuclei CVE probe, never reached autoblock or the CVE alert. The block is now
recorded after every armed block family and before traversal (step 1 keeps
the challenge/logonly tiers; `cfm_waf_bad_ua_shadow_test.lua`), and at
`::done::` when an earlier block ended evaluation, so the 201 hit stays in
`hits`. Same order fix, same cost shape as traversal: a fleet read of
2026-10-02..09 showed ~14.5k score-99 events a week (sampled, one per IP /
family / tier a minute; mostly `UA_FAKE_LEGACY_MSIE`, 76 `UA_SQLMAP`), which
now run the remaining budget-capped detectors before blocking. Side effects: those requests now
feed the per-IP burst counters (rules 510-512, armed, can ban them), cost what
a browser-UA request costs (~45 µs a GET, ~4 ms a 30 KB form POST), and the
challenge / logonly hits behind 201 now show in `also_rule_ids`, so burn-in
"also" counts include scanner traffic from this date. Mirror image, as for
traversal: an operator who arms `BAD_UA = 1` loses the 201 ban on a request
where an earlier held or un-armed block rule (10019/10020, a family set to
0) also matched; at the shipped arming neither side bans. Authorised scanners (Nessus,
Acunetix/AWVS, AppScan are score 99) that send an armed payload are now banned
too; `ALLOW_NETS` / `ALLOW_UA_CONTAINS` exempt them. A rule that raises behind
the deferred block no longer lets the scanner through under `fail_open`
(cfm.lua's `waf_error` path): `_M.check` runs the pipeline under `xpcall`
and, when a 201 block is pending, blocks as 201 and logs `[cfm_waf] rule
raised behind a deferred rule-201 block`.

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

## Edge ban — clients behind a trusted proxy (2026-10-10)

An nft ban drops by the address on the wire. A client behind a trusted proxy
(Cloudflare) arrives from the proxy's address, and the edge learns the real one
from `CF-Connecting-IP` via realip, so `ip saddr @block_v4 drop` never sees it:
34.153.214.160 was banned for 7 days by `waf_security` and kept hitting
`cpanel.`/`cpcontacts.` hostnames through Cloudflare (titan, mars, orion,
speedhost, 2026-10-09).

`internal/edgeban` keeps the bans the edge enforces itself. **What goes in:**
the sink's bans for the web sections (`edgeban.WebSection`: waf_security,
webdetector, challenge_*, modsec, cfm_endpoints, cpanel), the challenge
server's self-protection blocks, and manual bans (`POST /api/v1/firewall/block`,
cfm-admin's "Block selected" `POST /api/v1/firewall/block/batch`, `cfm block`
through `POST /api/v1/webdet/edge-ban`; a CIDR block is not). **What stays
out:** fleet feeds (`block_ext_*`), `cfm.deny` (it can hold thousands of
entries), port-scan / flood bans (L3/L4; some may be proxy addresses), mail /
SSH / FTP / database sections. It is not an nft mirror.

**Proxied requests only.** `cfm_decision.lua` adds `px=1` to the decision RPC
when realip replaced the TCP peer (`$realip_remote_addr ~= $remote_addr`); the
bridge answers the store only then. A direct client is nft's alone: its ban
drops it before the edge, and nft's allow sets decide for it. An older edge
sends no `px` and gets nothing from the store.

**Allows win, as in nft.** A reconcile reads every set nft accepts before its
block drops (`self_v4/v6`, `allow_v4/v6`, `allow_dyn_*`, `allow_ext_*` hosts
and nets — the fleet whitelist — and `allow_*_nets`; hosts, CIDRs and ranges),
and the store never answers an address they cover, even for a ban added after
the read (a ban added right after a NEW allow, before the next reconcile, is
the one residual). Nor does it answer a trusted proxy's own address
(trusted_proxies.conf): realip leaves `remote_addr` at a Cloudflare address
when CF-Connecting-IP names one (a Worker's subrequest), and a ban of it would
403 every visitor arriving that way. `cfm allow --ttl` lifts the edge ban for
good; when the allow expires nft blocks again but the edge does not (fails
safe).

**Consistency.** Every in-daemon unblock removes the entry
(`/api/v1/unblock`, `unblock.DoMany` — the agent's fleet unblock — and
`ForceUnblock`, which `cfm unblock` reaches over the API); `cfm allow` (over
`edge-ban?unban=1`) and a `cfm.allow` host lift it too. Every two minutes a
reconcile reads the block and allow sets — all of them or none: a failed or
partial read skips the reconcile, and three in a row make it answer nothing,
to the edge too, until a read works (it keeps its entries; the next working
read narrows them to nft) — and
*narrows* the store: an entry nft no longer blocks (expired, unblocked from the
CLI, flushed) is dropped unless it was written after the read began, and an
earlier nft expiry clamps it. It never imports from nft. The store persists in
`/var/lib/cfm/edgeban.json` (one writer at a time) and answers nothing until
the first reconcile after a start.

**Enforcement at the edge (B2).** `cfm_edgeban.lua` keeps the edge's own
copy of the list, pulled from `GET /nginx/edgeban` (`edge_ban_feed.go`). The
daemon keeps what the edge should hold (every address the store answers, less
IGNORE_IPS, capped at 20 000) and a numbered journal of the changes to it (the
last 4 096; an epoch per daemon start). It resyncs that list against the store
only when the store's version moves (every write, reconcile and switch), an
entry in it expires, or after 5 minutes: an idle poll is a version compare.
The edge sends its position (`epoch`, `seq`) and gets the changes since
(`set` / `del`), so a poll costs what changed, not the list; the whole list
comes on its first poll, after a daemon restart, when it is further behind
than the journal reaches, and every 10 minutes (a consistency check). A store
that has not reconciled yet replies `{"ready":false}` and the edge keeps its
copy.

One worker at a time (a dict lock held while a poll is in flight) polls every
5 s from a timer started by any `cfm.lua` request (the static location only
reads). The list lives in two slots of the `cfm_edgeban` dict (`cfm_decisions`
until the conf is reloaded), each value the id of the whole list it belongs
to: a whole list is written into the other slot and `eb:cur` flips to it in
one set, so a lookup never sees half a list and a leftover never matches;
changes are written into the live slot. Each entry lives as long as its ban
(a permanent one has no TTL), as in nft, so a daemon outage does not lift
bans at the edge. The dict is sized for two copies of the 20 000 cap (16m;
eight different 20k-IPv6 lists in a row kept the live list whole on nginx
1.24): a write into a full dict does not fail, it evicts the least recently
used keys, the leftovers of older lists. Past that size evictions would
reach live entries silently (back with the next whole list), and a lost
`eb:cur` makes the next poll ask for one. A store CLEARED after three
failed nft reads (the table gone after `cfm disable`) publishes an empty
list, so the edge drops its copy; only a store not yet reconciled since a
start replies `{"ready":false}`. An IPv4-mapped peer is looked up as IPv4.

**Mode.** `[webdetector] EDGE_BAN_MODE`, sent with every reply: `log` (the
default, the burn-in) counts and logs what it would block, `enforce` answers
403 (`X-CFM-Action: block`, `X-CFM-Edge-Ban: 1`, `$cfm_upstream = cfm_block`).
One `would_block edge_ban` / `block edge_ban` line per address per minute in
the edge error log. The edge's counts ride on its next poll; `GET
/api/v1/webdet/edge-ban` (admin; `edge-ban.json` in a `cfm debug` bundle) and
the bridge status show the mode, the journal position, the list size, the
last poll and full list, the would-block / blocked totals and the last resync
time. The decision path (B1) answers bans regardless of the mode, so during
the burn-in `would_block` also counts requests Step 3 blocks anyway: it is an
upper bound of what enforce adds (the clearance cookie, cached allows, 0d,
0a1 and static files are the difference).

`cfm.lua` checks it in **Step 0e**, right after the static IP/CIDR bypass
(`cfm_bypass_ip`, the crawler/CDN list) and before every other exemption:
the panel targeted bypass, the local-origin bypass, `/.well-known/` (0a1),
the cPanel proxy-subdomain passthrough (0d), the clearance cookie (2b) and the
decision's cached clean allows (up to 90 s). The static-asset locations, which
skip `cfm.lua`, call `cfm_edgeban.static_gate()` before the Site Cache gate.
Proxied requests only. On a proxied request it is two dict gets; on a direct
one, a variable compare. A ban or unban reaches the edge within one poll (5 s
plus the RPC). `cfm_edgeban_test.lua` pins the module and where `cfm.lua` and
both confs call it.

**Not covered:** the panel ports (2083/2087/2096, B3), the challenge page and
`/__cfm_verify`, `/cpanelwebcall` and `/cfm-admin`, which skip `cfm.lua` and
are not static assets.

### Burn-in read (2026-10-10, ~4 h after the deploy) — enforce is gated on it

`EDGE_BAN_MODE = log` on titan, earth, mars, rigel, orion, virgo, speedhost
since 2026-10-10 ~12:20 UTC. The first read, per node (store size /
`would_block` count from `edge-ban.json`; `would_block` lines are one per
address per minute):

| node | store | would_block | lines / IPs | |
|---|---|---|---|---|
| mars | 140 | 6 146 | 644 / 54 | 97% of lines on scanner paths |
| orion | 103 | 2 961 | 623 / 62 | 95% |
| titan | 31 | 1 765 | 23 / 12 | 87% |
| earth, rigel, virgo | 40 / 8 / 10 | 0 | — | |

Sources: `waf_security` and `webdetector` almost entirely (one `modsec`). The
bulk is a distributed `POST /xmlrpc.php` brute force through Cloudflare with a
forged `Jetpack by WordPress.com` / `WordPress.com` UA from residential
addresses worldwide (not Automattic's ranges), banned by rules 510-512: each
address ~150 requests, ~95% already 403 at the WAF, the ban stops the rest.
The others are scanners on `/wp-content/plugins/*/…php`, `/xyz.php`,
`/.env`-style paths, and cloud-hosted crawlers (Azure, GCP, DigitalOcean).
No Lua error, no latency change (titan `luams` p50/p95/p99 1/3/15 → 1/2/11
ms), edge-ban CPU ~0.1% of a core.

**Two false positives, both from `webdetector`'s `WEB/403` (`403_flood`), and
both pre-date the edge ban** (nft already banned them and reported them to the
fleet blocklist with `ttl=3600`; behind Cloudflare the nft ban missed them, the
edge ban in `enforce` would not):

- **Googlebot** (66.249.x.x, FCrDNS-verified — `abuse_shadow` already labels
  it `good_bot=googlebot verdict=exempt_goodbot`) crawling a WooCommerce
  shop's `?add_to_wishlist=` links, which the origin answers 403. Orion banned
  and reported a Googlebot address 10 times between 2026-10-02 and 10-10,
  mars once. `emitIPBlocks` has no good-bot exemption.
- **A logged-in WordPress admin** (Greek residential ISP) on the Site Kit
  dashboard: it polls `admin-ajax.php?action=rest-nonce` (200) and
  `wp-json/google-site-kit/v1/` (403 from the origin) every ~5 s, a third of
  its requests 403, above the 25% share gate.

**Good bots (fixed 2026-10-10):** `emitIPBlocks` — every webdetector IP ban
and challenge (`WEB/403`, `WEB/404`, `WEB/40X`, `WEB/403WAF`, `WEB/BOT`,
`WEB/MALPATH`, `WEB/RPS`) — now skips a verified good bot (`goodBotForBan`):
the same sources as the solver-farm finding's `good_bots`, the canonical
crawler PTR list forward-confirmed (FCrDNS, the bridge's verdict cache, inline
here) and the exclude file's `verify_fcrdns=1` PTR rules. Not the file's
`ua=` / `asn=` rules: a UA is a claim, and Google's ASN is all of GCP. The
skip is a `block_trigger` history row with `outcome=exempt_goodbot`. Other
sections that ban web clients (`waf_security`, `modsec`, challenge_*) do not
consult it: a WAF block-tier hit is the request's own payload.

**Gate for `enforce`:** the good-bot fix deployed (above), the
logged-in-origin-403 case decided, then a fresh read of every node shows no
would-block on a verified good bot or a residential address with a normal
browsing pattern. The next read is scheduled for 2026-10-20.
