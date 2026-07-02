# WAF → autoblock via the detector framework — design

> **Status: DESIGN PROPOSAL — not yet implemented.** This document is for
> review before any code. Nothing here describes current behaviour; the WAF
> today enforces per-request (`logonly`/`challenge`/`block`) at the edge and
> does not feed a persistent IP block. When Phase 1 lands, update this banner.

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
attribution) — the same split `api_abuse` uses for its stages.

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
SQLI            = 1      ; WAF_SQLI + WAF_SQLI_LEXICAL — 0-FP by design
RCE             = 1      ; WAF_RCE (320)
BACKDOOR        = 1      ; WAF_BACKDOOR (430-437)
UPLOAD_EXPLOIT  = 1      ; WAF_UPLOAD_FNAME/_CONTENT (401/402) — Joomla JCE etc.
WEBSHELL        = 2      ; WAF_WEBSHELL probe scans (410/411)
XXE             = 2      ; WAF_XXE (307)
SSRF            = 2      ; WAF_SSRF (7xx)
BAD_UA          = 40     ; WAF_BAD_UA (201) — scanner floods, accumulate
IP_HOST         = 25     ; WAF_IP_HOST (602) — bare-IP-Host scanners
; AUTH_BURST deliberately does NOT feed autoblock — a legitimate admin/dev
; doing bulk WordPress logins across many sites once tripped an auth-burst
; *block* (real incident). It stays edge-`challenge` (rule 501, a human solves
; it in the browser); it must never become a persistent nft ban here.
AUTH_BURST      = 0      ; WAF_AUTH_BURST (501/502/510-512) — edge-challenge only
; observe-only families NEVER feed autoblock:
SUPERGLOBAL     = 0      ; WAF_SUPERGLOBAL (318, logonly)
BAD_UTF8        = 0      ; WAF_BAD_UTF8 (611, logonly)

; Per-RULE overrides (by numeric rule id) win over the family default above.
; For rules that behave differently from their family — tighten the ones that
; are almost-always-attack, loosen the noisy ones — same idea as
; exim_security's core-rule + per-signal "specials".
;RULE_511 = 2           ; xmlrpc pingback: near-always attack → strict
;RULE_501 = 25          ; generic auth-burst: extra-lenient (bulk-admin devs)
;RULE_411 = 1           ; webshell-ping fingerprint: instant

; False-positive escape hatch (same keys api_abuse uses). For a KNOWN legit
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

`meta.Register(... LeniencySupported: true)` (as `api_abuse` does) is what
activates the `[waf_security.leniency]` section — no extra code.

## What already exists vs. what to build

**Reused, no new code:** leniency (`[.leniency]`), `ALLOW_IPS`/`ALLOW_NETS` +
global ignore, nft block, `cfm.detectors.log`, cfm-web unblock API + "where &
why" findings, email notifications, per-IP counters/windows, the periodic
`RunOnce → core.Alert` pipeline.

**Phase 1 (new):**
1. `webdetector.SubscribeWAFHitEvents(func(WAFHitEvent))` — the WAF engine
   already calls `record()` on every hit; emit a per-hit event carrying
   `ip / reason / rule_id / host / uri / method / status / ua`. (Today only
   per-host hit-rate *counters* cross to Go; this adds the per-IP event.)
2. `internal/detectors/wafsec/` — a near-copy of `internal/detectors/apiabuse`
   (per-IP counters keyed by reason-family, thresholds, allow-lists,
   `RunOnce → core.Alert`).
3. `internal/detectors/waf_security_register.go` — a near-copy of
   `api_abuse_register.go` (`meta.Register` + `Register("waf_security", …)` +
   `SubscribeWAFHitEvents`).
4. `[waf_security]` + `[waf_security.leniency]` in `configs/detectors.conf`.
5. **Retire the edge in-RAM ban shared-dict** for block-state (keep it only for
   hit-rate counting). The per-request WAF rule still 403s during the
   ≤`EVERY` window before nft takes over, so there is no coverage gap.

**Phase 2:** tune per-family thresholds from live `cfm.detectors.log` data
(e.g. does `BAD_UA=40` over `WINDOW=30m` block real scanners without catching
a busy legit crawler?).

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
- **Leniency for unambiguous SQLi:** even GR/CY — temp-ban (proposed, softer)
  vs no leniency (SQLi is 0-FP, so arguably block GR/CY too). The temp-ban +
  API-surface path is safer for the rare compromised-local-host case.
