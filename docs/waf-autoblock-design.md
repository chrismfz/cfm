# WAF → autoblock via the detector framework — design

**Status.** Phase 1 is built: the `waf_security` detector
(`internal/detectors/wafsec/`, registered in
`internal/detectors/waf_security_register.go`), the per-hit hook
`webdetector.SubscribeWAFHitEvents` (published from
`Engine.RecordWAFTrigger`), and the `[waf_security]` +
`[waf_security.leniency]` sections of `configs/detectors.conf`. Only
**edge-`block` hits** feed it, and it ships a **soft TTL block**
(`BLOCK = "6h"`) with a GR/CY 15 min lenient tier. Phase 2 (feed
challenge-tier hits) and Phase 3 (per-/24 / per-ASN escalation) are not
built. Which families and rules can ban: "Arming" below; the code registry
is the source.

## Motivation

A 6-server `cfm.waf.log` review (2026-07) found the SQLi families 100%
precise (24/24 `WAF_SQLI`, 188/188 `WAF_SQLI_LEXICAL`, 0 FP) and dominated by
**distributed** campaigns (one error-based sqlmap sweep used ~180 rotating
proxy IPs against one host). A per-request `block` stops each request, but
the same IPs keep coming: there was no persistent, cross-request L3/L4 ban.
The ban should live where every other detector ban lives: nftables
(`cfm which` / `cfm search`), `cfm.detectors.log`, the cfm-web unblock API
(who / where / why / which rule) and the notifier.

This is not a new mechanism. `internal/detectors/api_abuse_register.go`
already did "subscribe to a webdetector event stream → count per IP → block
through the shared framework (leniency, allow-lists, blocklist, API,
email)". `waf_security` is the same shape with a new signal source.

## Principle

> **The WAF *detects* (in-path, per request). The detector framework
> *decides the persistent block* (cross-request, stateful, geo-aware).**

The Lua WAF is stateless per request and must not own ban state, geo logic
or leniency. The detector only emits `core.Alert`; blocking, leniency, API
reporting, the edge ban store and email are the section sink's job
(`internal/detectors/autoblock_sink.go`).

## Two orthogonal decisions (read this first)

There are two independent knobs, and conflating them is the easy mistake:

1. **Edge WAF action** — what happens to *this* request, in Lua:
   `logonly` / `challenge` / `challenge_v2` / `block` (403 now).
2. **`[waf_security]` threshold** — how many hits in `WINDOW` move this
   **IP** to a **persistent nft ban**, per reason family (`0` = never).

The detector itself scores by family threshold and ignores the edge action
(`WAFHitEvent.InputEvent()` does not carry it). **Phase 1 adds one gate in
front of it:** the subscribe callback in `waf_security_register.go` drops
every hit whose action is not `block`. So today:

| Family (example) | Edge action | `[waf_security]` | Result |
|---|---|---|---|
| `WAF_SQLI` (301) | `block` | `SQLI = 1` | 403 now **+** nft ban on the first hit |
| `WAF_TRAVERSAL` (101) | `block` | `TRAVERSAL = 0` | 403 now, no ban |
| `WAF_BAD_UA` (201) | `challenge_v2` (score ≥ 99: `block`) | `BAD_UA = 0` | edge only, no ban |
| `WAF_SUPERGLOBAL` (318) | `challenge_v2` | `SUPERGLOBAL = 0` | edge only |

A family with no block-tier rule is inert in Phase 1 **whatever its
threshold**: setting `BAD_UA = 40` does nothing until the gate is relaxed.
The family split is still needed inside one family, because families mix
tiers (`WAF_RCE`: block 320 / 329 / 332, challenge_v2 322-327, logonly
331; `WAF_BACKDOOR`: block 438 / 440, challenge_v2 437, logonly the rest of
430-439): keying on family alone would ban logonly recon. The Lua side keeps
the tiers apart as well (`should_push`, "Flow").

**Why feeding challenge-tier hits would be safe (the Phase 2 design).**
Passing a challenge mints a clearance (~1 h), and while it holds the
challenge-tier rules do not re-fire for that client. A human who solves the
challenge once emits no further challenge-tier hits and never nears a
threshold; the clients that keep generating them are the ones that never
clear it. Fed by a challenge-tier family, the nft counter is a
**bot-persistence** counter. "Show the challenge" and "count it as an nft
candidate" are different acts, and clearance keeps the second off real
visitors. That is why the emit path publishes every hit and the gate sits
in the subscribe callback: Phase 2 is a change to that one gate plus
per-family thresholds, not to the emit path.

## Flow

```
 Lua WAF rule fires, record()                 configs/lua/cfm_waf.lua
        │  cfm.lua pushes the HEADLINE hit only (ip_push),
        │  de-duped by should_push (below)
        ▼
 Engine.RecordWAFTrigger → publishWAFHitEvent  internal/webdetector/waf_hit_events.go
        │  WAFHitEvent (every tier)
        ▼
 subscribe callback: Action != "block" → drop   waf_security_register.go
        │  core.InputEvent
        ▼
 wafsec.Detector                               internal/detectors/wafsec/
        │  allow-lists, per-(ip, family) sliding counter, threshold
        ▼  core.Alert{Kind:"WAF/<family>", Key:ip, Extra:{rule_id, host, uri, …}}
 section sink                                  internal/detectors/autoblock_sink.go
        ├── leniency ([waf_security.leniency])
        ├── nft block (BLOCK: TTL / permanent / dryrun / no)
        ├── edge ban store, for proxied clients (internal/edgeban, below)
        ├── cfm.detectors.log
        ├── cfm-web API (fleet blocklist, or lenient-only)
        └── notifier (Slack / mail)
```

**Edge push de-dup.** `cfm_waf.lua` `should_push` keys its
`push_cooldown_sec` (60 s) window on `(ip, reason family, action tier)`,
plus the rule id for the `block` tier: a family can mix armed and held block
rules, and a held rule's push must not swallow an armed one's. At threshold
1 this is harmless (the first block hit is what counts); an accumulating
threshold counts cooldown windows, not raw hits.

**Headline only.** `record()` gives the headline to the first block-tier hit
and `goto done` ends evaluation; `cfm.lua` pushes only the headline. So the
family `wafsec` sees on a request that trips two block rules is whichever
ran first. Held rules therefore run late ("Decision record" below).

## Event → Alert contract

`core.InputEvent` (`internal/detectors/core/input_event.go`) carries the
hit, with no WAF-specific struct:

| `core.InputEvent` field | WAF value |
|---|---|
| `Source` | `"waf"` |
| `Reason` | the raw reason, e.g. `WAF_SQLI:UNION_SELECT`; the family is the part before the first `:` |
| `Signal` | the rule id as a string (`"301"`); `""` when the edge sent none |
| `Scope` | the host |
| `SrcIP` | the client IP (counter and block key) |
| `Path` / `Method` / `UserAgent` | from the request |
| `When` | hit time |

Country / ASN are not in the event: the sink's leniency resolves the IP at
block time, as for every other section. The TLS fingerprint is not in it
either, by design (`CLAUDE.md` §6, traffic classifier: no signal keys
enforcement on a fingerprint automatically).

The detector emits (`wafsec/detector.go`):

```go
core.Alert{
    Kind:  "WAF/" + strings.TrimPrefix(family, "WAF_"), // WAF/SQLI, WAF/UPLOAD_FNAME, …
    Key:   ev.SrcIP,
    Count: count,                                       // hits in WINDOW
    Extra: map[string]string{
        "ip", "source", "reason", "family", "rule_id", "host", "uri", "method",
        // WAF_CVE with a CVE_* reason tag: Kind = "WAF/CVE-2025-34085", plus "cve"
        // DRY_RUN = 1: "enforcement": "dryrun" (the sink logs "would block")
    },
}
```

### Per-rule visibility

Attribution lives at two levels:

- **By family** — `Kind` (`WAF/SQLI`, `WAF/RCE`, `WAF/UPLOAD_FNAME`, …):
  one counter and threshold per family, notifier grouping.
- **By rule** — `Extra["rule_id"]`, so `cfm.detectors.log` shows whether
  301 or 309 banned an IP. For `WAF_CVE` the `Kind` itself names the
  vulnerability (`WAF/CVE-YYYY-NNNN`, `cveFromReason`).

## Arming — which families and rules can ban

The default threshold of a family is `1` iff it has an edge-`block` rule
(`webdetector.WAFFamilyHasBlockRule`: some `DefaultMode: "block"` in
`internal/webdetector/waf_rule_ids.go`), except a family in
`heldAutoblockFamilies`, which defaults to `0`. A rule with
`HoldAutoblock: true` defaults its `RULE_<id>` to `0` while its family stays
armed. An operator's family key or `RULE_<id>` in `detectors.conf` wins over
both (`RULE_<id>` also wins over the family).

The registry today:

| Family (config key) | Block rules | Held in code | Default |
|---|---|---|---|
| `SQLI` | 301 | — | 1 |
| `SQLI_LEXICAL` | 309 | — | 1 |
| `RCE` | 320, 329, 332 | — | 1 |
| `UPLOAD_FNAME` | 401, 414 | — | 1 |
| `UPLOAD_CONTENT` | 402 | — | 1 |
| `WEBSHELL` | 413 | — | 1 |
| `BACKDOOR` | 438, 440 | `RULE_440` | 1 |
| `PHP_WRAPPER` | 305 | — | 1 |
| `AUTH_BURST` | 510, 511, 512 | `RULE_511` | 1 |
| `CVE` | every 10xxx rule (10001-10033; 10031-10033 logonly, so they feed no ban) | `RULE_10020`, `RULE_10022`, `RULE_10026`, `RULE_10028` | 1 |
| `JS_PROTO` | 303 | `RULE_303` | 1 |
| `XXE` | 307 | `RULE_307` | 1 |
| `PHP_WEBSHELL_BODY` | 416 | `RULE_416` | 1 |
| `TRAVERSAL` | 101, 103 | the family (`heldAutoblockFamilies`) | **0** |

Every other family has no block rule, defaults to `0` and is inert in
Phase 1. Every family is a knob (key = family minus `WAF_`), and
`TestWAFSecurityFamilyCoverage` asserts the whole registry is covered and
the armed / held defaults. The per-rule and per-family rationale (why each
hold, the volumes) is in the comments of `configs/detectors.conf`
`[waf_security]` and `waf_security_register.go`; it is not repeated here.

**Promoting a rule to `block` silently arms its family** on every node whose
`detectors.conf` does not list it. Decide the autoblock intent in the same
change: arm, hold the rule (`HoldAutoblock`), or hold the family
(`heldAutoblockFamilies`). A held block rule must also run late in
`cfm_waf.lua` (next section).

**Config keys** (`[waf_security]`): `ENABLED`, `EVERY` (20 s), `WINDOW`
(30 m), `SAMPLE_LIMIT` (10), `DRY_RUN`, one key per family, `RULE_<id>`,
`ALLOW_IPS` / `ALLOW_NETS` / `ALLOW_UA_CONTAINS` / `PATH_EXCEPTIONS` (on top
of `[global]` `IGNORE_IPS` / `IGNORE_NETS`), and the sink's `BLOCK` (`6h`
shipped) / `BLOCK_COOLDOWN`. An alert fires once per `(ip, family)` until
that pair's window drains. `[waf_security.leniency]` (its presence turns it
on, `internal/detectors/manager.go`): `MATCH_COUNTRY = "GR,CY"`,
`BLOCK = "15m"`, `BLOCK_COOLDOWN = "15m"`, `SEND_TO_API = YES`,
`SEND_TO_BLOCKLIST = lenient` (recorded centrally, never served to the
fleet).

### Leniency: geo-only, a temp ban, never a skip (decided 2026-07)

Challenge already does the human-or-bot triage at the edge, per request. A
leniency tier only meets hits that can feed an nft ban, and in Phase 1
those are block-tier only. Re-scanning the six production `cfm.waf.log`
files (85 797 WAF events, 2026-06/07) at that time:

| bucket | count | families seen |
|---|---|---|
| **GR — block** | **0** | — |
| **CY — block** | **0** | — |
| GR — challenge | 129 | `BAD_UA` (108), `AUTH_BURST` (11), `IP_HOST` (8), `XSS` (2) |
| CY — challenge | 19 | `BAD_UA` (19) |
| GR — logonly | 108 | `BAD_UTF8` (108) |

No GR or CY IP hit a block-tier rule; every GR/CY hit was benign infra or
the human-or-bot grey zone the challenge decides. (`AUTH_BURST` was
challenge-tier rule 501 then; its block rules 510-512 came later.) So:

1. The GR/CY tier is `15m + API + lenient blocklist`: it costs nothing on
   real Greek customers and still surfaces the rare compromised local host.
2. Leniency stays a **temp ban, never a skip**, because GeoIP is game-able:
   a GR-geolocated reseller VPS range was brute-forcing `xmlrpc.php` in the
   same sample. A skip for "GR" would hand attackers a bypass for the price
   of GR-geolocated space.

## Resolved design questions

- **Detector name:** a standalone `waf_security` section (sibling of
  `exim_security`), not part of `[webdetector]`: clean per-family config,
  and it is a distinct signal source.
- **Counter granularity:** per-IP per-family thresholds, with `RULE_<id>`
  overrides for rules that behave unlike their family. A rule override
  replaces the threshold for that rule's hits. The counter is per
  `(ip, family)`, except under a `RULE_<id>` above 1: that rule counts its
  own hits, per `(ip, family, rule)` (2026-11-18). Before, the family's other
  rules filled it, so `RULE_329 = 2` under `RCE = 5` fired on 329's first hit
  after one other RCE hit. At 0 and 1 the key changes nothing, so every
  shipped config behaves as before. Still one alert per IP and family:
  whichever of the family and rule counters trips first alerts, and neither
  alerts again for that IP until the family has had no hit, on any of its
  counters, for a full `WINDOW` (with one shared counter that is exactly
  "the counter drained"). Known legit
  sources are handled by `ALLOW_IPS` / `ALLOW_NETS` / `ALLOW_UA_CONTAINS`.
- **`Kind` granularity:** `WAF/<family>` (one counter and threshold per
  family), `rule_id` in `Extra`; `WAF_CVE` names the CVE in `Kind`.
- **Soft TTL block, not `permanent`:** `BLOCK = "6h"` self-heals a surprise;
  `DRY_RUN = 1` is the watch-first option.

## Not built

**Phase 2:** relax the subscribe gate so challenge-tier hits feed the
counter, and turn challenge-tier families on one at a time (`BAD_UA`,
`IP_HOST`, `SSRF`, …) with thresholds tuned from live data (does
`BAD_UA = 40` over 30 min ban real scanners without catching a busy legit
crawler?). The push de-dup counts windows, not hits, so an accumulating
threshold needs retuning then. `AUTH_BURST`'s challenge-tier rules
(501 / 502) must never feed a persistent ban: a legitimate admin doing bulk
WordPress logins across many sites once tripped an auth-burst block, and a
human solves the challenge in the browser. The family itself is armed today
for its block rules 510-512, so relaxing the gate must not let 501 / 502
in through the family threshold.

**Phase 3:** distributed-campaign escalation — per-/24 or per-ASN counters,
so a rotating swarm (~180 IPs, 1-2 hits each) escalates to a range / ASN
block. Per-IP instant blocking already bans each swarm IP on its first hit;
this is an optimisation.

## Decision record — held block families and evaluation order (2026-09-05)

`record()` gives the headline to the FIRST block-tier hit and `goto done`
ends evaluation; `cfm.lua` pushes only that headline, so the family `wafsec`
sees on a request that trips two block families is whichever ran first.
That was harmless while every block family was armed. Rule 101
(`WAF_TRAVERSAL`) was the first block family held at 0, and evaluated first
it would have shadowed `WAF_RCE` / `WAF_PHP_WRAPPER` / … on wrapper-LFI and
LFI→RCE requests and cost them their ban. The fix is ORDER: the traversal
steps (101, then 103) run after every armed block family in `cfm_waf.lua`
(pinned by `scripts/tests/cfm_waf_traversal_test.lua` and
`cfm_waf_severity_test.lua` test 15b).

**"Push every block-tier hit" was considered and deliberately rejected.** It
would require removing the block short-circuit (every block `goto done`),
i.e. running the heavy body / upload / base64 scanners on every request
already blocked at a cheap step. The short-circuit is the cheap-rules-first
design of the pipeline, and the requests it saves are exactly the scanner
floods. It also needed a new `ip_push` field, a Go ingest change and four
tests changing semantics, all for a case that does not occur at the shipped
arming. The "mirror image" (an operator arms `TRAVERSAL` and un-arms an
earlier family) is a misconfiguration, documented in `CLAUDE.md` §6. Known
cost of the order fix: a traversal-only scanner request runs the remaining
detectors before blocking (~11.5k such requests a week fleet-wide in 2026-09,
a few string scans each).

**Revisit only if a second held FAMILY appears** — two held families cannot
both run last. Even then the cheap fix is not to drop the short-circuit but
to let `record()` keep evaluating only past a block hit of a held family (a
small Lua-side set mirroring `heldAutoblockFamilies`), so armed families
still short-circuit as today. Held RULES (below) do not trigger this: they
are placed in the late group like traversal.

The late group, in evaluation order: the TranslatePress / PHP multipart /
Magento PolyShell / PixelYourSite CVE legs (10018-10020, 10022, 10028,
10026), then 511, 201, 440, 303, 307, 416, then traversal 101 / 103. A held
block rule must go there; an armed rule there is merely late.

**Rule 201's block joins the late group (2026-10-09).** `WAF_BAD_UA` has no
block-tier rule (default `challenge_v2`), so it is not armed, yet a
score ≥ 99 scanner identity (sqlmap, nikto, nuclei, zgrab, the fake legacy
MSIE / Windows UAs) or an operator `block` mode blocks. Recorded at step 1
it was the first block hit on every such request: sqlmap's own SQLi payload
or a nuclei CVE probe never reached autoblock or the CVE alert. The block is
now recorded after every armed block family and before traversal (step 1
keeps the challenge / logonly tiers; `cfm_waf_bad_ua_shadow_test.lua`), and
at `::done::` when an earlier block ended evaluation, so the 201 hit stays
in `hits`. Side effects, accepted: those requests run the remaining
budget-capped detectors before blocking (~14.5k score-99 events a week in
2026-10), feed the per-IP burst counters (510-512, armed), and the challenge
/ logonly hits behind 201 show in `also_rule_ids`. Authorised scanners
(Nessus, Acunetix, AppScan are score 99) that send an armed payload are
banned; `ALLOW_NETS` / `ALLOW_UA_CONTAINS` exempt them. A rule that raises
behind the deferred block does not let the scanner through under
`fail_open`: `_M.check` runs the pipeline under `xpcall` and, with a 201
block pending, blocks as 201 and logs `[cfm_waf] rule raised behind a
deferred rule-201 block`. Mirror image: an operator who arms `BAD_UA = 1`
loses the 201 ban where an earlier held or un-armed block rule also
matched.

**Rule 511 is held per rule and joins the late group (2026-10-15).** Every
`pingback.ping` still gets a 403, but `HoldAutoblock` holds its ban: a
WordPress site sends a pingback (UA `The Incutio XML-RPC PHP Library --
WordPress/x`) when a post links to one of ours, and at threshold 1 the ban
landed on the sender's shared hosting server, every port. A UA carve-out was
rejected (a one-line spoof; `ALLOW_UA_CONTAINS` exempts every family). As a
held block rule it is recorded late (`st.xmlrpc_pingback`, after the CVE
legs and before 201, at `::done::`, and on a raise as for 201). What counts
as a real pingback: the method IXR dispatches, the LAST `methodName`, is
`pingback.ping`, in a body the edge saw whole (`body_was_cut`, the test 501
uses). A real pingback that 511 STOPS (`block`, `challenge`,
`challenge_v2`: a server never solves a challenge) skips 512 and leaves an
IP decision of `block_ttl_sec` (10 s), not the 30 min that 403'd every
request from the sender's server on every vhost. The words anywhere else in
the first 2 KB are still a 511 block but keep the 30 min decision and count
toward 512, or adding them to a `wp.getUsersBlogs` guess would buy a sprayer
out of 512 and every ban. A pingback 511 lets through (`logonly`, excluded)
reaches WordPress and counts toward 512 as before. Two review rounds
disagreed on that last case (512 is per IP, so a distributed reflection
flood stays under it anyway); it was kept as before to keep the change to
what it fixes. Revisit with the per-IP 512 question on its own.

**Rules 303, 307 and 416 block with their bans held, in the late group
(2026-11-17).** A 7-day read of the 8 edge nodes promoted them to block: 303
(`__proto__`, the React2Shell sweep, ~5 800 IPs a week, no solve), 307
(XXE, all datacenter) and 416 (a PHP file as the raw body, the PHPUnit
`eval-stdin.php` sweep). Each is its family's only block rule, so the
promotion arms the family; the ban is held per rule (`HoldAutoblock`)
rather than per family, so `heldAutoblockFamilies` still holds one family
and the "second held family" trigger above is not reached. 303 was step 14
and 307 step 22, ahead of the armed SQLi / upload / CVE rules; 416 was 60e,
ahead of the armed 10018. They now run in the late group before traversal
(`cfm_waf_tier_review_2026_11_17_test.lua` pins an armed 301 keeping the
headline over each). 332 (`WAF_RCE`) and 438 (`WAF_BACKDOOR`), promoted the
same day, are armed and stay where they are; 10019 was un-held (armed) and
stays in the late group.

## Edge ban — clients behind a trusted proxy (2026-10-10)

An nft ban drops by the address on the wire. A client behind a trusted
proxy (Cloudflare) arrives from the proxy's address, and the edge learns the
real one from `CF-Connecting-IP` via realip, so `ip saddr @block_v4 drop`
never sees it: an address banned for 7 days by `waf_security` kept hitting
sites through Cloudflare on four nodes (2026-10-09).

`internal/edgeban` keeps the bans the edge enforces itself. **What goes in:**
the sink's bans for the web sections (`edgeban.WebSection`: `waf_security`,
`webdetector`, `challenge_*`, `modsec`, `cfm_endpoints`, `cpanel`,
`login_bruteforce`), the challenge server's self-protection and abuse
blocks, and manual bans (`POST /api/v1/firewall/block`, cfm-admin's "Block
selected" `POST /api/v1/firewall/block/batch`, `cfm block` through
`POST /api/v1/webdet/edge-ban`; a CIDR block is not). **What stays out:**
fleet feeds (`block_ext_*`), `cfm.deny` (it can hold thousands of entries),
port-scan / flood bans (L3/L4; some may be proxy addresses), mail / SSH /
FTP / database sections. It is not an nft mirror. The rest of nft's IP
filter reaches a proxied client through `internal/proxyipfilter` instead
(`docs/proxied-ipfilter.md`).

**Proxied requests only.** `cfm_decision.lua` adds `px=1` to the decision
RPC when realip replaced the TCP peer (`$realip_remote_addr ~=
$remote_addr`); the bridge answers the store only then. A direct client is
nft's alone: its ban drops it before the edge, and nft's allow sets decide
for it. An older edge sends no `px` and gets nothing from the store.

**Allows win, as in nft.** A reconcile reads every set nft accepts before
its block drops (`self_v4/v6`, `allow_v4/v6`, `allow_dyn_*`, `allow_ext_*`
hosts and nets — the fleet whitelist — and `allow_*_nets`; hosts, CIDRs and
ranges), and the store never answers an address they cover, even for a ban
added after the read (a ban added right after a NEW allow, before the next
reconcile, is the one residual). Nor does it answer a trusted proxy's own
address (`trusted_proxies.conf`): realip leaves `remote_addr` at a
Cloudflare address when CF-Connecting-IP names one (a Worker's subrequest),
and a ban of it would 403 every visitor arriving that way. `cfm allow --ttl`
lifts the edge ban for good; when the allow expires nft blocks again but the
edge does not (fails safe).

**Consistency.** Every in-daemon unblock removes the entry
(`/api/v1/unblock`, `unblock.DoMany` — the agent's fleet unblock — and
`ForceUnblock`, which `cfm unblock` reaches over the API); `cfm allow` (over
`edge-ban?unban=1`) and a `cfm.allow` host lift it too. A new web blocker,
unblock or allow path must call `edgeban.Ban` / `edgeban.Unban`. Every two
minutes (`cmd/cfm/edgeban_reconcile.go`) a reconcile reads the block and
allow sets — all of them or none: a failed or partial read skips the
reconcile, and three in a row clear the store so it answers nothing, to the
edge too, until a read works — and *narrows* the store: an entry nft no
longer blocks (expired, unblocked from the CLI, flushed) is dropped unless
it was written after the read began, and an earlier nft expiry clamps it. It
never imports from nft. The store persists in `/var/lib/cfm/edgeban.json`
(one writer at a time) and answers nothing until the first reconcile after a
start.

**Enforcement at the edge.** `cfm_edgeban.lua` keeps the edge's own copy of
the list, pulled from `GET /nginx/edgeban` (`edge_ban_feed.go`). The daemon
keeps what the edge should hold (every address the store answers, less
`IGNORE_IPS`, capped at 20 000) and a numbered journal of the changes to it
(the last 4 096; an epoch per daemon start). It resyncs that list against
the store only when the store's version moves (a write, a reconcile that
changed something, a switch) or after 5 minutes: an idle poll is a version
compare. An expiry alone does not move it: the edge drops an entry at its
expiry by itself (the dict TTL), and the next resync deletes it from the
list. A resync checks each ban against the nft allow sets merged into sorted
intervals and searched, not scanned (a linear scan over ~23 000 bans took
100-150 ms per resync on a busy node). The edge sends its position (`epoch`,
`seq`) and gets the changes since (`set` / `del`), so a poll costs what
changed; the whole list comes on its first poll, after a daemon restart,
when it is further behind than the journal reaches, and every 10 minutes (a
consistency check). A store that has not reconciled since a start replies
`{"ready":false}` and the edge keeps its copy; a store CLEARED after three
failed nft reads (the table gone after `cfm disable`) publishes an empty
list, so the edge drops its copy.

One worker at a time (a dict lock held while a poll is in flight) polls
every 5 s from a timer started by any `cfm.lua` request. The list lives in
two slots of the `cfm_edgeban` dict, each value the id of the whole list it
belongs to: a whole list is written into the other slot and `eb:cur` flips
to it in one set, so a lookup never sees half a list and a leftover never
matches; changes are written into the live slot. Each entry lives as long
as its ban (a permanent one has no TTL), as in nft, so a daemon outage does
not lift bans at the edge. The dict is sized for two copies of the 20 000
cap (16m, measured on nginx 1.24): a write into a full dict evicts the least
recently used keys, the leftovers of older lists; past that size evictions
would reach live entries silently (back with the next whole list), and a
lost `eb:cur` makes the next poll ask for one. An IPv4-mapped peer is looked
up as IPv4.

`cfm.lua` checks it in **Step 0e**, right after the static IP/CIDR bypass
(`cfm_bypass_ip`, the crawler / CDN list) and before every other exemption:
the panel targeted bypass, the local-origin bypass, `/.well-known/` (0a1),
the cPanel proxy-subdomain passthrough (0d), the clearance cookie (2b) and
the decision's cached clean allows (up to 90 s). A new exemption step goes
AFTER it. The static-asset locations, which skip `cfm.lua`, call
`cfm_edgeban.static_gate()` before the Site Cache gate. On a proxied request
it is two dict gets; on a direct one, a variable compare. A ban or unban
reaches the edge within one poll (5 s plus the RPC). `cfm_edgeban_test.lua`
pins the module and where `cfm.lua` and both confs call it.

**Not covered:** the panel ports (2083/2087/2096), the challenge page and
`/__cfm_verify`, `/cpanelwebcall` and `/cfm-admin`, which skip `cfm.lua` and
are not static assets.

**Mode.** `[webdetector] EDGE_BAN_MODE`, sent with every reply: `enforce`
(the default) answers 403 (`X-CFM-Action: block`, `X-CFM-Edge-Ban: 1`,
`$cfm_upstream = cfm_block`); `log` only counts and logs what it would
block. One `would_block edge_ban` / `block edge_ban` line per address per
minute in the edge error log. Kill switch: `[webdetector] EDGE_BAN = 0`
empties the list. `GET /api/v1/webdet/edge-ban` (admin; `edge-ban.json` in
a `cfm debug` bundle) and the bridge status show the mode, the journal
position, the list size, the last poll and full list, the would-block /
blocked totals and the last resync time. The decision path answers bans
regardless of the mode, so in `log` mode `would_block` also counts requests
Step 3 blocks anyway: it is an upper bound of what `enforce` adds.

**Enforce became the default (2026-11-10)**, on all eight edge nodes, after
a `log` burn-in from 2026-10-10. The read that day: 389 addresses with a
`would_block` line, none Greek or Cypriot, nearly all `waf_security` bans
(scanners and xmlrpc brute forcers on datacenter networks). Without it a
banned client behind Cloudflare walked through (171 such addresses on one
node that day). The burn-in found two false-positive classes, both from
`webdetector`'s `403_flood` and both predating the edge ban (nft had
already banned and reported them; behind Cloudflare the ban had simply
missed them). They were fixed in the detector, not in the edge ban — the
decisions below.

### Webdetector bans that the edge-ban burn-in corrected

**Verified good bots are never banned (2026-10-10).** Googlebot
(FCrDNS-verified) crawling a WooCommerce shop's `?add_to_wishlist=` links,
which the origin answers 403, was banned and reported repeatedly.
`emitIPBlocks` — every webdetector IP ban and challenge (`WEB/403`,
`WEB/404`, `WEB/40X`, `WEB/403WAF`, `WEB/BOT`, `WEB/MALPATH`, `WEB/RPS`) —
now skips a verified good bot (`goodBotForBan`, `ban_goodbot.go`): the
canonical crawler PTR list forward-confirmed (FCrDNS, the bridge's verdict
cache) and the exclude file's `verify_fcrdns=1` PTR rules. Not the file's
`ua=` / `asn=` rules: a UA is a claim, and Google's ASN is all of GCP. A
PTR lookup that fails is inconclusive, never "no PTR" (that would ban a
crawler on a DNS blip). The skip is a `block_trigger` history row with
`outcome=exempt_goodbot`. Challenge alerts (`emitIPChallenges`,
`WEB/CHALLENGE`) do not consult it; the edge exempts a verified crawler when
serving one (`CHALLENGE_GOODBOT_EXEMPT`). Other sections that ban web
clients (`waf_security`, `modsec`, `challenge_*`) do not consult it either:
a WAF block-tier hit is the request's own payload.

**Origin 403 on WordPress REST calls (2026-10-20).** The 403 counters
(`403_flood`, and `40x_combo`'s 403 side) no longer count the 403 WordPress
itself gives a REST call (`/wp-json/…` at the root or one directory down,
or a root `?rest_route=…`; `isWPRestOrigin403`). WordPress answers 403 when
the caller may not do that one thing, so a working client polling one route
crossed `IP403_COUNT` on the origin's own answers: a logged-in admin on the
Site Kit dashboard, and a WooCommerce stock sync whose API key lacked write
access. Neither country nor ASN tells these apart from an attack (a GR
residential address ran a `wp-login.php` brute force that `403_flood`
correctly banned in the same weeks). Three limits keep it from hiding an
attack: only the ORIGIN's 403 is skipped (the edge's own REST 403s are the
WAF stopping scanners, and keep counting); a route that takes a credential
(`token`, `login`, `auth`, `jwt`, `passw`) keeps counting, because JWT Auth
answers a wrong password with 403 and rule 501 does not see REST logins;
and the marker must sit behind a plain install directory, with no climb or
escape. A query `rest_route` is read the way PHP and WordPress read it (it
overrides the path, the last duplicate wins, `rest.route` is the same key).
Residual: a `rest_route` in a POST body, which the log does not carry, also
overrides the path, so a REST credential brute force sent that way is not
counted. The request still counts in the IP's total, so it dilutes the 403
share.

**Origin 403 on wp-admin AJAX, and a traffic rule's 403 (2026-11-17).** Two
more 403s left both counters, after a week's read of the 8 edge nodes found
Greek clients banned by them. (a) The ORIGIN's 403 to `admin-ajax.php`
(root or one install directory down, not the `index.php` PATH_INFO
pseudo-directory) with a small non-empty body (1-128 bytes: the app's own
`-1` / `0` or a plugin's JSON error, never an origin WAF's block page) whose
Referer is a `/wp-admin/` page of the same host and install, unless any
`action` key names a credential (`isWPAdminAjaxOrigin403`): a shop's own
admin, whose open order list kept polling a plugin's AJAX after the session
expired, was banned at 317 such 403s. The Referer is the client's to forge;
what a forger gains is small app-answered admin-ajax refusals that no longer
count, while the WAF and malicious-path counters still see them, and an
origin WAF's refusals (ModSecurity, Imunify, Wordfence pages) keep counting.
(b) The edge's 403 for a request only a traffic rule blocked: `cfm.lua` logs
it as `$cfm_upstream = cfm_block_rule` (IP / vhost / WAF / edge-ban refusals
stay `cfm_block`), and the counters skip it (`isRuleBlock403`): a rule
blocking WhatsApp's fetcher on one shop turned a shopper's link-preview
retries into an hour's nft ban of their home IP. An edge on older Lua still
writes `cfm_block` there, so its rule blocks keep counting until it is
upgraded. One predicate (`skip403`, `wp_rest_403.go`) decides all of this,
and the per-IP challenge counters (`CHALLENGE_RPS_4XX`,
`CHALLENGE_ERR_RATIO`) read it too.
