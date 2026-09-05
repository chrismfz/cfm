# Traffic Rules (cfm-admin) — UX review & redesign proposal

Status: **Phase 1 landed** (guided editor, recipes, banners, simulator pre-fill, docs fix — plus the F12 engine fix below). **Phase 2 partially landed:** `country_not_in`, `ip_any` and `verified_bot` (engine + editor chips + recipes). Remaining Phase 2 (`asn_in`, simulate `draft`/`trace`, `group`) and Phase 3 are still proposals. Scope: the
`/cfm-admin/webdetector/rules/` page (`internal/webui/static/webdetector/rules/`,
`assets/webdet/feature-rules.js`), the rule model in
`internal/webdetector/traffic_rules.go`, and the edge application path in
`configs/lua/cfm.lua` Step 3.

The trigger: operators building rules by hand in the current editor get it
wrong often enough that we "struggle" with every non-trivial rule. This doc
(1) lists what the current UI gets wrong or hides, (2) proposes a guided
"what do you want to do → what to match → where" builder with multi-rule
**recipes**, and (3) lists the small engine additions the recipes need.

---

## 1. How rules actually behave today (the facts the UI must surface)

These are verified against the code, not the README. Several of them are
the direct cause of wrong rules.

| # | Fact | Where | Why it bites |
|---|---|---|---|
| F1 | **`allow` only means "stop evaluating traffic rules".** It does **not** bypass a per-IP block, a vhost-wide challenge, the WAF, or the good-bot logic. In `cfm.lua` block/challenge are OR'd across `ip_action`, `vhost_action`, `rule_action`; `rule_action == "allow"` is never consulted. | `cfm.lua` ~L1474-1500; `nginx_bridge.go` appends `rule_action` after ip/vhost actions are final | The screenshot rule (`allow` POST `/ws_vtrack/json_v2.php`) was almost certainly meant to *exempt* an integration from a challenge. It cannot. The right tools are the **Challenge excludes** page or `isChallengeExemptEndpoint`. README §15 says `allow` is "enforced" — misleading. |
| F2 | **Rules are skipped for clients holding a valid clearance cookie.** Step 2b (`clearance_allow`) returns to origin *before* Step 3 (bridge decision, where rules run). | `cfm.lua` Step 2b vs Step 3 | A country/UA `block` rule does not apply to a browser that solved a challenge on that host within the clearance TTL. Operators test with their own browser and conclude "the rule doesn't work". |
| F3 | **Rules are in-path-edge only** (OpenResty/Angie bridge RPC). Nothing evaluates them in DNAT mode. | only caller is `handleDecision` in `nginx_bridge.go` | A rule saved for a DNAT-mode vhost silently does nothing. |
| F4 | **First match wins, ordered by `priority` ascending, then id.** Within a rule all set fields are AND'd; within a list field values are OR'd. Empty field = match everything. | `trafficRuleStore.Simulate`, `ruleMatchFilters` | The only hint is a tooltip on the Priority field. There is no view of "which rule wins for this request", nor of shadowed rules. |
| F5 | **No negation, no IP/CIDR, no ASN.** Match fields are `country_in`, `ua_any`, `path_any`, `methods`, `has_qs`, `qs_not_rx`. | `TrafficRuleMatch` | "Block everything except GR/CY" is only expressible as two rules (allow GR,CY at prio N; block-all at prio N+1). "Allow my office IP" is not expressible at all. |
| F6 | **Unknown country is `""`**, which matches no `country_in` list. | `geo_country_cached` → `""` when unresolved | A "block all except GR/CY" composition blocks every IP the geo DB cannot resolve (private ranges, some monitors, fresh allocations). |
| F7 | **A `block` rule fires on verified good bots too.** The FCrDNS good-bot exemption (`goodBotDowngrade`) only softens `ip_action`/`vhost_action` *challenge*; rule decisions are appended afterwards. The `allow_good_bots` preset is UA-glob based, i.e. trivially spoofable and also incomplete. | `nginx_bridge.go` good-bot block, `applyPreset("allow_good_bots")` | A geo-fence recipe without a good-bot allow *first* de-indexes the site. A UA-based allow first re-opens the fence to anyone who sets `User-Agent: Googlebot`. |
| F8 | **Presets prefill `example.com`** on the Rules page: `applyPreset` reads `vhostFocusHost`/`activeHost`, which are not in this page's data. Several presets are `enabled: true` (block empty UA, block xmlrpc, throttle scrapers). | `feature-rules.js applyPreset`, `core.js` (`vhostFocusHost` only on vhost pages) | Preset → forget to replace vhost → nothing happens (or hits the wrong host). Preset → Add → a live `block` with one click and no confirmation. |
| F9 | **Simulation tests the saved set, not the draft**, and needs the operator to retype host/path/UA. Result is one muted line. The vhost input of the editor has no `list="cfm-vhost-list"` (the simulator's does). | `runRuleSimulation`, `index.html` | Test-before-enable is the stated workflow but the UI makes it a separate manual exercise, so it is skipped. |
| F10 | **Validation happens only server-side on save.** Country codes must be exactly 2 letters (`normalizeCodeList`); UA patterns are case-insensitive glob **or** substring when no `*`; path patterns are prefix unless they contain `*`/`?`; `?k=v` is per-parameter. Throttle profile is free text (`soft_bot` 2 r/s burst 20, `medium_bot` 1/10, `hard_bot` 0.5/5). | `traffic_rules.go`, `cfm_rules.lua PROFILES` | Operators learn the grammar from error messages after the fact; a typo'd profile silently falls back to `soft_bot` at the edge (`PROFILES[k] or PROFILES.soft_bot`). |
| F11 | **Rules have no hit counters / last-hit.** `rule_id` is logged on block and throttle route lines but not on challenge. | `cfm.lua log_route` | No way to see whether a rule ever fired, or which rule is producing collateral. |
| F12 | **Disabled rules were enforced.** `Simulate` (also the bridge's `RuleDecision`) never checked `Enabled`. Found while implementing Phase 1; fixed in the same PR — disabled rules are skipped for the verdict and reported as `disabled_match`. | `traffic_rules.go Simulate` | Every "start disabled, validate first" preset was live. |

Items F1–F3, F7 and F12 are the ones that produce *silently wrong* configurations
and must be surfaced in the UI regardless of which redesign option is taken.

---

## 2. Proposal — three layers, one page

Keep the existing page and API. Replace the single flat form with three
entry points that all end in the same **Review & test** step:

```
┌ Traffic rules ──────────────────────────────────────────────────────────┐
│ [ + New rule ]  [ 📚 Recipes ▾ ]  [ Advanced editor ]        Search […] │
│                                                                         │
│ ▸ Rules for ksilokosmos.gr (12)      ▸ *.example.com (3)     ▸ all (7)  │
│  prio  on  action     matches (plain language)          hits  last      │
│   10   ●   allow      verified search/social crawlers     1.2k  2m       │
│   20   ●   allow      country GR, CY                    38k  now      │
│  900   ○   block      everything else (disabled)          –    –        │
│   ↳ shadowed by #20 for GR/CY traffic — expected                        │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Guided builder ("+ New rule") — three questions, then review

**Step 1 — What do you want to do?** Four large radio cards, each with a
one-line consequence written in plain language:

- **Allow** — "Skip the remaining traffic rules for matching requests.
  ⚠ Does **not** bypass the WAF, a vhost challenge or an IP block. To
  exempt an endpoint from the challenge use *Challenge excludes* →." (F1)
- **Block** — "Return 403 at the edge. Cleared browsers (clearance cookie)
  are not affected until their clearance expires." (F2)
- **Challenge** — "Serve the interactive challenge. Non-browser clients
  (APIs, webhooks, crawlers) cannot pass it."
- **Throttle** — profile selector showing the real numbers (`soft_bot`
  2 req/s · burst 20, …) instead of free text. (F10)

**Step 2 — What should it match?** Chips the operator adds one at a time;
each opens a focused input with its own grammar help and inline validation:

| Chip | Input | Inline help / validation |
|---|---|---|
| Endpoint | path list | prefix vs `*`-glob vs `?k=v` explained *next to the field*, with a live "would match / would not match" example pair |
| User-agent | **bot picker** (curated groups, see §2.3) + free glob | shows substring-vs-glob behaviour; warns that UA is client-controlled |
| Country | multi-select with names + flags, "is / is not" toggle | `is not` needs `country_not_in` (§3); shows the "unknown country" caveat (F6) |
| Method | checkboxes GET/POST/HEAD/… | — |
| IP / CIDR | list | needs `ip_any` (§3) |
| ASN | list with org-name lookup from the enrichment cache | needs `asn_in` (§3) |
| Query string | has-QS + pass-through regex | existing fields, moved out of the main path |

An empty step 2 is allowed but rendered as a red banner: "matches **every**
request on the selected vhosts".

**Step 3 — Where?** Vhost multi-select fed by `knownVhosts` (the datalist
the simulator already uses; the rule editor never got it — F9), with
"all my vhosts" for scoped users, plus an **edge-mode badge** per vhost
("in-path" / "DNAT — rules do not apply here", F3).

**Review & test** (always shown, replaces the current disconnected
simulator):

- A generated sentence: *"On **ksilokosmos.gr**, **allow** `POST` requests
  to `/ws_vtrack/json_v2.php` (skip the rules below). Does not bypass
  WAF/challenge."*
- Auto-assigned priority with position preview: "runs after #10 (allow
  good bots), before #100 (throttle Meta)". Bands: allow 10–99, throttle
  100–199, challenge 200–299, block 300+, editable. (F4)
- **Test this draft**: the simulator form pre-filled from the draft (host,
  first path, first method, first country, a sample UA), executed against
  *saved rules + this draft* (needs the `draft` simulate extension, §3),
  returning a **trace**: every rule in order with matched / skipped-because.
- **Enabled** defaults to **off** for `block` and `challenge`; the save
  button for an enabled `block` with no match chips asks for confirmation.
  (F8)

### 2.2 Recipes — multi-rule bundles, not single-rule prefill

The current presets prefill one rule; the things operators actually want
are *compositions* that only work with the right relative priorities.
A recipe shows the rules it will create (as a mini table), asks only for
the free variables (vhosts, country list), creates them via the existing
`rules/add` in order, and tags them so they can be listed/disabled/removed
as a group (phase 1: `note` prefix `recipe:<name>`; phase 2: a `group`
field, §3).

| Recipe | Rules created (in priority order) | Notes |
|---|---|---|
| **Geo-fence: allow only \<countries\>** | 1. `allow` verified good bots (prio 10, see F7 / §3 `verified_bot`)  2. `allow` country in \<GR, CY\> (prio 20)  3. `block` everything (prio 900, **disabled**) | Banner: cleared browsers keep access until clearance expires (F2); unresolved-geo IPs are blocked (F6) — offers to add an `allow ip_any` for office/monitor ranges. |
| **Geo-fence the admin area** | 1. `allow` country in \<GR\> ∧ path `/wp-admin/`, `/wp-login.php` (prio 100)  2. `challenge` (or `block`) path `/wp-admin/`, `/wp-login.php` (prio 101) | Works today with first-match, no negation needed. |
| **Protect login endpoints** | `challenge` POST `/wp-login.php`; `block` POST `/xmlrpc.php` | Existing presets merged; xmlrpc block off by default with a "Jetpack/app uses xmlrpc?" hint. |
| **Tame bots** | `allow` verified good bots (10); `throttle soft` SEO crawlers (130); `throttle medium` AI crawlers (110, off); `block` empty UA (50) | Existing presets merged with the correct ordering baked in. |
| **Exempt an integration endpoint** | *not a rule* — deep-links to Challenge excludes with the path pre-filled | This is what F1 says the screenshot rule needed. Putting it in the recipe list is how we stop `allow` misuse. |
| **Block a scraper (from an incident)** | `block` UA glob(s) + optional country/ASN, prio 300, **on** | Entry point from Forensics / IP drilldown ("Block this UA pattern as a rule") so the match is pasted, not retyped. |

**Landed 2026-09 from a fleet traffic review** (titan / rigel / orion, 24 h of
`waf_activity`, `top_talkers`, `hot_ips`, `abuse_shadow`, `edge_access_tail`).
Each row names the shape that motivated it; the value order is the order in
the recipe grid.

| Recipe (key) | Rules created (in priority order) | Motivating traffic |
|---|---|---|
| **Block secret / dev-file probes** (`block_probe_paths`) | `block` path ∈ `PROBE_PATHS` (`/.env`, `/.git/`, `/*phpinfo.php`, `/*.php.bak`, `/*.sql`, `/_profiler/`, `/server-status`…) + operator extras, prio 305, **on** | Google-Cloud sweeps of `/.env*` and `/phpinfo.php` in 40 directories (200+ hits / 2 min per IP, dozens of IPs). Refuses `/.well-known/` (ACME/DCV). |
| **Crawlers are read-only** (`bots_read_only`) | one `block` POST/PUT/PATCH/DELETE per bot group (350+), social/AI/SEO **on**, scripts/empty/search **off**. Deliberately no `verified_bot` allow in front: Meta's crawler is FCrDNS-verified too and would slip through. | meta-externalagent POSTing `gui-todaytips.php?delete-tip=1&dir=…` and `?wc-ajax=get_refreshed_fragments`; search engines stay out of the default set because Googlebot POSTs while rendering. |
| **Bots stay off filter / facet URLs** (`bots_no_qs`) | one `block` (360+) or `throttle hard_bot` (170+) per bot group, `has_qs` + `qs_not_rx` = `BOT_QS_PASSTHROUGH` (click ids, UTM, pagination, feeds), **off** | ladyfox.gr `?min_price&filter_color` grid crawled by Meta; bet-prognostika `?lg-min/lv-max` permutations by Meta + GPTBot; SemrushBot on `?ind=k&ind=n…`. Generalises `block_meta_qs`. |
| **Lock panel service subdomains** (`lock_panel_subdomains`) | (`allow` office IPs 15) · `challenge` `cpanel.*, webmail.*` outside \<GR, CY\> (252, off) · `block` `cpcalendars.*, cpcontacts.*, webdisk.*, autodiscover.*, autoconfig.*` outside (312, off) | 401 brute-force at 9 rps on `cpcalendars.*`, uniq-path sweeps on `autodiscover.*`/`autoconfig.*`. DAV / autodiscovery clients cannot solve a challenge, hence block. |
| **Challenge visitors from / outside countries** (`geo_challenge`) | 1. `allow` verified (10) 2. `allow` unverifiable + Meta previews by UA (11) 3. (`allow` office IPs 15) 4. `challenge` `country_in` **or** `country_not_in`, optional paths (260, off) | 130 Singapore-datacenter IPs (Byteplus / Zenlayer) behind three browser UAs on one shop, 18 579 distinct URLs — the case `asn_in` (§3) would key on directly. |
| **Block dataset / anonymous crawlers** (`block_dataset_crawlers`) | `block` UA ∈ new **dataset** group, prio 335, **on** | `Mozilla/5.0 (compatible; crawler)` from residential proxies, `imagebot/img2dataset`, `eurovl-fetch`, `*DatasetCrawler`. |
| **Throttle an expensive endpoint** (`throttle_hot_path`) | `throttle` path ∈ \<admin-ajax.php, /?wc-ajax, forum download\> for everyone, prio 180, **off** | 20 admin-ajax POST/s from one visitor; 4 803 `rate_outlier` would-challenge rows in `abuse_shadow` (a few IPs at many× the vhost's per-IP median). |
| **Lock dev / staging subdomains** (`lock_dev_sites`) | (`allow` office IPs 15) · `challenge` outside \<GR\> (255, off) | `dev.*` hosts are the first stop of phpinfo / `.env` sweeps. Keyed on country because a catch-all challenge cannot be saved enabled. |
| **Lock down xmlrpc.php server-wide** (`xmlrpc_lockdown`) | (`allow` Jetpack ranges on `/xmlrpc.php` 16) · `block` POST `/xmlrpc.php` (315, off), vhosts default `*` | One xmlrpc POST every 25 s behind rotating browser UAs, 200 OK — under the WAF burst threshold. Jetpack ranges are an operator var, never hard-coded. |
| **Keep the challenge off your uptime monitor** (`monitoring_probes`) | *not a rule* — link to Challenge excludes | The fleet's own `uptime-kuma` probe was being served the challenge page on an auto-challenged vhost. |

### 2.3 Bot picker groups (for the User-agent chip and recipes)

Curated, versioned in one JS module so the UI, recipes and docs never
drift (CLAUDE.md §5: never keep a second copy of a list):

- **Search engines** — Googlebot, bingbot, DuckDuckBot, Applebot, YandexBot, Baiduspider
- **Social previews** — facebookexternalhit, meta-externalagent, Twitterbot, LinkedInBot, Slackbot, WhatsApp, TelegramBot
- **AI crawlers** — GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, anthropic-ai, Bytespider, CCBot, Amazonbot, PerplexityBot, Google-Extended, ReflectionBot, ExaSearchBot. Deliberately **not** Claude-User / Claude-SearchBot: Claude-User is also the User-Agent of the claude.ai MCP connector behind `/cfm-admin/mcp`, so a `*`-scoped bot rule carrying it would throttle or block cfm-admin itself.
- **SEO tools** — AhrefsBot, SemrushBot, MJ12bot, DotBot, BLEXBot, PetalBot, DataForSeoBot
- **Script tools** — python-requests, python-urllib, Go-http-client, curl, wget, libwww-perl, Java/, okhttp. Also what webhooks, IoT posters and integrations announce, so recipes create rules for this group **disabled**.
- **Dataset / anonymous crawlers** (2026-09) — `Mozilla/5.0 (compatible; crawler)`, img2dataset / imagebot, eurovl-fetch, `*DatasetCrawler`, VelenPublicWebCrawler — bulk harvesters with no benefit to the site.
- **Empty / dash UA** — `-`

Each group shows its glob expansion and a "UA is spoofable — prefer
*verified* for allow rules" hint where applicable.

### 2.4 Rule list improvements (independent of the builder)

- Group by vhost (collapsible), sorted by priority; inline on/off toggle;
  Duplicate; "Test with…" that opens the simulator pre-filled from the rule.
- Plain-language match column instead of `ua×6 | path×2`.
- **Hits / last hit** per rule from the history store, keyed on the
  `rule_id` already in the route log (add `rule_id` to the challenge log
  line too — F11).
- **Shadowing hints**: a rule whose match set is a subset of a
  lower-priority rule with a different action gets a "never reached for X"
  note. Cheap version: run the simulator on the rule's own sample request
  and report if a different rule wins.
- Page-level banners: "clearance-cookie holders bypass rules", "N of your
  vhosts are in DNAT mode — rules do not apply there".

---

## 3. Engine additions the proposal depends on (small, backward-compatible)

All additive JSON fields; absent = current behaviour. Each ships with
`traffic_rules_test.go` coverage, a README §15 update and a CHANGELOG entry.

| Addition | Why | Notes |
|---|---|---|
| `match.country_not_in []string` — **landed** | "is not" toggle; single-rule geo-fence | Empty country (`""`) does **not** match `not_in`: it is the edge's fail-open sentinel (geo down, cache miss, `cfm_panel.lua`), so the fence fails open instead of 403-ing everyone during a geo hiccup. Mutually exclusive with `country_in`. |
| `match.ip_any []string` (IPv4/IPv6 CIDR) — **landed** | allow office/monitor IPs; block a range as a rule instead of an nft ban | `net/netip` prefixes, masked + canonical, cap 20; v4-mapped v6 unmapped; no/invalid client IP never matches. |
| `match.asn_in []uint` | block/throttle a hosting ASN per vhost | Cache-only lookup via `b.enr.LookupCachedOrAsync(ip)` on the hot path, same pattern as the good-bot check; a miss = no match (fail-open) and an async fill. |
| `match.verified_bot bool` — **landed** | the good-bot allow in recipes must not be UA-glob based (F7) | Reuses `b.goodBot.verified(ip, ptrFn, now)` (cache-only on the hot path, consulted only while an enabled rule uses the field); the simulate API resolves inline via `verifiedSync` and honours a caller override. |
| `POST rules/simulate` accepts `draft` (an unsaved rule) and returns `trace []` | "Test this draft" and shadowing hints | Trace row: `{id, priority, matched, skipped_by: "country"|"path"|…}`. Scope check: `draft.scope.vhosts` must pass `scopeAllowsVhosts`. |
| `group string` on the rule | list/toggle/remove a recipe as a unit | Phase 1 uses `note` prefix; promote when the recipes stabilise. |
| Persist positive good-bot verdicts across restarts | with `verified_bot` a first-seen crawler IP gets the fence's action once; after a daemon restart that is every crawler IP again | The enrich layer already has a persistent PTR store (`sharedPTRStore`); seed the good-bot cache from it or persist `(ip, name, until)` for positives. Follow-up to Phase 2b. |
| `rule_id` on the challenge route log line | hit counters (F11) | one-line `cfm.lua` change. |

Deliberately **not** proposed: making `allow` bypass challenge/WAF. That
would turn a first-match rule engine into a second exclude mechanism and
duplicate the Challenge-excludes scoping/security work (CLAUDE.md §6). The
fix for F1 is to say what `allow` does and route operators to excludes.

---

## 4. Phasing

1. **Phase 1 — LANDED (UI + docs, plus the F12 fix).** Facts F1/F2/F3/F8/F9
   surfaced as banners/help; vhost datalist on the editor; profile select;
   inline validation mirroring `normalizeTrafficRule`; presets converted to
   recipes that create the correctly-ordered rules (geo-fence uses the
   UA-based good-bot allow *with* a spoofability warning until
   `verified_bot` lands); simulator pre-fill from draft/row; plain-language
   match column; README §15 `allow` note corrected. Fixes the screenshot
   class of mistake outright.
2. **Phase 2 — engine additions** from §3 in single-concern PRs:
   `country_not_in` + `ip_any` **landed**, `verified_bot` **landed** (editor
   chips, recipes, README field table); next `simulate draft/trace`, then
   `asn_in`.
3. **Phase 3 — hit counters, shadowing hints, incident entry points**
   (Forensics → "block this UA as a rule").

Each phase is a normal CFM PR: adversarial self-review, `make lua` /
`make test-lua` when `cfm.lua` is touched, and the challenge/WAF release
checklist for edge-affecting changes.
