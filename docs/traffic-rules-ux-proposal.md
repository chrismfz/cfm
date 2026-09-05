# Traffic Rules (cfm-admin) — UX review & redesign proposal

Status: **proposal** (nothing here is implemented yet). Scope: the
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

Items F1–F3 and F7 are the ones that produce *silently wrong* configurations
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

### 2.3 Bot picker groups (for the User-agent chip and recipes)

Curated, versioned in one JS module so the UI, recipes and docs never
drift (CLAUDE.md §5: never keep a second copy of a list):

- **Search engines** — Googlebot, bingbot, DuckDuckBot, Applebot, YandexBot, Baiduspider
- **Social previews** — facebookexternalhit, meta-externalagent, Twitterbot, LinkedInBot, Slackbot, WhatsApp, TelegramBot
- **AI crawlers** — GPTBot, ChatGPT-User, ClaudeBot, anthropic-ai, Bytespider, CCBot, Amazonbot, PerplexityBot, Google-Extended
- **SEO tools** — AhrefsBot, SemrushBot, MJ12bot, DotBot, BLEXBot, PetalBot, DataForSeoBot
- **Script tools** — python-requests, python-urllib, Go-http-client, curl, wget, libwww-perl, Java/, okhttp
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
| `match.country_not_in []string` | "is not" toggle; single-rule geo-fence | Empty country (`""`) **matches** `not_in` — document it; the UI shows the F6 caveat. |
| `match.ip_any []string` (IPv4/IPv6 CIDR) | allow office/monitor IPs; block a range as a rule instead of an nft ban | `net/netip` prefixes, cap 20 like other lists. |
| `match.asn_in []uint` | block/throttle a hosting ASN per vhost | Cache-only lookup via `b.enr.LookupCachedOrAsync(ip)` on the hot path, same pattern as the good-bot check; a miss = no match (fail-open) and an async fill. |
| `match.verified_bot bool` | the good-bot allow in recipes must not be UA-glob based (F7) | Reuse `b.goodBot.verified(ip, ptrFn, now)`; matches only FCrDNS-confirmed crawlers. |
| `POST rules/simulate` accepts `draft` (an unsaved rule) and returns `trace []` | "Test this draft" and shadowing hints | Trace row: `{id, priority, matched, skipped_by: "country"|"path"|…}`. Scope check: `draft.scope.vhosts` must pass `scopeAllowsVhosts`. |
| `group string` on the rule | list/toggle/remove a recipe as a unit | Phase 1 uses `note` prefix; promote when the recipes stabilise. |
| `rule_id` on the challenge route log line | hit counters (F11) | one-line `cfm.lua` change. |

Deliberately **not** proposed: making `allow` bypass challenge/WAF. That
would turn a first-match rule engine into a second exclude mechanism and
duplicate the Challenge-excludes scoping/security work (CLAUDE.md §6). The
fix for F1 is to say what `allow` does and route operators to excludes.

---

## 4. Phasing

1. **Phase 1 — no engine changes (UI + docs only).** Facts F1/F2/F3/F8/F9
   surfaced as banners/help; vhost datalist on the editor; profile select;
   inline validation mirroring `normalizeTrafficRule`; presets converted to
   recipes that create the correctly-ordered rules (geo-fence uses the
   UA-based good-bot allow *with* a spoofability warning until
   `verified_bot` lands); simulator pre-fill from draft/row; plain-language
   match column; README §15 `allow` note corrected. Fixes the screenshot
   class of mistake outright.
2. **Phase 2 — engine additions** from §3 in single-concern PRs
   (`country_not_in` + `ip_any` first, then `simulate draft/trace`, then
   `verified_bot`/`asn_in`), each wiring its chip into the builder.
3. **Phase 3 — hit counters, shadowing hints, incident entry points**
   (Forensics → "block this UA as a rule").

Each phase is a normal CFM PR: adversarial self-review, `make lua` /
`make test-lua` when `cfm.lua` is touched, and the challenge/WAF release
checklist for edge-affecting changes.
