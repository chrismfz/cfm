# Challenge Access-Control — design proposal

Status: **Phase 0 (backend + edge enforcement) LANDED** on branch
`claude/challenge-enforce-points`; UI (Phase 1) and Challenge-Recipes (Phase 2)
still proposed. As-built notes are inline in §3/§6.

The ask (operator): *"If a client is auto-arm challenged by some rule, and I
want to allow/bypass a specific **UA / IP / ASN / Country / URL path**, how do
I do it? Like WAF excludes, but for the challenge — with a cfm-admin view that
shows what we have globally and per-vhost, and maybe Challenge-Recipes like the
WAF/traffic recipes."*

This doc (1) states what exists today and why it does not cover the ask, (2)
proposes a **Challenge Access-Control** allow-list that mirrors the WAF-exclude
persistence/security skeleton but reuses the **traffic-rule match grammar**, (3)
specifies the edge/engine enforcement points, the cfm-admin UI, and
Challenge-Recipes, and (4) phases the work into single-concern CFM PRs.

---

## 1. What exists today (verified against code)

There are **three** challenge-suppression mechanisms and **none** lets an
operator exempt a request from a *still-active vhost challenge* by
path/UA/country, per-vhost, from the UI.

| # | Mechanism | Dimensions | Layer | Gap for the ask |
|---|---|---|---|---|
| M1 | **`IGNORE_IPS` / `IGNORE_NETS`** (`[global]` in `detectors.conf`; `internal/detectors/ignore.go`) | IP / CIDR | Both (Lua `is_self_origin` + Go bridge `bypassFunc`, `nginx_bridge.go:1723`) | Full bypass of **WAF + challenge + autoblock** — too broad; no path/UA/country/ASN; not per-vhost |
| M2 | **Static file** `/etc/cfm/webdetector_challenge_exclude.txt` (`CHALLENGE_EXCLUDE_FILE`; `internal/detectors/challenge_exclude.go`) | UA, ASN, PTR, host + FCrDNS | Go log-driven (`autoblock_sink.go:233`) | FCrDNS-crawler-oriented; **no path, no country, no IP/CIDR**; file-only (not UI/API/per-tenant); `skip`/`skip_vhost_only` only |
| M3 | **Runtime store** `/var/lib/cfm/webdetector_challenge_excludes.json` (`excludeStore`; `internal/webdetector/exclude_store.go`) | **host only** | Both (arming `hostChallengeExcluded` `challenge_rules.go:207`; edge via `MatchChallenge`) | `path` entries feed **WAF only**, never challenge (`rebuildCompiledLocked` `:443-467`); no country/UA/IP/ASN |
| — | **FCrDNS good-bot downgrade** (`CHALLENGE_GOODBOT_EXEMPT`, default on; `goodBotDowngrade` `nginx_bridge.go:1826`) | verified crawler (PTR) | Go bridge | Eventual/cache-cold; only the 6 registry crawlers; not operator-extensible per path |
| — | **`isChallengeExemptEndpoint`** (`challenge_rules.go:155`) | **hardcoded** path list (`wp-json/wc/`, webhooks, `/ws_vtrack/`) | Go bridge (`:1801`) | Not operator-editable |
| — | **Traffic-rule `allow`** (`traffic_rules.go`) | country/ip/ua/path/method | edge rule engine | **Does NOT bypass challenge** — `allow` is only a first-match terminal inside the rule engine; `cfm.lua:1483` OR-guards never consult `rule_action=="allow"` (see `docs/traffic-rules-ux-proposal.md` F1, and the deliberate rejection at that doc §3) |

**Conclusion.** The architecture already *decided* (traffic-rules UX proposal §3)
that challenge exemption belongs to the **Challenge-excludes** subsystem, not a
traffic-rule action. But that subsystem is **host-only** today. The work is to
grow M3 into a real multi-dimension, per-vhost, UI-managed **allow-list** —
without duplicating the traffic-rule match grammar and without weakening WAF or
IP blocks.

### 1.1 The motivating incident (google-xrawler feed)

A Cloudflare-fronted vhost is vhost-wide challenged. Google's feed fetcher
(`ua=google-xrawler`, client `74.125.76.x` = AS15169) requests
`/wp-content/plugins/woofeed/files/google.xml` and gets `302 → /__cfm_challenge`.
Being non-interactive it never solves the challenge, so the Google Merchant feed
breaks. Each hit is a **different** Google IP, so the eventual FCrDNS good-bot
cache never warms → perpetual challenge. Today the only fixes are blunt
(`IGNORE_NETS` whole-range bypass, or exclude the entire vhost). The operator
wants a surgical *"exempt this path (or this ASN, or this verified crawler) from
the challenge on this vhost — but keep WAF and IP-blocking active."* That is
exactly what M1–M3 cannot express.

---

## 2. Design

### 2.1 Principle — an allow-list that ONLY downgrades the challenge

A Challenge Access-Control entry, when it matches a request, **downgrades a
`challenge` verdict to `allow`** — and does nothing else. It mirrors
`goodBotDowngrade` (`nginx_bridge.go:1826`, which "never softens a block"):

- It **never** weakens the **WAF** — SQLi/RCE/upload/webshell rules (`cfm_waf.lua`,
  `rule_action`) still fire and 403. (Same belt the static file already documents:
  "challenge-suppression ONLY … the WAF rule engine stays fully armed.")
- It **never** weakens an **IP block / autoblock** — an nft-banned or
  `ip_action=="block"` source stays blocked.
- It is **fail-open on enrichment** — an unresolved country/ASN does **not**
  match (same sentinel contract as `TrafficRuleMatch.CountryNotIn`), so a geo/ASN
  hiccup can never *grant* an exemption it shouldn't, nor *deny* traffic.

This is strictly narrower and safer than `IGNORE_NETS` (M1), which bypasses
everything.

### 2.2 One match grammar, not two (CLAUDE.md §5)

Reuse the **traffic-rule match model** (`internal/webdetector/traffic_rules.go`
`TrafficRuleMatch`, mirrored in `internal/webui/static/assets/webdet/rules-model.js`)
so operators learn one grammar and the UI reuses the existing chip builder and
`rules-model.test.js` parity harness. The Challenge Access entry embeds the same
match fields:

- `country_in[]` / `country_not_in[]` (mutually exclusive; `""` never matches — fail-open)
- `ip_any[]` (IPv4/IPv6 CIDR, canonical)
- `asn_in[]` — **new field, shared with traffic rules** (the traffic-rules roadmap
  already lists `asn_in` as Phase 2; land it once, in the shared matcher — see §3.3)
- `ua_any[]` (substring / `*?` glob; `-` = empty UA)
- `path_any[]` (path prefix / glob, optional `?k=v` per-param)
- `methods[]`
- `verified_bot` (FCrDNS crawler; reuses `goodBot.verified`, cache-only on the hot path)

Match semantics within an entry: **all set fields AND, values within a field OR,
empty field = match anything** (identical to traffic rules). Across the list:
**any enabled entry that matches ⇒ exempt** (flat allow-list, no priorities, no
shadowing — simpler and safer than the ordered rule engine).

### 2.3 Data model

New store `internal/webdetector/challenge_access.go`, persisted to
`/var/lib/cfm/webdetector_challenge_access.json` (config key
`CHALLENGE_ACCESS_STORE_PATH`, default in `webdetector_register.go`). Entry:

```go
// ChallengeAccessEntry exempts matching requests from the interactive
// challenge (challenge -> allow) and NOTHING else: WAF rules and IP blocks
// stay fully armed. A flat allow-list — any enabled entry that matches wins.
type ChallengeAccessEntry struct {
    ID        string             `json:"id"`
    Enabled   bool               `json:"enabled"`
    Scope     TrafficRuleScope   `json:"scope"`   // vhosts[] — required; the host dimension
    Match     TrafficRuleMatch   `json:"match"`   // reused grammar (+ AsnIn, see §3.3)
    Note      string             `json:"note,omitempty"`
    CreatedAt time.Time          `json:"created_at"`
    UpdatedAt time.Time          `json:"updated_at"`
    Unsupported bool             `json:"unsupported,omitempty"` // forward-compat (as TrafficRule)
}
```

Reuse verbatim from the exclude/traffic-rule code: `TrafficRuleScope` (host
match `ruleHostMatch`), `TrafficRuleMatch` + its `normalizeTrafficRule`
validation/compilation, and the exclude store's atomic-JSON persistence pattern
(`saveLocked`, `0600`/`0750`, temp+rename).

Matcher:

```go
// MatchExempt reports whether any enabled entry exempts this request from the
// challenge. Cache-only on the hot path (ASN/verified-bot lookups never block).
func (s *ChallengeAccessStore) MatchExempt(in ChallengeAccessInput) bool
// ChallengeAccessInput{ Host, IP, UA, Path, Method, Country, ASN uint, VerifiedBot bool }
```

`ChallengeAccessInput` is `TrafficRuleEvalInput` plus `ASN uint`.

### 2.4 Enforcement points (two, mirroring the existing two-layer model)

**(A) Decision-time downgrade — the primary mechanism (in-path edge).**
In `NginxBridge.handleDecision` (`nginx_bridge.go`), *after* `ip_action` /
`vhost_action` are computed and *after* the existing `goodBotDowngrade`, add:

```
if (ipAction == "challenge" || vhAction == "challenge") &&
    challengeAccess.MatchExempt(in) {
    // downgrade challenge -> allow; leave any "block" untouched
    if ipAction  == "challenge" { ipAction  = "allow" }
    if vhAction  == "challenge" { vhAction  = "allow" }
}
```

This is what makes a **per-path / per-UA / per-country carve-out work inside a
still-challenged vhost** — the exact gap M3 has. It requires the request context
the edge already sends to `/nginx/decision` (`cfm.lua:1454`
`decision:get(ip, host, uri, qs, method, scheme, ua, country, scope)`), plus ASN
(see §3.3 — one field-read from the `LookupCachedOrAsync(ip)` call
`handleDecision` already makes for country at `nginx_bridge.go:1705-1715`). **No
edge/Lua change and no new DNS/geo lookup.**

**(B) Arming-time suppression — secondary (scoring hygiene + DNAT).**
Extend the arming-side host check (`hostChallengeExcluded` / `isExcluded`,
`challenge_rules.go:207`, `engine.go:3635`) so a Challenge Access entry that
matches on **host / ASN / IP / verified_bot** (dimensions knowable without a
specific request) also keeps a legit crawler from *inflating* the suspicious-vhost
score and from being redirected in DNAT mode. `path` / `ua` / `country` /
`method` cannot be honored at arming/redirect time (no per-request context), so
they are decision-time-only — see the DNAT limitation in §2.6.

### 2.5 Scoped-mode (cPanel) security boundary

Reuse the exclude API's tenant-isolation model exactly
(`exclude_api_handlers.go`): admin = global, any dimension, may set `scope_hosts`;
a **scoped token** may write an entry **only when every vhost in `Scope.Vhosts`
is inside its own token scope** (`scopedExcludeHostAllowed`,
`validateScopedExcludeWrite`, `effectiveExcludeScope`), and the list endpoint
filters out entries outside its scope (`filterExcludeListForScope`). The
deliberate, reviewed *extension* here: a scoped user may now use the richer
dimensions (path/ua/country/ip/asn) — but always **pinned under a vhost in
their scope** (a vhost-less scoped token stays denied, audit F02). No entry a
scoped user can create can ever affect another tenant's vhost. Update
`docs/endpoint_scope_inventory.md` and `docs/security/challenge-scope-mapping.md`
in the same PR.

### 2.6 Known limitations (document, don't hide)

- **DNAT mode**: in DNAT, a flagged IP is redirected *before* the in-path
  decision runs, so only the arming-time (B) dimensions (host/ASN/IP/verified_bot)
  take effect there; path/UA/country/method exemptions are honored in
  in-path OpenResty/Angie mode only. Same class of caveat as the `/.well-known/`
  two-sided carve-out (`docs/challenge-waf-release-checklist`, CLAUDE.md §6).
- **Clearance cookie** already short-circuits before the decision (`cfm.lua`
  Step 2b), so a solved browser is unaffected regardless.
- **Not a WAF bypass**: to exempt a path from a WAF *rule*, use WAF excludes; to
  exempt from the challenge, use this. The UI must state this (the two are
  intentionally separate surfaces).

---

## 3. Backend work items (single-concern PRs)

### 3.1 `challenge_access.go` store + matcher + tests
New store, JSON persistence, `MatchExempt`, `normalizeChallengeAccess` (reusing
`normalizeTrafficRule` field validators). Go tests mirror `traffic_rules_test.go`
(each dimension: match/no-match, fail-open country/ASN, AND/OR semantics, block
never downgraded).

### 3.2 Wire into `handleDecision` (enforcement A) + arming (enforcement B)
The downgrade block above; the arming-side extension. `nginx_bridge` tests for
the downgrade (challenge→allow, block preserved, WAF `rule_action` preserved).

### 3.3 `asn_in` (challenge-access dimension; resolved lazily)
**As built (Phase 0):** `asn_in` landed as a **challenge-access-only** field
(`challengeAccessMatch` embeds `TrafficRuleMatch` and adds `AsnIn []uint32`),
resolved cache-only via `b.enr.LookupCachedOrAsync(ip).ASN` — the value is
already returned by the call `handleDecision` makes for country; `.ASN` was
simply discarded. To avoid a wasted mmdb read on every challenged request, the
bridge passes a **lazy `asnFn`** that `MatchExempt` invokes (memoized) only when
a host-matched entry actually uses `asn_in`.

The match **grammar** is still shared (the entry reuses `normalizeMatch` and
`ruleMatchFilters` — one validator, one evaluator, CLAUDE.md §5); only the ASN
field is challenge-access-local for now. Promoting `asn_in` onto
`TrafficRuleMatch` for the traffic-rules engine + `rules-model.js` (the pending
traffic-rules roadmap item) is a **separate PR**, kept out of Phase 0 so the
traffic-rules UI/parity harness is untouched; when it lands, the field moves from
the wrapper to the base and the wrapper drops it.

### 3.4 API + CLI (reuse the exclude skeleton)
`/api/v1/challenge/access/{list,add,update,remove}` in `exclude_api_handlers.go`
style, with the same scope validators. CLI verbs in `cli_exclude.go` style.
Already inside the scoped self-service allowlist pattern
(`core.js:281 isScopedSelfServiceWrite` whitelists `v1/challenge/...`).

### 3.5 Migration / reconciliation
On first load, migrate existing host-only `webdetector_challenge_excludes.json`
(M3) entries into Challenge Access entries (`Scope.Vhosts=[value]`, empty match).
Keep the **static file** M2 as-is (curated FCrDNS crawler defaults, ops-managed)
and surface it **read-only** in the UI (§4.3) so operators see the full picture
without a second editable copy (CLAUDE.md §5).

---

## 4. cfm-admin UI

A new page **Challenge Access** under the **Rules & engine** nav group
(`assets/shared/nav.js:42`), served from
`internal/webui/static/webdetector/challenge-access/index.html`
(`pageMode:"challenge-access"`, mixin `feature-challenge-access.js`), registered
in `embed.go`, `core.js` page computeds, and `controller-bootstrap.js` if
admin-gated for the global view. It reuses three existing patterns wholesale.

### 4.1 The exempt builder (reuse the traffic-rules chip editor)
The same Step-2 **chip** builder as the rules editor (`rules/index.html`,
`feature-rules.js toggleChip`, model in `rules-model.js`): chips for **Endpoint
(path)**, **User-agent / bot group**, **Country (is / is not)**, **IP / range**,
**ASN**, **Method**, **Verified crawler**. Step 1 is **not** an action picker —
the action is fixed. A prominent banner states the semantics:

> *Exempts matching requests from the **interactive challenge** on the selected
> vhosts. **Does not** bypass the WAF or an IP block. Unknown country/ASN never
> matches (fails open).*

Step 3 is the **vhost multi-select** (`knownVhosts` datalist, "all my vhosts"
for scoped users), plus an edge-mode badge per vhost ("in-path" / "DNAT — path &
UA exemptions do not apply here", per §2.6).

### 4.2 Global + per-vhost view (reuse the rules list pattern)
A single table grouped by vhost, with the `rulesVhostFilter` dropdown and the
`?vhost=<host>` deep-link (`core.js:519`, and a command-palette "Challenge access
for `<host>`" action in `nav.js`). A `*`-scoped entry renders as **Global**; a
vhost-scoped entry shows its host list. Columns: On / Vhosts / Exempts (plain
language via `describeMatch`) / Note / ID / Actions. Inline enable-toggle +
Duplicate + "Test with…" (deep-link to the challenge simulator prefilled).

### 4.3 Read-only view of the static crawler file (M2)
A collapsed "Verified crawlers (managed in `webdetector_challenge_exclude.txt`)"
panel listing the parsed FCrDNS rules, so the operator sees the whole exemption
surface in one place without a second editable list.

---

## 5. Challenge-Recipes (mirror the WAF/traffic recipes)

Recipes are front-end only today — a catalog in `rules-model.js:933 RECIPES`
(schema `{key, kind: multi|single|link, title, description, vars[], warnings[],
build(vars)}`) applied by looping the create API (`feature-rules.js
createRecipeRules`). Add a **`CHALLENGE_ACCESS_RECIPES`** catalog (same schema,
`build()` emits `challenge/access/add` payloads) surfaced in a Recipes pane on
the new page. Seed set (each maps to the real traffic we see):

| Recipe (key) | Creates | Motivating case |
|---|---|---|
| **Let product-feed fetchers reach feeds** (`allow_feed_fetchers`) | exempt `asn_in=[AS15169]` **AND** `path_any=[*/google.xml, */*feed*.xml]` (or `verified_bot` + path), vhosts=`<pick>` | the google-xrawler / WooFeed incident (§1.1) |
| **Let verified search/social crawlers through** (`allow_verified_crawlers`) | exempt `verified_bot`, vhosts=`*` (or picked) | search/social bots on an auto-challenged shop |
| **Exempt an uptime monitor** (`allow_monitor`) | exempt `ip_any=[<monitor ranges>]` | the fleet's own uptime-kuma probe hitting the challenge page |
| **Exempt a machine/integration endpoint** (`allow_integration_path`) | exempt `path_any=[<path>]` (+ optional `methods`) | webhook / API integration that can't solve a challenge |
| **Exempt an office ASN/country from challenge** (`allow_office`) | exempt `asn_in`/`country_in` + optional path | trusted partner/office network |

Each recipe shows a preview + warnings (e.g. *"ASN alone is broad — add a path
or verified_bot to narrow"*, the UA-spoofability hint) and tags created entries
`recipe:<key>` for group list/disable/remove, exactly as the traffic recipes do.
The two existing traffic-rules recipes that are **`kind:"link"` stubs**
(`exempt_integration`, `monitoring_probes`) should be repointed from the WAF page
to this new Challenge Access page.

---

## 6. Phasing

1. **Phase 0 — backend core (no UI). LANDED.** store + matcher (`challenge_access.go`)
   + `handleDecision` downgrade + lazy `asn_in` + CRUD API
   (`/api/v1/challenge/access/*`) with the scoped tenant boundary + Go tests
   (per-dimension match, block-never-softened, disk round-trip, scope filter) +
   CHANGELOG. Fixes the google-xrawler class of incident immediately via the API.
   **Deferred to follow-ups** (each its own PR): the CLI verbs (§3.4), a
   `challenge/access/simulate` endpoint for the UI "Test" button, the arming-time
   suppression (§2.4 B; decision-time downgrade is the shipped mechanism), and
   migrating the legacy host-only challenge excludes (§3.5 — the new store is
   additive, so M3 keeps working meanwhile). Forward-compat for unknown future
   fields on downgrade is not yet implemented — consistent with the sibling WAF
   exclude store, which also plain-decodes; the elaborate `frozen` guard is
   traffic-rules-only.
2. **Phase 1 — UI.** §4: the Challenge Access page (builder + global/per-vhost
   table + nav slot + scope gating + read-only M2 panel).
3. **Phase 2 — Challenge-Recipes.** §5, plus incident entry points (challenge
   events / IP-drilldown → "Exempt this UA/ASN/path from challenge").
4. **Phase 3 — polish.** Hit/last-hit counters (needs the challenge route log to
   carry the matched entry id, the same F11 gap the rules have); shadow/overlap
   hints; DNAT-mode badges.

Each phase is a normal CFM PR: adversarial self-review (CLAUDE.md §9),
`make lua`/`make test-lua` if `cfm.lua` is touched (Phase 0 should not need it —
ASN is threaded in Go, the decision call already exists), `make test-js` for
`rules-model.js` parity, the scoped post-deploy checks
(`docs/scoped-postdeploy-verification.md`), the challenge/WAF release checklist
for any edge-affecting change, and a `[Unreleased]` CHANGELOG entry.

---

## 7. Why not just extend Traffic Rules with a `challenge_exempt` action?

Considered and not chosen, matching the existing decision in
`docs/traffic-rules-ux-proposal.md` §3:

- Traffic rules are a **first-match-wins ordered engine**; an exemption is an
  order-independent **allow-list**. Modelling exemptions as rules reintroduces
  priority/shadowing complexity for no benefit.
- The scoped-tenant security work already lives on the **exclude** API; an
  exemption action on rules would duplicate it.
- `allow` already exists and is *not* a bypass; adding a second, subtly
  different bypass action to the same object is exactly the ambiguity F1
  documents as a source of wrong configs.

We **do** share the match grammar and `asn_in` with traffic rules (§2.2/§3.3), so
there is one grammar and one place ASN is resolved — just two consumers (an
ordered enforcement engine, and a flat exemption list).
