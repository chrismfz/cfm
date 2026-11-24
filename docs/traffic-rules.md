# Traffic rules

Per-vhost rules the edge applies to every request that reaches rule
evaluation (`cfm.lua` Step 3): `block`, `challenge`, `challenge_v2`,
`throttle` (with a `throttle_profile`), `throttle_total` (one budget for all
matching clients, see [Emergency rules](#emergency-rules-expiry-and-a-total-throttle))
or `allow`. Managed from cfm-admin
(Traffic rules, with its Recipes tab), `cfm webtop rules …` or the API. The
engine is `internal/webdetector/traffic_rules.go`; the cfm-admin model is
`rules-model.js`, kept in step with it. UX review and the remaining
proposals: `docs/traffic-rules-ux-proposal.md`.

## Ready-made rules

See ready-to-use files under `docs/examples/`:

- `traffic-rule-allow-verified-crawler.json` (`verified_bot`)
- `traffic-rule-allow-office-ips.json` (`ip_any`)
- `traffic-rule-block-country.json` (`country_in`)
- `traffic-rule-block-outside-countries.json` (`country_not_in` geo-fence)
- `traffic-rule-block-geedo.json` (`ua_any` — block the Geedo shop scraper; also the one-click "Block the Geedo shop scraper" recipe in cfm-admin)
- `traffic-rule-block-probe-paths.json` (`path_any` — block `/.env`, `/.git/`, phpinfo, `*.php.bak`, `*.sql` probes; the "Block secret / dev-file probes" recipe. `*` also matches `/`, so `/*phpinfo.php` covers any directory)
- `traffic-rule-bots-read-only.json` (`ua_any` + `methods` — social crawlers never POST/PUT/PATCH/DELETE; one rule of the "Crawlers are read-only" recipe — deliberately with no `verified_bot` allow in front, since Meta's crawler is FCrDNS-verified too)
- `traffic-rule-challenge-login.json`
- `traffic-rule-throttle-meta.json`

The cfm-admin **Recipes** tab (Traffic rules → Recipes) builds these and the
other multi-rule bundles (geo-fence, geo-challenge, tame bots, bots off facet
URLs, panel-subdomain lock, dev-site lock, xmlrpc lockdown, expensive-endpoint
throttle) with the right relative priorities; each created rule carries a
`recipe:<key>` note so the group can be found again. Source of truth:
`internal/webui/static/assets/webdet/rules-model.js` (`RECIPES`, `BOT_GROUPS`).

## Match fields

All optional; set fields are AND'd, values inside a list are OR'd;
an empty `match` matches every request on the scoped vhosts):

| Field | Matches when… | Notes |
|---|---|---|
| `country_in` | the client's country is one of the codes | ISO 3166-1 alpha-2, ≤64 |
| `country_not_in` | the client's country is known and **not** one of the codes | mutually exclusive with `country_in`; an unknown country (`""` — geo not resolved / geo module down / panel requests) does **not** match, so a geo hiccup never turns the fence into a block of everyone |
| `ip_any` | the client IP is inside one of the IPv4/IPv6 CIDRs | ≤500 (a scraper's top IPs); a bare address is `/32` / `/128`; stored masked+canonical (v4-mapped v6 becomes plain v4); no/invalid client IP never matches |
| `verified_bot` | the client IP is an **FCrDNS-verified crawler** (Googlebot, Bingbot, Yahoo, Applebot, Yandex, Meta — `goodBotPTRSuffixes` minus the generic `google` verdict, Google's special-case crawlers such as AdsBot (`rate-limited-proxy-*`); Google's user-triggered fetchers, `google-proxy-*`, verify as nothing since 2026-11-24) | the PTR must forward-confirm to the IP; a User-Agent string earns nothing. On the decision path the verdict is cache-only and consulted only for hosts an enabled `verified_bot` rule covers: a first-seen crawler IP (and every crawler IP after a daemon restart — the verdict cache is in-memory) matches from about its third request (request 1 fetches the PTR, request 2 kicks the forward-confirm), then an expired verdict is served stale while it re-verifies (dropped at once if the PTR no longer looks like a crawler). A cached PTR *failure* (resolver timeout / SERVFAIL, not a definitive "no PTR") is retried every 5 min rather than pinned for the 24 h geo TTL. The simulate API resolves it inline (its own small slot bound, direct reverse DNS — never the shared enrich cache), honours a caller-supplied `verified_bot` name as an override, and echoes the verdict (`verified_bot`; `verified_bot_excluded` for the generic google verdict; `verified_bot_inconclusive` = `timeout` / `transient` / `no_resolver` / `no_bridge` / `not_checked` when it could not tell — never a silent negative; alongside a name it flags a stale verdict) in the result |
| `ua_any` | the User-Agent matches a case-insensitive `*`-glob, or contains the value when it has no wildcard | a lone `-` means "no User-Agent header" |
| `path_any` | the decoded path has the value as a prefix (or matches the glob); a `?k=v` suffix matches per query parameter | |
| `methods` | the HTTP method is listed | |
| `has_qs` / `qs_not_rx` | a query string is present / the query does **not** match the RE2 regex | `qs_not_rx` applies whenever a query is present, independently of `has_qs` |
| `until` | (not a condition) the rule matches **nothing** from this RFC3339 time on | the rule's expiry, see [Emergency rules](#emergency-rules-expiry-and-a-total-throttle) |

A rule whose `match` or `scope` carries a key the running binary does not know
— or whose `action.type` is a value it does not know — (written by a newer
cfm) is listed disabled + `unsupported`, never evaluated, refused by update,
and written back to disk **verbatim** (its original bytes, including
`enabled`), so nothing is widened or lost until the upgrade; conversely a cfm
older than 2026-09 drops `country_not_in` / `ip_any` silently, and one older
than 2026-09-22 **deletes** a `challenge_v2` rule from disk on its next save
(the action-value freeze shipped together with the action) — disable such
rules before downgrading below those versions.

## Emergency rules: expiry and a total throttle

For an incident (a crawler on hundreds of IPs loading a node) a rule can end by
itself and can cap the matching traffic as a whole. cfm-admin's Web Traffic
page makes these from a client row ("Deny…" / "Throttle…",
`webdet/emergency-model.js`): note `emergency: <reason>`, priority 1–9 (so they
run before the operator's own rules, allows included), a UA family as
`*<family>*` or the client's top IPs, and lists the live ones with +1 h /
End now. Like every rule, it never
sees a client that leaves `cfm.lua` earlier: an address in
`challenge_waf_bypass.conf` (Google, Bing and the other listed crawler and CDN
ranges, Step 0) or a client holding a valid clearance cookie (Step 2b). A
throttle on `*Googlebot*` therefore does nothing; Meta's crawlers are not on
that list, so a Meta throttle bites.

- **`match.until`** (RFC3339, stored UTC): past it the rule matches nothing,
  with no restart or save needed (`ruleMatchFilters`; a Challenge Access entry
  refuses an `until`). An add, an import or an update that sets a past `until`
  is refused; an update that keeps the rule's own past `until` (disabling an
  expired rule) is not. The
  expired rule stays listed (cfm-admin shows `expired`) and is deleted by the
  first rule write a day after it expired. The expiry is a **match** key on
  purpose: a cfm older than this one freezes a rule carrying it (listed
  `unsupported`, never enforced), so a downgrade leaves an emergency rule
  inert, never permanent.
- **`throttle_total`** (`action.rate_rps` 0.1–10000, `action.per` `vhost` |
  `node`): one budget for every client the rule matches, per vhost or for the
  whole node (all the vhosts the rule covers together), counted over 10 s
  windows at the edge (`cfm_rules.lua` `total_hit`, key
  `trt|<rule id>|<host or *>|<window>`; the limit is `rate × 10` requests a
  window). Over it a request gets `429` + `Retry-After`, whatever IP it came
  from. It is a fixed window: a window's whole budget can pass at once, and up
  to twice the rate in the second around a window edge. Per vhost is keyed on
  the request's Host, so on a `*` scope a client that reaches rule evaluation
  with Host values of its own choosing gets a budget per value: use `node`
  there. A per-client throttle does not stop a crawler spread over hundreds of
  IPs: on titan (2026-11-24) a per-IP or per-vhost limit cut 0–4% of Meta's
  origin load, a node total of 5 r/s cut 65%. Match it narrowly (a User-Agent):
  legitimate clients that match share the budget. It ends evaluation like a
  `throttle` (a later rule never runs for what it matches) and sits in the same
  priority band. On the wire it is `rule_action: "throttle"` plus
  `throttle_rate`, `throttle_per` and `rule_id`; an older edge ignores those
  and applies the per-client `soft_bot` throttle. A cfm older than this one
  freezes a `throttle_total` rule (unknown action type), and this one freezes a
  rule whose `action` carries a key it does not know.

```bash
UNTIL=$(date -u -d '+6 hours' +%Y-%m-%dT%H:%M:%SZ)
curl -sS -X POST "$CFM_API/api/v1/webdet/rules/add" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"enabled":true,"priority":5,"scope":{"vhosts":["*"]},
  "match":{"ua_any":["*meta-externalagent*"],"until":"'"$UNTIL"'"},
  "action":{"type":"throttle_total","rate_rps":5,"per":"node"},"note":"incident: Meta load"}' | jq
```

## API

Endpoints (admin, or scoped to the token's vhosts): `GET /api/v1/webdet/rules`,
`rules/get?id=`, `POST rules/add`, `rules/update?id=`, `rules/remove?id=`,
`rules/simulate`, `GET rules/export[?vhost=]`, `POST rules/import[?dry_run=1][&disabled=1]`
(export/import: a portable document without ids or timestamps; import is
all-or-nothing, duplicates skipped).

```bash
CFM_API=http://127.0.0.1:6060
TOKEN=$(awk -F' *= *' '$1=="AUTH_TOKEN"{gsub(/"/,"",$2);print $2}' /etc/cfm/cfm.conf)

curl -sS -X POST "$CFM_API/api/v1/webdet/rules/add" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' --data-binary @docs/examples/traffic-rule-throttle-meta.json | jq
curl -sS "$CFM_API/api/v1/webdet/rules" -H "Authorization: Bearer $TOKEN" | jq
curl -sS -X POST "$CFM_API/api/v1/webdet/rules/simulate" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com","ua":"facebookexternalhit/1.1","path":"/","method":"GET","country":"US"}' | jq
```

CLI: `cfm webtop rules list|get|add|update|remove|simulate|export|import`
(`docs/cli.md`).

## How rules are applied

> **Semantics (verified against `cfm.lua` Step 3):** rules are evaluated in
> priority order (lowest first) and the **first match wins**; **only enabled
> rules are enforced**. In the in-path request path (OpenResty or Angie) the
> edge enforces `block`, `challenge` and `throttle` (with `throttle_profile`).
> `challenge_v2` stores/simulates as itself but rides the wire as plain
> `challenge` (identical page; the daemon records the v2 intent per (ip, host)
> so the SOLVE must also pass the passive humanity check — see ChallengeV2).
> **`allow` is NOT an exemption** — it only stops the remaining rules from being
> evaluated; it does not bypass the WAF, a vhost-wide challenge or a per-IP
> block (use challenge/WAF excludes for that). Clients holding a valid clearance
> cookie never reach the rule evaluation. The edge's short-TTL decision cache is keyed on ip/host/path (+query)
> but deliberately NOT on User-Agent, so a UA-keyed rule can be masked for up to
> one cache TTL by a clean-allow the same IP just earned with a different UA.
> `simulate` runs the exact enforcement evaluation and additionally
> returns `disabled_match` — the highest-priority *disabled* rule that would
> have matched had it been enabled — so a rule can be saved disabled, tested,
> then enabled from the cfm-admin table.
