# Traffic rules

Per-vhost rules the edge applies to every request that reaches rule
evaluation (`cfm.lua` Step 3): `block`, `challenge`, `challenge_v2`,
`throttle` (with a `throttle_profile`) or `allow`. Managed from cfm-admin
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
| `country_in` | the client's country is one of the codes | ISO 3166-1 alpha-2, ≤20 |
| `country_not_in` | the client's country is known and **not** one of the codes | mutually exclusive with `country_in`; an unknown country (`""` — geo not resolved / geo module down / panel requests) does **not** match, so a geo hiccup never turns the fence into a block of everyone |
| `ip_any` | the client IP is inside one of the IPv4/IPv6 CIDRs | a bare address is `/32` / `/128`; stored masked+canonical (v4-mapped v6 becomes plain v4); no/invalid client IP never matches |
| `verified_bot` | the client IP is an **FCrDNS-verified crawler** (Googlebot, Bingbot, Yahoo, Applebot, Yandex, Meta — `goodBotPTRSuffixes` minus the generic `google` verdict, which covers Translate/AMP proxies) | the PTR must forward-confirm to the IP; a User-Agent string earns nothing. On the decision path the verdict is cache-only and consulted only for hosts an enabled `verified_bot` rule covers: a first-seen crawler IP (and every crawler IP after a daemon restart — the verdict cache is in-memory) matches from about its third request (request 1 fetches the PTR, request 2 kicks the forward-confirm), then an expired verdict is served stale while it re-verifies (dropped at once if the PTR no longer looks like a crawler). A cached PTR *failure* (resolver timeout / SERVFAIL, not a definitive "no PTR") is retried every 5 min rather than pinned for the 24 h geo TTL. The simulate API resolves it inline (its own small slot bound, direct reverse DNS — never the shared enrich cache), honours a caller-supplied `verified_bot` name as an override, and echoes the verdict (`verified_bot`; `verified_bot_excluded` for the generic google verdict; `verified_bot_inconclusive` = `timeout` / `transient` / `no_resolver` / `no_bridge` / `not_checked` when it could not tell — never a silent negative; alongside a name it flags a stale verdict) in the result |
| `ua_any` | the User-Agent matches a case-insensitive `*`-glob, or contains the value when it has no wildcard | a lone `-` means "no User-Agent header" |
| `path_any` | the decoded path has the value as a prefix (or matches the glob); a `?k=v` suffix matches per query parameter | |
| `methods` | the HTTP method is listed | |
| `has_qs` / `qs_not_rx` | a query string is present / the query does **not** match the RE2 regex | `qs_not_rx` applies whenever a query is present, independently of `has_qs` |

A rule whose `match` or `scope` carries a key the running binary does not know
— or whose `action.type` is a value it does not know — (written by a newer
cfm) is listed disabled + `unsupported`, never evaluated, refused by update,
and written back to disk **verbatim** (its original bytes, including
`enabled`), so nothing is widened or lost until the upgrade; conversely a cfm
older than 2026-09 drops `country_not_in` / `ip_any` silently, and one older
than 2026-09-22 **deletes** a `challenge_v2` rule from disk on its next save
(the action-value freeze shipped together with the action) — disable such
rules before downgrading below those versions.

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
