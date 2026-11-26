# Endpoint scope inventory

Every route on the daemon's apiserver mux (plaintext `:6060` and the TLS
`:6061` listener serve the same handler stack), with its auth class and where
that class is enforced. References are `file:line` of the handler (and of the
registration where that says more); paths are relative to the repo root,
`internal/` dropped where the package is obvious. Line numbers drift: re-grep
before relying on one.

Auth classes:

- **admin-only**: any non-admin caller gets `403`. Enforced by the
  `adminOnlyHandler` wrapper (`internal/apiserver/apiserver.go:712`) or an
  in-handler `RequireAdmin` (`internal/webdetector/authz.go:22`); both key on
  `IsAdminRequest` (`internal/webdetector/vhost_filter.go:174`): the request is
  authenticated AND carries the admin role (admin bearer token, admin SSO
  cookie, or a goauth login session). A nil scope is never what makes a
  caller admin.
- **scoped-allowed**: admin or scoped caller (a scoped bearer token or the
  scoped embed cookie); the handler applies vhost/user scoping
  (`parseVhostFilter`, `vhostAllowed`, `validateScopedVhostQuery`,
  `scopeCheckHost`, `scopeAllowsVhosts`, the `validateScoped*` write guards, or
  `scopedMySQLFilterHandler`'s derived filters).
- **session-only**: a goauth cfm-admin login session and nothing else.
- **public / self-authenticating**: `TokenMiddleware` lets the request through
  without a CFM credential; the handler authenticates it itself (one-time code,
  actor assertion, MCP bearer / OAuth) or serves nothing protected.

**The `nil` scope sentinel means admin/loopback ONLY.** `vhostScopeFromContext`
(`internal/webdetector/vhost_filter.go:71`) normalizes a *scoped*-role request
that carries no scope map (e.g. a DB-only viewer token whose vhost set is nil)
to a non-nil **empty** set, so every `nil == no restriction` consumer
(`vhostAllowed`, `parseVhostFilter`, the `*ForScope` list filters, and the
`validateScoped*` write guards) fails closed for it — a vhost-less scoped token
matches no host and sees no rows, rather than being mistaken for admin. Code
that reads `CtxScopeKey{}` **directly** instead of through that helper must keep
its own guard. Two do today: `deriveScopedMySQLOwners`
(`internal/apiserver/apiserver.go:819`, `len(scope)==0` → no owners) and
`mailTrafficScope` (`internal/apiserver/system_status_endpoint.go:1097`, which
builds a non-nil, possibly empty set for any scoped caller and drops the
host-wide `*` key).

**What a cPanel scoped token's vhost set holds** (since 2026-11-10). The
plugin mints it from `/api/v1/cpanel/user-info`, which returns the account's
domains from `/etc/userdatadomains` plus the names their sites answer on:
`www.<domain>` for each, and the domain's cPanel ServerAlias list
(`panelmap.WithWebAliases`). A name is kept only at or under one of the
account's own domains, and wildcards are dropped. Before, the set held only
the bare names, while traffic is logged under the requested Host (nearly
always `www.`), so scope checks matched almost none of the account's traffic.

**Who wins when a browser carries both cookies** (`TokenMiddleware`,
`internal/apiserver/middleware.go:403`): a bearer token, then the admin SSO
cookie (cfm-web / WHM SSO, step 2a at `:513`), then the admin login session
(non-embedded requests only, step 2c at `:528`), then the scoped embed cookie
(step 2b at `:555`). An admin who has also opened a customer's cPanel CFM on
the same host (the embed cookie ignores the port) therefore keeps browsing as
the admin (order since 2026-11-10). An *embedded* request (below) never uses
the session, so in the iframe the scoped cookie is the identity.

**Admin-only cfm-admin PAGES** (HTML, not endpoints): a scoped GET/HEAD for
one of `scopedAdminOnlyPages` (`internal/apiserver/scoped_page_redirect.go:26`,
mirroring the nav's `ADMIN_ONLY_NAV_PATHS`), or for an unknown page path
(served as the dashboard), gets a `303` to `/cfm-admin/webdetector/controls/`
(`scopedAdminPageRedirect`, `:45`). Assets, files and `/api/` paths are never
redirected, and admin requests never are.

## Request pipeline (auth-relevant behaviour)

Handler stack, outermost first (`Start`, `internal/apiserver/apiserver.go:310-358`):
RequestLog → SecurityHeaders → AdminTransportRedirect → APISecurityAnomaly →
PprofWriteTimeout → SessionCookieTransport → goauth LoadAndSave →
**`TokenMiddleware`** → **`CSRFMiddleware`** → RateLimit → mux.

- **Public paths are an exact list.** `publicPaths`
  (`internal/apiserver/middleware.go:191`: `/login`, `/login/`,
  `/login/verify`, `/login/webauthn/begin`, `/login/webauthn/finish`,
  `/logout`, `/api/v1/embed/bootstrap`, `/api/v1/embed/admin-bootstrap`) and
  `mcpPublicPaths` (`:206`: `/mcp`, `/mcp/oauth/{register,authorize,token}`,
  `/.well-known/oauth-protected-resource`,
  `/.well-known/oauth-authorization-server`,
  `/.well-known/openid-configuration`) are matched exactly, never as prefixes
  (since 2026-11-18). `/login/` has no route of its own: the UI catch-all
  serves it the static shell, as it did before the list was exact. GET/HEAD
  of a static file under `/assets/` with a known extension and no `..` is
  public too (`isPublicAssetPath`, `:256`). The MCP
  paths skip `TokenMiddleware` entirely (`:441`; MCP owns its bearer/OAuth
  gate). On the other public paths a supplied bearer token is still validated
  first (an invalid one is `401`); with no token the request passes (`:508`).
  `GET /api/v1/cpanel/user-info` carrying `X-CFM-Actor-Assertion` passes the
  same way (`isCpanelPluginSelfServicePath`, `:390`); its handler checks the
  assertion.
- **An encoded separator in the path is `404` before any auth decision**
  (since 2026-11-18; `hasEncodedPathSeparator`, `internal/apiserver/middleware.go:612`,
  called first in `TokenMiddleware`, `:433`): `%2F` / `%5C` in any case, or a
  raw `\`, in the escaped path. The auth checks below read the decoded path
  and the mux the escaped one; this is the one place the two disagree (`/a%2fb`
  is one segment to the mux, two to the auth path). It applies to every
  credential and to the MCP paths. No client sends one: the only route with a
  path parameter is `/api/v1/debug/capture/<timestamp>`, everything else takes
  its arguments in the query, and the edge passes the client's encoding
  through or decodes it, never adding one.
- **The auth path strips every leading `/cfm-admin`.** The public-path match
  runs on `authMiddlewarePath` → `stripCfmAdminPrefixes` (`:246`), so the auth
  check reads the path the router serves. The `/cfm-admin/` dispatcher
  (`cfmAdminPrefixHandler`, `internal/apiserver/apiserver.go:685`, registered
  at `:185`) strips ONE prefix and re-dispatches on the same mux; a path that
  still starts with `/cfm-admin` after that is answered `404`. The edge does
  the same: `location ^~ /cfm-admin/cfm-admin/ { return 404; }`
  (`configs/openresty.conf:1388`, `:2905`; `configs/angie.conf:1368`, `:2878`)
  ahead of the `^~ /cfm-admin/` proxy block, which rewrites one prefix away.
- **Credentials, in order** (`TokenMiddleware`): bearer / `X-CFM-Token` /
  `Token` header (admin token → admin role; a scoped token from the token store
  → scoped role with its vhost and DB scope; anything else `401`); then, with
  no token header, the admin SSO cookie, the goauth session (not for embedded
  requests), the scoped embed cookie. Both embed cookies are honoured only when
  the effective base is `/cfm-admin` (`cfmBase`, `:145`: the
  `X-Forwarded-Prefix` / `X-CFM-Base` headers are trusted from a loopback peer
  only, else the request path's own prefix). An *embedded* request
  (`X-CFM-Embedded` / `X-CPanel-Embedded` header, or any `/api/v1/cpanel/`
  path, `isCpanelEmbeddedRequest`, `:292`) with neither a token nor an embed
  cookie is `401`, with no session fallback (`:580`). Anything else without a
  credential: an HTML request is redirected to `<base>/login?next=…`, an API
  request gets `401` (`:591`).
- **Iframe shell exemption** (`isEmbedShellBootstrapRequest`, `:312`): an
  uncredentialed request is served the UI's static HTML shell, with no
  identity, only when it is a GET, its `Accept` holds `text/html`, it carries
  `cfmExpectedOrigin` in the query OR `Sec-Fetch-Dest: iframe`, and its path is
  a UI page path (`isEmbedShellPagePath`, `:359`): a clean path (no `//`,
  `/./`, `/../`, backslash or NUL, no nested `/cfm-admin/cfm-admin`) whose
  first segment after the prefix is not a non-page root (`api`, `mcp`,
  `login`, `logout`, `me`, `search`, `unblock`, `.well-known`, `assets`) and
  that is not under `/debug/pprof`. The shell's own API calls then
  authenticate with the token the parent frame posts to it.
- **Every web-detector route requires an identity.** The engine's route table
  (`apiRoutes`, `internal/webdetector/http_api.go:41`) is registered by
  `RegisterHTTP` (`:141`), which wraps every route except
  `/api/v1/cpanel/user-info` (`selfAuthenticatingRoutes`, `:156`) in
  `requireIdentity` (`:164` → `RequireScopedOrAdmin`): a request the
  middleware did not mark admin or scoped is `403` whatever path led to the
  engine mux. Handlers that read "no vhost scope" as the operator's view rely
  on this. The shared apiserver reaches the engine mux through
  `webdetRoutesProxy` on the `SharedAPIPrefixes` (`http_api.go:21`;
  registration `internal/detectors/webdetector_register.go:198`).
- **CSRF** (`CSRFMiddleware`, `internal/apiserver/csrf_middleware.go:42`):
  POST/PUT/PATCH/DELETE requests authenticated by an ambient browser credential
  — the goauth session, the scoped embed cookie (SameSite=None, for the cPanel
  iframe) or the admin SSO cookie — must carry an `Origin` (else a `Referer`)
  naming this request's own host (`csrfRequiresCheck`, `:62`;
  `validateCSRFSameOrigin`, `:74`). Bearer-token requests are not checked (a
  cross-site form cannot set the header), and neither are public routes. The
  allowed hosts are the request's `Host` plus `X-Forwarded-Host`, the latter
  only from a loopback peer (`trustedForwardedHost`, `:181`). A source with a
  default port (80/443 dropped) matches on the host; a source with an explicit
  other port must have arrived on that same port (`csrfHosts.match`, `:113`;
  since 2026-11-18), so the panel and webmail ports of the same host are other
  origins. The edge sends the browser's own `Host`, port included, as
  `X-Forwarded-Host` (`map $http_host $cfm_admin_xfh`, falling back to `$host`
  when HTTP/3 leaves `$http_host` empty: `configs/openresty.conf:214`,
  `configs/angie.conf:208`), while the proxied `Host` is `$host` (no port).
  A failure is `403 {"error":"forbidden"}`, logged as `csrf_reject`.
- **Logout ignores a cross-site request.** `handleLogout`
  (`internal/apiserver/login.go:237`) answers a `Sec-Fetch-Site: cross-site`
  request with a redirect to the base and ends no session; otherwise it
  destroys the goauth session, expires both embed cookies and redirects to
  `<base>/login`. A browser that sends no `Sec-Fetch-Site` is logged
  out normally. (Logout is a GET link, so CSRF does not cover it.)

## Web detector routes (`internal/webdetector/http_api.go` `apiRoutes()` + handlers)

All behind `requireIdentity` (see the pipeline) unless noted; the class below
is what the handler adds on top. Handler files are under `internal/webdetector/`.

### Scoped-allowed

- `/api/v1/webdet/top-short`, `/api/v1/webdet/top` (alias) (`handleTopShort`,
  `http_api.go:246`; `validateScopedVhostQuery` on `?vhosts=` + `parseVhostFilter`).
  `/api/v1/webdet/suspicious` (`handleSuspicious`, `http_api.go:308`; `?limit=` 1..500, default 50, since 2026-11-24) and
  `/api/v1/webdet/long-top` (`handleLongTop`, `http_api.go:352`) share
  `suspiciousRows` (`:326`). Since 2026-11-18 the vhost filter (a scoped
  caller's scope, or an admin's `?vhosts=`) is applied BEFORE the limit
  (`limitUnlessFiltered`): the caller gets up to `limit` of its own rows, and
  the row count says nothing about where its hosts rank among other tenants'.
- `/api/v1/webdet/drilldown` (`handleDrilldown`, `http_api.go:377`;
  `validateScopedVhostQuery` + `vhostAllowed(host, parseVhostFilter)`)
- `/api/v1/webdet/analyze-host` (`handleAnalyzeHost`, `http_api.go:485`; `vhostAllowed`)
- `/api/v1/webdet/host-access-history` (`handleHostAccessHistory`, `host_access_api.go:50`, `vhostAllowed`) — bounded ARCHIVAL traffic profile of one vhost from the edge's FULL access log (the `if=$log_main_request` access.log only — the focused `access.cfm.log` is never a candidate) plus rotated siblings via `edgelog.ScanHost`; optional `combine` section joins history-store challenge/WAF stats over EXACTLY the same absolute `[from,to)` window as the access scan — with `merge_www` across both twins (combined + `detector_by_host`; `detector_partial=true` if a twin query failed, and `detector_coverage` reports the store's real retention/oldest retained event so partial history never looks complete). Result is keyed to a single vhost, so a scoped token may profile only its own hosts — same host-param scope model as `analyze-host`; with `merge_www=1` the www/bare TWIN is a separate vhost key and must also be in scope (fail-closed 403). Expensive by nature (up to 60M log lines / 120s per call), so archive scans are capped node-wide at TWO concurrent (`hostAccessScanSlots`), and since 2026-11-18 a scoped caller must also take the single `hostAccessScopedSlots` slot, so scoped callers together hold at most one and one slot always stays free for the operator (`429` + `Retry-After: 30` beyond). `hours` is clamped to ≤90 days at the API boundary before it reaches either the scan or the history queries. For a non-admin caller the result names no log file (since 2026-11-18): `stripScanFileNames` (`host_access_api.go:315`) clears `log_file`, `files_scanned` and `files_failed` on the access section and on the bad-request section, and a scan error is answered with a generic `502` without the error text or `available_logs` (admins get both). What remains node-wide is a few aggregate scan-evidence counters (`scanned`, `skipped_no_host`, bad-request section totals) with no foreign hosts or paths. Backs the MCP `host_access_history` tool.
- `/api/v1/webdet/vhosts` (`handleWebdetVhosts`, `vhost_controls_api_handlers.go:69`; `validateScopedVhostQuery` + `parseVhostFilterWithAliases` + `vhostAllowed`). Each row also carries `site_cache_static` / `site_cache_micro` (the tiers of the policy that decides the host at the edge, a covering operator wildcard included; the policy key is not reported) and `rules`, the count of live traffic rules whose scope takes the host among those the caller may list (`scopeFilterRules`): a scoped caller never counts an operator's rule it cannot see, such as a `*` one (since 2026-11-24).
- `/api/v1/webdet/rules`, `rules/get|add|update|remove|simulate|export|import` (`traffic_rules_api_handlers.go`: list `:139`, get `:150`, add `:177`, update `:209`, remove `:262`, simulate `:299`; export/import `traffic_rules_transfer.go:465`, `:492`). Reads (since 2026-11-18): the list shows every rule with at least one vhost in the caller's scope (`scopeFilterRules`), each with `scope.vhosts` cut to the caller's own vhosts and its `note` dropped when a vhost was cut (`scopeTrimRuleVhosts` / `scopeListRules`); `rules/get` answers any rule the list shows, exactly as the list shows it (`403` only for a rule with no vhost in scope). `rules/simulate` (POST) checks the body's `host` with `scopeAllowsVhosts` and trims the matched rule and `disabled_match` the same way, except that a bare `"*"` vhost is kept (`simulateTrimRuleVhosts`): it names no tenant. Writes: `rules/add` needs every vhost in scope; `rules/update` and `rules/remove` need every vhost of the EXISTING rule in scope (a rule shared with another tenant is visible but not writable), and `update` the new vhosts too (`scopeAllowsVhosts`, fail-closed for nil/`*`/wildcard values the token does not literally hold). `rules/export` (GET, 2026-10-14) is the list's `scopeFilterRules` set, optionally narrowed by `?vhost=`; for a scoped caller each exported rule is the list's view of it (`scopeListRules`: `scope.vhosts` cut to the caller's own vhosts, `note` dropped when one was cut), so a rule the operator shares with another tenant does not name that tenant in the file. `rules/import` (POST, `?dry_run=1`, `?disabled=1`) checks every rule's normalized vhosts with `scopeAllowsVhosts` like `rules/add` and is all-or-nothing: one out-of-scope rule rejects the whole file (`403` when scope is the only failure, as `rules/add`; `400` for any other invalid rule, including a key this build does not know at any level of a rule, or a rule with no `match` object; `409` when an identical rule was added between the plan and the write). The plan's duplicate and priority warnings name only rules on the caller's own vhosts, and the cap error carries no node-wide count (`traffic_rules_transfer.go`).
- `/api/v1/webdet/history/events|summary|challenge-outcomes|waf-by-rule|vhost-overview` (`history_api_handlers.go`: events `:254`, summary `:306`, challenge-outcomes `:332`, waf-by-rule `:405`, vhost-overview `:444`; `RequireScopedOrAdmin` + `scopeCheckHost`, `:12`). `events` pages newest-first with `before_ts` + `before_id` (the last row of the page shown; since 2026-11-25): a cursor only, it reads through the same host check, type filter and redaction as the first page. The answer carries `next` (those two values) when an older page exists, computed before a scoped caller's server-only rows are dropped: a position, never a dropped row's content. **Payload redaction on `history/events`:** rows are returned with their stored `payload_json` verbatim EXCEPT that `payload.sig`, `payload.ptr`, `payload.src`, `payload.scope`, the ChallengeV2 arm family (`payload.v2` and every `v2_*` key, by prefix — `v2_via`, `v2_waived`, `v2_rescued`, `v2_waiver_miss`, and since 2026-11-17 `v2_confirm` / `v2_confirm_ms` — plus `payload.ms`), the `solver_farm` address sample (`payload.ips`, `payload.good_bots`) and the `solver_farm` humanity summary (`payload.humanity`) are stripped for non-admin callers (`redactScopedHistoryRows`, `history_api_handlers.go`; the one key list is `scopedRedactedPayloadKeys`). `sig` is the ChallengeV2 Rung-1 device report (`hardwareConcurrency`, `deviceMemory`, `devicePixelRatio`, pointer/touch/key counts, and since 2026-09-29 the pointer trajectory: straightness, timing jitter, largest jump, duration, untrusted/coalesced event counts; since 2026-10-22 `hid`, whether the page was hidden when it posted; since 2026-11-10 `rf`, the software-renderer family — a short enum such as `swiftshader` / `llvmpipe`, never the raw WebGL renderer string) that CFM's own challenge page collects from each visitor, added 2026-09-22. A tenant could measure the same values from their own site's JS, so it is not secret — but it is per-visitor browser-fingerprinting material CFM gathered, and the scoped surface otherwise carries nothing of the kind (the UA is the most it exposes), so the boundary default is closed. Nothing is lost operationally: the burn-in readout `sig` exists for is admin/MCP. `ptr` (added 2026-09-22, on `challenge_solved` and `challenge_v2_reject` rows) is the solving client's reverse DNS, and its stripping is **defence in depth, not a boundary**: scoped callers already get a per-IP PTR for their own vhosts from `/api/v1/webdet/drilldown` (`HostDetail`) and `/api/v1/webdet/analyze-host`, and anyone holding the IP can resolve it. It is stripped only so scoped history rows look as they did before these rows carried one — do not read it as "PTR is admin-only". (`enrich=1` stops at country/ASN to avoid blocking reverse DNS, not for privacy.) `src` (added 2026-09-23, on `challenge_solved` and `challenge_v2_reject` rows) is the challenge-provenance snapshot taken at verify (`challenge_src.go`); it is closed by default because two of its tokens are the OPERATOR's fleet policy rather than tenant data — `fp`/`geo` reveal that an admin-armed fingerprint or country/ASN policy covers the visitor, and `rule:<id>` names an operator traffic rule. `country`/`country_iso`/`asn`/`asn_name` are NOT stripped: `enrich=1` already gives them to scoped callers. `scope` (added 2026-09-29, on `challenge_solved` and `challenge_v2_reject` rows) is the surface the solve was verified on (`web` / `panel:<port>`); it is closed by default because on a tenant's row `panel:2087` says the visitor IP used WHM through the tenant's hostname — in practice the operator's or a reseller's admin address. The ChallengeV2 arm family (stripped since 2026-09-29, on `challenge_solved` and `challenge_v2_reject` rows) goes whole: `v2` is the grain (`fp` / `geo` / `vhost` / `mark`), and `v2=fp` / `v2=geo` say an admin-armed fingerprint or country/ASN policy covered the visitor — the same operator policy `src` is stripped for. Every other member narrows the grain (`v2_via` exists only for `vhost`; a waiver — `v2_waived`, or any `v2_waiver_miss` but `grain` — only under `geo`/`vhost`; `v2_rescued` only under an arm), so stripping `v2` alone would still give an exact `v2=geo` on a waived solve without `v2_via`, and with `enrich=1` the armed country. `v2_confirm` / `v2_confirm_ms` (the under-attack confirm step, `challenge_confirm.go`) say that an operator's under-attack override, and the node's audience policy, covered the visitor: operator state, withheld like the rest. `ms` (server verify time) goes with them because it times a waiver: it is re-measured after the inline good-bot forward-confirm, which runs only under `geo`/`vhost`. The residual is aggregate, not per row: a `challenge_v2_reject` row still says, by existing, that SOME arm covered the visitor. So on a vhost the tenant knows is not at v2, rejects clustering on one country across many fingerprints point at a country policy, and a cluster sharing one `tls_fp` points at a fingerprint policy. Hiding `challenge_v2_reject` rows from scoped callers would close that, at the cost of the tenant's own false-reject view; that is an operator decision. The `solver_farm` address sample (stripped since 2026-09-29) is `payload.ips` and the `good_bots` map keyed by it: a `solver_farm` row is written for one vhost, but on a cross-host finding the sample is drawn from the convicted fingerprint's addresses on every vhost it dominates (up to 128) — visitors of other tenants' vhosts, and a fingerprint is a population, so real browsers can be among them. The keys go whole, per-host findings included, and on every row type (a future tenant-facing `ips` list needs another key name). The counts (`distinct_ips`, `distinct_subnets`, `distinct_countries`, `hosts`, `host_share`) and the `fingerprint` stay: aggregates with no identity, and evidence rather than operator policy. The fleet store's pull is an admin read and is unaffected. The `solver_farm` humanity summary (`payload.humanity`, since 2026-11-03: the convicted cluster's ChallengeV2 Rung-1 hs buckets, top `tells` strings and top countries of the cluster's passed solves on the row's vhost) is stripped too, as **defence in depth, not a boundary**: a scoped caller can rebuild the same aggregate from its own `challenge_solved` rows, whose `hs` / `tells` / `country` stay visible. It goes because the aggregate, framed around a convicted fingerprint, is the operator's farm-conviction and arm-sizing view (what the operator reads before arming a fingerprint policy), not tenant data. A generic key name, withheld on every row type like `ips`. Scoped callers keep the rest of the payload (`hs`, `tells`, `ua`, `solve_ms`, `tls_fp`, `country`, `asn`, …). Any future admin-only payload key goes in the same helper and this line. `history/events` returns at most 5000 rows per call, for every caller, admin included (`maxHistoryQueryLimit`, `history_store.go`, since 2026-11-18; the query holds the store's lock). **Whole rows dropped for scoped callers** (since 2026-10-08, `dropServerOnlyRows`): `mail_*` and `backup_*` node-fault rows, written under the server's own hostname and carrying other tenants' subjects, script directories, recipients and account names. A scoped caller whose scope happens to include the hostname must not read them; cfm-web pulls them with an admin token. They are not counted either: a scoped caller's `history/summary` `total_events`, and the combined detector summary of `host-access-history`, leave them out (`SummarizeTenant` / `SummarizeRangeTenant`, `history_store.go`; the one type check is `isServerOnlyEventType`, since 2026-11-18).
- `/api/v1/challenge/vhost`, `/api/v1/challenge/events`, `/api/v1/challenge/vhost/add|remove|rung|lockdown|tier|status|attack` (`vhostAllowed` checks; `challenge_api_handlers.go`: vhost `:135`, events `:246` — a scoped caller must pass an in-scope `?host=`, `403` without one; `challenge_manual_handlers.go`: add `:159`, lockdown `:330`, rung `:479`, tier `:558`, remove `:689`, attack `:758`, status `:906`; the mutators are POST-only via `requirePOST`, `tier` POST/GET). `vhost/lockdown` (2026-10-27) switches the LOCKDOWN of the ACTIVE manual challenge covering the host (no client exemption at all: crawler bypass, good bots, Access-Control, exclude file; `docs/vhost-lockdown.md`) — expiry, reason and tier kept, `409` without an arm, default 30m, capped at 6h and at the arm (`lockdown_capped`), wildcard hosts refused; `vhost/add` takes the same as `lockdown=1|0` + `lockdown_ttl` (absent keeps). Scoped tokens may lock down their own vhosts (it only adds challenges, on a vhost they own); the arm changed is `manualRungTarget`'s and the scope check covers THAT host too (`403` for a `www.` host whose covering arm is on an apex outside scope). Audited as `challenge_vhost_lockdown` (`lockdown`/`until`/`actor`; lifting an absent lockdown writes nothing). `vhost/status`, `vhost`, `vhosts` add `lockdown`/`lockdown_until` and the webdet controls rows `challenge_lockdown_until` (additive, no scope change). `vhost/tier` (2026-09-29) POST pins the tier of AUTOMATIC vhost challenges on a host (`rung=v1|v2|auto`, optional `ttl`; `auto` removes the pin) — it never creates, extends or clears a challenge; a manual arm at v2 stays v2 and one at v1 never downgrades an automatic v2 (so a tenant's panic-button arm is no way around an operator's v2 pin). A tenant MAY pin its own vhost to v1 against the node default — no escalation: the same token can already exclude its vhost from challenges altogether (`challenge/exclude/*`); an operator who wants a tenant held at v2 sets a v2 pin, which the tenant cannot touch (`vhost` / `vhost/status` add `rung_pin_locked=true` for a scoped caller looking at an operator's pin); the response's `tier` is the effective result. Scoped tokens may pin their own vhosts (challenge-tier trust model, like `vhost/rung`) but every scoped pin is TTL-capped at `scopedMaxChallengeTTL` (24h, `ttl_capped=true`) — never a permanent tier; clearing on a `www.` host acts on the apex pin covering it, and the scope check covers THAT host too (`403` otherwise); and a pin the OPERATOR set (actor ≠ `scoped`) covering the host is not the tenant's to replace, clear or shadow with its own `www.` pin (`403`). Audited as `challenge_vhost_tier_pin` (`from`/`rung`/`actor`; a no-op writes nothing). GET lists the live pins and is admin-only (`RequireAdmin`: it spans tenants). The `vhost`, `vhosts` and `vhost/status` reads carry the host's EFFECTIVE tier — `rung` plus `rung_source` (manual|pin|auto), `rung_trigger`, `rung_pin`, `rung_auto` (the tier the automatic side gives on its own, even under a manual v2 arm) — from `challengeV2VhostTier`, the verify gate's own resolver (additive, no scope change); the webdet controls rows carry it as `challenge_rung*`. `vhost/rung` (2026-09-23) switches the tier of the ACTIVE manual challenge covering the host between v1 and v2 in place — expiry and reason kept, never creates or extends an arm (`409` when none is active), audited as `challenge_vhost_manual_rung` with `from`/`rung`/`actor` (a switch to the current tier is a no-op: `changed=false`, no audit row); same challenge-tier trust model as `vhost/add`, so a scoped token may re-tier its own vhost's arm. The arm changed is the one the verify gate reads (`manualRungTarget`: the host's own arm, else the apex's for a `www.` host), and the scope check covers THAT host too — a token holding only `www.example.com` gets `403` rather than re-tiering an `example.com` arm. `vhost/add` without `rung` (2026-11-14): the tier of the manual arm COVERING the host (`manualRungTarget`'s resolution: its own, else the apex's for a `www.` host — a `www.` arm never shadows its apex's tier), else the node default (`CHALLENGE_V2_MANUAL`, v2; a wildcard host v1 with `rung_note`), answered `rung_default=true` — one resolver, `tierlessArmRung`, the same for scoped and admin callers (challenge-tier only, no scope change); `vhost/status` adds `manual_default_rung`, that resolver's answer for the host now (what the pickers' Default would get). `vhost/add`: a SCOPED caller's TTL is clamped to `scopedMaxChallengeTTL` (24h) with `ttl_capped=true` in the response — the customer panic button is a temporary shield, not standing config; admin/loopback uncapped (slice D, 2026-09-22). `vhost/attack` is the Under-Attack operator override (`?host=&on=1|0[&ttl=]` → `ForceVhostAttackAs`, `under_attack_overrides.go`): a scoped token may force its own vhost into/out of UNDER_ATTACK (same trust model as manual challenge add/remove). Since 2026-11-17:
  - every `on=1` holds for a TTL: the call's `ttl`, else `UNDER_ATTACK_OVERRIDE_TTL` (6h). A SCOPED caller is capped at the panic-button arm's 24h ceiling (`ttl_capped=true`).
  - `on=1` arms a manual vhost challenge on the same host for the same window when no manual challenge covers it (reason `under_attack`; the response's `challenge_armed`, and `rung`, the arm's tier: the vhost's tier pin (whoever set it) decides it at arm time, else the tier-less default; a pin set later does not re-tier the arm — `vhost/rung` does). A scoped caller may do that already through `vhost/add`, on its own vhost, so this is no new capability.
  - When a manual challenge not armed by an earlier `on=1` covers the host (any caller's, the apex's included), it is left as it is and the override is cut to its expiry (`ttl_clipped=true`); the response carries `challenge_expires_at` and the effective verify tier (`tier`, as `vhost/add`). A refresh keeps its own arm's tier. `400` for a wildcard host; `409` for `on=1` on a `CHALLENGE_HOST_BYPASS` (cfm.allow) vhost.
  - The override is persisted (`webdetector_attack_overrides.json`) and restored after a reload; its ON alert is re-sent by the new Engine only if the old one never sent it (`announced`).
  - `on=0` removes only the challenge its `on=1` armed: the record names the arm's expiry, so an operator's own arm with reason `under_attack` is neither refreshed nor removed.
  - One store per state file is shared across Engine rebuilds, so an `on`/`off` sent during a reload reaches the file (the next reload restores it) instead of being overwritten; the new Engine's tracker and arm do not see it until then (the manual challenges have the same window).

  The response carries `ttl`, `expires_at`, `challenge_armed` and (armed) `rung`. Expiry returns the vhost to AUTO control, audited via `challenge_vhost_attack_override` (`payload.ttl_sec`, `payload.challenge_armed`). Returns `409` when `UNDER_ATTACK` is disabled. The read rows (`vhost`, `vhosts`, drilldown) carry an additive `state` (normal|suspicious|challenged|under_attack), stamped by the single `deriveVhostState` helper — no scope change.
- `/api/v1/challenge/exclude/list|add|remove`, `/api/v1/waf/exclude/list|add|remove` (`exclude_api_handlers.go`: challenge list `:182`, add `:375`, remove `:401`; WAF list `:427`, add `:444`, remove `:475`). Writes go through `validateScopedExcludeWrite` (`:82`): the unscoped-write role is the EXPLICIT admin role (`IsAdminRequest`), not a nil vhost scope — a non-admin caller with an empty/nil scope is denied (fail-closed), so a vhost-less DB-only scoped token cannot write global/out-of-scope excludes. Scoped tokens are otherwise limited to `type=host` within their vhost allowlist (`scopedExcludeHostAllowed`: an exact match, or an exact host under a wildcard the scope holds). WAF add/remove also accept an admin-only `scope_hosts` qualifier via `effectiveExcludeScope` — likewise gated on `IsAdminRequest`: it can only *narrow* an admin-global entry to specific vhosts, and a scoped caller's effective scope is always pinned to its own context vhost set, so the param can never widen or redirect a scoped write. A scoped write stores the token's vhost set as the entry's `scope_hosts`; at match time a LITERAL scope host also takes its `www.` alias, for challenge host excludes (`MatchChallenge`, since 2026-11-25) as for WAF and challenge path excludes (one test, `scopeTakes`: cPanel lists a domain without its `www.` name, so a tenant's token cannot name it). The alias is `www.` + a host the scope names literally, never a glob scope host and never a sibling, so it reaches only the www. name of a site the scope already names (cPanel makes it that site's alias); the value still has to match too. **Challenge PATH excludes** (`type=path` on `/api/v1/challenge/exclude/add|remove`, since 2026-11-20; `challengePathExcludeWrite` / `challengePathExcludeScope`) are the one exception to "scoped = host only": they carve a path out of the log-driven malpath checks (CHALLENGE_PATHS + the MALPATH ban) on named hosts only, so the entry ALWAYS carries `scope_hosts`, and a literal scope host also covers its `www.` alias at match time (`MatchChallengePath`; cPanel lists a domain without it, so a tenant could not name it). Value: the first path segment must be literal (`validChallengePathExcludeValue`: `/`, `/*`, `/*.php`, `/[!/]*` → `400`), and a request path with a dot segment, `//`, a backslash or an encoded dot/slash/backslash is never carved out (`plainExcludablePath`). Admin: `scope_hosts` is required to add (`400` without it); a glob scope host must be `*.<domain>` with a dot in the domain that is not a public suffix (`wideScopeHost`: `*`, `*.*`, `*-*`, `*.gr`, `*.com.gr` → `400`), and a value glob that does not compile is `400`; a remove takes the exact scope, and without `scope_hosts` targets an unscoped entry an older version stored (inert at match time). Scoped: an add is pinned to the token's LITERAL vhosts (globs dropped; `403` when none is left, e.g. a vhost-less or wildcard-only token), and `scope_hosts` may only NARROW them to vhosts the token holds literally (`403` otherwise; a glob is never a tenant's scope, another account may own a name under it). A scoped remove takes the caller's hosts (or the named subset) out of every entry on that path (`RemovePathHosts`) and deletes an entry left with none: an entry shared with another tenant keeps covering that tenant, and one a domain move left behind is removable by the domain's new owner (removing a carve-out only restores protection). The challenge list shows a scoped caller its in-scope host entries plus every path entry with at least one LITERAL host it holds, `scope_hosts` cut to those (`filterChallengePathExcludesForScope`; a glob scope host — only an admin writes one — is never listed to a tenant, so an admin `*.example.gr` entry covering a tenant's site is the admin's to manage). Trust decision: a tenant's path exclude also stops the MALPATH nft ban — a server-wide signal — from counting those hits, on its own vhosts only; the same IP's hits on every other vhost still count, the tenant could already exclude its vhosts from challenges, and the value / plain-path rules keep it to named files or folders (the elFinder / Duplicator cases need the ban carve-out: 20 thumbnails in 120 s ban the admin). **WAF writes by a scoped token** (since 2026-11-26; `scopedWAFExcludeAdd`, `waf_exclude_tenant.go`; rules and table in `docs/waf.md` "What a site owner may write") are narrower than "host excludes": (1) the WAF switch (`type=host`, no `rule_ids`) is stored with `keep_critical`, so the `WAF_CVE` / `WAF_WEBSHELL` families keep running on that vhost; (2) a rule exclude on a host needs exactly ONE rule id, not of those families (`403`), and a `ttl` of 1h to 7d (`400` without); (3) a WAF PATH exclude is allowed with the same one-rule + expiry rules, a literal path, and a scope pinned to the token's literal vhosts (`challengePathExcludeScope`; `scope_hosts` only narrows). A path exclude without a rule stays `403`. Scoped WAF list: its host entries plus the path entries a scoped token wrote (`by: "scoped"`, `filterTenantWAFPathExcludes`); an operator's path entry narrowed to the tenant's site is hidden and not removable by it (`RemoveTenantPathHosts` touches `by: "scoped"` entries only). Every scoped WAF write / remove is logged, written to history (`waf_exclude_change`) and published to the notifier (`SetTenantPolicySink` → `tenant_waf_exclude`). The operator's add gains an optional `ttl`.
  - **List reads** (`filterExcludeListForScope`, `:149`): a scoped caller sees only `type=host` entries whose value its scope covers (path entries are hidden, except the challenge list's path entries: below), and since 2026-11-18 each entry's `scope_hosts` is narrowed to the caller's own vhosts (`scopeHostsSeenBy`, `:133`; `nil` when none is left), so an entry another account wrote does not name that account's other domains.
  - **Remove** (`RemoveWithRuleIDs`, `exclude_store.go:167`) first looks for the exact `(type, value, scope_hosts, rule_ids)` entry. Since 2026-11-18, failing that, a `type=host` remove falls back to `removeHostAnyScopeLocked` (`exclude_store.go:200`): it removes the TENANT-written entries (non-empty `scope_hosts`) on exactly that host with the same rule-id set, whatever `scope_hosts` they were written with — for a scoped caller only when its scope holds that host itself (a wildcard alias that matches it is not enough). Entries the operator wrote (nil `scope_hosts`) are never removed this way, and path excludes need the exact match (a scoped challenge path remove is the exception: below). The same store backs `/api/v1/clam/override/*` and `/api/v1/clam/mode/*`, so their removes behave the same (there an operator host entry turns scanning on and stays the operator's).
- `/api/v1/challenge/access`, `/api/v1/challenge/access/get|add|update|remove|simulate` (`challenge_access_api_handlers.go`: list `:63`, get `:76`, add `:104`, update `:131`, remove `:177`, simulate `:209`; each also calls `RequireScopedOrAdmin`; `scopeAllowsVhosts` + `scopeFilterChallengeAccess`, `:38`, the same model as `/api/v1/webdet/rules/*`). The Challenge Access-Control allow-list: entries EXEMPT matching requests from the interactive challenge (challenge→allow only; never softens a per-IP block, never touches the WAF). Every write (add/update) requires that ALL vhosts in `scope.vhosts` — both the existing entry's and the target's — are inside the token's vhost allowlist (`scopeAllowsVhosts`, fail-closed for nil/`*`/wildcard values a scoped token does not literally hold), and so must every vhost of the existing entry for `remove`. Reads (since 2026-11-18): the list shows every entry with at least one vhost in the caller's scope, with `scope.vhosts` cut to the caller's own vhosts and `note` dropped when a vhost was cut (`scopeFilterChallengeAccess`); `access/get` answers any entry the list shows, exactly as the list shows it. `access/simulate` (POST, read-only) checks the body's `host` with `scopeAllowsVhosts` and trims the matched entry the same way (unlike rules simulate it keeps no bare `*`: a vhost the scope does not literally hold is cut). Unlike the host-only `/challenge/exclude/*`, a scoped token MAY use the richer match dimensions (path/ua/country/ip/asn/method/verified_bot) — but they are always pinned under an in-scope vhost, so an entry can never affect another tenant. Admin/loopback (nil scope) may scope entries to any vhost incl. `*`.
- `/api/v1/clam/override/list|add|remove` (`exclude_api_handlers.go` `:535`, `:548`, `:576`; `validateScopedExcludeWrite`, `type=host` only: per-vhost ClamAV upload-scan override; a scoped token can flip only its own vhost, list reads use `filterExcludeListForScope` (own hosts, `scope_hosts` narrowed). The override XORs the vhost against the global `CLAM_SCAN_DEFAULT`)
- `/api/v1/clam/sigignore/list|add|remove` (`clam_sigignore_api_handlers.go`: list `:65`, add `:87`, remove `:117`; `validateScopedSigIgnoreWrite`, `:53`: per-signature ClamAV excludes — log-only downgrade. The write validator keys on `IsAdminRequest` (any host, or a GLOBAL entry with `host` empty); anyone else needs a non-empty scope and an in-scope host, so GLOBAL entries are admin-only. The scoped list shows only entries for hosts in the caller's scope, never global ones, and since 2026-11-18 narrows each entry's `scope_hosts` to the caller's own vhosts. All writes and denied attempts audit-logged to `cfm.clam.log`)
- `/api/v1/clam/mode/list|add|remove` (`exclude_api_handlers.go` `:610`, `:623`, `:628`; `validateScopedExcludeWrite`, `type=host` only: per-vhost ClamAV scan-mode flip — XOR against the global `CLAM_SCAN_MODE`. A scoped token flips only its own vhost (inline blocks that vhost's own uploads — self-inflicted, same trust model as the scan toggle); list reads scope-filtered; writes + denied attempts audit-logged as `[clam_mode]`)
- `/api/v1/waf/engine/summary` (`handleWAFEngineSummary`, `waf_engine_api_handlers.go:92`; `RequireScopedOrAdmin` + `vhostAllowed` filter — scoped callers see only their own vhosts' WAF-engine stats; verified by `authz_integration_test.go`)
- `/api/v1/http3/list|enable|disable` (`http3_api_handlers.go`: list `:64`, enable `:82`, disable `:106`). Writes: `validateScopedHTTP3Write` (`:52`) keys on `IsAdminRequest` (any host); anyone else needs a non-empty scope and a host `scopedExcludeHostAllowed` accepts. The scoped list shows only opt-ins inside the caller's scope and, since 2026-11-18, narrows each entry's `scope_hosts` to the caller's own vhosts (`filterHTTP3ListForScope`, `:34`).
- `/api/v1/site-cache/list|get|set|remove|purge` (`site_cache_api_handlers.go`: list `:110`, get `:133`, set `:171`, remove `:215`, purge `:244`; `scopeAllowsVhosts` + `scopeFilterSiteCache` — per-vhost edge caching opt-in, host-keyed; see `site_cache_api_handlers.go`). A scoped token may set/get/remove/purge only hosts inside its vhost allowlist (fail-closed for a scoped token whose scope is empty; a nil scope is admin/loopback, unrestricted), and list reads are scope-filtered. A scoped `purge` needs an explicit in-scope `?host=` (400 without one). `set` is a MERGE (only the fields in the body change) and records the opt-in attribution from the token, never the body: a scoped creator is stored as `scope_hosts=[host]` — exactly the host, never the token's whole allowlist (older entries that carry a whole allowlist are trimmed to `[host]` on load and the file is rewritten). An entry with both tiers off is an opt-out that also overrides a broader armed `*.suffix` wildcard (for an exact host, or a narrower wildcard); `remove` deletes the entry, after which the host follows that wildcard. Scope matching is literal: a token whose scope holds `*.example.com` itself (a cPanel wildcard subdomain) manages that pattern's policy, even an admin-created one. `list` also returns `unloadable` — the hosts of stored rows this build cannot load — filtered with `vhostAllowed` like the rows — and `switches`, the node's `SITE_CACHE` / `MICRO_CACHE_ENFORCE` as last written to the edge, UNFILTERED: node-wide settings, not another tenant's data, and a scoped page needs them to tell a dry-run micro tier from a live one. Every authenticated write naming a host — including those refused for scope, admin-only purge-all or validation (not a body that fails before naming a host) — is audit-logged to `cfm.log` as `[site_cache] … actor=admin|scoped:<vhosts>`. **`purge?all=1` is admin-only** (`RequireAdmin`): a global purge spans every tenant. Enabling a tier records INTENT only — the never-cache rails live at the edge and are not disableable here (see `docs/site-cache-design.md` §4).
- `/api/v1/site-cache/stats[?host=]` (`handleSiteCacheStats`, `site_cache_stats.go:299`): per-vhost edge cache counters. `?host=` outside the token allowlist is `403`; an in-scope `?host=` resolves only to a policy key inside the caller's scope (`SiteCacheStatsHost` — a scoped tenant drilling into its own `a.example.com` never gets an admin `*.example.com` row, which aggregates every sub-host under the pattern, other tenants' included); the unfiltered list is filtered with `vhostAllowed`, so a scoped caller sees only rows whose key its scope literally holds (a `*.example.com` row only if the scope holds `*.example.com`). An in-scope `?host=` that resolves to nothing (unarmed, an opt-out, or only an out-of-scope key) returns `200` with `rows: null`, not `403`. Backs the MCP `site_cache_stats` tool (`list` backs `site_cache_status`).
- `/api/v1/waf/hit-rates` (`handleWAFHitRates`, `waf_hit_rates_api_handler.go:69`; keyed on `IsAdminRequest`: a non-admin caller must target one host inside a non-empty scope — an empty host, which aggregates every tenant, an empty/nil scope and any out-of-scope host are `403`; admin/loopback may pass any host or none. Audit F02.)
- `/api/v1/waf/rules` (`handleWAFRules`, `waf_rules_api_handler.go:18`; `RequireScopedOrAdmin`, GET only): the static WAF rule registry (ids, names, groups, reason families, default modes) — no tenant data, so any identity may read it.

### Admin-only (in-handler `RequireAdmin` unless noted)

- `/api/v1/webdet/summary` (`handleWebdetSummary`, `http_api.go:210`)
- `/api/v1/webdet/ingest-source` (`handleIngestSource`, `http_api.go:222`): the log-ingest arbiter's state (socket vs file tailer); node-wide.
- `/api/v1/webdet/hot-ips` (`http_api.go:419`), `/api/v1/webdet/ip-short` (`:285`), `/api/v1/webdet/ip-drilldown` (`:434`), `/api/v1/webdet/analyze-ip` (`:448`): per-IP views span every vhost.
- `/api/v1/webdet/access-recent` (`handleAccessRecent`, `access_api.go:19`): the recent edge access-log ring across ALL vhosts, filterable by ip/host/method/status/path/since. Backs the MCP `edge_access_tail` tool.
- `/api/v1/webdet/auth-corpus` (`handleAuthCorpus`, `auth_corpus.go:680`, since 2026-11-04): the login-outcome corpus, login POST shapes with example hosts of every tenant. Node-wide, so admin-only. Backs the MCP `auth_corpus` tool.
- `/api/v1/webdet/history/stats|prune|truncate` (`history_api_handlers.go:514`, `:466`, `:490`)
- `/api/v1/webdet/force-unblock-ip` (`force_unblock_handler.go:27`; `cfm unblock`'s path into the daemon: clears the per-IP WAF planes and the edge ban) and `/api/v1/webdet/edge-ban` (`edge_ban_handler.go:24`, since 2026-10-10: POST — `cfm block` records a manual ban in the edge ban store, `internal/edgeban`, so the edge also blocks the client behind a trusted proxy; GET — the edge copy's status, mode and would-block / blocked counts, and since 2026-11-17 `proxied_ipfilter`: the proxied-client IP filter's modes, counts and source sizes, `internal/proxyipfilter`)
- `/api/v1/webdet/ua-top`, `/api/v1/webdet/ua-drill`, `/api/v1/webdet/ua-emergency` (`ua_api_handlers.go:35`, `:58`, `:76`; global "Web Bots" UA controls; `ua-emergency` serves GET list and POST mutate)
- `POST /api/v1/challenge/ip/add`, `POST /api/v1/challenge/ip/remove` (`handleChallengeIPAdd` / `handleChallengeIPRemove`, `challenge_ip_manual.go`, since 2026-11-24): the operator's per-IP challenge on a list of IPs (the Web Traffic page's "Challenge its IPs"), and lifting it. They act on any tenant's visitors, so admin-only. Never a ban; IGNORE_IPS and blocked IPs are skipped.
- `/api/v1/webdet/traffic-mix` (`handleTrafficMix`, `traffic_mix.go`, since 2026-11-24): the node's traffic mix (classes, top vhosts, top clients and their IPs) across every tenant. Node-wide, so admin-only, `?host=` and `merge_www` included (a scoped view would need its own filtered handler). Backs the MCP `traffic_mix` tool.
- `/api/v1/webdet/vhost-profile?host=` (`handleVhostProfile`, `vhost_profile.go`, since 2026-11-24): one host's posture for the cfm-admin Vhost page — its `/webdet/vhosts` controls row, its `/challenge/vhost/status` body, the WAF and challenge excludes that cover it, the Site Cache policy that decides it (exact or a covering `*.suffix`) with the node switches, every traffic rule whose scope takes it (with its state), and the known hosts of its registrable domain. It names operator policy whatever its scope (tier sources and pins, every exclude and rule, admin-written ones included), so admin-only; a scoped version would need its own filtered handler.
- `/api/v1/clam/health` (`clam_health_api.go:50`: box-level ClamAV scanner status — clamd reachability, circuit breaker, queue geometry, lifetime counters, 24h infection count (persisted), global scan default. Not per-vhost, so admin-only. Per-vhost scan coverage on the ClamAV page comes from the scoped `/api/v1/webdet/vhosts` instead.)
- `/api/v1/challenge/summary|vhosts|ips|ip` (`challenge_api_handlers.go:12`, `:96`, `:201`, `:222`)
- `GET /api/v1/challenge/vhost/tier` (the pin list, `challenge_manual_handlers.go:558`; it spans tenants — POST is scoped-allowed, above)
- `/api/v1/site-cache/purge?all=1` (`RequireAdmin` inside `handleSiteCachePurge`, `site_cache_api_handlers.go:257`: a global purge spans every tenant; a scoped attempt is `403` and audit-logged as denied — see the scoped `/api/v1/site-cache/*` entry above)

### Self-authenticating

- `/api/v1/cpanel/user-info` (`handleCpanelUserInfo`, `cpanel_api_handlers.go:46`), the only engine route without `requireIdentity`. Authenticated by an actor assertion in `X-CFM-Actor-Assertion` only (`authorizePluginAssertion`: HMAC with the plugin assertion key, expiry, single-use nonce); admin and scoped tokens cannot use it, and a bearer-only request gets `401`. `?user=` must equal the assertion's subject (`403 actor mismatch`). Failures are counted per IP and per (IP, user) and briefly denied (`429`). The cPanel plugin calls it server-side over loopback to learn the account's domains (see "What a cPanel scoped token's vhost set holds") and DB users, then mints the scoped token. A `debug` reason is added to an error body only for a direct loopback call with `X-CFM-Debug: 1` and no `X-Real-IP` / `X-Forwarded-For` (`cfmDebugEnabledForRequest`, `:430`; since 2026-11-18): a request relayed by the edge never gets it.

## apiserver routes (`internal/apiserver/`)

Registered in `Start` (`apiserver.go:138`) and the `Register*` functions it
calls; handler files are under `internal/apiserver/` unless noted.

### Scoped-allowed

- `/api/v1/mysql/user-summary|user-kills|user-history` via `scopedMySQLFilterHandler` (`apiserver.go:726`; routes `mysqlScopedRoutes`, `:676`, mounted by `registerMySQLGovernorRoutes`, `:641`, only when the governor lifecycle exists; handlers in `internal/detectors/mysql/governor_api.go`). Explicit `?user=` / `?db=` must be inside the scope, else the filter is derived from the token's DB scope or its vhosts' cPanel owners; only `IsAdminRequest` runs unfiltered. A scoped caller's `user-summary` lock graph holds only its own blocker and its own waiters, each waiter filtered on its own user/db (`filterGovernorState`; since 2026-11-18: the graph groups waiters by database name alone, so a blocker's group can hold other accounts' connections).
- `/api/v1/mysql/user-kill` (POST) via `scopedMySQLFilterHandler` — kills one connection/query; `handleUserKill` (`internal/detectors/mysql/governor_api.go:438`) enforces the target `(user, db)` is within scope (`userDBMatch`); admin (no filter) may target any pid.
- `/api/v1/tokens/me` (`token_api.go:62`, `RequireScopedOrAdmin`, GET): self descriptor only. Admin (any admin mechanism) gets a synthetic `{role: admin, vhosts: null}`; a scoped caller gets its own token's metadata (id, label, role, vhosts, DB scope, expiry; never the token value), looked up from the header token or the embed cookie's token id. `no-store`.
- `/api/v1/mail/dns` (`handleMailDNS`, `system_status_endpoint.go:1212`) — DNS mail-auth check (SPF/DMARC/DKIM/PTR/MX) for a `?domain=`. Scope from `mailTrafficScope` (`:1097`): admin may check any domain; a scoped caller must own the domain or a parent of it (`domainInScope` over the token's vhost set), else `403`. Records are public DNS, but the scope gate stops using the box as a general DNS-probe proxy. Sender IPs come from `selfip` (public only), not the caller.
- `/api/v1/mail/traffic` (`handleMailTraffic`, `system_status_endpoint.go:1131`; `mailTrafficScope` → `mailtraffic.TrafficSummary`) — the Mail page's counters (Outbound / Inbound tabs). Admin (nil scope) sees the whole server; a scoped caller is filtered to its own mail domains (`domain IN (allowlist)`), following the `nil=admin / non-nil=scoped / empty=owns-nothing` convention. Host-wide (`*`) and local-unix-user rows key to domain `*`, which is never in a vhost allowlist, so they are admin-only by construction (`totals.rejected`/`top_local_submitters` are empty for scoped); the scope helper also defensively drops `*` from a scoped allowlist. Ignores `?vhosts=` (scope comes only from the token). The `deliverability` block (per-provider delivered/deferred/bounced + top reasons) is **admin-only** — it is populated only when scope is nil, since remote-delivery lines are host-wide and not attributable to a tenant. The mail-abuse findings (`abuse`, `abuse_checked_at`) are likewise added only for an admin caller. Sibling mail reads `/api/v1/system/mail-queue` and `/api/v1/system/mail-log` remain `RequireAdmin`.

### Admin-only

- `/api/v1/mysql/state|processlist|top|locks|kills|history|history/events|history/summary|history/prune|history/truncate|history/timeline|cpu` via `adminOnlyHandler` (`mysqlAdminRoutes`, `apiserver.go:661`).
- `/api/v1/auth/token` (POST, issue a scoped token; `token_store.go:402`, `RequireAdmin`), `/api/v1/tokens/list` (GET, `token_api.go:25`, `RequireAdmin`), `/api/v1/tokens/revoke` (POST, `token_api.go:38`, `RequireAdmin`).
- `/api/v1/embed/admin-code` (GET, `embed_admin_bootstrap.go:131`): not a public path, and the handler also requires the admin role in the context, so a scoped token or scoped embed cookie cannot mint an admin SSO code. Mints the one-time code `/api/v1/embed/admin-bootstrap` redeems; rate-limited; `no-store`.
- `/api/v1/firewall/block` via `adminOnlyHandler` (`block_endpoint.go:55`, handler `:59`; global IP block).
- `/api/v1/firewall/block/batch` via `adminOnlyHandler` (`block_endpoint.go:56`, handler `:130`) (bulk global IP block, ≤256 IPs/request; skips the server's own IPs and the calling admin's IP with per-IP `skipped` reasons).
- `/api/v1/firewall/list` via `adminOnlyHandler` (`firewall_list_endpoint.go:36`, handler `:39`) — read-only dump of the manual/global block list with TTL + GeoIP; a node-wide list is meaningless to a scoped token.
- `/api/v1/firewall/counters` via `adminOnlyHandler` (`firewall_counters_endpoint.go:62`, handler `:65`) — read-only nft named-counter view (per-rule match volume: portflood/connlimit/synflood/ppsflood/hardening/smtpblock), parsed from `ListTableJSON`; node-wide firewall internals.
- `/api/v1/firewall/selftest` via `adminOnlyHandler` (`firewall_selftest_endpoint.go:28`, handler `:31`) — read-only nftlib backend self-diagnostics (EnsureBase timing split, per-set feed writes, `netlink` call counts/timeouts/slow calls), plus `host_probe` on both engines (block/allow batches planned from per-address kernel gets vs whole-set reads, last failed probe); node-wide firewall internals.
- `/api/v1/firewall/feeds` via `adminOnlyHandler` (`firewall_feeds_endpoint.go:26`, handler `:29`) — read-only `cfm.blocklists` feed state (last fetch/OK/apply, HTTP status, error, counts, `api_origin`/`token_sent`; URL query redacted, token never returned); node-wide firewall internals.
- `/api/v1/firewall/path` via `adminOnlyHandler` (`netfilter_path_endpoint.go:32`, handler `:35`) — read-only host-wide nftables base-chain order and NAT/redirect rules across CFM, Imunify/WebShield, iptables-nft, and other tables. Uses terse ruleset JSON so blocklist set elements are never returned; still exposes node-wide topology and is therefore admin-only.
- `/unblock` (POST) via `adminOnlyHandler` (`unblock_endpoint.go:48`, handler `:53`) — removes the IP from every blocking plane (nft, cfm.deny, fail2ban, imunify360's drop/captcha/splashscreen lists, OpenResty/Lua WAF), allows it in nft for 24h when a feed lists it (never shortening an allow already there) and gives it a 1h imunify360 white grace entry (not when an operator's white entry for the IP, or for its IPv6 /64, is already there, nor for an IPv6 IP whose /64 imunify wasn't blocking — imunify takes IPv6 only as a /64); host-wide state change with no per-vhost meaning. Consumers are admin-token callers (cfm-web fleet controller, `cfm` CLI).
- `/search` (GET) via `adminOnlyHandler` (`search_endpoint.go:36`, handler `:39`) — read-only multi-source locate (nft/cfm.deny/fail2ban/imunify) that enumerates where an arbitrary IP is blocked host-wide; cross-tenant data with no per-vhost scoping.
- `/debug/pprof/` and the named profilers `/debug/pprof/{cmdline,profile,symbol,trace}` via `adminOnlyHandler` (`apiserver_debug.go:41-45`, `registerPprofHandlers`) — Go runtime profiling (heap/goroutine/allocs/block/mutex dumps, CPU profile, execution trace, daemon command line). Host-global process introspection with no per-vhost meaning, so admin-only. `/debug/pprof/` (`pprof.Index`) fans out to all sub-profiles, so the single gate covers heap/goroutine/allocs/… too, and the `/cfm-admin/debug/pprof/` prefix re-dispatches onto the same mux and inherits it. `PprofWriteTimeoutMiddleware` (write-deadline relaxation for CPU/trace) runs outside the gate. `/debug/pprof` is also excluded from the iframe shell exemption. Audit finding R02.
- `/api/v1/admin/authcheck` (`token_api.go:130`; admin-only auth probe for the edge `auth_request`; GET, `RequireAdmin` → 200 for admin, 403 for scoped/anonymous; returns no data, `no-store`).
- `/api/v1/system/dnat` (`:1337`), `/api/v1/system/ssl/stats` (`:1357`), `/api/v1/system/ssl/refresh` (POST, `:1410`) — `RequireAdmin` — and `/api/v1/health/{snapshot,timeseries,anomalies,ingest}` (`:1433`, `:1450`, `:1541`, `:1567`) — `requireHealthAccess` (`:266`, admin only) — all in `system_status_endpoint.go`, registered by `RegisterSystemStatus` (`:212`, routes `:234-263`); back the dashboard's system/Node-health cards and the "Rescan certs" button.
- `/api/v1/system/processes` (`:281`), `/api/v1/system/listeners` (`:344`), `/api/v1/system/dmesg` (`:372`), `/api/v1/system/services` (`:412`), `/api/v1/system/ip-forensics` (`:452`), `/api/v1/system/mysql-log` (`:874`), `/api/v1/system/mail-log` (`:1018`), `/api/v1/system/mail-queue` (`:1064`) — all `RequireAdmin` in `system_status_endpoint.go`: process table, listening sockets, kernel log, service states, the per-IP log forensics scan, and the bounded tails of the MySQL and mail logs and the mail queue. Host-wide, so admin-only by construction. Back the matching MCP tools.
- `/api/v1/system/edge-health` (`handleSystemEdgeHealth`, `edge_health_endpoint.go:193`) — `RequireAdmin`; the edge health checks (`docs/edge-health.md`). Node-wide.
- `/api/v1/system/process-health` (`handleSystemProcessHealth`, `process_health_endpoint.go:28`; registered through `Register` from an `init`, `:17-23`) — `RequireAdmin`, GET; the single-scan `/proc` health summary.
- `/api/v1/dnat/state` via `adminOnlyHandler` (`dnat_state_endpoint.go:28`, handler `:31`) — the daemon's in-memory DNAT transition/probe state, read by `cfm dnat status` (the CLI is a separate process).
- `/api/v1/debug/live`, `/api/v1/debug/capture` (start), `/api/v1/debug/capture/<id>` (status), `/api/v1/debug/export` via `adminOnlyHandler` (`debug_api.go:26-29`; handlers `:38`, `:52`, `:79`, `:98`) — live telemetry snapshot and the debug-capture runbook's capture/export (`docs/debug-capture-runbook.md`).
- `/api/v1/notifier/config|reload|test|metrics|status|history|history/truncate|validate|preview|backups|backups/diff|backups/restore` via `adminOnlyHandler` (`notifier_api.go:19-52`, `RegisterNotifierEndpoints` `:14`) — notifier configuration, delivery metrics and history; node-wide.
- `/api/v1/detectors/config|validate|preview|reload|backups|backups/diff|backups/restore|test|live|status|catalog` via `adminOnlyHandler` (`detectors_api.go:77-108`, `RegisterDetectorsEndpoints` `:51`) — `detectors.conf` editing, validation, backups, live state and catalog; node-wide.
- `/api/v1/system/edge-error-log` (`system_status_endpoint.go:519`, `handleSystemEdgeErrorLog` → `edgelog.TailError`) — `RequireAdmin`; bounded on-demand tail of the edge (OpenResty/Angie) ERROR log with optional grep. Host-wide (all vhosts share one error log), so admin-only by construction. Backs the MCP `edge_error_tail` tool. Same admin-only, allow-listed-path, bounded-tail family as the sibling on-demand log reads `/api/v1/system/ip-forensics`, `/api/v1/system/mysql-log`, and `/api/v1/system/mail-log`.
- `/api/v1/system/lve-cpu` (`system_status_endpoint.go:792`, `handleSystemLVECPU` → `lvecpu.Latest`) — `RequireAdmin`; per-tenant CPU pressure ranking on CloudLinux (every LVE's cores + %-of-limit from the in-memory `/proc/lve/list` sampler). Host-wide (all tenants across all resellers), so admin-only by construction. Backs the MCP `lve_cpu` tool. `available:false` off CloudLinux.
- `/api/v1/system/waf-fp-hunt` (`system_status_endpoint.go:571`, `handleSystemWAFFPHunt` → `edgelog.ScanError` + `panelfp.Summarize`) — `RequireAdmin`; scans the edge ERROR log for the panel LOGONLY markers (`[cfm_panel_waf]` / `[cfm_panel_decision]`) and returns node-wide aggregates (scanner-vs-non-scanner split, per-rule/verdict breakdowns, candidate FPs). Host-wide (one error log across all panel vhosts) and an enforcement-readiness view, so admin-only by construction. Backs the MCP `waf_fp_hunt` tool. Same admin-only, allow-listed-path, bounded-tail family as `/api/v1/system/edge-error-log`.
- `/api/v1/system/abuse-shadow` (`system_status_endpoint.go:636`, `handleSystemAbuseShadow` → `abuseshadow.ScanTail` + `abuseshadow.Summarize`) — `RequireAdmin`; tails the node-wide LOG-ONLY abuse-shadow log (`/var/log/cfm/cfm.abuse_shadow.log`, Signal C rate-outlier burn-in) and returns aggregates (would_challenge vs exempt_goodbot counts, top would-challenge (host,ip) outliers, datacenter-provider + verified-good-bot splits). Host-wide (one shadow log per node) enforcement-readiness view → admin-only by construction. Backs the MCP `abuse_shadow` tool. Same admin-only, bounded-tail family as `waf-fp-hunt`.
- `/api/v1/system/lsm-detections` (`system_status_endpoint.go:691`, `handleSystemLSMDetections` → `cfmlog.TailFile(which=lsm)` + `lsmdetect.Summarize`) — `RequireAdmin`; aggregates the node-wide cfm-lsm DETECT lines (per-policy counts + rate-cap suppression roll-up, top repeat offenders by policy×comm×exe). Kernel-level events carry no vhost notion, so admin-only by construction. Backs the MCP `lsm_detections` tool. Same admin-only, allow-listed-path, bounded-tail family as `/api/v1/system/cfm-log`.
- `/api/v1/health/backup` (`health_backup_endpoint.go:36`, `handleHealthBackup` → `health.LastBackupStatus()`) — `requireHealthAccess` (admin); the node's latest backup check (jobs, last success, findings). Host-wide backup state → admin-only. Backs the MCP `backup_status` tool and cfm-web's fleet Backups poll.
- `/api/v1/alerts`, `/api/v1/alerts/summary`, `/api/v1/alerts/overview`, `/api/v1/alerts/stats` (`alerts_api.go:32-35`, handlers `:51`, `:80`, `:107`, `:129`; `adminOnlyHandler`) — the node's alert store (`internal/alerts`, docs/alerts.md): every event raised for the notifier, for every tenant (client IPs, vhosts, MySQL users, sample log lines) → admin-only. Back the cfm-admin Alerts page and the MCP `alerts` / `alerts_summary` tools.
- `/api/v1/system/lsm-status` (`system_status_endpoint.go:736`, `handleSystemLSMStatus` → `lsm.RunStatus(JSON)` + `Conf` allow-list accessors) — `RequireAdmin`; the `cfm lsm status --json` wire format (preflight, enabled, pinned BPF state, per-policy mode/runtime) augmented with `effective_allows` (merged allow_exe/allow_comm/allow_path per policy). Host-wide kernel/daemon state → admin-only by construction. Backs the MCP `lsm_status` tool.
- `/api/v1/system/config-drift` (`config_drift_endpoint.go:64`, `handleSystemConfigDrift` → `detectors.ReadSectionsFile` + `configdrift`) — `RequireAdmin`; stock (`/usr/share/cfm/configs/`) vs live (`/etc/cfm/`) config comparison (missing sections/keys = shipped features the live conffile never received). Host-wide config state → admin-only by construction. Backs the MCP `config_drift` tool.
- `/api/v1/detectors/coverage` (`detector_coverage_endpoint.go:55`, `handleDetectorsCoverage` → `meta.Catalog()` + `detectorstatus.GetSnapshot()` + `svcstat.Status` over a curated type→units affinity table; registered `detectors_api.go:110`) — admin-gated like its sibling `/api/v1/detectors/*` endpoints via `adminOnlyHandler`; daemon-vs-detector coverage matrix with host-reality verdicts. Backs the MCP `detector_coverage` tool.
- `/api/v1/detectors/source-resolution` (`detectors_api.go:56`, injected `detectorSourceReport` → `detectors.SourceReport` planners, GET-only) — admin-gated via `adminOnlyHandler` like its sibling `/api/v1/detectors/*` endpoints; dry-run source resolution per section (journald unit / file / docker container + reason, provisional/self-disable verdicts) using the SAME planners the registers wire with — probes run (journalctl/systemctl/docker/stat), nothing starts or changes. Host-wide source/probe surface → admin-only by construction. Backs `cfm detectors-srcresolve` (alias `detectors-resolve`), the cfm-admin "Source resolution" card, and the MCP `detectors_srcresolve` tool.
- `/api/v1/system/cpu-throttle` (`system_status_endpoint.go:850`, `handleSystemCPUThrottle` → `cputhrottle.ReadAndClassify`) — `RequireAdmin`; classifies whether high CPU load is thermal throttling / a frequency cap / genuine demand / idle / no-cpufreq (VM), from the box-wide cpufreq/thermal/utilization signals. Host-wide (whole-CPU state, not per-vhost), so admin-only by construction. Backs the MCP `cpu_throttle` tool.
- `/api/v1/system/cfm-log` (`system_status_endpoint.go:919`, `handleSystemCFMLog` → `cfmlog.TailFile`) — `RequireAdmin`; bounded on-demand tail of one of CFM's own `/var/log/cfm/*` logs (curated `which` allow-list; caller never supplies a path). `which=api` reads the canonical `cfm.api.log` auth/control-plane audit trail (current and legacy paths). Host-wide daemon/subsystem logs, so admin-only by construction. Backs the MCP `cfm_log_tail` tool. Same admin-only, allow-listed, bounded-tail family as `/api/v1/system/mysql-log` and `/api/v1/system/mail-log`.
- `/api/v1/system/journal` (`system_status_endpoint.go:970`, `handleSystemJournal` → `cfmlog.TailJournal`) — `RequireAdmin`; bounded `journalctl -n` tail of an **allow-listed** systemd unit (cfm + hosting-stack units; an arbitrary unit is rejected 400, so the read surface can't reach any unit on the box). Host-wide unit journals, so admin-only by construction. Backs the MCP `journal_tail` tool.
- `/api/v1/mail/runtime` (`system_status_endpoint.go:1280`, `handleMailRuntime` → `mailruntime.Live` + `Discover{EximMaxima,SpamdMaxChildren}`) — `RequireAdmin`; SMTP/spamd runtime saturation snapshot (current inbound SMTP sessions vs `smtp_accept_max`, active spamd children vs `--max-children`, each as utilisation% + `ok`/`warn`/`critical`; `unknown` when a cap can't be resolved). Host-wide daemon capacity (whole-box SMTP listener + spamd pool, not per-vhost), so admin-only by construction. Backs the MCP `mail_runtime` tool.

### Self-service account security (goauth login session only)

Neither scoped-allowed nor admin-only: these accept **only a goauth cfm-admin
login session** (goauth `Require`). A bearer token (admin or scoped), the
admin SSO cookie and the scoped embed cookie alone get `401`; every caller
acts on its own account only.

- `/me/security/*` (`me_security_routes.go:88`, `registerMeSecurityRoutes`; the bare `/me/security` is `404`, `:92`) —
  goauth's `RegisterMeSecurityRoutes` (password, TOTP enroll start/confirm,
  MFA disable, recovery-code regenerate, passkey register start/finish,
  factors), registered on a mux of their own and mounted through
  `meSecurityHandler` (`me_security_mount.go:26`). Registered only when goauth
  is configured (`AUTH_DB_PATH`). The wrapper adds the
  server-made QR image to enrollment start, and refuses enrollment start
  (`409`) while `AUTH_MFA_LOGIN_VERIFY_ENABLED` is off. Changing a factor
  needs the password or an MFA proof from the last 10 minutes (goauth).
- `/api/v1/me/password` (POST; `me_security_routes.go:99`, `handleMePasswordChange` `:102`) — goauth `Require` (`authRequireAny`, `503` when goauth is not configured);
  current-password guesses limited by `passwordChangeLimiter` (the login
  limiter's rules, its own state); keeps the caller's session
  (`KeepSession`) and ends the user's others.
- Edge case: an *embedded* request (`X-CFM-Embedded` header) carrying both
  the scoped embed cookie and the admin's own goauth cookie (WHM "log in as
  user" in the same browser) is tagged scoped by `TokenMiddleware` (embedded
  requests never use the session), but these routes act as the goauth user,
  i.e. the admin's own account. A non-embedded request with both is tagged
  admin (session before scoped cookie). CSRF applies either way.

### Public / self-authenticating (apiserver)

- `/login` (GET page, POST credentials; `login.go:181`), `/login/verify`
  (`:258`, the MFA step; `404` while `AUTH_MFA_LOGIN_VERIFY_ENABLED` is off),
  `/login/webauthn/begin` (`:304`), `/login/webauthn/finish` (`:313`) —
  registered by `RegisterLoginRoutes` (`:173`); public paths. Login attempts
  are rate-limited per IP and account (`login_rate_limit.go`); at the edge
  `/cfm-admin/login*` additionally runs through `cfm.lua` with a forced
  challenge (`location ^~ /cfm-admin/login`, `configs/openresty.conf:1396`).
- `/logout` (`handleLogout`, `login.go:237`) — public path; ignores a
  `Sec-Fetch-Site: cross-site` request (see the pipeline), else destroys the
  goauth session and expires the admin SSO and scoped embed cookies.
- `/api/v1/embed/bootstrap` (GET, `embed_bootstrap.go:202`) — public path;
  redeems a single-use code (bound to its `next` path) minted by
  `/api/v1/embed/code`, sets the scoped embed cookie for that token and
  redirects to `next` (carrying a sanitized `cfmExpectedOrigin`).
  Rate-limited per IP and token. At the edge it has its own exact location
  (`location = /cfm-admin/api/v1/embed/bootstrap`, `configs/openresty.conf:1446`).
- `/api/v1/embed/code` (GET, `embed_bootstrap.go:168`) — NOT public: the
  middleware requires a credential, and the handler then looks the presented
  header token up in the scoped-token store, so only a **scoped bearer token**
  can mint a code (the admin token, cookies and sessions get `401`).
  Rate-limited.
- `/api/v1/embed/admin-bootstrap` (GET, `embed_admin_bootstrap.go:170`) —
  public path; rate-limited before the code is consumed; redeems a single-use
  code from `/api/v1/embed/admin-code` (admin-only, above), sets the admin SSO
  cookie (`Path=/cfm-admin/`) and redirects to `next`. `no-store`.
- `/` (`webUIHandler`, `scoped_page_redirect.go:92`; registered
  `apiserver.go:174`) — the embedded cfm-admin UI. Static assets are public;
  page HTML needs a credential (or the iframe shell exemption), and a scoped
  caller asking for an admin-only page is redirected (see the top notes).
- `/cfm-admin/` (`cfmAdminPrefixHandler`, `apiserver.go:685`; registered
  `:185`) — strips one `/cfm-admin` and re-dispatches on the same mux, so
  every route keeps its own class; a nested prefix is `404`.

### MCP server (`internal/mcpserver`, mounted by `registerMCPServer`, `internal/apiserver/mcp_wire.go:164`)

All on `mcpPublicPaths`, so `TokenMiddleware` lets them through and the MCP
package authenticates. Mounted only when `AUTH_TOKEN` is set, `MCP` is not
`off` and an MCP token (configured, or generated and persisted at
`/var/lib/cfm/mcp_token`) is at least 24 characters. Reached at the edge as
`/cfm-admin/mcp` and `/cfm-admin/.well-known/…` through the general
`/cfm-admin/` block.

- `/mcp` (`Handler.Register`, `internal/mcpserver/server.go:168`;
  `requireMCPBearer`, `:177`) — bearer required (`Authorization: Bearer`, the
  scheme in any case; the first header if several): the static `MCP_TOKEN`,
  the admin `AUTH_TOKEN` (for a fleet gateway that already holds it), or an
  unexpired, audience-bound OAuth access token this server minted; otherwise
  `401` with a `WWW-Authenticate` pointing at the protected-resource metadata.
  Scoped viewer tokens, the embed and SSO cookies, the session and the
  `X-CFM-Token` / `Token` headers are not accepted here. The admin token
  carries `ADMIN_TOKEN_IP_BINDING` as on `/api/v1` (`mcpStaticBearer`,
  `internal/apiserver/mcp_wire.go:61` → `refuseForeignAdminToken`, the one
  helper both doors call, since 2026-11-18): under `enforce` a
  foreign source gets `403` with an opaque body.
  The tools are read-only: each runs one allow-listed GET in-process with the
  admin token through `TokenMiddleware` (not CSRF/session), so it gets exactly
  the admin answer of the `/api/v1` route behind it. `MCP_TOKEN` and OAuth
  tokens are not valid on `/api/v1`.
- `/mcp/oauth/register` (dynamic client registration), `/mcp/oauth/authorize`
  (consent: the form must be submitted with `MCP_TOKEN`, throttled per source
  IP), `/mcp/oauth/token` (`internal/mcpserver/oauth.go:160-162`, handlers
  `:210`, `:267`, `:403`) — the OAuth flow itself; unauthenticated by design.
  Registration accepts only absolute `https` redirect URIs with a host and no
  userinfo, or `http` on `localhost` / `127.0.0.1` (`validRedirect`, `:608`; re-checked at authorize);
  PKCE `S256` is required; a code and its refresh tokens are single use and
  refused when the request names another `client_id` (`clientMatches`,
  `:527`; a request naming none is accepted).
- `/.well-known/oauth-protected-resource`,
  `/.well-known/oauth-authorization-server`,
  `/.well-known/openid-configuration` (`oauth.go:156-158`, handlers `:177`,
  `:190`) — public discovery documents; no protected data.

## Edge-served admin endpoints (OpenResty / Angie)

Present in **both** `configs/openresty.conf` and `configs/angie.conf` (two
server blocks each). Everything else under `/cfm-admin/` is proxied to the
daemon (`location ^~ /cfm-admin/`, `configs/openresty.conf:1420`, `:2937`;
`configs/angie.conf:1400`, `:2910`): one prefix rewritten away, `X-CFM-Base` /
`X-Forwarded-Prefix: /cfm-admin`, `Host $host`, and `X-Forwarded-Host
$cfm_admin_xfh` (the browser's Host, see CSRF above). `/cfm-admin` alone is a
`301` to `/cfm-admin/`; `/cfm-admin/cfm-admin/…` is `404`.

### Admin-only

- `/cfm-admin/lua-stats` (`configs/openresty.conf:1509`, `:3026`;
  `configs/angie.conf:1489`, `:2992`) — fleet-wide decision-cache / sslcache /
  WAF-exclude / WAF-rule-mode stats, rendered inside the edge (Go cannot read
  nginx shdicts). Its admin gate is delegated to Go: `auth_request
  /__cfm_admin_auth_check` → `/api/v1/admin/authcheck` (`RequireAdmin`: `200`
  for an admin, `403` for a scoped caller or anonymous). The gate must stay on
  that admin-only probe, never on the scoped-or-admin `/api/v1/tokens/me`.
  Audit F01.

### Loopback + token only

- `/cfm-admin/purge-ip` (`configs/openresty.conf:1541`, `:3058`;
  `configs/angie.conf:1521`, `:3024`) — deletes one IP's keys from the edge's
  shared dicts during a force unblock; called by the daemon
  (`NginxBridge.purgeShared`). `allow 127.0.0.1; allow ::1; deny all;` is a
  coarse first filter; the Lua module enforces the real peer is loopback
  (`check_loopback()` on `$realip_remote_addr`) AND the bridge token
  (`check_token()`), else `403`. No browser identity is accepted.
