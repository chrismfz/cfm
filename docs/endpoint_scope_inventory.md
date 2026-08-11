# Endpoint scope inventory (backend pass)

This inventory documents the effective authz classification enforced by the backend:

- **scoped-allowed**: endpoint is allowed for scoped tokens, but must apply vhost/user scoping (`parseVhostFilter`, `vhostAllowed`, `scopeCheckHost`, or `scopedMySQLFilterHandler` derived filters).
- **admin-only**: endpoint rejects scoped tokens with `403` via `IsAdminRequest`/admin wrappers.

**The `nil` scope sentinel means admin/loopback ONLY.** `vhostScopeFromContext`
normalizes a *scoped*-role request that carries no scope map (e.g. a DB-only
viewer token whose vhost set is nil) to a non-nil **empty** set, so every
`nil == no restriction` consumer above (`vhostAllowed`, `parseVhostFilter`, the
`*ForScope` list filters, and the `validateScoped*` write guards) fails closed
for it — a vhost-less scoped token matches no host and sees no rows, rather
than being mistaken for admin. Code that reads `CtxScopeKey{}` **directly**
(bypassing that helper — today only `deriveScopedMySQLOwners`) must keep its own
`len(scope)==0` guard.

## `internal/webdetector/http_api.go` + related handlers

### Scoped-allowed

- `/api/v1/webdet/top-short`, `/api/v1/webdet/top` (`parseVhostFilter`)
- `/api/v1/webdet/suspicious` (`parseVhostFilter`)
- `/api/v1/webdet/long-top` (`parseVhostFilter`)
- `/api/v1/webdet/drilldown` (`vhostAllowed` + `parseVhostFilter`)
- `/api/v1/webdet/analyze-host` (`vhostAllowed`)
- `/api/v1/webdet/vhosts` (`parseVhostFilterWithAliases` + `vhostAllowed`)
- `/api/v1/webdet/rules*` (scope helpers in `traffic_rules_api_handlers.go`)
- `/api/v1/webdet/history/events|summary|challenge-outcomes|waf-by-rule|vhost-overview` (`scopeCheckHost`)
- `/api/v1/challenge/vhost`, `/api/v1/challenge/events`, `/api/v1/challenge/vhost/add|remove|status` (`vhostAllowed` checks)
- `/api/v1/challenge/exclude/*`, `/api/v1/waf/exclude/*` (`validateScopedExcludeWrite`: the unscoped-write role is the EXPLICIT admin role (`IsAdminRequest`), not a nil vhost scope — a non-admin caller with an empty/nil scope is denied (fail-closed), so a vhost-less DB-only scoped token cannot write global/out-of-scope excludes. Scoped tokens are otherwise limited to `type=host` within their vhost allowlist; list reads are scope-filtered. WAF add/remove also accept an admin-only `scope_hosts` qualifier via `effectiveExcludeScope` — likewise gated on `IsAdminRequest`: it can only *narrow* an admin-global entry to specific vhosts, and a scoped caller's effective scope is always pinned to its own context vhost set, so the param can never widen or redirect a scoped write)
- `/api/v1/clam/override/list|add|remove` (`validateScopedExcludeWrite`, `type=host` only: per-vhost ClamAV upload-scan override; a scoped token can flip only its own vhost, list reads are scope-filtered. The override XORs the vhost against the global `CLAM_SCAN_DEFAULT`)
- `/api/v1/clam/sigignore/list|add|remove` (`validateScopedSigIgnoreWrite`: per-signature ClamAV excludes — log-only downgrade. GLOBAL entries (`host` empty) are admin-only; a scoped token may add/remove/see only entries for hosts in its vhost scope. All writes and denied attempts audit-logged to `cfm.clam.log`)
- `/api/v1/clam/mode/list|add|remove` (`validateScopedExcludeWrite`, `type=host` only: per-vhost ClamAV scan-mode flip — XOR against the global `CLAM_SCAN_MODE`. A scoped token flips only its own vhost (inline blocks that vhost's own uploads — self-inflicted, same trust model as the scan toggle); list reads scope-filtered; writes + denied attempts audit-logged as `[clam_mode]`)
- `/api/v1/waf/engine/summary` (`vhostAllowed` filter — scoped callers see only their own vhosts' WAF-engine stats; verified by `authz_integration_test.go`)
- `/api/v1/http3/enable|disable` (`validateScopedHTTP3Write` host-scope check)
- `/api/v1/waf/hit-rates` (`vhostAllowed` host-scope guard in `handleWAFHitRates`: a scoped caller must target one in-scope host — an empty host, which aggregates every tenant, and any out-of-scope host are `403`; admin/loopback may pass any host or none. Audit F02.)

### Admin-only

- `/api/v1/webdet/summary`
- `/api/v1/webdet/hot-ips`, `/api/v1/webdet/ip-short`, `/api/v1/webdet/ip-drilldown`, `/api/v1/webdet/analyze-ip`
- `/api/v1/webdet/history/stats|prune|truncate`
- `/api/v1/webdet/ua-top`, `/api/v1/webdet/ua-drill`, `/api/v1/webdet/ua-emergency` (global "Web Bots" UA controls — `RequireAdmin`)
- `/api/v1/clam/health` (`RequireAdmin`: box-level ClamAV scanner status — clamd reachability, circuit breaker, queue geometry, lifetime counters, 24h infection count (persisted), global scan default. Not per-vhost, so admin-only. Per-vhost scan coverage on the ClamAV page comes from the scoped `/api/v1/webdet/vhosts` instead.)
- `/api/v1/challenge/summary|vhosts|ips|ip`

## `internal/apiserver/apiserver.go` + token/mysql endpoints

### Scoped-allowed

- `/api/v1/mysql/user-summary|user-kills|user-history` via `scopedMySQLFilterHandler` (explicit `?user=` or derived scoped owners).
- `/api/v1/mysql/user-kill` (POST) via `scopedMySQLFilterHandler` — kills one connection/query; `handleUserKill` enforces the target `(user, db)` is within scope (`userDBMatch`); admin (no filter) may target any pid.
- `/api/v1/tokens/me` (self descriptor only; scoped callers only see their own token metadata).
- `/api/v1/mail/dns` (`system_status_endpoint.go`, `handleMailDNS`) — DNS mail-auth check (SPF/DMARC/DKIM/PTR/MX) for a `?domain=`. Admin (nil scope) may check any domain; a scoped caller must own the domain or a parent of it (`domainInScope` over the token's vhost set), else `403`. Records are public DNS, but the scope gate stops using the box as a general DNS-probe proxy. Sender IPs come from `selfip` (public only), not the caller.
- `/api/v1/mail/traffic` (`system_status_endpoint.go`, `mailTrafficScope` → `mailtraffic.TrafficSummary`) — Mail Monitor traffic view. Admin (nil scope) sees the whole server; a scoped caller is filtered to its own mail domains (`domain IN (allowlist)`), following the `nil=admin / non-nil=scoped / empty=owns-nothing` convention. Host-wide (`*`) and local-unix-user rows key to domain `*`, which is never in a vhost allowlist, so they are admin-only by construction (`totals.rejected`/`top_local_submitters` are empty for scoped); the scope helper also defensively drops `*` from a scoped allowlist. Ignores `?vhosts=` (scope comes only from the token). The `deliverability` block (per-provider delivered/deferred/bounced + top reasons) is **admin-only** — it is populated only when scope is nil, since remote-delivery lines are host-wide and not attributable to a tenant. Sibling mail reads `/api/v1/system/mail-queue` and `/api/v1/system/mail-log` remain `RequireAdmin`.

### Admin-only

- `/api/v1/mysql/state|processlist|top|locks|kills|history|history/events|history/summary|history/prune|history/truncate|history/timeline|cpu` via `adminOnlyHandler`.
- `/api/v1/auth/token` (issue token), `/api/v1/tokens/list`, `/api/v1/tokens/revoke`.
- `/api/v1/firewall/block` via `adminOnlyHandler` (global IP block).
- `/api/v1/firewall/block/batch` via `adminOnlyHandler` (bulk global IP block, ≤256 IPs/request; skips the server's own IPs and the calling admin's IP with per-IP `skipped` reasons).
- `/api/v1/firewall/list` via `adminOnlyHandler` (`firewall_list_endpoint.go`) — read-only dump of the manual/global block list with TTL + GeoIP; a node-wide list is meaningless to a scoped token.
- `/api/v1/firewall/selftest` via `adminOnlyHandler` (`firewall_selftest_endpoint.go`) — read-only nftlib backend self-diagnostics (EnsureBase timing split, per-set feed writes); node-wide firewall internals.
- `/unblock` (POST) via `adminOnlyHandler` (`unblock_endpoint.go`) — removes a global nft block AND lays down a 24h allow-whitelist across every plane (nft, cfm.deny, csf, fail2ban, imunify, OpenResty/Lua WAF); host-wide state change with no per-vhost meaning. Consumers are admin-token callers (cfm-web fleet controller, `cfm` CLI). Was previously ungated behind mux-wide `TokenMiddleware`, so any authenticated scoped token could unblock+whitelist any IP.
- `/search` (GET) via `adminOnlyHandler` (`search_endpoint.go`) — read-only multi-source locate (nft/cfm.deny/csf/fail2ban/imunify) that enumerates where an arbitrary IP is blocked host-wide; cross-tenant recon with no per-vhost scoping. Was previously ungated behind mux-wide `TokenMiddleware`.
- `/api/v1/admin/authcheck` (admin-only auth probe for the edge `auth_request`; `RequireAdmin` → 200 for admin, 403 for scoped/anonymous; returns no data).
- `/api/v1/system/dnat`, `/api/v1/system/ssl/stats`, `/api/v1/system/ssl/refresh` (POST) and `/api/v1/health/{snapshot,timeseries,anomalies,ingest}` — all `RequireAdmin` (`system_status_endpoint.go`); back the dashboard's system/Node-health cards and the "Rescan certs" button.

## Edge-served admin endpoints (OpenResty / Angie)

Rendered entirely inside the edge proxy (Go cannot read nginx shdicts), so their
admin gate is delegated to Go via `auth_request` → `/api/v1/admin/authcheck`
(`RequireAdmin`). Present in **both** `configs/openresty.conf` and
`configs/angie.conf` (two server blocks each).

### Admin-only

- `/cfm-admin/lua-stats` (fleet-wide decision-cache / sslcache / WAF-exclude /
  WAF-rule-mode stats). The `auth_request` gate previously pointed at
  `/api/v1/tokens/me`, which is scoped-OR-admin, so a scoped cPanel viewer passed
  it and received the whole fleet's WAF excludes + rule tiers — a scoped-vs-admin
  boundary break. Repointed to the admin-only `/api/v1/admin/authcheck`. Audit F01.

