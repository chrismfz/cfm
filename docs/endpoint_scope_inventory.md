# Endpoint scope inventory (backend pass)

This inventory documents the effective authz classification enforced by the backend:

- **scoped-allowed**: endpoint is allowed for scoped tokens, but must apply vhost/user scoping (`parseVhostFilter`, `vhostAllowed`, `scopeCheckHost`, or `scopedMySQLFilterHandler` derived filters).
- **admin-only**: endpoint rejects scoped tokens with `403` via `IsAdminRequest`/admin wrappers.

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
- `/api/v1/challenge/exclude/*`, `/api/v1/waf/exclude/*` (`validateScopedExcludeWrite`: scoped tokens limited to `type=host` within their vhost allowlist; list reads are scope-filtered)
- `/api/v1/waf/engine/summary` (`vhostAllowed` filter — scoped callers see only their own vhosts' WAF-engine stats; verified by `authz_integration_test.go`)
- `/api/v1/http3/enable|disable` (`validateScopedHTTP3Write` host-scope check)
- `/api/v1/waf/hit-rates` (`vhostAllowed` host-scope guard in `handleWAFHitRates`: a scoped caller must target one in-scope host — an empty host, which aggregates every tenant, and any out-of-scope host are `403`; admin/loopback may pass any host or none. Audit F02.)

### Admin-only

- `/api/v1/webdet/summary`
- `/api/v1/webdet/hot-ips`, `/api/v1/webdet/ip-short`, `/api/v1/webdet/ip-drilldown`, `/api/v1/webdet/analyze-ip`
- `/api/v1/webdet/history/stats|prune|truncate`
- `/api/v1/webdet/ua-top`, `/api/v1/webdet/ua-emergency` (global "Web Bots" UA controls — `RequireAdmin`)
- `/api/v1/challenge/summary|vhosts|ips|ip`

## `internal/apiserver/apiserver.go` + token/mysql endpoints

### Scoped-allowed

- `/api/v1/mysql/user-summary|user-kills|user-history` via `scopedMySQLFilterHandler` (explicit `?user=` or derived scoped owners).
- `/api/v1/mysql/user-kill` (POST) via `scopedMySQLFilterHandler` — kills one connection/query; `handleUserKill` enforces the target `(user, db)` is within scope (`userDBMatch`); admin (no filter) may target any pid.
- `/api/v1/tokens/me` (self descriptor only; scoped callers only see their own token metadata).

### Admin-only

- `/api/v1/mysql/state|processlist|top|locks|kills|history|history/events|history/summary|history/prune|history/truncate|history/timeline|cpu` via `adminOnlyHandler`.
- `/api/v1/auth/token` (issue token), `/api/v1/tokens/list`, `/api/v1/tokens/revoke`.
- `/api/v1/firewall/block` via `adminOnlyHandler` (global IP block; the customer-facing unblock flow is separate and intentionally not admin-gated).
- `/api/v1/firewall/block/batch` via `adminOnlyHandler` (bulk global IP block, ≤256 IPs/request; skips the server's own IPs and the calling admin's IP with per-IP `skipped` reasons).
- `/api/v1/admin/authcheck` (admin-only auth probe for the edge `auth_request`; `RequireAdmin` → 200 for admin, 403 for scoped/anonymous; returns no data).

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

