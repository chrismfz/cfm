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

### Admin-only

- `/api/v1/webdet/summary`
- `/api/v1/webdet/hot-ips`, `/api/v1/webdet/ip-short`, `/api/v1/webdet/ip-drilldown`, `/api/v1/webdet/analyze-ip`
- `/api/v1/webdet/history/stats|prune|truncate`
- `/api/v1/challenge/summary|vhosts|ips|ip`
- `/api/v1/challenge/exclude/*`, `/api/v1/waf/exclude/*`
- `/api/v1/waf/engine/summary`

## `internal/apiserver/apiserver.go` + token/mysql endpoints

### Scoped-allowed

- `/api/v1/mysql/user-summary|user-kills|user-history` via `scopedMySQLFilterHandler` (explicit `?user=` or derived scoped owners).
- `/api/v1/tokens/me` (self descriptor only; scoped callers only see their own token metadata).

### Admin-only

- `/api/v1/mysql/state|processlist|top|locks|kills|history|history/events|history/summary|history/prune|history/truncate|history/timeline|cpu` via `adminOnlyHandler`.
- `/api/v1/auth/token` (issue token), `/api/v1/tokens/list`, `/api/v1/tokens/revoke`.

