# MCP.md — CFM read-only MCP server (as-built + roadmap)

CFM embeds a **read-only [Model Context Protocol](https://modelcontextprotocol.io)
server** so an MCP client (notably the **claude.ai remote "custom connector"**, or
Claude Code) can *read* what this node's security stack is seeing and doing: WAF
hits, challenge state, suspicious traffic, firewall blocks, detector status,
health, mail, MySQL. Every tool runs **GET requests against `/api/v1` read
endpoints the CLI and web UI already use**. Nothing here blocks, unblocks,
challenges, or changes configuration.

This doc is the as-built map, how to arm it, and the open roadmap. The code is the
source of truth: `internal/mcpserver/` (the `registerTools` list in `tools.go` is
the single choke point) and `internal/apiserver/mcp_wire.go`. When you add, remove
or change a tool, change §4 in the same PR. A tool's `Description` and argument
`jsonschema` tags are what the client actually sees in `tools/list`. This doc
summarises them; when they disagree, the code wins and this doc is the bug.

**Fleet context.** This is the per-node server. The fleet-wide MCP gateway lives
in **cfm-web**, not in this repo. It has its own central tools (e.g. `list_nodes`,
`check_ip`, `recent_fleet_events`, `fleet_backup_status`, `fingerprints`), and it
forwards `node_tools` / `node_call` to a node's `/mcp`. `node_call node="all"` fans
one node tool out to every up node. The gateway authenticates to each node with
the `AUTH_TOKEN` it already stores (§2). The node server stays read-only; the
fleet's write tools (central blocklist, BGP blackhole, notify) are cfm-web's and
are gated there (`docs/ROADMAP.md` §3).

---

## 1. How it works

```
   Claude (claude.ai connector / Claude Code)       cfm-web gateway
        │  HTTPS                                          │
        ▼                                                 │
   OpenResty/Angie edge                                   │
     location ^~ /cfm-admin/  (rewrite /cfm-admin/x → /x, │
     X-Forwarded-Prefix + X-CFM-Base: /cfm-admin,         │
     X-Forwarded-Proto)  ──▶ 127.0.0.1:6060               │
        │                                                 │
        ▼                                                 ▼
   apiserver mux (same stack on :6060 and :6061)
      /mcp                                   bearer/OAuth-gated MCP endpoint
      /mcp/oauth/{register,authorize,token}  OAuth 2.1 authorization server
      /.well-known/oauth-protected-resource  RFC 9728 metadata
      /.well-known/oauth-authorization-server  RFC 8414 metadata
      /.well-known/openid-configuration      alias of the RFC 8414 document
        │
        ▼  each tool call = in-process GET to a hard-coded read path
   TokenMiddleware(AUTH_TOKEN)(mux) ──▶ the existing /api/v1 handlers
```

Key properties:

- **Served through the edge under `/cfm-admin/mcp`.** There is no new port and no
  MCP-specific edge location. The existing `location ^~ /cfm-admin/` in
  `configs/openresty.conf` / `configs/angie.conf` proxies `/cfm-admin/mcp`,
  `/cfm-admin/mcp/oauth/*` and `/cfm-admin/.well-known/*` to the daemon. It sends
  `X-Forwarded-Prefix: /cfm-admin`, `X-CFM-Base: /cfm-admin` and
  `X-Forwarded-Proto`. Package upgrades do not necessarily replace live edge
  conffiles, so check the header after an upgrade. If an older live config omits
  `X-Forwarded-Proto`, `mcpRequestScheme` (`mcp_wire.go`) falls back to `https`
  only for a trusted loopback peer that also sent the trusted prefix. An explicit
  `http` is kept as is.
- **The daemon paths are unprefixed** (`/mcp`, `/mcp/oauth/*`, `/.well-known/…`).
  Every advertised URL (metadata, endpoints, token audience) is rebuilt per
  request as `scheme://Host + /cfm-admin` from the forwarded headers.
  `isMCPPublicPath` (`internal/apiserver/middleware.go`) lists exactly these five
  paths. `TokenMiddleware` hands them straight to the MCP/OAuth gate, which does
  its own authentication. The control-plane `RateLimitMiddleware` skips them too.
  The mux is served by both listeners (`docs/security/control-plane.md` §1, §3),
  so `/mcp` also answers on the direct `:6060`/`:6061` doors, under the same gate.
- **Stateless streamable HTTP** (`Stateless + JSONResponse`, `server.go`
  `statelessMCP`). Every call is a self-contained POST→JSON exchange, so there is
  no long-lived SSE stream to drop behind the proxy. A dropped stream made the
  connector show "disconnected" and ask for permission again.
- **`DisableLocalhostProtection` is set on purpose.** The go-sdk's DNS-rebinding
  guard returns 403 to any request whose accepted-connection LocalAddr is loopback
  but whose Host header is not. That suits a localhost-only dev server. CFM's
  edge terminates TLS and upstreams over `127.0.0.1:6060` while forwarding the
  public Host, so every `/mcp` call would get a 403 after a successful OAuth flow.
  `/mcp` is bearer-gated, not cookie/session, so it is not CSRF-reachable. The
  bearer/OAuth gate is the only authority. (`TestMCPBehindProxyNonLoopbackHost`.)
- **Tools reuse the existing handlers.** `mcp_wire.go`'s `dispatch` builds a
  synthetic `GET` (method fixed to `http.MethodGet`) to a path the tool hard-codes,
  with typed query params. It sets `Authorization: Bearer <AUTH_TOKEN>` and
  `RemoteAddr 127.0.0.1:0`, and runs the request through
  `TokenMiddleware(AUTH_TOKEN)(mux)`, without CSRF, session or MFA layers. So
  every tool sees the **admin** view of its endpoint. The caller never chooses the
  path or the verb. Admin-only endpoints such as `/search` (`ip_locate`) and
  `firewall/counters` work. Scoped-viewer filtering does not apply, and there are
  no per-tool roles. The dispatch is an in-process call, so the control-plane
  rate limiter does not see it. It also suppresses the auth audit, so it does not
  log fake loopback admin logins. Any occurrence of the admin token in a response
  body is replaced by `[redacted]` as defence in depth.
- **CFM never hands the admin token to a client.** It uses the token only for
  in-process dispatch. A gateway that already stores it may present it at `/mcp`
  (§2, option B). Every other client uses `MCP_TOKEN` or a CFM-minted OAuth access
  token. Both are honoured only at the `/mcp` gate and do not authenticate
  against `/api/v1`.

Code: `internal/mcpserver/` (`server.go` handler, bearer gate, dispatch helpers and
the server `instructions` string; `oauth.go`; `ratelimit.go`; `tools.go` plus one
file per larger tool) and `internal/apiserver/mcp_wire.go` (arming, dispatch,
static bearer, audit hooks), mounted last in `apiserver.go` (`registerMCPServer`).

---

## 2. How to arm it

### Arming: default-on, with an auto-generated `MCP_TOKEN`

The MCP server has its own client credential, `MCP_TOKEN`, separate from the
admin/API `AUTH_TOKEN`. The arming policy is `mcpArmToken` (`mcp_wire.go`),
evaluated once when the apiserver starts:

1. `MCP` (alias `MCP_ENABLED`) parsed as false in `cfm.conf` → **not mounted**.
   This is the per-node kill switch. `parseBool` reads only `1/true/yes/on` as
   true, so any unrecognised value also counts as off. Unset or `on` → continue.
2. `AUTH_TOKEN` empty → **not mounted**, because the in-process dispatch
   authenticates as admin.
3. `MCP_TOKEN` empty → the daemon loads `/var/lib/cfm/mcp_token`. If that file is
   missing or empty, the daemon generates 32 random bytes, encodes them as
   URL-safe base64 (43 chars) and writes the file atomically with mode `0600`.
   This file is daemon-only, unlike the group-readable Lua token files.
4. The resulting token, trimmed, must be ≥ 24 chars (`minMCPTokenLen`). A
   configured token that is shorter is **not replaced**. The server stays
   unmounted (fail-closed).

A hand-set `MCP_TOKEN` equal to `AUTH_TOKEN` mounts the server but logs a warning.

```
# /etc/cfm/cfm.conf  (reference: configs/cfm.conf)
MCP_TOKEN = ""     # empty = auto-generate; set >= 24 chars only to pin a value
MCP = on           # off = do not mount the MCP server on this node
```

Startup lines in the API log (`logging.LogfAPI`):

- `[apiserver] mcp: read-only MCP server mounted at /mcp (edge: /cfm-admin/mcp)`,
  with `; armed with an auto-generated MCP_TOKEN persisted at /var/lib/cfm/mcp_token …`
  when the token was generated.
- When the server is off: `[apiserver] mcp: MCP server disabled (<reason>)`.
  `<reason>` is one of `disabled by config (MCP=off)`, `AUTH_TOKEN not set`,
  `MCP_TOKEN not set and auto-generate failed: …` or
  `MCP_TOKEN too weak (need >= 24 chars)`.

`MCP_TOKEN` (set or generated) does three jobs. It is the consent credential, a
static bearer, and the source of the OAuth signing key (an HMAC-SHA256 derivation
with domain label `cfm-mcp-oauth-signing-v1`, `deriveOAuthKey`).

The connector URL is:

```
https://<your-panel-hostname>/cfm-admin/mcp
```

### Option A: claude.ai web connector (OAuth)

The claude.ai web UI has no header field, so it authenticates a remote MCP server
through OAuth. CFM ships a minimal, stateless OAuth 2.1 + PKCE authorization server
for this (`oauth.go`).

1. In claude.ai, add a custom connector with the URL `https://<host>/cfm-admin/mcp`.
2. The client calls `/mcp` without a token and gets `401` with
   `WWW-Authenticate: Bearer resource_metadata="https://<host>/cfm-admin/.well-known/oauth-protected-resource"`
   (RFC 9728 §5.1).
3. The client reads the AS metadata, served both at the RFC 8414 path
   (`/.well-known/oauth-authorization-server`) and at the OIDC discovery path
   (`/.well-known/openid-configuration`). The claude.ai connector probes the OIDC
   path first. The metadata advertises response type `code`, grant types
   `authorization_code` + `refresh_token`, PKCE `S256`, token auth method `none`
   and scope `mcp`.
4. The client registers dynamically (`POST /mcp/oauth/register`, RFC 7591).
   Registration is open to anyone. Every `redirect_uris` entry must be an
   absolute `https` URL with a host and no userinfo, or `http` on `localhost` /
   `127.0.0.1`. The `client_id` is itself a signed value (10-year expiry, unique
   per registration), so nothing is stored.
5. The browser opens the consent page, `/cfm-admin/mcp/oauth/authorize`. Paste
   `MCP_TOKEN` (never `AUTH_TOKEN`; the consent check accepts only `MCP_TOKEN`) and
   click **Approve**.
6. The client exchanges the code at `/mcp/oauth/token` for a **1-hour access
   token** and a **7-day refresh token**. Both are audience-bound to
   `https://<host>/cfm-admin/mcp`. The authorization code is valid for 2 minutes.

### Option B: Claude Code / API / curl / fleet gateway (static bearer)

A client that can send a header may skip OAuth and send
`Authorization: Bearer <token>` directly. `StaticBearer` in `mcp_wire.go` accepts
two tokens, each compared in constant time:

- `MCP_TOKEN`, audited as `mcp_static`.
- The admin `AUTH_TOKEN`, audited as `token_admin`. This lets a fleet gateway such
  as cfm-web, which already holds each node's `AUTH_TOKEN` for `/api/v1`, speak
  MCP without a second per-node secret. It does not widen anything. The `/mcp`
  surface is read-only whichever token authenticated, and an `AUTH_TOKEN` holder
  can already do everything through `/api/v1`. The admin token keeps its
  source-IP binding here: with `ADMIN_TOKEN_IP_BINDING = enforce` it opens
  `/mcp` only from the sources it opens `/api/v1` from, and anywhere else gets
  `403` (`logonly` logs `would_block`), with the same audit line and the same
  `ADMIN_TOKEN_FOREIGN_IP` anomaly.

```bash
# Claude Code: a remote MCP server with an auth header
claude mcp add --transport http cfm https://<host>/cfm-admin/mcp \
  --header "Authorization: Bearer $MCP_TOKEN"

# Smoke test with curl (stateless streamable endpoint):
curl -sS https://<host>/cfm-admin/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

The auto-generated token is in `/var/lib/cfm/mcp_token` (root only).

### Disable / revoke

The token and the `MCP` switch are read only at startup, so each change below
needs a daemon restart (`systemctl restart cfm`).

- **Revoke every OAuth grant and change the static MCP token:** rotate
  `MCP_TOKEN`. Every OAuth artifact (client_id, code, access and refresh token) is
  signed with a key derived from it, so all become invalid. For the generated
  token, delete `/var/lib/cfm/mcp_token`; a new one is minted on the next start.
  For a pinned token, change the value in `cfm.conf`. Neither touches `AUTH_TOKEN`,
  so `/cfm-admin`, the API and the gateway's static-bearer access keep working.
- **Cut off the fleet gateway's MCP access:** that means rotating `AUTH_TOKEN`,
  which also cuts its `/api/v1` access. Only `MCP=off` blocks MCP alone.
- **Disable the server:** set `MCP = off` and restart. The five MCP/OAuth paths
  are not mounted; the rest of the API is unaffected. Leaving `MCP_TOKEN` empty
  does not disable it, because an empty token is auto-generated.

---

## 3. Security model

The control-plane picture (listeners, every credential, handler stack, IP binding)
is `docs/security/control-plane.md`. This section covers what is specific to MCP.

- **Read-only by construction.** Every tool is registered with
  `ReadOnlyHint: true` (and `OpenWorldHint: true`). It calls only `dispatch`,
  whose method is always `GET`, on a path literal in the tool's code. User args
  become query parameters only. No tool takes a path, a verb or a URL. The one
  GET known to have a side effect, `webdet/ua-drill` (it arms 10-minute UA
  tracking, `ArmUAObserve`), is deliberately not exposed. Some reads do run
  bounded host commands or lookups: `tail`/`grep` on logs, `journalctl -n`,
  `dmesg`, `ss`, `systemctl status`, the edge binary's `-v` (never `-t` or a
  reload), and live DNS for `mail_dns_check`.
- **Credentials.** `MCP_TOKEN`, and OAuth tokens minted from it, are inert against
  `/api/v1`: `TokenMiddleware` never accepts them. A leaked MCP token therefore
  grants read-only MCP access, not admin API or `/cfm-admin` access. `AUTH_TOKEN`
  is also accepted at `/mcp` for the gateway (§2 B). Scoped viewer tokens and
  session cookies are not accepted at `/mcp`.
- **No per-caller scoping.** Every authenticated MCP caller gets every tool with
  the admin view (§1). Tool descriptions that mention what "scoped callers" don't
  see refer to the underlying HTTP API, not to MCP callers. `detectors_config`
  redacts secret-named keys itself (`internal/secretkeys`; it fails closed if the
  body can't be parsed). `notifier_status` and `blocklist_feeds` never return
  channel secrets or tokens.
- **OAuth.** PKCE `S256` is mandatory: a missing `code_challenge` or another
  method is refused. A `resource` whose host differs from the request host is
  refused (`invalid_target`). A code, and every refresh token descended from
  it, records the `client_id` it was issued to, and a token request that
  names another `client_id` gets `invalid_grant`. A request that names none
  is not refused: a code is still bound by its `redirect_uri` and PKCE
  verifier, while a refresh token's protection is its single use and rotation
  (a stolen refresh token stays usable until rotated or `MCP_TOKEN` changes).
  Refresh tokens minted before this check carry no client. Access tokens are checked against the exact
  `https://<host>/cfm-admin/mcp` audience. The authorize endpoint validates the
  `client_id` + `redirect_uri` pair before any redirect (open-redirect guard). The
  consent page is never framed (`X-Frame-Options: DENY`,
  `frame-ancestors 'none'`). Registration is open, so the consent page shows the
  host the code will go to and warns when it is not this server's own hostname.
  That warning is the anti-phishing control. OAuth and discovery responses send
  `Access-Control-Allow-Origin: *` and never `Allow-Credentials`; the gate is
  bearer-only.
- **Single use and its limit.** Codes and refresh tokens carry a nonce that is
  consumed on redemption. A replayed code or refresh token is rejected, and
  refresh tokens rotate. The used-nonce set is **in memory**, so a daemon restart
  forgets it. Access tokens cannot be revoked one by one; rotating `MCP_TOKEN`
  revokes all of them (see §6).
- **Consent throttle.** Consent POSTs are limited to 10 per 5 minutes per client
  identity (`consentRLBurst` / `consentRLWindow`, `ratelimit.go`). Past that the
  server answers `429` with `Retry-After: 300`, logs
  `event=mcp_oauth_consent_ratelimited`, and publishes the API anomaly
  `AUTH_MCP_CONSENT_RATE_LIMIT`. Requests with no attributable identity share one
  `unattributed` bucket. The token's entropy (≥ 24 chars) remains the primary
  control.
- **No other MCP rate limit.** `/mcp` bypasses the control-plane
  `RateLimitMiddleware`, and in-process dispatches never reach it.
  `host_access_history` has its own cap: at most two archive scans per node, and
  further calls get `429` with `Retry-After`.
- **Audit.** Each MCP bearer decision and each consent submission emits one
  secret-free auth-attempt audit (`auditAuthAttempt`; kind `mcp_token` or
  `mcp_consent`; mechanism `mcp_static`, `token_admin`, `mcp_oauth` or `unknown`).
  An invalid or malformed bearer also marks the request as an auth anomaly and
  publishes `AUTH_MCP_TOKEN_INVALID`. A denied consent also logs
  `event=mcp_oauth_consent_denied`. Internal dispatches are suppressed. Client
  identity comes from `realIPFromRequest`, which trusts forwarded headers only
  from the loopback edge, one hop.

---

## 4. Active tools (as-built)

**62 tools**, all registered unconditionally by `registerTools` (`tools.go`).
`alerts.go` registers two of them: `alerts` and `alerts_summary`. No tool is
hidden behind a feature flag or node capability. When a subsystem is absent, the
tool still answers, with a marker such as `available:false`, `found:false`,
`ready:false`, `enabled:false` or an empty summary. In a single-endpoint tool a
non-2xx answer becomes a tool error carrying the endpoint's body. In a composed
tool (`whats_wrong`, `security_overview`, `system_health`) the failing section
becomes an `{"error":…}` object and the other sections are still returned.

Conventions in the tables:

- `*` marks a required argument. The SDK schema requires it, and most handlers
  also reject an empty value.
- Types are `int`, `bool` and `string`. "csv" means a comma-separated string.
- "server default" means the tool passes nothing and the endpoint picks the value.
- An `int` of 0 or below is not sent at all.
- Endpoints are under `/api/v1/` unless shown with a leading `/`.

### 4.1 Triage & overview

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `whats_wrong` | **Start here** for "is anything wrong right now?". Fetches 11 sections in parallel, each with a 25 s budget, and returns findings ranked critical → warning → info. Each finding has a `tool` (+ `args`) to drill into next. It covers disk/inode, load, memory/swap, conntrack, ECC errors, process-health D-state/zombie anomalies, failed or flapping services, equal-priority netfilter ambiguity and CFM priority drift, MySQL connection saturation, frozen mail, mail-abuse findings and anomalies, SMTP/spamd saturation, API-abuse bursts, panel burn-in residue, and edge_health warn/critical findings (origin premature-close, 421 reuse, keepalive degradation, CDN-cached challenge). It is deliberately conservative: routine WAF/firewall activity is not a finding. `status:"ok"` means no findings among the signals it could read; `sources` marks each input `ok` / `unavailable` / `degraded: …` / `error: …` | `health/snapshot`, `system/process-health`, `health/anomalies`, `system/services`, `firewall/path`, `mysql/top`, `system/mail-queue`, `mail/traffic`, `mail/runtime`, `system/waf-fp-hunt`, `system/edge-health` | — |
| `security_overview` | Compact headline: health, WAF in the last hour (summary without raw rows), active challenged vhosts, the firewall block list (first 10 rows + `rows_total`), and the top 20 suspicious hosts. The five sections run in parallel, each with a 25 s budget | `health/snapshot`, `waf/engine/summary` (hours=1, top=10), `challenge/vhosts` (status=active, mode=all, limit=100), `firewall/list`, `webdet/suspicious` (limit=20) | — |
| `system_health` | Health snapshot (load, memory, disk, service/edge liveness, ingest) plus recent health anomalies | `health/snapshot`, `health/anomalies` | `since` string (anomalies window: RFC3339 or a duration like `1h`) |

### 4.2 WAF

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `waf_activity` | Recent in-path WAF hits with FP evidence: time, event type, IP, country/ISO/ASN, host, URL, method, action, reason/rule ID, UA/referer/content type when available. Also filtered totals, top rules/IPs and an hourly histogram. Filters combine. Bodies are never included; secret-looking referer params are redacted | `waf/engine/summary` (enrich=1) | `hours` int (default 24), `limit` int, `top` int (server default), `country` string (ISO-2, csv), `rule` string (reason/family substring or exact rule ID), `ip` string (exact), `host` string (exact), `path` string (substring), `ua` string (substring) |
| `waf_rules` | Loaded WAF rules: id, reason family, tier (logonly / challenge / challenge_v2 / block) | `waf/rules` | — |
| `waf_rule_detail` | One rule or family across both surfaces. Returns `matched_rules` (registry); a `web` slice (events, blocked, unique IPs/hosts, top reasons/IPs/hosts/countries); a `panel` slice (hits, scanner vs non-scanner, `nonscanner_would_block`, rule_ids, samples). A numeric id also returns `web_by_id` (`also_matches` behind a stronger headline rule; sampled from the de-duplicated push). Read the `notes` | `waf/rules`, `waf/engine/summary`, `system/waf-fp-hunt` | `rule`* string (family, substring or numeric id), `hours` int (default 24, max 720) |
| `waf_fp_hunt` | Panel LOGONLY burn-in from the edge error log (`[cfm_panel_waf]`, `[cfm_panel_decision]`). Separates scanner noise (by UA) from the customer-facing residue. The gates are `panel_waf.nonscanner_would_block` and `panel_decision.ip_block_count`. Body rules are not represented (the panel WAF reads no body) | `system/waf-fp-hunt` | `lines` int (default 5000, max 200000), `source` string (edge error-log basename or path from the available list) |

### 4.3 Challenge engine

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `challenge_vhosts` | Vhosts under a challenge, manual or auto, with state. `lockdown=true` / `lockdown_until` marks a manual challenge with no client exemption | `challenge/vhosts` | `status` string (e.g. `active`; omit for all), `mode` string (`manual`/`auto`/`all`, default all), `limit` int |
| `challenge_events` | Recent arm/pass/fail events, newest first | `challenge/events` | `limit` int, `host` string |

### 4.4 Web traffic & request evidence

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `suspicious_hosts` | Long-window suspicious vhosts by behavioural score | `webdet/suspicious` | `limit` int |
| `top_talkers` | Busiest vhosts by request volume/rate | `webdet/top-short`, or `webdet/long-top` when `window=long` | `limit` int, `window` string (`short` default / `long`) |
| `hot_ips` | Hottest source IPs by recent rate | `webdet/ip-short` | `limit` int |
| `host_drilldown` | Top paths and IPs for one vhost, short and long windows | `webdet/drilldown` | `host`* string, `top` int |
| `ip_drilldown` | Which vhosts/paths one IP touches, its pattern and score | `webdet/ip-drilldown` | `ip`* string |
| `bots_top` | Top user-agents by volume | `webdet/ua-top` | `limit` int |
| `traffic_mix` | Who the traffic is and what it costs the origin, last 5m..24h, from in-memory counters: four classes (crawler / bot / automation = browser UA with no static or XHR / human) with requests, origin seconds, bytes, status mix, edge-served, average and peak r/s; a 5-minute series; the top vhosts by origin time with their split; the top clients (UA family, or raw UA for the browser classes) with their top IPs over the last hour. Older than an hour, each 5-minute bucket keeps its top 256 vhosts and 64 clients per class (the rest summed under `_other`). Labels only, never an enforcement decision. Survives a config reload, not a restart | `webdet/traffic-mix` | `window` string (`5m`..`24h`, default `1h`; starts on a 5-minute boundary), `host` string (one vhost: no status mix, edge-served or clients), `merge_www` bool (with `host`: the www. twin too), `hosts` int (default 20, max 500), `clients` int (default 20, max 500) |
| `edge_access_tail` | Recent edge access-log lines from the in-memory ring, newest last. Secret-looking query params are redacted; no bodies | `webdet/access-recent` | `ip`, `host`, `method` strings; `status` string (exact `403` or class digit `4`); `path` string (URI substring); `since` string (`10m`, `2h`); `limit` int (default 50, max 500) |
| `auth_corpus` | Login POSTs seen since the daemon started, grouped by shape: tag, outcome, logged-in-cookie bit, upstream, method, status, normalised path, Location path, Set-Cookie names. Each shape has counts, distinct IPs/hosts and example hosts. In memory and bounded (2000 shapes, 16 per /24 or /64); emptied by a restart or config reload. No cookie values, query strings or bodies | `webdet/auth-corpus` | `tag` string (e.g. `WP_LOGIN`, `JOOMLA_ADMIN`, `LOGIN_POST`), `outcome` string (`ok`/`fail`/`mfa`/`na`/`?`), `limit` int (default 100, max 1000) |
| `ip_forensics` | Raw edge access-log lines for one IP (bounded `tail \| grep` with a timeout). With `include_rotated`, also scans rotated siblings (`.1`, `.N.gz`, `-YYYYMMDD.gz`) newest-first under a shared line budget. Returns `files_scanned` | `system/ip-forensics` | `ip`* string, `lines` int (default 300000, max 2000000), `limit` int (default 200, max 1000), `source` string (access-log basename or path), `include_rotated` bool (default false), `max_files` int (default 10, max 60) |
| `host_access_history` | Archival profile of one vhost from the edge's full access log and its rotations. Covers requests, an hourly series with peaks vs median, status/method mix, top IPs, UAs (with a browser vs bot-like split) and paths. A separate `bad_requests` section reads `access.bad_request.log` (400/408/414/431/494/499). With `combine` it joins detector history over the same window and reports `detector_coverage`. Every reach bound sets `truncated`; `log_changed_during_scan` means rerun. Max 2 concurrent scans per node (`429` + `Retry-After`). Compare `coverage_oldest_unix` with the requested window before claiming a long reach | `webdet/host-access-history` | `host`* string; `hours` int (default 168, max 2160); `merge_www` bool; `include_rotated` bool (**default true**); `combine` bool (**default true**); `max_files` int (default 40, max 60); `lines` int (live tail, default 1000000); `max_lines` int (default 8000000, max 60000000); `top` int (default 20, max 50) |
| `abuse_shadow` | Aggregates the log-only `/var/log/cfm/cfm.abuse_shadow.log`. Signals: `rate_outlier` (Signal C), `facet_expansion`, `cost_pressure`, `dc_fraction`, `origin_403_burst` (`would_ban`, `top_origin_403`). Includes the per-IP `challenge_score` (would_harden / would_deny, by_fp with `convicted`) and a `humanity` section for ChallengeV2 `would_v2` lines (by_src, by_scope, by_tells, `rescued`, …). Nothing is enforced; this is a sizing view. Empty when the feature is off | `system/abuse-shadow` | `lines` int (default 5000, max 200000) |

### 4.5 Durable history & alerts

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `detection_history` | Persisted, GeoIP-enriched event timeline: WAF, challenge issued/solved, `challenge_v2_reject`, ClamAV, ECC (`hardware_ecc`), login-spray signals, `solver_farm`, … `ip=` tells why CFM acted on an IP; manual and blocklist bans leave no event (use `ip_locate`). The tool description documents the ChallengeV2 payload keys (`hs`, `tells`, `v2`, `v2_via`, `sig`, `src`, `scope`, `v2_waived`, `v2_rescued`, `v2_confirm`, `v2_waiver_miss`, …) | `webdet/history/events` (enrich=1) | `limit` int, `type` string, `host` string, `ip` string |
| `alerts` | The node's alert log (`internal/alerts`, `docs/alerts.md`): every event raised for the notifier, recorded even when no mail went out. Rows carry category, kind, severity, IP + geo/ASN/PTR, vhost, reason, ban mode/TTL, count, `delivery` (`notified`, `send_failed`, `deduped`, `notifier_off`, `no_channels`, `muted`, `below_severity`, `queue_full`), up to 5 samples and extras. Newest first, cursor-paged | `alerts` | filters: `hours` int (default 24, max 2160; store keeps 30 days by default); `category` csv (e.g. `WAF,PORTSCAN`); `kind` csv (`WAF/SQLI`); `min_severity` string (`info`/`warning`/`critical`); `ip`, `country` (ISO-2 or name part), `asn` (number, `AS…` or name part), `vhost` strings (`-` = none); `mode` string (`ttl`/`permanent`); `delivery` csv; `q` string (free text). Plus `limit` int (default 100, max 500), `cursor` string (`next_cursor`) |
| `alerts_summary` | The same log grouped by up to 3 dimensions: count, distinct IPs, first/last, label. Top groups by count; time buckets in time order | `alerts/summary` | the `alerts` filters, plus `group_by` csv (from `category, kind, severity, ip, country, asn, vhost, reason, mode, delivery, section, hour, day`; default `category`), `top` int (default 50, max 500) |

### 4.6 Firewall

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `firewall_blocks` | Active nft bans. With no facet: a summary (`total`, permanent/temporary, `countries_total`, top 15 `by_country` and `by_asn`). With a facet: the matching rows plus a top-10 ASN breakdown for FP judgement. Facets combine | `firewall/list` (summarised in the tool) | `country` string (case-insensitive substring of the country name), `asn` int, `reason` string (ban-comment substring), `limit` int (drill-down rows, default 100, max 1000) |
| `ip_locate` | Where and why an IP or CIDR is blocked across nft, cfm.deny, csf, fail2ban and imunify360, with the cfm.deny autoblock reason. Equivalent to `cfm which/search` | `/search` (outside `/api/v1`) | `ip`* string (IP or CIDR) |
| `nft_counters` | Named-counter match volume in `table inet cfm` by family (portflood / connlimit / synflood / ppsflood / hardening / smtpblock), busiest first + `by_family`. Does not reflect edge WAF/bridge 403s. Returns `available:false` on the nftlib engine | `firewall/counters` | `nonzero` bool (hide idle counters) |
| `firewall_selftest` | nftlib self-diagnostics: recent EnsureBase timings (lock_wait / netlink / CLI, worst call), per-set feed writes, and `netlink` (counts, errors, `timeouts`, slow or timed-out calls). Returns `available:false` on the exec-nft engine | `firewall/selftest` | — |
| `blocklist_feeds` | Per external feed (`cfm.blocklists`): type, URL (query and userinfo redacted), interval, last fetch / OK / apply, HTTP status, error, v4/v6 counts; plus `failing`. `api_origin` / `token_sent` / `token_rejected` show whether cfm-web feeds were pulled with AUTH_TOKEN (the token is never shown) | `firewall/feeds` | — |
| `netfilter_path` | Host-wide nftables hook order (CFM, Imunify/WebShield, iptables-nft, others): base chains by numeric priority, reachable NAT/DNAT/redirect rules, CFM configured-vs-runtime priority drift, equal-priority ambiguity, ordered overlaps. Blocklist set elements are never returned | `firewall/path` | `hook` string (`ingress, prerouting, input, forward, output, postrouting, egress`), `family` string (`ip, ip6, inet, bridge, arp, netdev`), `proto` string (`tcp`/`udp`), `dport` int (1–65535) |

### 4.7 Detectors & configuration

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `detectors_status` | Detector framework runtime: which detectors are enabled and running, recent activity | `detectors/status` | — |
| `detectors_config` | Parsed `detectors.conf` **with values** (global, core, leniency, advanced sections; path, `exists`, `overlay_files`). `merged=true` returns the effective view (base + `/etc/cfm/detectors.d/*.conf`) plus `overrides` (base value, effective value, winning overlay). Secret-named keys become `[redacted]` and are listed in `redacted_keys` | `detectors/config` (`view=merged` when merged) | `merged` bool |
| `detector_coverage` | Daemon-vs-detector matrix with a verdict per type: ok / GAP / disabled / dormant / absent / na. Start at `summary.gaps` and `summary.dormant` | `detectors/coverage` | — |
| `detectors_srcresolve` | Dry run of detector source resolution: which journald unit, file or container each section would tail now, and why. Includes `provisional` and `would_disable`. Nothing starts | `detectors/source-resolution` | — |
| `config_drift` | Stock (`/usr/share/cfm/configs/`) vs live (`/etc/cfm/`). For `detectors.conf`: missing sections/keys, extras, value_diffs; overlays count as present and are not diffed. For `cfm.conf`: stock keys absent from the live text | `system/config-drift` | — |

### 4.8 Edge (OpenResty / Angie)

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `edge_health` | Edge → origin correctness, `overall` ok/warn/critical/unknown, with these checks: (A) engine/version and the nginx ≥ 1.29.7 native-keepalive trap; (B) 421 warm-reuse fingerprint, recency-aware; (C) `[cfm_origin_ka]` tiers; (D) `ORIGIN_KEEPALIVE` state; (E) origin premature-close (gateway 5xx with `uht=-` and a real upstream); (F) CDN-cached challenge; (G) origin real-IP trust; (H) `web-dnat-order` (another DNAT, e.g. Imunify WebShield, ahead of CFM's web redirect). Runs the edge `-v` only. Design: `docs/edge-health.md` | `system/edge-health` | `window` int (access-log lines, default 50000, max 500000) |
| `edge_error_tail` | Tail of the edge error log: Lua `ngx.log()`, panel LOGONLY verdicts, module-load failures. Newest matches kept | `system/edge-error-log` | `grep` string, `lines` int (default 5000, max 200000), `limit` int (default 200, max 1000), `source` string |
| `http3_status` | Vhosts with HTTP/3 (QUIC) enabled at the edge | `http3/list` | — |
| `site_cache_status` | Site Cache per-vhost policies (exact or `*.suffix`): static/micro tier, recipe/TTL, enabled, purge generation, `unloadable` entries, and `switches` (`site_cache`, `micro_cache_enforce` as last handed to the edge). The description gives the resolution rules (exact entry first, then the most specific wildcard; an entry with both tiers off is an opt-out) | `site-cache/list` | — |
| `site_cache_stats` | Site Cache effectiveness per armed vhost: HIT / MISS / EXPIRED / STALE / UPDATING / REVALIDATED / BYPASS and a strict hit ratio. Pushed by the edge about every 60 s. Emptied by a daemon restart, a detectors.conf/overlay save, or rotation of a tailed log | `site-cache/stats` | `host` string (resolved to its policy key as the edge does) |

### 4.9 Host, processes & services

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `process_list` | Busiest processes, top-style: pid, ppid, user, state, %cpu, %mem, rss, threads, command name (COMM). Filters apply before the top cut. `details=true` adds direct child PIDs and a bounded, sanitised argv. The raw `/proc/<pid>/cmdline` is never returned | `system/processes` | `top` int (default 15, max 200), `match` string (COMM substring), `pid` int, `details` bool |
| `process_health` | One `/proc` scan: totals, scan completeness, state counts, COMM-family aggregates, RSS/count rankings, fanout. Includes a conservative evaluation of D-state pile-ups and zombies; a partial scan gives `evaluation.status=degraded`. No cmdline, NSS lookups or CPU sampling | `system/process-health` | — |
| `listening_ports` | Listening TCP/UDP sockets grouped by (proto, port, process), with the owner COMM + pid and a bounded address sample (`ss -tlnp` style). No connections or peers | `system/listeners` | — |
| `service_status` | systemd unit status: loaded, active, enabled, sub-state, main pid, memory, restarts, uptime | `system/services` | `units` csv (bare name = `.service`; default is the curated CFM + hosting-stack set with uninstalled units elided) |
| `journal_tail` | `journalctl -n` for one allow-listed unit; any other unit is rejected; `available:false` without systemd | `system/journal` | `unit`* string (`cfm, angie, openresty, nginx, httpd, apache2, mysql, mysqld, mariadb, exim, dovecot, postfix, sshd, clamd, named`), `lines` int (default 500, max 20000), `grep` string, `limit` int (default 200, max 2000) |
| `dmesg_tail` | Kernel ring buffer: OOM kills, I/O errors, segfaults, nft drops | `system/dmesg` | `lines` int (default 80, max 1000), `grep` string |
| `cpu_throttle` | Root cause of high load. `cause` is one of `genuine_demand`, `thermal_throttling`, `frequency_capped`, `frequency_reduced`, `low_load` or `no_cpufreq_data` (typical on VMs), with the freq ratio, governor, temperature and throttle counters. Load-gated | `system/cpu-throttle` | — |
| `lve_cpu` | Per-tenant CPU on CloudLinux from a ~15 s `/proc/lve/list` sampler: uid, username, cores, `pct_of_limit` (100 = throttled), lCPU/nCPU, EP/NPROC. `available:false` off CloudLinux; `ready:false` while warming up | `system/lve-cpu` | `top` int (default 25, max 500) |
| `backup_status` | Latest backup check (JetBackup 5 / Virtualmin / Proxmox vzdump, run every 15 min): per job the last result, last success, schedule and running flag, plus findings (`backup_failed`, `_stale`, `_stuck`, `_partial`, `_uncovered`, `_dest`, `_no_job`). `enabled:false` means BACKUP_ALERT is off; `status:null` means no check has finished. See `docs/backup-check.md` | `health/backup` | — |

### 4.10 MySQL / MariaDB

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `mysql_pressure` | Connection saturation plus per-user connections merged with CPU/busy/query deltas. Ranked by active connections, then CPU, then busy_sec, then queries, then connections. The `perf` block says which numbers are real (busy_sec stands in for CPU on many CloudLinux MariaDB builds). Errors if `mysql/top` fails (e.g. the governor is not running) | `mysql/top`, `mysql/cpu` | `top` int (default 25, max 200) |
| `db_web_pressure` | Per-cPanel-account DB pressure × web request rate. Flags `few_hits_high_pressure` accounts first, then sorts by pressure per hit. Attribution is cPanel-only; elsewhere it reports `web_attribution.vhosts_mapped=0` and a note. Errors if `mysql/cpu` or `webdet/top-short` fail; `mysql/top` is optional | `mysql/cpu`, `mysql/top`, `webdet/top-short` | `top` int (default 25, max 200) |
| `mysql_log_tail` | MySQL error log tail | `system/mysql-log` (which=error) | `lines` int (default 200, max 5000), `grep` string, `limit` int (default 200, max 2000) |
| `mysql_slow_queries` | Slow-query log tail; `found:false` when the slow log is not configured | `system/mysql-log` (which=slow) | same as `mysql_log_tail` |

### 4.11 Mail

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `mail_queue_summary` | Queue breakdown (exim or postfix, auto-detected): total/frozen/deferred, age buckets, top sender/recipient domains, `top_senders`, oldest messages, top defer/freeze reasons. Reads the queue detector's report; `available:false` without one | `system/mail-queue` | — |
| `mail_traffic` | Mail Monitor over a window: top outbound senders, domains, inbound mailboxes, local-script submitters by unix user, and reject/throttle/over-quota/failed-login tallies. Also `anomalies` (spike / new-sender, with `peak` / `under_peak`), `deliverability` per provider, and `abuse` (findings refreshed every 5 min: `mail_script_spike`, `mail_outbound_spike`, `mail_hijack`, `mail_bounce_spike`, `mail_queue_hog`, `mail_rbl_listed`, with context). `available:false` until the collector has run. See `docs/mail-abuse.md` | `mail/traffic` | `hours` int (default 24, max 720), `limit` int (default 20, max 200) |
| `mail_runtime` | SMTP/spamd saturation: inbound SMTP sessions vs Exim `smtp_accept_max`, spamd children vs `--max-children`, each with utilisation % and class ok/warn/critical, plus the worst of the two. A cap it cannot read shows `unknown` | `mail/runtime` | — |
| `mail_log_tail` | Mail log tail. The path comes from a fixed candidate list; `found:false` when the service does not log there | `system/mail-log` | `which` string (`exim` default / `dovecot` / `postfix`), `lines` int (default 500, max 20000), `grep` string, `limit` int (default 200, max 2000) |
| `mail_dns_check` | Mail-auth DNS for a domain: SPF (lists this server's IP? all-qualifier), DMARC policy, DKIM key at the selector(s), sending-IP PTR/FCrDNS, MX, plus findings. Live lookups | `mail/dns` | `domain`* string, `dkim_selector` csv (default `default`) |

### 4.12 CFM's own logs & subsystems

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `cfm_log_tail` | Tail one of CFM's own logs (`/var/log/cfm/*`, with legacy `/var/log/cfm.*` fallbacks). `found:false` when the log is absent. `window_full` means the live window was saturated. `rotated=N` also scans N rotated siblings, newest first, gz-transparent and bounded; `files_scanned` and `truncated` report the reach | `system/cfm-log` | `which` string (`main` default, `error, api, detector, challenges, smtp, mysql, waf, clam, socket, lsm, service, abuse_shadow`), `lines` int (default 500, max 20000), `grep` string, `limit` int (default 200, max 2000), `rotated` int (default 0, max 60) |
| `lsm_detections` | cfm-lsm DETECT events aggregated from the lsm log: per-policy totals with suppression roll-up, top (policy, comm, exe) offenders. Aggregates the newest ≤ 2000 detect lines; `window_full` means older ones exist | `system/lsm-detections` | `lines` int (default 5000, max 20000) |
| `lsm_status` | cfm-lsm kernel-side state (`cfm lsm status --json` format): preflight, enabled/attached, BTF drift picks, per-policy configured vs live mode, plus `effective_allows` (merged allow_exe / allow_comm / allow_path per policy) | `system/lsm-status` | — |
| `clam_status` | ClamAV upload scanner: enabled, scope/mode, circuit breaker, queue len/cap, lifetime counters | `clam/health` | — |
| `notifier_status` | Alert-notifier channels (Slack/email/webhook/…) and delivery state; no secrets | `notifier/status` | — |

**Removed tools.** `challenge_ip_status` (added and removed 2026.08.11) dumped the
per-IP challenge-DNAT sets. It was retired with that machinery; the edge Lua
clearance cookie is the only clearance model (`docs/edge-unification-plan.md`).
Old notes may still mention it.

---

## 5. Read endpoints not exposed as tools

The read API is larger than the tool set. These GET endpoints exist and have no
tool yet. They were held back for focus, not for technical reasons: a
pass-through tool is a few lines in `status_reads.go`.

- **MySQL governor** beyond `top` and `cpu`: `mysql/state`, `processlist`,
  `locks`, `history`, `kills`, `user-summary`, `user-history`, `user-kills`. These
  need care around the scoped filter. `mysql/user-kill` is an action, not a read.
- **Forensic analysers:** `webdet/analyze-ip`, `webdet/analyze-host`. They are
  heavier; the `*_drilldown` tools cover the common case.
- **Other status reads:** `system/ssl/stats`, `dnat/state`, `health/timeseries`,
  `webdet/rules` (traffic rules), `challenge/exclude/list`, `waf/exclude/list`,
  `clam/sigignore/list`, `notifier/history` and `notifier/metrics`, `tokens/list`,
  and `debug/*` captures. `tokens/me` would only describe the internal admin
  identity.
- **Deliberately excluded:** `webdet/ua-drill`. A GET to it arms 10-minute UA/IP
  tracking (`ArmUAObserve`), so it is not a pure read.

**Out of scope on the node:** every mutating verb. Several of the endpoints above
also accept POST/PUT/DELETE (block, unblock, exclude add/remove, config change,
kill, purge). The node MCP server issues GET only and registers no write tool.
Fleet writes live in cfm-web behind per-ability tokens (`docs/ROADMAP.md` §3).

---

## 6. Roadmap / ideas (open)

- **Breadth:** promote the §5 reads into tools: a `mysql_*` group, `analyze_*`,
  `ssl_stats`, `dnat_state`, `health_timeseries`, traffic rules and exclude
  lists.
- **Per-tenant scoped MCP tokens:** today every MCP credential gets node-wide
  admin reads. A scoped mode would mint an MCP token bound to a cPanel user's
  viewer scope and dispatch with that scope instead of the admin token, keeping
  the scoped/admin boundary.
- **Session-based consent:** approve behind the existing `/cfm-admin` admin login
  instead of pasting `MCP_TOKEN` on the consent page.
- **Revocable OAuth grants:** move from stateless HMAC tokens to entries in the
  existing revocable token store (shown in the tokens UI), so one connector can be
  revoked without rotating `MCP_TOKEN`. This would also make the used-nonce set
  (single-use codes, refresh rotation) survive a restart; today it is in memory.
- **Prompts / resources:** the server registers tools only (`HasTools`). A couple
  of MCP prompts ("triage this IP", "explain these WAF hits") could compose the
  read tools.
- **Server `instructions` string** (`server.go`): its orientation lists only the
  first-generation tools. Expanding it to the current groups would help clients
  that read it.

---

## 7. Release history

See `CHANGELOG.md` and `git log -- internal/mcpserver MCP.md`. Kept decisions:
`webdet/ua-drill` stays unexposed (side effect, §5); `challenge_ip_status` was
removed (§4).
