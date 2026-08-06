# MCP.md — CFM read-only MCP server (as-built + roadmap)

CFM embeds a **read-only [Model Context Protocol](https://modelcontextprotocol.io)
server** so an MCP client — notably the **claude.ai remote "custom connector"** —
can *read* what this node's security stack is seeing and doing: WAF hits,
challenge state, suspicious traffic, firewall blocks, detector status, health.
It exposes the **same `/api/v1` read endpoints the CLI and web UI already use** —
nothing here blocks, unblocks, challenges, or changes configuration.

This doc is the as-built map + how to arm it + the roadmap. Keep it in sync with
the registered tool set (`internal/mcpserver/tools.go`).

---

## 1. How it works

```
   Claude (claude.ai connector / Claude Code)
        │  HTTPS
        ▼
   OpenResty edge  ── location ^~ /cfm-admin/ ──▶ 127.0.0.1:6060 (cfm daemon)
        │  (TLS terminated here; adds X-Forwarded-Prefix: /cfm-admin)
        ▼
   apiserver mux  ──▶  /mcp        (bearer/OAuth-gated MCP endpoint)
                  ──▶  /mcp/oauth/*        (OAuth 2.1 authorization server)
                  ──▶  /.well-known/oauth-*  (discovery metadata)
        │
        ▼  each tool call = in-process GET to an allow-listed /api/v1 read handler
   TokenMiddleware(admin token)(mux) ──▶ existing WAF / challenge / webdet /
                                          firewall / detectors / health handlers
```

Key properties:

- **Served through the edge under `/cfm-admin/mcp`.** No new port. The existing
  `location ^~ /cfm-admin/` already proxies `/cfm-admin/mcp`, `/cfm-admin/mcp/oauth/*`
  and `/cfm-admin/.well-known/*` to the daemon with the `X-Forwarded-Prefix`
  header — **no edge config change** was required.
- **Stateless streamable HTTP** (`Stateless + JSONResponse`): every tool call is a
  self-contained POST→JSON exchange, so there is no long-lived SSE stream to drop
  behind the proxy (which otherwise causes the connector to show "disconnected"
  and re-ask for permission).
- **`DisableLocalhostProtection` is set on purpose.** The go-sdk's DNS-rebinding
  guard 403s any request whose accepted-connection LocalAddr is loopback but whose
  Host header is not — right for a localhost-only dev server, wrong for us: the
  edge terminates TLS and upstreams over `127.0.0.1:6060` while forwarding the
  public Host, so an OAuth-authenticated client would get 403 on every `/mcp` call
  after a fully successful auth flow. `/mcp` is bearer/OAuth-gated (not
  cookie/session, so not CSRF-reachable), so the guard only breaks the real
  topology; the bearer/OAuth gate is the sole authority. (`TestMCPBehindProxyNonLoopbackHost`.)
- **Tools reuse existing handlers.** Each tool dispatches a GET to a hard-coded,
  allow-listed `/api/v1` path **in-process** (a synthetic request run through
  `TokenMiddleware(admin-token)(mux)`), so it reuses every existing handler and
  its scope/admin gate verbatim and tracks the hot-swappable webdetector engine.
  The tool never controls the path, so the surface stays read-only and bounded.
- **The admin token never leaves the process.** It is used only for the in-process
  dispatch. The MCP client only ever holds a read-only OAuth token (below), which
  is **inert against `/api/v1`** — it is honoured *only* at the `/mcp` gate.

Code: `internal/mcpserver/` (`server.go`, `oauth.go`, `tools.go`) +
`internal/apiserver/mcp_wire.go` (wiring) + a `/mcp` entry in `isPublicPath`.

---

## 2. How to arm it

### Prerequisite: a dedicated `MCP_TOKEN`

The MCP server has its **own** credential, `MCP_TOKEN` in `cfm.conf`, kept
separate from the admin/API `AUTH_TOKEN` (which CFM also uses for `/cfm-admin`
and the Laravel API). The MCP client only ever sees `MCP_TOKEN`; the admin token
is used solely for the in-process read dispatch and never leaves the daemon.

The server is mounted **only when both** hold:

- `AUTH_TOKEN` is set (needed for the internal read dispatch), and
- `MCP_TOKEN` is set **and at least 24 characters** (a short/weak/missing
  `MCP_TOKEN` keeps the server **disabled** — it is internet-reachable through the
  edge, so a guessable credential is treated as misconfiguration).

`MCP_TOKEN` is the consent credential, the static bearer, and the OAuth signing
key — **rotating it revokes every issued MCP token.** Use a value distinct from
`AUTH_TOKEN` (if they are equal the daemon logs a warning), e.g.:

```
# /etc/cfm/cfm.conf
MCP_TOKEN=<32+ random chars, e.g. `openssl rand -hex 24`>
```

Startup log lines when disabled: `mcp: MCP_TOKEN not set — MCP server disabled`
or `mcp: MCP_TOKEN too weak (need >= 24 chars) — MCP server disabled`.

The connector URL is always:

```
https://<your-panel-hostname>/cfm-admin/mcp
```

### Option A — claude.ai web connector (OAuth, recommended)

The claude.ai web UI has no header field; it authenticates a remote MCP server
via OAuth. CFM ships a minimal OAuth 2.1 + PKCE authorization server for exactly
this, so **no manual token handling in Claude** is needed.

1. In claude.ai, add a **custom connector** with URL
   `https://<host>/cfm-admin/mcp`.
2. Claude discovers the OAuth flow automatically: the `/mcp` endpoint answers an
   unauthenticated request with `401` +
   `WWW-Authenticate: … resource_metadata="https://<host>/cfm-admin/.well-known/oauth-protected-resource"`,
   which Claude follows (RFC 9728) → registers a client → opens a **consent page**
   in *your* browser. Authorization-server metadata is served both at the RFC 8414
   path (`/.well-known/oauth-authorization-server`) and, as an alias, at the OIDC
   discovery path (`/.well-known/openid-configuration`) — the claude.ai connector
   probes the OIDC URL first, so serving it there is what lets registration
   complete (all three are proxied under `/cfm-admin/` by the edge; no edge change).
3. On the consent page (`/cfm-admin/mcp/oauth/authorize`), **paste your
   `MCP_TOKEN`** and click **Approve**. Claude receives a **read-only** access
   token bound to this node.
4. Done — the connector is connected and the read-only tools are available.

> The pasted `MCP_TOKEN` goes to your own panel over HTTPS. Claude never receives
> the admin `AUTH_TOKEN` at all, and the OAuth token it does receive is read-only
> and inert against `/api/v1`.

### Option B — Claude Code / API / curl (static bearer)

Clients that *can* send a header may skip OAuth and present `MCP_TOKEN` directly:

```bash
# Claude Code (project or user config): a remote MCP server with an auth header
claude mcp add --transport http cfm https://<host>/cfm-admin/mcp \
  --header "Authorization: Bearer $MCP_TOKEN"

# Smoke test with curl (stateless streamable endpoint):
curl -sS https://<host>/cfm-admin/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

### Disable / revoke

- **Revoke all issued MCP tokens:** rotate `MCP_TOKEN` in `cfm.conf` and reload —
  every OAuth artifact (signed with a key derived from it) becomes invalid. This
  does **not** touch `AUTH_TOKEN`, so `/cfm-admin` and the API keep working.
- **Disable the server entirely:** unset `MCP_TOKEN` (or set one shorter than 24
  chars) — the MCP surface is not mounted; the rest of the API is unaffected.

---

## 3. Security model

- **Read-only by construction.** Only GET, only a fixed allow-list of `/api/v1`
  read paths, only read tools are registered. The tool never chooses the HTTP verb
  or an arbitrary path.
- **Dedicated, least-exposure credential.** MCP clients authenticate with
  `MCP_TOKEN`, never the admin `AUTH_TOKEN`. The OAuth access token minted from it
  is audience-bound to `https://<host>/cfm-admin/mcp` and validated *only* at the
  `/mcp` gate; it does not authenticate against `/api/v1`. So a leaked MCP token
  grants read-only MCP access — not admin API access, and not `/cfm-admin`/Laravel
  API access (those use `AUTH_TOKEN`).
- **Admin/scoped boundary preserved.** The admin token is used purely in-process
  for the read dispatch; it is never handed to a client. (See `CLAUDE.md` §5 —
  scoped-vs-admin is a hard boundary.)
- **Weak-token fail-closed.** A missing or <24-char `MCP_TOKEN` leaves the server
  unmounted rather than exposing a guessable internet-facing credential.
- **PKCE S256 mandatory**, dynamic client registration restricted to `https` (or
  `http://localhost`) redirect URIs, consent page is frame-denied (clickjacking),
  and all OAuth/discovery responses are CORS-open but credential-less (Bearer-only,
  no cookies, `Allow-Credentials` never set — no ambient cross-origin read).
- **Anti-phishing consent:** DCR is open (any client can register), so the consent
  page **displays the redirect host** the grant will be delivered to and **warns**
  when it is not this server's own hostname — the operator can see where a code is
  going before approving.
- **Single-use artifacts:** authorization codes are single-use (replay rejected),
  and refresh tokens rotate with reuse detection (a redeemed refresh token is
  invalidated). Access tokens are audience-bound and validated only at `/mcp`.
- **CSRF:** `/mcp*` is bearer/OAuth-authenticated (not session), so it is naturally
  outside the session-cookie CSRF check.
- **Forwarded-header trust:** the advertised scheme/prefix are taken from
  `X-Forwarded-*` **only** when the peer is the loopback edge; a direct non-loopback
  caller cannot spoof them.

---

## 4. Active tools (as-built)

25 read-only tools. Each wraps the `/api/v1` endpoint(s) shown (the same the
CLI/UI use). All carry the `readOnlyHint` annotation.

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `security_overview` | "What's going on right now?" — one-call headline (compact: counts + top-N, not full lists) | `health/snapshot` + `waf/engine/summary` + `challenge/vhosts` + `firewall/list` + `webdet/suspicious` | — |
| `waf_activity` | Recent WAF hits, top rules, top IPs, per-hour histogram | `waf/engine/summary` | `hours`, `limit`, `top` |
| `waf_rules` | Loaded WAF rules + enforcement tier | `waf/rules` | — |
| `challenge_vhosts` | Which vhosts are challenged (manual/auto) and state | `challenge/vhosts` | `status`, `mode`, `limit` |
| `challenge_events` | Recent challenge arm/pass/fail | `challenge/events` | `limit`, `host` |
| `suspicious_hosts` | Long-window scanners/attackers by score | `webdet/suspicious` | `limit` |
| `top_talkers` | Busiest vhosts by request volume/rate | `webdet/top-short` \| `webdet/long-top` | `limit`, `window` |
| `hot_ips` | Hottest source IPs by recent rate | `webdet/ip-short` | `limit` |
| `host_drilldown` | Top paths/IPs for one vhost (the "why") | `webdet/drilldown` | `host`*, `top` |
| `ip_drilldown` | What one source IP is doing | `webdet/ip-drilldown` | `ip`* |
| `edge_access_tail` | Recent edge access-log lines (method/URI/status/UA/timing) — raw request context around a WAF hit, for FP triage | `webdet/access-recent` | `ip`, `host`, `method`, `status`, `path`, `since`, `limit` |
| `ip_forensics` | On-demand raw access-log lines for one IP (bounded `tail … \| grep`) — correlate an OLDER WAF hit; reaches back further than the live ring | `system/ip-forensics` | `ip`*, `lines`, `limit`, `source` |
| `mysql_pressure` | MySQL/MariaDB pressure now (mysqltop): connection saturation + per-user conns MERGED with CPU/query deltas, ranked — catch the offender ("few conns, high CPU") | `mysql/top` + `mysql/cpu` | `top` |
| `mysql_log_tail` | Tail the MySQL ERROR log (crashes, deadlocks, aborted conns, InnoDB errors) — "what's erroring?" | `system/mysql-log` | `lines`, `grep`, `limit` |
| `mysql_slow_queries` | Tail the MySQL SLOW-QUERY log (where enabled) — the slow statements behind high CPU | `system/mysql-log` | `lines`, `grep`, `limit` |
| `mail_queue_summary` | Mail-queue breakdown (exim/postfix, auto) — total/frozen/deferred, age buckets, top sender+recipient domains, oldest, + top defer/freeze reasons — "why is mail backing up / stuck?" (detector-published, no probe) | `system/mail-queue` | — |
| `detection_history` | Durable timeline of detections (WAF/challenge/clam/…). `ip=<addr>` attributes one IP — the WAF/detector/challenge events behind why CFM acted on it (a `firewall_blocks` ban with no comment → check here; manual/blocklist bans leave no event). Same data as `cfm webtop history events --ip` | `webdet/history/events` | `limit`, `type`, `host`, `ip` |
| `bots_top` | Top user-agents (bots/crawlers/scrapers) | `webdet/ua-top` | `limit` |
| `ip_locate` | Where + WHY an IP is blocked across ALL sources (nft/cfm.deny/csf/fail2ban/imunify360), incl. the cfm.deny autoblock reason (e.g. "autoblock: portscan …"). The `cfm which/search` equivalent; explains a `firewall_blocks` ban whose nft entry has no comment | `/search` | `ip`* |
| `firewall_blocks` | Active nft bans (WAF autoblocks/detector bans/blocklist). No args → compact SUMMARY (total, perm/temp, top `by_country`, top `by_asn`); the list is often thousands of IPs. Drill down with `country`/`asn`/`reason` → matching rows + within-facet ASN breakdown for FP judgement (residential ISP vs VPS) | `firewall/list` | `country`, `asn`, `reason`, `limit` |
| `detectors_status` | Which detectors run + recent activity | `detectors/status` | — |
| `system_health` | Health snapshot + recent anomalies | `health/snapshot` + `health/anomalies` | `since` |
| `process_list` | Busiest processes (top-like: pid/user/state/%cpu/%mem/rss/threads/comm) — "load is high, who's eating it?" | `system/processes` | `top` |
| `listening_ports` | Listening TCP/UDP sockets + owning process (`ss -tlnp`) — "is the edge/daemon/panel up, who owns :443?" | `system/listeners` | — |
| `dmesg_tail` | Kernel ring buffer tail (OOM kills, I/O errors, segfaults, nft drops) — "why did it OOM/crash/reset?" | `system/dmesg` | `lines`, `grep` |
| `service_status` | systemd unit status (loaded/active/enabled, sub-state, pid, memory, restarts, uptime) — "is cfm/edge/mysql/mail up, anything flapping?" | `system/services` | `units` |

`*` required.

> `process_list` returns the process **COMM** (executable name) only — never the
> full cmdline, which routinely carries secrets (`mysql -pXXXX`, `--token=…`).

---

## 5. Available but NOT yet exposed (deliberate)

The read-only API surface is larger (~70 GET endpoints; see the CLI/UI). These are
intentionally held back for a focused first cut, not by any technical limit — the
in-process dispatch makes adding one a few lines:

- **MySQL governor** (`/api/v1/mysql/*`) — large subsystem with scoped-filter
  nuances; wants its own tool group + care around the scoped/admin filter.
- **Forensic analyzers** (`webdet/analyze-ip`, `analyze-host`) — heavier; the
  lighter `*_drilldown` tools cover the common case first.
- **HTTP/3** (`http3/*`), **ClamAV detail** (`clam/health`, `sigignore/list`),
  **Notifier** (`notifier/*`), **SSL stats** (`system/ssl/stats`), **DNAT state**
  (`dnat/state`), **Traffic rules** (`webdet/rules`), **Excludes**
  (`challenge/exclude/list`, `waf/exclude/list`), **Tokens** (`tokens/list|me`),
  **Debug captures** (`debug/*`).
- **Health timeseries** (`health/timeseries`) — snapshot + anomalies ship first.
- **UA drill** (`webdet/ua-drill`) — intentionally excluded: it *arms* 10-minute
  tracking (a side effect), so it is not a pure read.

**Explicitly out of scope:** every mutating verb. Several endpoints above also
accept POST/PUT/DELETE (block, unblock, exclude add/remove, config change, kill,
prune). The MCP server issues **GET only** and never registers a write tool.

---

## 6. Roadmap / ideas

- **Phase 2 — breadth:** promote the deferred read endpoints above into tools,
  grouped (a `mysql_*` group, `analyze_*`, `http3_status`, `clam_status`,
  `ssl_stats`, `dnat_state`, `notifier_status`, `health_timeseries`).
- **Per-tenant / scoped tokens:** today the MCP token grants node-wide read via the
  admin dispatch. A future mode could mint a **scoped** MCP token (cPanel-user
  viewer scope) so a tenant sees only their vhosts — reusing CFM's existing scoped
  token model, keeping the scoped/admin boundary intact.
- **Session-based consent:** replace the paste-admin-token consent with an
  "Approve" behind the existing `/cfm-admin` admin login session (nicer UX; no
  token pasting).
- **Revocable token store:** move from stateless HMAC tokens to entries in the
  existing revocable token store, surfaced in `/ui/tokens`, for per-connector
  revocation without rotating `MCP_TOKEN`. (Today: codes/refresh are single-use
  via an in-memory nonce set, but individual access tokens can only be revoked en
  masse by rotating `MCP_TOKEN`.)
- ~~**Consent-failure backoff**~~ **(done 2026.08.06):** the consent POST is now
  rate-limited per source IP (`consentRLBurst=10` per `consentRLWindow=5m`,
  `internal/mcpserver/ratelimit.go`); exceeding it returns `429` with a
  `Retry-After` and logs `event=mcp_oauth_consent_ratelimited`. Defence-in-depth
  against brute-forcing `MCP_TOKEN` through the form and against
  `mcp_oauth_consent_*` log spam — the token entropy (>=24 chars) remains the
  primary control.
- **Guarded write tools (far later, opt-in):** a *very* narrow, confirm-gated set
  (e.g. temporary exclude, manual challenge on/off) behind an explicit server-side
  opt-in — mirroring how the sibling projects gate their write tools OFF by
  default. Not planned until the read surface is proven.
- **Prompts / resources:** expose a couple of MCP "prompts" (e.g. "triage this
  IP", "explain these WAF hits") that compose the read tools.

---

## 7. Release history

The MCP surface is versioned by CFM's date-based releases (see `CHANGELOG.md`).
"Information visible" = the tool set active as of that release.

| Release | MCP status | Tools active |
|---|---|---|
| 2026.08.05 | **Introduced** — read-only MCP server; dedicated `MCP_TOKEN` credential (min 24 chars, fail-closed) separate from `AUTH_TOKEN`; OAuth 2.1 + PKCE for the claude.ai connector, static-bearer for Claude Code/API | The 15 tools in §4 (WAF, challenge, suspicious/traffic, drilldowns, history, bots, firewall blocks, detectors, health) |
| 2026.08.06 | Edge-proxy connectivity fixes (OIDC-discovery alias, DNS-rebinding guard disabled); consent POST rate-limit; enrich reverse-DNS perf (waf/security summaries ~60s→~1.5s) | **+`process_list`, +`listening_ports`, +`dmesg_tail`, +`service_status`, +`edge_access_tail`, +`ip_forensics`, +`mysql_pressure`, +`mysql_log_tail`, +`mysql_slow_queries`, +`mail_queue_summary`** (25 tools) — node system diagnostics (busiest processes; listening sockets + owner; kernel ring buffer; systemd unit status) + WAF triage (recent edge access lines around a hit; on-demand bounded per-IP access-log lookup) + MySQL pressure (per-user conns×CPU) + MySQL error/slow-log tails + exim mail-queue breakdown; `security_overview` made compact |
