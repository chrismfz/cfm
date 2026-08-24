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
  header. Current OpenResty/Angie reference configs also send canonical
  `X-Forwarded-Proto`; package upgrades do not necessarily replace live edge
  conffiles, so verify that header after upgrade. MCP preserves the historical
  HTTPS fallback only for a valid loopback client identity plus trusted public
  prefix when the old live config omits XFP; explicit `http` remains authoritative.
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
- **CFM never exposes the admin token.** It uses the token for in-process dispatch;
  a trusted fleet gateway may independently present the admin token it already
  stores. Other clients use static `MCP_TOKEN` or a read-only OAuth token, both
  **inert against `/api/v1`** and honoured only at the `/mcp` gate.

Code: `internal/mcpserver/` (`server.go`, `oauth.go`, `tools.go`) +
`internal/apiserver/mcp_wire.go` (wiring) + a `/mcp` entry in `isPublicPath`.

---

## 2. How to arm it

### Arming: DEFAULT-ON, with an auto-generated `MCP_TOKEN`

The MCP server has its **own** credential, `MCP_TOKEN`, kept separate from the
admin/API `AUTH_TOKEN` (which CFM also uses for `/cfm-admin` and the Laravel
API). Interactive and direct MCP clients should use `MCP_TOKEN`. The trusted
fleet gateway may reuse the `AUTH_TOKEN` it already holds as a static `/mcp`
bearer; CFM itself never returns or exposes that admin token to an MCP client.

As of 2026-08 the server is **default-ON**. It mounts when:

- `AUTH_TOKEN` is set (needed for the internal read dispatch), **and**
- MCP is not turned off (`MCP = off` in `cfm.conf` is a per-node kill switch;
  unset/`on` = armed).

You **no longer have to set `MCP_TOKEN` per node.** If none is configured the
daemon **auto-generates a strong, distinct one** and persists it at
`/var/lib/cfm/mcp_token` (`0600 root:root` — a daemon-only secret; unlike the
edge-consumed Lua token files it is never group-readable). This is what lets the
fleet gateway reach every node's `/mcp` with the `AUTH_TOKEN` it already holds,
with **no per-node `MCP_TOKEN` to distribute** across ~20 servers. A distinct
auto-generated token preserves "an MCP leak is not an admin leak".

Set `MCP_TOKEN` explicitly only to **pin** a specific value (must be ≥ 24 chars;
a configured-but-weak token is treated as misconfiguration and keeps the server
disabled — the daemon does not silently replace your explicit value). A
hand-set `MCP_TOKEN` equal to `AUTH_TOKEN` logs a warning.

```
# /etc/cfm/cfm.conf
# (nothing needed — default ON; the daemon self-arms with a generated token)
# MCP_TOKEN=<32+ random chars>   # only to pin a specific token
# MCP = off                      # only to disable on this node
```

`MCP_TOKEN` (whether set or auto-generated) is the consent credential, the
static bearer, and the OAuth signing key — **rotating it revokes every issued
MCP token** (delete `/var/lib/cfm/mcp_token` to roll the auto-generated one).

Startup log lines: `mcp: read-only MCP server mounted at /mcp … armed with an
auto-generated MCP_TOKEN persisted at /var/lib/cfm/mcp_token` (default path), or
when off: `mcp: MCP server disabled (disabled by config (MCP=off))` /
`… (AUTH_TOKEN not set)` / `… (MCP_TOKEN too weak …)`.

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

Clients that *can* send a header may skip OAuth and present `MCP_TOKEN` directly.
The static-bearer gate **also accepts the admin `AUTH_TOKEN`** — so a fleet
gateway (e.g. the Laravel cfm-web) that already stores each node's `AUTH_TOKEN`
to reach `/api/v1` can speak MCP to the node **without a second, separately
managed `MCP_TOKEN`** in its agents table. This does not widen the boundary:
`MCP_TOKEN` still cannot touch `/api/v1`, the `/mcp` tool surface is read-only
whichever token authenticated, and an `AUTH_TOKEN` holder can already do
everything via `/api/v1`. (The OAuth *consent* flow in Option A stays
`MCP_TOKEN`-only — `AUTH_TOKEN` is never pasted into a browser.)

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

- **Revoke all issued MCP tokens:** rotate `MCP_TOKEN` and reload — every OAuth
  artifact (signed with a key derived from it) becomes invalid. If the token is
  the auto-generated one, delete `/var/lib/cfm/mcp_token` (the daemon mints a
  fresh one on next start); if pinned, change the `MCP_TOKEN` value in
  `cfm.conf`. Either way this does **not** touch `AUTH_TOKEN`, so `/cfm-admin`
  and the API keep working.
- **Disable the server entirely:** set `MCP = off` in `cfm.conf` and reload — the
  MCP surface is not mounted; the rest of the API is unaffected. (Since arming is
  now default-ON, unsetting `MCP_TOKEN` no longer disables it — use `MCP = off`.)

---

## 3. Security model

- **Read-only by construction.** Only GET, only a fixed allow-list of `/api/v1`
  read paths, only read tools are registered. The tool never chooses the HTTP verb
  or an arbitrary path.
- **Dedicated, least-exposure credential.** Interactive/direct MCP clients use
  `MCP_TOKEN`; the trusted fleet gateway may authenticate with the admin token it
  already holds. The OAuth access token minted from `MCP_TOKEN`
  is audience-bound to `https://<host>/cfm-admin/mcp` and validated *only* at the
  `/mcp` gate; it does not authenticate against `/api/v1`. So a leaked MCP token
  grants read-only MCP access — not admin API access, and not `/cfm-admin`/Laravel
  API access (those use `AUTH_TOKEN`).
- **Admin/scoped boundary preserved.** CFM uses the admin token in-process for
  read dispatch and never hands it to a client. A gateway that already stores
  that token may present it at `/mcp`; scoped tokens do not gain that access.
  (See `CLAUDE.md` §5 — scoped-vs-admin is a hard boundary.)
- **Weak-token fail-closed.** An explicitly configured <24-char `MCP_TOKEN`
  leaves the server unmounted; an absent token is generated securely and
  persisted rather than exposing a guessable internet-facing credential.
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
  caller cannot spoof them. Consent rate limits and MCP auth audits use the same
  canonical client identity. Each supplied static/OAuth/consent credential emits
  one secret-free `cfm.api.log` auth attempt; internal admin-token dispatches are
  suppressed so they cannot create misleading loopback records. A malformed
  forwarded identity is rate-limited in one unattributed bucket and may notify,
  but can never challenge or block an inferred address.

---

## 4. Active tools (as-built)

52 read-only tools. Each wraps the `/api/v1` endpoint(s) shown (the same the
CLI/UI use). All carry the `readOnlyHint` annotation.

| Tool | What it answers | Endpoint(s) | Args |
|---|---|---|---|
| `whats_wrong` | "Is anything wrong right now?" — one-call triage: pulls health/services/mysql/mail/panel-burn-in signals concurrently and returns a SEVERITY-RANKED (critical→warning→info) list of concrete problems (disk/inode near-full, high load, swap/conntrack pressure, failed/flapping service, edge/frontend down/degraded, MySQL near max conns, frozen mail backlog, suspected outbound-mail spikes, API-abuse bursts, and real non-scanner clients a panel BLOCK rule / the bridge would/did act on), each with the drill-down tool to use next. Conservative (no routine WAF/block noise); `sources` reports which signals were read/unavailable/errored (an unread signal is never assumed healthy) | `health/snapshot` + `health/anomalies` + `system/services` + `mysql/top` + `system/mail-queue` + `mail/traffic` + `system/waf-fp-hunt` | — |
| `security_overview` | "What's going on right now?" — one-call headline (compact: counts + top-N, not full lists) | `health/snapshot` + `waf/engine/summary` + `challenge/vhosts` + `firewall/list` + `webdet/suspicious` | — |
| `waf_activity` | Recent WAF hits with FP evidence (timestamp/event type, IP, country/ISO/ASN, host, URL, action, reason/rule ID and available UA/referer/content type), plus top rules/IPs and per-hour histogram. Filters combine before aggregation; older observation rows may lack optional forensic fields. Correlate matching rows with `edge_access_tail` by IP/host/path or `ip_forensics` by IP | `waf/engine/summary` | `hours`, `limit`, `top`, `country`, `rule`, `ip`, `host`, `path`, `ua` |
| `waf_rules` | Loaded WAF rules + enforcement tier | `waf/rules` | — |
| `waf_rule_detail` | Deep-dive ONE rule / reason-family across BOTH surfaces (web edge + panel), since the panel runs the same cfm_waf ruleset. Give a family/substring (`WAF_SQLI`) or numeric id (`320`, resolved to its family for the web side). Returns matched registry rules (id/family/default_mode), the WEB slice (events/blocked/unique ips+hosts/top reasons/ips/hosts/countries over `hours`), and the PANEL slice (hits, scanner vs non-scanner, `nonscanner_would_block`, matched rule_ids, sample requests). "Is rule X safe to enforce?" + spots a rule clean on web but FP-ing on the panel. Composes `waf/rules`+`waf/engine/summary`+`system/waf-fp-hunt` | `waf/engine/summary`, `waf/rules`, `system/waf-fp-hunt` | `rule`*, `hours` |
| `challenge_vhosts` | Which vhosts are challenged (manual/auto) and state | `challenge/vhosts` | `status`, `mode`, `limit` |
| `challenge_events` | Recent challenge arm/pass/fail | `challenge/events` | `limit`, `host` |
| `suspicious_hosts` | Long-window scanners/attackers by score | `webdet/suspicious` | `limit` |
| `top_talkers` | Busiest vhosts by request volume/rate | `webdet/top-short` \| `webdet/long-top` | `limit`, `window` |
| `hot_ips` | Hottest source IPs by recent rate | `webdet/ip-short` | `limit` |
| `host_drilldown` | Top paths/IPs for one vhost (the "why") | `webdet/drilldown` | `host`*, `top` |
| `ip_drilldown` | What one source IP is doing | `webdet/ip-drilldown` | `ip`* |
| `edge_access_tail` | Recent edge access-log lines (method/URI/status/UA/timing) — raw request context around a WAF hit, for FP triage | `webdet/access-recent` | `ip`, `host`, `method`, `status`, `path`, `since`, `limit` |
| `ip_forensics` | On-demand raw access-log lines for one IP (bounded `tail … \| grep`) — correlate an OLDER WAF hit; reaches back further than the live ring. `include_rotated=true` also scans the rotated siblings (`.1`, `.2.gz`, `-YYYYMMDD.gz`) newest-first for evidence from before the last logrotate (bounded: `max_files` default 10, a shared line budget, one timeout, gz streamed); returns `files_scanned` | `system/ip-forensics` | `ip`*, `lines`, `limit`, `source`, `include_rotated`, `max_files` |
| `host_access_history` | ARCHIVAL traffic profile of ONE VHOST reconstructed from the edge access log incl. rotated siblings (OpenResty/Angie alike): total requests, per-hour series + peaks-vs-median, status mix, top IPs, top UAs with bot/human split (bot_ratio_pct), top paths, method mix. Reaches far beyond host_drilldown/edge_access_tail retention — but nodes keep limited rotation, so check `coverage_oldest_unix` vs the requested window before claiming "a month". Bounded: shared line budget across files (`max_lines`), one timeout, key-capped tops; rotated reach ON by default (`include_rotated=false` for live only). `combine` (default on) joins detector history for the same host/window: challenge issued/solved, block triggers, suspicious, WAF observed + per-rule breakdown | `webdet/host-access-history` | `host`*, `hours`, `merge_www`, `include_rotated`, `max_files`, `lines`, `max_lines`, `top` |
| `edge_error_tail` | Tail the edge (OpenResty/Angie) ERROR log — where the in-path Lua writes `ngx.log()`: panel LOGONLY decision verdicts (`logonly=would_enforce`), module-load failures, Lua errors. The error-log companion to `edge_access_tail` (which is the access ring). Bounded `tail` + optional grep, newest matches kept | `system/edge-error-log` | `grep`, `lines`, `limit`, `source` |
| `waf_fp_hunt` | "Is it safe to enforce on the panel?" — aggregates the panel LOGONLY burn-in from the edge error log (`[cfm_panel_waf]` would-be actions + `[cfm_panel_decision]` would-enforce verdicts), SEPARATING known-scanner noise (Censys/Shodan/… by UA) from the customer-facing residue. Headline gates: `panel_waf.nonscanner_would_block` + `panel_decision.ip_block_count`. Also per-rule breakdown, candidate FPs (worst first, with samples), top UAs. Body rules not represented (panel WAF reads no body). The aggregated view over `edge_error_tail`'s raw lines | `system/waf-fp-hunt` | `lines`, `source` |
| `abuse_shadow` | "What would the entity-abuse signals have challenged, and is it safe to enforce?" — aggregates the LOG-ONLY abuse-shadow log (`/var/log/cfm/cfm.abuse_shadow.log`). Signal C flags a per-IP request-rate OUTLIER vs the vhost's OWN median (the concentrated shape hiding under the aggregate score, e.g. a scraper melting one shop's backend). Returns would_challenge vs exempt_goodbot counts, unique hosts/IPs, top would-challenge (host,ip) outliers by peak ratio (+ datacenter provider tag), and the by-provider (datacenter-ASN) / by-good-bot (FCrDNS-verified) splits. NOTHING enforced — the burn-in measurement view to tune `ABUSE_SHADOW_RATE_*` before promotion. Empty when the feature is off | `system/abuse-shadow` | `lines` |
| `lsm_detections` | Aggregate cfm-lsm (BPF LSM) DETECT events from CFM's own lsm log: per-policy totals + rate-cap suppression roll-up (`suppressed_total`), and top repeat offenders ranked by (policy, comm, exe) with last-seen, user, short exe sha256. Answers "is cfm-lsm firing at anything real, or is this one noisy FP?" — e.g. hundreds of `CFML-CRED-002` from sssd/sssd_kcm/panel perl = uid-transition noise → silence via `allow_comm=`/`allow_exe=` under `[policy]` in `/etc/cfm/lsm.conf` + `cfm lsm restart`; ONE event with exe under /tmp,/dev/shm or `(deleted)` = dropper pattern worth escalating. Aggregates the newest ≤2000 detect lines of the window; `window_full=true` ⇒ older exist (raw lines via `cfm_log_tail` which=lsm). Empty until cfm-lsm has fired | `system/lsm-detections` | `lines` |
| `lsm_status` | cfm-lsm kernel-side state: preflight checks (can this host load BPF LSM at all? with remediation), enabled/attached (pinned links) vs config mismatch, BTF drift picks, per-policy configured mode vs live runtime (attached / would-attach / skip / unavailable) — the `cfm lsm status --json` wire format — PLUS `effective_allows`: per policy the MERGED allow_exe/allow_comm/allow_path sets (compiled-in defaults + operator entries). Before blaming a noisy CRED-002 FP, check whether that binary is already allowed; propose additions as `[policy] allow_exe=/allow_comm=` + `cfm lsm restart`. What COULD fire and how; pair with lsm_detections for what IS firing | `system/lsm-status` | — |
| `mysql_pressure` | MySQL/MariaDB pressure now (mysqltop): connection saturation + per-user conns MERGED with CPU/query deltas, ranked — catch the offender ("few conns, high CPU") | `mysql/top` + `mysql/cpu` | `top` |
| `db_web_pressure` | Per-ACCOUNT DB pressure × web request volume — flags the "few web hits, high DB pressure" tenant (runaway cron/import, abusive script, compromised account), NOT "lots of traffic → lots of DB". Folds DB users (`acct_*`) + vhosts up to the owning cPanel account; flagged accounts (`few_hits_high_pressure`) sort first, then by pressure-per-hit. `perf` says if cpu is real (busy_sec proxy on CloudLinux MariaDB). Attribution is cPanel-only — `web_attribution.vhosts_mapped=0` + a `note` when it can't map (non-cPanel host) | `mysql/cpu` + `mysql/top` + `webdet/top-short` | `top` |
| `lve_cpu` | Per-tenant CPU pressure on CloudLinux (LVE) — which hosting account is burning CPU now. Each tenant hottest-first with `uid` + `username` (resolved login = the cPanel/DA account; empty if unresolved, uid 4294967295 labelled `(default LVE / outside)`), `cores` (CPU cores used) + `pct_of_limit` (% of its LVE CPU cap; 100 = throttled) + lCPU/nCPU + EP/NPROC. In-memory sampler of `/proc/lve/list` (~15s); the per-tenant companion to `mysql_pressure`. `available:false` off CloudLinux, `ready:false` while warming | `system/lve-cpu` | `top` |
| `cpu_throttle` | Root-cause for high CPU load: THROTTLED or genuine demand? Reads instantaneous cpufreq+thermal+loadavg from sysfs/proc → `cause`: `genuine_demand` (near max freq under load — hunt the workload), `thermal_throttling` (slow+hot/throttle-counters — check cooling), `frequency_capped` (slow but cool — powersave governor/policy cap), `frequency_reduced` (slow, cause unclear), `low_load` (idle downclock, normal), `no_cpufreq_data` (VM — check host CPU steal). Load-gated so an idle downclock is never called throttling; carries freq ratio, governor, temp, throttle counters + a plain summary | `system/cpu-throttle` | — |
| `mysql_log_tail` | Tail the MySQL ERROR log (crashes, deadlocks, aborted conns, InnoDB errors) — "what's erroring?" | `system/mysql-log` | `lines`, `grep`, `limit` |
| `mysql_slow_queries` | Tail the MySQL SLOW-QUERY log (where enabled) — the slow statements behind high CPU | `system/mysql-log` | `lines`, `grep`, `limit` |
| `cfm_log_tail` | Tail one of CFM's OWN logs (`/var/log/cfm/*` + legacy `/var/log/cfm.*` fallbacks) — `which` = main/error/api/detector/challenges/smtp/mysql/waf/clam/socket/lsm/service. "What did the daemon / a subsystem log?" when the edge access/error logs don't explain a symptom. Bounded tail + grep; a log not present → `found:false`; `window_full` flags a saturated tail window | `system/cfm-log` | `which`, `lines`, `grep`, `limit` |
| `journal_tail` | Tail the systemd journal for an ALLOW-LISTED unit (cfm, angie/openresty/nginx/httpd/apache2, mysql/mysqld/mariadb, exim, dovecot, postfix, sshd, clamd, named) — a service's own startup/crash/restart output ("did cfm/the edge/mysql fail to start, and why?"). Arbitrary units rejected; non-systemd host → `available:false`. Bounded (`journalctl -n`) + grep | `system/journal` | `unit`*, `lines`, `grep`, `limit` |
| `mail_log_tail` | Tail a mail log — `which=exim` (exim_mainlog, default) / `dovecot` / `postfix`. Raw-log companion to mail_queue_summary; where outbound-abuse evidence lives (`A=dovecot_login:` senders, `cwd=/home` scripts). Bounded tail + grep; path from a fixed candidate list; `found:false` if not logging there | `system/mail-log` | `which`, `lines`, `grep`, `limit` |
| `mail_queue_summary` | Mail-queue breakdown (exim/postfix, auto) — total/frozen/deferred, age buckets, top sender+recipient domains, oldest, + top defer/freeze reasons — "why is mail backing up / stuck?" (detector-published, no probe) | `system/mail-queue` | — |
| `mail_traffic` | Mail traffic over a window (Mail Monitor) — top outbound senders, most-sent domains, top inbound mailboxes, local-script (PHP/cron) submitters by unix user, + rejected/throttled/over-quota/failed-login tallies. "Who is sending a lot / which account is compromised" (per-hour counters persisted by the collector, no per-request probe; scope-aware) | `mail/traffic` | `hours`, `limit` |
| `mail_dns_check` | Mail-auth DNS for a domain — SPF (present? lists this server's IP? all-qualifier), DMARC (policy), DKIM (selector key), sending-IP PTR/FCrDNS, MX + plain findings. The DNS "why" behind a Gmail `421-4.7.27 SPF did not pass` / `550 unsolicited`. Live TXT lookups; scope-aware (scoped users → own domains) | `mail/dns` | `domain`, `dkim_selector` |
| `detection_history` | Durable timeline of detections (WAF/challenge/clam/…). `ip=<addr>` attributes one IP — the WAF/detector/challenge events behind why CFM acted on it (a `firewall_blocks` ban with no comment → check here; manual/blocklist bans leave no event). Same data as `cfm webtop history events --ip` | `webdet/history/events` | `limit`, `type`, `host`, `ip` |
| `bots_top` | Top user-agents (bots/crawlers/scrapers) | `webdet/ua-top` | `limit` |
| `ip_locate` | Where + WHY an IP is blocked across ALL sources (nft/cfm.deny/csf/fail2ban/imunify360), incl. the cfm.deny autoblock reason (e.g. "autoblock: portscan …"). The `cfm which/search` equivalent; explains a `firewall_blocks` ban whose nft entry has no comment | `/search` | `ip`* |
| `firewall_blocks` | Active nft bans (WAF autoblocks/detector bans/blocklist). No args → compact SUMMARY (total, perm/temp, top `by_country`, top `by_asn`); the list is often thousands of IPs. Drill down with `country`/`asn`/`reason` → matching rows + within-facet ASN breakdown for FP judgement (residential ISP vs VPS) | `firewall/list` | `country`, `asn`, `reason`, `limit` |
| `firewall_selftest` | nftlib backend self-diagnostics — recent EnsureBase timings split into lock_wait/netlink/CLI (+ worst call) and per-set feed-write sizes/errors. Root-cause an nftlib slowdown (EnsureBase duration climbing) or a feed that won't apply ("message too long"). `available:false` on exec-nft | `firewall/selftest` | — |
| `nft_counters` | nftables named-counter view — how much traffic each L3/L4 firewall RULE is matching in `table inet cfm`, grouped by family (portflood/connlimit/synflood/ppsflood/hardening/smtpblock), busiest first + `by_family` totals. The RULE-match volume (distinct from `firewall_blocks`, the blocked-IP sets): "which firewall rules are firing, how hard?" — a spiking `portflood_*`/`synrate` points at an active flood. Does NOT reflect panel/web WAF or bridge enforcement (edge 403s, not nft — use `waf_activity`/`waf_fp_hunt`). `nonzero=true` hides idle counters | `firewall/counters` | `nonzero` |
| `netfilter_path` | Host-wide nftables hook order across CFM, Imunify/WebShield, iptables-nft and other tables: actual numeric base-chain priorities, statically reachable NAT/DNAT/redirect rules, equal-priority ambiguity, configured/runtime CFM priority drift, and ordered overlaps for selected traffic. Safety bounds/unsupported verdict maps fail visibly as `analysis_incomplete`. Uses terse nft JSON; blocklist set elements are never returned | `firewall/path` | `hook`, `family`, `proto`, `dport` |
| `detectors_status` | Which detectors run + recent activity | `detectors/status` | — |
| `detector_coverage` | Daemon-vs-detector coverage matrix: for every registered detector type, probes whether the watched daemon's systemd unit exists/is active (curated type→units affinity), lists the live detectors.conf sections (configured/ENABLED/active/source-probe-ok) and returns a reality-aware verdict — ok; GAP (daemon running, detector unconfigured or all ENABLED=0 = the real "I forgot"); disabled; dormant (enabled but daemon absent/stopped); absent (daemon not present AND not configured — informational, not a complaint); na (event-driven). Start at summary.gaps/dormant | `detectors/coverage` | — |
| `config_drift` | Stock-vs-live config drift: compares the packaged reference configs (/usr/share/cfm/configs/) against /etc/cfm/ so you see features a release shipped that your conffiles never received (upgrades seed live once and never touch it again). detectors.conf via the daemon's own parser: missing_sections (e.g. a whole newer [waf_security]), missing_keys per section (newer knobs like challenge_cookie_discard settings = INACTIVE features), extra live-only entries, value_diffs (informational). cfm.conf: stock-documented keys absent from the live text entirely. Read-only; changes nothing | `system/config-drift` | — |
| `clam_status` | ClamAV on-upload scanner health (box-wide): enabled? scope/mode (archives-gate, async/inline, dry-run), circuit-breaker (open/since/consec-fails/last-OK/last-err), queue len/cap, lifetime counters (scanned OK, errors, breaker-skips, queue drops, inline blocks). "Is upload scanning running or has clamd tripped the breaker/filled the queue?" | `clam/health` | — |
| `notifier_status` | Alert-notifier runtime: which channels are enabled (Slack/email/webhook) + delivery state — "are CFM's alerts actually going out?". Secrets never returned | `notifier/status` | — |
| `http3_status` | HTTP/3 (QUIC) opt-in list — which vhosts have HTTP/3 enabled at the edge | `http3/list` | — |
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
| 2026.08.11 | Mail Monitor + triage flagship | **+`mail_log_tail`, +`mail_traffic`, +`mail_dns_check`** (Mail Monitor: raw mail-log tail; per-hour traffic/anomaly/deliverability summary; mail-auth DNS check) **+`whats_wrong`** (30 tools) — one-call SEVERITY-RANKED triage that synthesizes health/services/mysql/mail signals into concrete problems, each pointing at its drill-down tool; the new recommended entry point |
| 2026.08.11 | nftlib diagnostics | **+`firewall_selftest`** (31 tools) — read-only nftlib backend self-diagnostics: EnsureBase timing split (lock_wait/netlink/CLI) + per-set feed-write sizes/errors, to root-cause an nftlib EnsureBase slowdown or a feed failing to apply |
| 2026.08.11 | challenge-loop debug | **+`challenge_ip_status`** (32 tools) — read-only dump of the DNAT challenge sets with per-IP TTL (diagnostic for the challenge-loop incident) |
| 2026.08.11 | edge-unification 1b | **−`challenge_ip_status`** (31 tools) — retired with the per-IP challenge-DNAT machinery (the sets no longer exist; the edge Lua cookie is the only clearance model) |
| 2026.08.12 | edge-unification 2d observability | **+`edge_error_tail`** (32 tools) — bounded tail of the edge (OpenResty/Angie) ERROR log with optional grep; surfaces the panel LOGONLY decision verdicts (`logonly=would_enforce`) + edge-Lua module/runtime errors that the access-log ring can't carry |
| 2026.08.12 | edge-unification 2e burn-in analysis | **+`waf_fp_hunt`** (33 tools) — aggregates the panel LOGONLY signal (`[cfm_panel_waf]` + `[cfm_panel_decision]`) from the edge error log, separating known-scanner noise from the customer-facing residue (`nonscanner_would_block` + `ip_block_count`); the Phase-4 "safe to enforce?" read over `edge_error_tail`'s raw lines |
| 2026.08.12 | CloudLinux per-tenant CPU | **+`lve_cpu`** (34 tools) — per-tenant CPU pressure from an in-memory `/proc/lve/list` sampler (~15s): each LVE's cores + %-of-limit (100 = throttled), hottest-first; the per-tenant companion to `mysql_pressure` for "box load high, which account?". Unit calibrated to nanoseconds against live CL8/CL9 |
| 2026.08.12 | DB↔web correlation | **+`db_web_pressure`** (35 tools) — folds per-DB-user MySQL pressure and per-vhost web request rate up to the owning cPanel account and flags "few web hits, high DB pressure" tenants (runaway cron/import, abusive script, compromised account). Composes `mysql/cpu`+`mysql/top`+`webdet/top-short`; host→owner via the canonical `internal/panelmap` reader; pure join in `internal/dbwebcorr`. cPanel-only attribution (notes when it can't map) |
| 2026.08.12 | CPU throttle root-cause | **+`cpu_throttle`** (36 tools) — turns "load is high" into a root cause: reads instantaneous cpufreq/thermal/loadavg and classifies thermal throttling vs frequency cap (governor/policy) vs genuine demand vs idle downclock vs no-cpufreq (VM → check host steal). Load-gated classifier so a downclocked idle CPU is never mislabelled. Pure leaf `internal/cputhrottle` |
| 2026.08.12 | Minor status reads | **+`clam_status`, +`notifier_status`, +`http3_status`** (39 tools) — thin read-only wrappers over existing admin endpoints: ClamAV scanner health (breaker/queue/counters), alert-notifier channel + delivery state, and the HTTP/3 opt-in vhost list |
| 2026.08.12 | Logs group | **+`cfm_log_tail`, +`journal_tail`** (41 tools) — bounded on-demand tails of CFM's own `/var/log/cfm/*` logs (curated `which` allow-list) and of allow-listed systemd unit journals (`journalctl -n`, curated unit allow-list so an admin read tool can't tail arbitrary units); backed by `internal/cfmlog` |
| 2026.08.12 | Firewall drilldown | **+`nft_counters`** (42 tools) — nftables named-counter view over `table inet cfm`: per-rule L3/L4 match volume grouped by family (portflood/connlimit/synflood/ppsflood/hardening/smtpblock), busiest-first + `by_family` totals. "Which firewall rules are firing, how hard?" — distinct from `firewall_blocks` (blocked-IP sets); a spiking `portflood_*`/`synrate` flags an active flood. Backend-agnostic via `ListTableJSON` (no netlink object read); does NOT reflect panel/web WAF or bridge enforcement (edge 403s) |
| 2026.08.12 | WAF per-rule cross-surface | **+`waf_rule_detail`** (43 tools) — deep-dives ONE WAF rule / reason-family across BOTH surfaces (in-path web edge + panel), joining the web WAF-event history and the panel LOGONLY/enforce burn-in lines by reason family (numeric id resolved via the registry, since web events carry only the reason). Web slice (events/blocked/unique/top reasons+ips+hosts+countries) + panel slice (scanner vs non-scanner, `nonscanner_would_block`, sample requests): "is rule X safe to enforce?" and spots a rule clean on web but FP-ing on the panel. Composes `waf/rules`+`waf/engine/summary`+`system/waf-fp-hunt`, no new endpoint |
| 2026.08.21 | Abuse-shadow burn-in | **+`abuse_shadow`** (46 tools) — aggregates the LOG-ONLY abuse-shadow log (`internal/abuseshadow`): Signal C per-IP rate-outlier-vs-vhost-median lines (concentrated abuse hiding under the aggregate score), with would_challenge/exempt_goodbot counts, top outliers, and datacenter-provider + FCrDNS-good-bot splits. The "what would Signal C challenge, and is it safe to enforce?" read; reachable fleet-wide via the gateway `node_call node="all"`. Backs `docs/webdetector-refactor.md` |
| 2026.08.23 | cfm-lsm observability | **+`lsm_detections`, +`lsm_status`** (50 tools) — the cfm-lsm triage pair. `lsm_detections` aggregates the DETECT lines from CFM's own lsm log (`internal/lsmdetect`, endpoint `/api/v1/system/lsm-detections`): per-policy counts + rate-cap suppression roll-up, top repeat offenders by (policy, comm, exe) with last-seen/user/short-sha256 — "real compromise vs chatty CRED-002 false positive (sssd/sssd_kcm/cagefsctl/panel perl)". `lsm_status` exposes `/api/v1/system/lsm-status` (the `cfm lsm status --json` wire format + an effective_allows block with the merged per-policy allow_exe/allow_comm/allow_path sets) so allow-list additions start from what is already allowed. Companions to `cfm_log_tail which=lsm` (raw lines) and `dmesg_tail` (kernel-side copies) |
| 2026.08.23 | detector coverage + config drift | **+`detector_coverage`, +`config_drift`** (50 tools) — the "did I forget something?" pair. `detector_coverage` (`/api/v1/detectors/coverage`) cross-references registered catalogue × live detectors.conf state × a curated type→systemd-units affinity table: daemon-running-but-detector-off = GAP, enabled-but-daemon-absent = DORMANT, absent/absent = informational — ending the cfm-admin habit of complaining about detectors whose daemons don't exist on the host. `config_drift` (`/api/v1/system/config-drift`) diffs packaged reference configs vs /etc/cfm/: missing sections/keys are shipped features that never reached the live conffile (upgrades seed it once, never refresh); detectors.conf parsed with the daemon's own reader, cfm.conf checks stock-documented keys absent from live text |
