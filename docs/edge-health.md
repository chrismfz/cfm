# edge_health — focused edge origin-hop correctness check

`edge_health` is a **read-only** node MCP tool (and the `/api/v1/system/edge-health`
endpoint behind it) that answers one question the existing edge tools cannot in a
single call: **is the in-path edge → origin hop correct right now, on this engine,
with this config?**

It exists because of the 2026-08 `421 Misdirected Request` incident (see
`docs/proxy-performance.md`), which took a week to notice. The signal was in the
edge access log the whole time (`status=421`, warm `uct=0.000` through
`cfm_origin_https`) and the root cause was in the *live config × engine version*
(nginx ≥ 1.29.7 turned native upstream keepalive ON by default, SNI-blind) — but
nothing **correlated** the two. Every existing edge tool is either a raw tail
(`edge_access_tail`, `edge_error_tail`, `ip_forensics`) or generic drift
(`config_drift`); none checks the *semantic* origin-hop invariant. `edge_health`
does, and is meant to be the drill-down `whats_wrong` points to when it flags an
edge anomaly.

## Design principle

`edge_health` reads **logs AND live config AND engine version together** and
correlates them. It is a *doctor*, not a *tail*. The most valuable checks are the
config-invariant ones: a bad runtime *default* (like the native-keepalive flip)
is invisible in logs until it manifests as 421s, so the tool must inspect the
live config and the engine version directly — not wait for the symptom.

Read-only: it never blocks, reloads, or changes config. It may run
`openresty -v` / `angie -v` (and, when asked, `-t`) — validation only.

## Scope: Tier 1 (as shipped)

Five correlated checks. A–D, together, would have caught the 421 incident in
minutes; E covers the second origin-hop failure class we hit (below). Each
finding carries a `severity`; the tool's `overall` is the max of
them — **`ok | warn | critical | unknown`**, where `unknown` means a log/version
couldn't be read and is NEVER silently downgraded to `ok`.

### A. Origin 421 / warm-reuse fingerprint (edge access log)
- Count the real `status=421` field — anchored, so a URI/param containing
  `status=421` doesn't inflate it — over a bounded window. Flag the **warm-reuse**
  shape: a single `uct="0.000"` via `cfm_origin_https` (a retry list
  `uct="0.000, 0.052"` is a genuine fresh connect and is deliberately excluded).
  Surface the top `host`s.
- **Recency-aware.** An edge restart/reload wipes the upstream keepalive pool, so
  a cross-SNI 421 can only recur once pooling rebuilds. The verdict is therefore
  driven off warm-reuse 421s **inside a freshness window** (the `msec` epoch on
  each line, 5 min), not the raw count — otherwise a wide file-tail scan keeps
  re-reading the *pre-fix* storm and reads `critical` for minutes after the fix
  already took hold (exactly what we saw on the first live node). Evidence carries
  `recent_warm_421`, `newest_warm_421_age_sec`, and `fresh_window_sec`.
- **Verdict:** a warm-reuse 421 **inside the freshness window** ⇒ `critical` (a
  *live* incident); warm-reuse 421s present but **all older** than the window ⇒
  `warn` (a storm that has stopped — the fix/restart took hold; decays to `ok` as
  the lines scroll out); `status=421` without the warm-reuse shape ⇒ `warn`
  (possibly a genuinely misconfigured origin vhost, not pooling); none ⇒ `ok`.
  **Fail-safe:** if no warm line carries a parseable `msec`, recency is unknown
  and it reads `critical` — never silently downgraded.

### B. Engine + version trap (the root-cause namer)
- Report engine (OpenResty / Angie) and version, and the key gotcha: **nginx ≥
  1.29.7 (e.g. OpenResty 1.31.x) turns native upstream keepalive ON by default
  and SNI-blind**; Angie keeps it off (and rejects `keepalive 0`).
- **Verdict:** trap engine + knob on + warm-reuse 421s ⇒ `critical`. Trap engine
  + knob on + **no** 421s ⇒ `ok` (informative) — the class applies, but this
  Tier-1 check does NOT verify the `keepalive 0` config invariant (the CI gate
  `check_origin_ka_config.sh` and the future Tier-2 config check do); warning
  here would cry wolf on every healthy node forever. Knob off ⇒ `ok`. Engine
  known but its version, or the knob, unreadable ⇒ `unknown` (never all-clear).

### C. `[cfm_origin_ka]` tiers (edge error log)
- Classify the per-worker lines: `[cfm_origin_ka] ngx.balancer unavailable`
  (every origin request fails) and `[cfm] cfm_origin_ka load failed`
  (balancer_by_lua fell back to inline set_current_peer) ⇒ `critical`;
  `enable_keepalive` degradation / no-retry ⇒ `warn`.
- Absence of the once-per-worker activation lines is **not** a problem — they age
  out of the live error log on a healthy edge — so an empty classification is
  `ok`, never a false "module inactive" warning.

Check C (`[cfm_origin_ka]` tiers) gained the same treatment at the same time,
for the same reason: a *fatal* tier line is **worker-lifetime**, not
per-request, so it stayed `critical` for as long as it sat in the error-log
tail. Once Check C feeds `whats_wrong` that becomes a permanent false critical.
It is now degraded to `warn` when the newest fatal line is stale — never to
`ok`, because the module loads once per worker and the fault is still live if
the edge has not been reloaded since. The summary says exactly that, and the
acute symptom of a genuinely-broken module (a 502 storm) is carried by Check E
as its own `critical`, so nothing is hidden.

Recency is tracked **per tier**, not as one maximum: the switch reports
whichever problem tier matches first, so a shared "newest" would let a fresh
`module_load_failed` grade an already-fixed, hours-old `balancer_unavailable` as
a live `critical` — wrong severity *and* wrong root cause. The **degraded**
tiers are aged the same way; unlike a fatal tier they describe a capability gap
the edge tolerates (traffic still flows, just unpooled or without the
keepalive-race retry), so stale evidence leaves triage rather than being
downgraded one step, staying visible in the summary, the `tiers` map and
`tier_age_sec`.

### D. ORIGIN_KEEPALIVE knob (published bridge config)
- Read `origin_keepalive` from `/var/lib/cfm/lua/cfm_bridge_config.lua`
  (true/false/unknown); it drives the B and C correlations. Unreadable ⇒ feeds
  `unknown` into B rather than an all-clear.

### E. Origin premature-close / gateway 5xx (edge access log)

Added after a 2026-09 incident: on an Angie→Apache node, `mod_brotli` was
segfaulting the Apache workers. Roughly **900 requests a day across dozens of
vhosts** died with `upstream prematurely closed connection`, and nothing
surfaced it — the edge was up, `httpd.service` was `active`, load/RAM/disk were
green. `whats_wrong` returned two warnings, neither of them this. The 502s were
found only because an operator happened to be working on one of the sites.

The discriminator is **`uht="-"` on a gateway-class status** (502/503/504) **with
a real `uaddr=`**: the edge selected an origin peer and never got a response
header back.

- An application error (PHP fatal, a real 500) **always carries a header**, so it
  is excluded by construction — `500` is not even in the status set. This is what
  keeps the signal clean: it means "the origin failed us", not "the app errored".
- The `uaddr=` requirement is what keeps it about the ORIGIN hop. A response the
  edge produced by *itself* — a challenge page, a block, the admin
  upstream-error page while the daemon restarts — also logs `uht="-"` but names
  no peer, so it never counts. A connect/TLS failure *does* name its peer (nginx
  sets `$upstream_addr` once a peer is chosen) and correctly counts: never
  getting a usable connection is an origin-hop fault too.
- The status is read **only from unquoted text**. Several logged values are
  client-controlled and nginx does not escape spaces in them — and `cf=`
  (`$http_cf_connecting_ip`) sits *three fields before* `status=`, so
  `CF-Connecting-IP: 0 status=502 0` on an aborted request (real `status=499`,
  genuine `uht="-"`, genuine peer) would otherwise manufacture drops, and with
  ~100 of them a fake `critical` that now reaches `whats_wrong`. Blanking quoted
  regions before matching closes it for every such field at once, because nginx
  escapes a literal `"` inside a value as `\x22` — a client can never break out.
- `uht` carries **one value per upstream attempt**, comma-joined, and
  `cfm_origin_ka` arms `set_more_tries(1)` on every pooled port-80 origin
  request — so `uht="-, -"` is the *normal* failure shape on that path. Every
  element must be `-`: a retry that did get a header (`uht="-, 0.412"`) served
  the client and is not a drop.
- Reported with the affected **vhost spread**, which is the useful discriminator
  for whoever reads it: many vhosts ⇒ the origin itself (crashing workers,
  exhausted pool); one vhost ⇒ that app.
- Severity needs **both** an absolute event floor and a rate, so neither a quiet
  node (1 drop in a 2-line window ≠ 50% incident) nor a huge window (a handful of
  drops in 500k requests = background) can produce a false finding. Thresholds and
  their fleet calibration live next to the constants in
  `internal/apiserver/edge_health_endpoint.go`.
- **Recency-aware**, exactly like Check B: only drops inside a freshness window
  drive `critical`; a storm that has stopped but still sits in the file tail reads
  `warn` ("appears to have stopped"), and unparseable timestamps fail *safe*
  (treated as live) rather than silently downgrading a real incident.
- It rides the **same access-log pass** as Check B — one tail of a multi-GB log,
  two checks — so it costs no extra I/O.

Drill-down path the finding names, which is the one that actually solved the
incident: `edge_error_tail grep="upstream prematurely closed"` → `dmesg_tail
grep=segfault` → `service_status` for the origin daemon.

## Output shape

Structured JSON, most-severe first, so `whats_wrong` and a human read it the same
way:

```jsonc
{
  "engine": "openresty", "version": "1.31.1.1", "nginx": "1.31.1",
  "overall": "critical",              // ok | warn | critical | unknown
  "findings": [
    {
      "check": "origin-421-fingerprint",
      "severity": "critical",
      "summary": "1,204 status=421 in the last 50k access lines; 1,180 warm (uct≈0) via cfm_origin_https",
      "evidence": { "count": 1204, "warm_reuse": 1180, "window": "50000 lines",
                    "sample_hosts": ["pireasplus.gr", "footscan.gr"],
                    "origin_error_log_matches": 37 },
      "next": "edge_error_tail / check the origin-hop config (see origin-config-invariant)"
    },
    {
      "check": "engine-version-trap",
      "severity": "critical",
      "summary": "nginx 1.31.1 (>=1.29.7): native upstream keepalive default-on & SNI-blind, but cfm_origin_https has no `keepalive 0`",
      "evidence": { "nginx_ge_1_29_7": true, "cfm_origin_https_keepalive0": false }
    }
    // ...
  ]
}
```

Each finding carries a `check` id, a `severity`, a one-line `summary`, structured
`evidence`, and (when useful) a `next` pointer to the drill-down tool. `overall`
is the max severity.

## Inputs

- `window` / `since` — how far back to scan the access log (bounded, like the
  other archival tools; default a few tens-of-thousands of lines).
- `run_config_test` (default false) — also run `openresty -t` / `angie -t` and
  report validity + last-reload freshness (Tier 3; off by default because it
  execs the engine binary).
- `checks` — optionally restrict to a subset.

## How it plugs into monitoring (the "so we don't re-live it" part)

1. **`whats_wrong` signal — DONE (2026-09).** `whats_wrong` pulls
   `/api/v1/system/edge-health` as a section and maps every `warn`/`critical`
   finding into a ranked `edge` finding pointing back at `edge_health`
   (`evalEdgeHealth`, `internal/mcpserver/whats_wrong_edge_health.go`). `ok` and
   `unknown` emit nothing — `unknown` fires on any node with an unreadable
   version string, and surfacing it would cry wolf fleet-wide. The section is
   gated on the health snapshot resolving a **known** edge engine (the same
   `edgeEngineUnits` predicate `evalServices` uses), so a stale access log on a
   node that no longer runs an edge can't be read as live origin failure.
2. **Alert threshold.** Wire a 421-rate threshold into the existing notifier so a
   recurrence pages, instead of sitting invisible for a week.
3. **Cross-engine parity.** Because the fleet runs both OpenResty and Angie, the
   check is engine-aware and flags an unintended divergence (e.g. one engine
   missing the trio) rather than assuming both are configured the same way.

## Not in Tier 1 (follow-up)

- Tier 2: the **live-config origin-hop invariant** — parse the live
  `openresty.conf`/`angie.conf` and assert the trio the CI gate checks in the
  *reference* config (OpenResty `keepalive 0` on the 443 origin upstream,
  `proxy_ssl_session_reuse off` on the `proxy_ssl_name $host` locations, Angie
  *without* `keepalive 0`), turning Check A's "the class applies" into a
  positive/negative config verdict without waiting for a 421. Also: the
  **Apache-side AH02032** `421` fingerprint (origin error log), aborted lua
  threads, `openresty -t`/`angie -t` + reload-freshness (conf edited but not
  reloaded — the deployment gotcha), WAF/challenge Lua errors.
- Tier 3: latency split distribution (`uct`/`uht`/`luams`/`sslr`), 499/client-abort
  rates, worker respawns, cert/SSL edge errors. (The 5xx half of this landed
  early as **Check E** — the origin premature-close signal above.)
- The live **two-vhost same-IP integration test** (backend-observed SNI == Host,
  no connection/session crosses host, zero 421) — the runtime proof a static or
  unit test cannot give; it belongs in a test harness, not this read tool.

## Non-goals

`edge_health` does not replace `config_drift` (generic file drift), the raw tails,
or the CI gate `check_origin_ka_config.sh` (build-time, reads the *reference*
config). It is the runtime, semantic, correlated view that sits between them.
