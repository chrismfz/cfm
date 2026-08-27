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

Four correlated checks that, together, would have caught the 421 incident in
minutes. Each finding carries a `severity`; the tool's `overall` is the max of
them — **`ok | warn | critical | unknown`**, where `unknown` means a log/version
couldn't be read and is NEVER silently downgraded to `ok`.

### A. Origin 421 / warm-reuse fingerprint (edge access log)
- Count the real `status=421` field — anchored, so a URI/param containing
  `status=421` doesn't inflate it — over a bounded window. Flag the **warm-reuse**
  shape: a single `uct="0.000"` via `cfm_origin_https` (a retry list
  `uct="0.000, 0.052"` is a genuine fresh connect and is deliberately excluded).
  Surface the top `host`s.
- **Verdict:** any warm-reuse 421 ⇒ `critical` (the incident's exact shape);
  `status=421` without it ⇒ `warn` (possibly a genuinely misconfigured origin
  vhost, not pooling); none ⇒ `ok`.

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

### D. ORIGIN_KEEPALIVE knob (published bridge config)
- Read `origin_keepalive` from `/var/lib/cfm/lua/cfm_bridge_config.lua`
  (true/false/unknown); it drives the B and C correlations. Unreadable ⇒ feeds
  `unknown` into B rather than an all-clear.

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

1. **`whats_wrong` signal.** Add an edge-origin-hop check to `whats_wrong` that
   fires on a 421 spike or an origin-config-invariant violation and points to
   `edge_health` for the drill-down — so it surfaces *proactively*, not only when
   asked.
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
- Tier 3: latency split distribution (`uct`/`uht`/`luams`/`sslr`), 5xx/502/499
  rates, worker respawns, cert/SSL edge errors.
- The live **two-vhost same-IP integration test** (backend-observed SNI == Host,
  no connection/session crosses host, zero 421) — the runtime proof a static or
  unit test cannot give; it belongs in a test harness, not this read tool.

## Non-goals

`edge_health` does not replace `config_drift` (generic file drift), the raw tails,
or the CI gate `check_origin_ka_config.sh` (build-time, reads the *reference*
config). It is the runtime, semantic, correlated view that sits between them.
