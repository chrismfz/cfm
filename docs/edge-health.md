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

## Scope: Tier 1 (this iteration)

The four checks that, together, would have caught the 421 incident in minutes:

### 1. Origin 421 / SNI-mismatch fingerprint
- Count `status=421` in the edge access log over a window (default last N lines /
  since T). Correlate each with `pass=…cfm_origin_https` + `uct≈0.000` (the
  warm-reuse signature) and surface the offending `host` values.
- Scan the **origin** error log (Apache `AH02032` / "Misdirected Request", or the
  LiteSpeed equivalent) for SNI↔Host mismatch lines, and pair them with the
  access-log 421s by IP/timestamp when possible.
- **Verdict:** any recent 421 with the warm-reuse signature ⇒ `critical` (this is
  the incident's exact shape). 421s without it ⇒ `warn` (could be a genuinely
  misconfigured vhost, not a pooling bug) with the sample lines.

### 2. Live-config origin-hop invariant (the runtime twin of the CI gate)
Re-checks, against the **live** edge config (not the shipped reference — catches
`/etc/cfm` drift), the exact invariant `scripts/tests/check_origin_ka_config.sh`
enforces at build time:
- OpenResty: both `cfm_origin_*` upstreams carry `keepalive 0;`.
- Angie: neither carries a `keepalive` directive.
- Both: every HTTPS-origin location (inside an `ssl` server, proxying via
  `$cfm_pass` or any `proxy_pass https://…`) carries the full trio
  `proxy_ssl_server_name on` / `proxy_ssl_name $host` / `proxy_ssl_session_reuse off`.
- **Verdict:** any violation ⇒ `critical` — 443 backend reuse is possible.

### 3. Engine + version awareness (the trap detector)
- Report engine (OpenResty / Angie) and exact version.
- Flag the version-specific gotchas: **nginx ≥ 1.29.7 ⇒ native upstream keepalive
  is ON by default and SNI-blind**, so `keepalive 0` MUST be present on the
  balancer upstreams (cross-checks with #2); Angie keeps it off by default and
  **rejects** `keepalive 0` (so it must be absent there).
- **Verdict:** engine/version + invariant mismatch (e.g. nginx ≥ 1.29.7 but a
  `cfm_origin_*` upstream without `keepalive 0`) ⇒ `critical`; this is the single
  check that most directly names the incident's root cause.

### 4. ORIGIN_KEEPALIVE knob vs. reality
- Is the knob on (`detectors.conf [webdetector] ORIGIN_KEEPALIVE`)?
- Does the live proxy conf declare the `cfm_origin_*` upstreams + the
  `$cfm_origin_ka_conf` sentinel? (Arming the knob against a conf without them is
  a silent no-op — worth surfacing.)
- Are the `[cfm_origin_ka]` per-worker WARN lines present in the edge error log,
  and which tier did each worker land on (pooling active / 443 per-request /
  degraded / retry-unavailable)? This confirms the module is actually doing what
  the config says.
- **Verdict:** knob on but upstreams/sentinel absent, or degraded-tier WARNs ⇒
  `warn`.

## Output shape

Structured JSON, most-severe first, so `whats_wrong` and a human read it the same
way:

```jsonc
{
  "engine": "openresty", "version": "1.31.1.1", "nginx": "1.31.1",
  "overall": "critical",              // ok | warn | critical
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

- Tier 2: Lua module-load failures (`[cfm] cfm_origin_ka load failed`, aborted
  lua threads), `openresty -t`/`angie -t` + reload-freshness (conf edited but not
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
