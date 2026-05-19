# CFM WAF and Challenge-Clearance Boundary

## Status

The WAF rebuild is complete. **53 detectors across 9 rule-ID groups** (1xx-9xx)
inspect every dynamic request before it reaches origin. Severity-aggregation
returns the strongest rule's action; per-vhost exclusions let operators
whitelist specific rules on noisy hosts; hit-rate counters and the per-
trigger JSON hit log (`cfm.waf.log`) give operators data-driven evidence
before promoting any rule from `logonly` to `challenge` to `block`.

Open follow-ups (none blocking):

- **Promotion review** — most of the new detectors (Phase 1-5 + extensions)
  ship at `logonly`. Walk `cfm webtop waf hit-rates --hours 168` after a week
  of production data and promote well-behaved rules per the playbook below.
- **Inspector-audit deferred items** — see "Known gaps" item 8.

The git log on `configs/lua/cfm_waf*.lua` and `internal/webdetector/waf_*.go`
is the canonical record of what was shipped when. A snapshot of the rules and
their default modes lives in [Rule IDs](#rule-ids) below.

---

## Security principle

- **Challenge** is a bot/human gate. A solved `cfm_clearance` proves the client passed the gate.
- **WAF** is payload inspection. A clearance does **not** prove the request payload is safe.
- They complement each other. Clearance must skip repeated challenge gates; it must **never** skip exploit detection or block decisions.

Threat surface (shared hosting): outdated WordPress/Joomla/Drupal, vulnerable plugins, public upload handlers, admin AJAX/REST/XML-RPC, file managers, plugin/theme editors, backup/migration plugins, hijacked admin sessions. WAF inspection must continue post-clearance because authenticated attackers and stolen browser sessions are in scope.

---

## Severity model

Every WAF rule produces an action:

```
disabled (0) < logonly (1) < challenge (2) < block (3)
```

`_M.check` collects every match into a `hits` array and returns the strongest action. A `block` hit short-circuits later detectors (block is the cap). Rule order no longer affects enforcement.

Return shape: `(hit, reason, ttl, action, hits, waf_rule_id)`. The first four are the original API; `hits` is per-rule diagnostics; `waf_rule_id` is the strongest rule's stable numeric ID (see [Rule IDs](#rule-ids) below).

---

## Operating the WAF

This section is for the operator running the WAF in production. After landing
a new detector or after a stretch of production traffic, the question is
always: are these rules catching real attacks without flagging legit users?
The hit-rate aggregator is what makes that question answerable with data,
not eyeballing.

### Reviewing hit-rates

Run weekly. The window matters — a week of traffic gives a stable rate even
on low-volume vhosts.

```bash
cfm webtop waf hit-rates --hours 168                  # last 7 days, all hosts
cfm webtop waf hit-rates --hours 168 --host site.com  # one vhost
cfm webtop waf hit-rates --hours 168 --hint ok_to_promote  # only candidates
cfm webtop waf hit-rates --json                       # machine-readable
```

Output is one row per registered rule with a `promotion_hint` column. Read
the hint, look up the rule, decide what to do:

| Hint | Condition | Operator action |
|---|---|---|
| `ok_to_promote` | hits > 0 AND rate < 0.01% | Safe to promote one mode level. |
| `silent` | inspected > 0 AND hits == 0 | Verify the rule isn't broken before promoting. Run a known-positive sample (see "Testing a rule fires" below). If it fires, leave at logonly and wait. If not, debug. |
| `review` | 0.01% ≤ rate < 1% | Investigate FP candidates in `cfm.waf.log` before promoting. Tighten the rule or add per-vhost exclusions for noisy hosts. |
| `noisy` | rate ≥ 1% | Clear FP source. Either tighten the detector or add per-vhost exclusions. Don't promote. |
| `n_a` | inspected == 0 | Insufficient data — wait for the flusher (~1 minute) or for traffic. |

### Promoting a rule

```bash
cfm webtop waf set-rule rule_persistence challenge   # logonly → challenge
cfm webtop waf set-rule rule_persistence block       # challenge → block
```

**The playbook (don't skip steps):**

1. Land each new detector with mode `logonly`.
2. Wait at least one full week of production traffic.
3. Promote `logonly → challenge` only if `promotion_hint == ok_to_promote`.
4. Wait at least one more week with no operator complaints.
5. Promote `challenge → block` only if no operator complaints AND
   `promotion_hint == ok_to_promote`.
6. Never go `logonly → block` directly.
7. Per-rule kill-switch: `cfm webtop waf set-rule <name> disabled` — per-worker,
   doesn't survive reload.

False positives become tuning data: adjust score, context, or family — don't
just disable the rule. Most of the time the right move is a per-vhost
exclusion (see [Per-vhost rule exclusions](#per-vhost-rule-exclusions))
rather than disabling globally.

### Testing a rule fires (offline)

Before promoting, verify the rule actually catches its attack class. The
quickest path is a one-off `luajit` invocation that loads the WAF module
and feeds it a hand-crafted body:

```bash
luajit -e '
package.path = "configs/lua/?.lua;" .. package.path
_G.ngx = {
  now=function() return 1 end,
  decode_base64=function() return nil end,
  log=function() end,
  ERR=0, WARN=1, INFO=2,
}
local waf = require("cfm_waf")

-- Disable everything, then enable just the rule under test
local snap = waf.get_config()
for k in pairs(snap) do if k:sub(1,5)=="rule_" then waf.set_rule(k,"disabled") end end
waf.set_rule("rule_php_webshell_body", "challenge")

-- Feed a sample body and print the verdict
local hit, reason, _ttl, action, _hits, rule_id = waf.check({
  uri="/x.php", args="", method="POST", ip="1.2.3.4",
  headers={["Content-Type"]="application/x-www-form-urlencoded"},
  body=[[<?php $tmp=$_POST["k"]; include $tmp;]],
})
print(string.format("hit=%s reason=%s action=%s rule_id=%s",
  tostring(hit), tostring(reason), tostring(action), tostring(rule_id)))
'
```

Output:

```
hit=true reason=WAF_PHP_WEBSHELL_BODY:RAW_DYN_INCLUDE action=challenge rule_id=404
```

This is exactly what `cfm.lua` would see at access-phase time. Useful for:

- **`silent` rules** — confirm the detector is wired up and reachable.
- **`review`/`noisy` rules** — feed real samples from `cfm.waf.log` to
  see what triggers them.
- **New detectors** — sanity-check before pushing to production.

### Investigating FPs in `cfm.waf.log`

Every WAF trigger writes one JSON object per line to `cfm.waf.log`, with
all fields needed for FP investigation: UA, Referer, Content-Type, ASN,
country, action, TTL, and the rule id.

```bash
# Hits for a specific rule
grep '"waf_rule_id":410' /var/log/cfm/cfm.waf.log | jq

# Hits with a specific reason family
grep '"reason":"WAF_DYN_INCLUDE' /var/log/cfm/cfm.waf.log | jq

# Last 24h of hits on a specific vhost
grep '"host":"example.com"' /var/log/cfm/cfm.waf.log | jq
```

---

## Rule IDs

Every WAF rule has a stable numeric ID grouped by first digit:

| Group | Range | Family |
|---|---|---|
| 1xx | 100-199 | Path / traversal |
| 2xx | 200-299 | Client identity (UA) |
| 3xx | 300-399 | Injection (SQLi, XSS, RCE, b64, deserialization, XXE, shellshock, …) |
| 4xx | 400-499 | Upload / malware / obfuscation |
| 5xx | 500-599 | Auth abuse / brute force |
| 6xx | 600-699 | Header / protocol anomaly |
| 7xx | 700-799 | SSRF / external interaction |
| 8xx | 800-899 | Information disclosure / debug |
| 9xx | 900-999 | Reserved (future detectors) |

Stability rule: **never renumber** an existing ID. New rules get the next free slot in their semantic group. Drift between the Lua source of truth (`configs/lua/cfm_waf.lua`) and the Go mirror (`internal/webdetector/waf_rule_ids.go`) is caught by `TestWAFRuleIDs_LuaParity`.

Current assignments:

```
1xx — Path / traversal
  101  rule_traversal
  102  rule_long_path_segment

2xx — Client identity
  201  rule_bad_ua

3xx — Injection
  301  rule_sqli                       310  rule_cmd_params
  302  rule_xss                        311  rule_cmd_payload
  303  rule_js_proto                   312  rule_cmd_payload_semi_cmd
  304  rule_b64_injection              313  rule_cmd_payload_pipe_wget
  305  rule_php_wrappers               314  rule_cmd_payload_pipe_curl
  306  rule_serialize                  315  rule_cmd_payload_pipe_bash
  307  rule_xxe                        316  rule_cmd_payload_pipe_sh
  308  rule_shellshock                 317  rule_cmd_payload_backtick
                                       320  rule_rce
                                       321  rule_proxy_header_sqli
                                       322  rule_reverse_shell
                                       323  rule_persistence
                                       324  rule_rootkit_artifacts
                                       325  rule_lolbin
                                       326  rule_java_deserialize
                                       327  rule_coinminer
                                       328  rule_log4shell

4xx — Upload / malware
  401  rule_upload_filename            405  rule_script_obfuscation
  402  rule_upload_content             410  rule_webshell_path
  403  rule_upload_obfuscation         411  rule_webshell_ping
  404  rule_php_webshell_body          412  rule_polyglot_upload

5xx — Auth abuse
  501  rule_auth_burst                 510  rule_xmlrpc_multicall
  502  rule_auth_wp_checks             511  rule_xmlrpc_pingback
                                       512  rule_xmlrpc_post_burst

6xx — Header / protocol anomaly
  601  rule_ctrl_chars                 605  rule_crlf_injection
  602  rule_ip_host                    606  rule_http_smuggling
  603  rule_header_vulns               607  rule_exploit_methods
  604  rule_content_type_anomaly       608  rule_smuggling_cl
                                       609  rule_header_flood
                                       610  rule_range_abuse
                                       611  rule_bad_utf8

7xx — SSRF / external interaction
  701  rule_ssrf
  702  rule_c2_tunnel

8xx — Info disclosure / debug
  801  rule_debug_toggles
```

### Where IDs surface

- **WAF log line** — `cfm.waf.log` events carry `waf_rule_id=N` alongside the existing `reason=` field.
- **History persistence** — stored in `HistoryEvent.Payload["waf_rule_id"]` for forensic queries.
- **API** — `GET /api/v1/waf/rules` returns the registry with group / group_name / reason_family / default_mode.
- **CLI** — `cfm webtop waf rules` prints the table grouped by family. `--json` for scripts.
- **Public Lua API** — `_M.get_rule_ids()` returns a copy of the `RULE_IDS` table; `_M.rule_id_for("rule_traversal")` looks up a single ID.

The `rule_id` field returned by the bridge's `/nginx/decision` endpoint is a **separate** namespace (decision-engine traffic-rule IDs, not WAF rule IDs). The WAF path uses `waf_rule_id` everywhere to avoid collision.

---

## Per-vhost rule exclusions

Operators can suppress specific WAF rules on specific hosts/paths without disabling the whole WAF for that scope. This solves the canonical "scraper triggers `WAF_PROXY_HDR` on one site" pattern (3xK Tech / vitolighting from `docs/waf-analysis-2026-05-08.md`) — keep the rest of the ruleset hot, drop just the noisy rule on the affected host.

### Data model

`internal/webdetector/exclude_store.go`'s `excludeEntry` carries an optional `RuleIDs []int`:

| Entry shape | Meaning |
|---|---|
| `RuleIDs == nil` | **Whole-WAF skip.** All WAF rules suppressed for this host/path. The legacy "WAF off for this vhost" case. |
| `RuleIDs == []int{}` (zero length but non-nil) | Stored as `nil` by `normalizeRuleIDs`; never round-trips as empty. |
| `RuleIDs == [101, 320, …]` | **Rule-scoped skip.** Only the listed `waf_rule_id`s are suppressed; everything else still fires. |

Whole-WAF wins on collision. Two rule-scoped entries on the same host/path get merged via `MatchWAFRules` (sorted, deduplicated union).

### CLI

```
cfm webtop waf exclude list
cfm webtop waf exclude add    <value> [--type host|path] [--rule N|Nxx|N-M ...]
cfm webtop waf exclude remove <value> [--type host|path] [--rule N|Nxx|N-M ...]
```

`<value>` is matched with `strings.Contains` (plain text) or as a glob when it
contains any of `* ? [ ]`. `--type host` matches against the request host;
`--type path` matches against the request path. `--type` defaults to `host`.
Each entry is single-axis — host **or** path, not both — so to scope a path
exclusion to one site, pick a path string that's unique to that site, or use
a glob like `*/plexusnet/*`.

Omitting `--rule` creates a **whole-WAF** entry (legacy "WAF off for this
scope"). Pass `--rule` one or more times to create a **rule-scoped** entry
that suppresses only the listed `waf_rule_id`s.

Rule-ID spec accepts:

- Bare ID: `--rule 320`
- Wildcard: `--rule 3xx` → expanded to 300-399 at parse time
- Range: `--rule 310-317`
- List: `--rule 320,3xx,605` (deduped)
- Repeat: `--rule 201 --rule 605` (merged)

### Worked example — desktop-client false positive

A Greek clinical-software vendor's desktop activator phones home from many
residential IPs without sending `User-Agent`, `Accept`, or `Referer`. It
trips `rule_bad_ua` (`waf_rule_id=201`, reason `WAF_BAD_UA:UA_EMPTY+NO_ACCEPT+NO_REFERER:score=4`)
on every check-in. The traffic is legit; the rule is doing exactly what it
should for everyone *else*.

Right answer — narrow path-scoped exclusion of just rule 201:

```
cfm webtop waf exclude add /plexusnet/updates_v4/plexus4activator.php --type path --rule 201
```

Now `rule_bad_ua` keeps firing on every other URL on every other vhost, the
activator URL stops being challenged, and the rest of the WAF still inspects
the request (SQLi, RCE, upload rules, etc. all still apply). Confirm with:

```
cfm webtop waf exclude list
```

Wrong answers, for reference:
- `cfm webtop waf exclude add www.iqdevelopment.gr --type host` — disables the **entire WAF** for that vhost. Way too broad.
- `cfm webtop waf set rule_bad_ua disabled` — disables rule 201 globally. Worse.
- Editing the Lua detector — rule 201's bot signal is correct in general; the fix is operator-side configuration.

### API

```
GET  /api/v1/waf/exclude/list
POST /api/v1/waf/exclude/add?type=host&value=example.com[&rule_ids=320,3xx,310-317]
POST /api/v1/waf/exclude/remove?type=path&value=/plexusnet/&rule_ids=201
```

`rule_ids` is a CSV string in the same spec format as `--rule`. Empty / missing → whole-WAF entry.

`GET /api/v1/waf/exclude/list` returns each entry's `rule_ids` (sorted, deduped) when set; the field is omitted otherwise.

### Lua wiring

cfm.lua's `waf_skip_for(host, path)` returns one of:

```
nil                      -- no exclusion
{whole = true}           -- skip whole WAF
{rule_ids = {[101]=true, [320]=true, …}}  -- skip these specific rules
```

The Lua-side WAF (`cfm_waf.lua` `_M.check`) reads `ctx.skip_rule_ids` (a set keyed by integer rule_id) and passes it to `record()`. Each rule fire that has a `skip_rule_ids` match returns the same shape as a no-hit (`severity = 0`), so it never leaks into severity, hits[], or the engine's strongest-action selection.

cfm.lua's vhost-controls panel still shows the "WAF on/off for this host" toggle, but only counts whole-WAF entries — rule-scoped entries are filtered out so they don't change the toggle state.

### Tests

`scripts/tests/cfm_waf_severity_test.lua` covers `ctx.skip_rule_ids` end-to-end. `internal/webdetector/exclude_store_test.go` covers the matching layer. `internal/webdetector/exclude_rule_ids_test.go` covers the rule-ID-spec parser.

---

## Hit-rate measurement

The "Operating the WAF" section above covers the operator workflow. This
section documents the pipeline.

### Pipeline

```
[ cfm.lua ] every WAF check:
   waf_insp_incr(host)            # 2 shdict.incr ops per request (per-host + global)
   maybe_flush_waf_insp()         # 1 shdict.get; only one worker per minute wins
                                  # the SH:add lock and POSTs the snapshot
                  │
                  ▼  POST /nginx/waf/stats {rows:[{hour_unix, host, count}, ...]}
[ Go bridge ] handleWAFStats → SetWAFStatsHook → engine.RecordWAFInspected
                  │
                  ▼  UPSERT waf_inspected(hour_unix, host) ← absolute count
[ SQLite ] waf_inspected table (sparse, ~240 rows/day per host)
```

Each push carries the **absolute** value of the live shdict counter for the current hour. Repeated pushes for the same `(hour, host)` simply overwrite — `INSERT … ON CONFLICT DO UPDATE`. Lock TTL races are safe (idempotent).

### API: `/api/v1/waf/hit-rates`

```
GET /api/v1/waf/hit-rates?hours=24          # global, 24h
GET /api/v1/waf/hit-rates?hours=168&host=X  # per-vhost, 7 days
```

Response (one row per registered rule, even when `hits=0`):

```json
{
  "hours": 24,
  "host": "",
  "inspected_total": 1500000,
  "rules": [
    {"id": 320, "name": "rule_rce", "group": 3, "group_name": "injection",
     "reason_family": "WAF_RCE", "default_mode": "block",
     "hits": 12, "rate_pct": 0.0008, "promotion_hint": "ok_to_promote"},
    {"id": 101, "name": "rule_traversal", "group": 1, "group_name": "path",
     "hits": 75000, "rate_pct": 5.0, "promotion_hint": "noisy"}
  ]
}
```

Per-rule precision uses `json_extract(payload_json, '$.waf_rule_id')` so families with multiple rules (e.g. all `WAF_AUTH_BURST` tags) are counted separately. Events from before the rule-IDs PR have NULL `waf_rule_id` and are excluded from the per-rule view (they still appear in the legacy `WAFByRule` reason-aggregation).

### Hit log format

Every WAF trigger writes one JSON object per line to `cfm.waf.log`,
carrying enrichment (ASN / country) and the per-request forensic fields
(UA, Referer, Content-Type) that drive FP investigation.

```json
{"ip":"1.2.3.4","host":"example.com","uri":"/admin/upload",
 "method":"POST","action":"block","reason":"WAF_UPLOAD_FNAME:PHTML",
 "waf_rule_id":401,"ttl_sec":3600,
 "ua":"curl/7.81.0","referer":"","ct":"multipart/form-data; boundary=...",
 "asn":12345,"asn_name":"EXAMPLE-AS","country":"US"}
```

The earlier split (compact text in `cfm.waf.log` + a sampled JSON in
`cfm.waf.sampled.log`, gated by `CFM_WAF_SAMPLE_RATE`) is gone. Operators
tail / grep `cfm.waf.log` directly for FP investigation.

### Cost / regression notes

| Path | Cost | Notes |
|---|---|---|
| Per WAF check | ~3-5µs | Two shdict incr + one get-and-compare. <1% of WAF check cost. |
| Per flush (~1/min cluster-wide) | ~3µs on the lock winner | Snapshot+RPC runs in `ngx.timer.at(0, …)`; RPC latency is 100% off the request path. |
| Per WAF trigger | ~50µs | Forensic fields (UA / Referer / CT) attached on every push; JSON encode + one file write. |
| `/api/v1/waf/hit-rates` | <100ms typical | `json_extract` is O(N events in window); operator-pulled, never on hot path. |

#### Body-aware scan path (php_wrappers / ssrf_proto / js_proto)

Measured on bench host with the three body-aware rules enabled, running through `_M.check` end-to-end. "Plain JSON" = realistic JSON with no `%xx` sequences (the common case). "%-encoded" = body full of `%xx` escapes (forces the slow `url_decode_once` path).

| Body | Content-Type | Effective cap | Per-request CPU |
|---|---|---|---|
| 2 KB plain JSON | application/json | 2 KB (within budget) | ~10 µs |
| 30 KB plain JSON | text/plain | 2 KB (truncated by `other` budget) | ~11 µs |
| 30 KB plain JSON | application/json | 30 KB (`json` budget=32K) | ~71 µs |
| 500 KB plain JSON | application/json | 32 KB (capped by `json` budget) | ~87 µs |
| 30 KB %-encoded | application/json | 30 KB | ~2 ms (slow path: two gsub passes) |

End-to-end ceiling in production is bounded by `CFM_WAF_BODY_MAX_LEN` (default 8192); `body_scan_budget.json = 32768` only takes effect once the env var is also raised. Until then, JSON traffic is effectively capped at 8 KB regardless of the table value — still a 4× improvement over the previous 2 KB `max_scan_len`.

`normalize()` short-circuits when input contains no `%`, so the gsub passes only run when actual percent-encoding is present. JSON / multipart bodies almost never carry `%xx`, so the fast path covers the dominant case and dropped baseline cost ~12× vs the previous unconditional double-gsub.

Backward compat: all new wire fields are `omitempty`; `CREATE TABLE IF NOT EXISTS` upgrades existing SQLite DBs silently.

Kill switch: `CFM_WAF_STATS_ENABLE=0` disables hit-rate counters + flushing.

---

## Request flow

```
[ nginx: location-level dispatch ]
  ├─ /__cfm_challenge, /__cfm_verify, /cpanelwebcall, /cfm-admin/  → bypass cfm.lua
  ├─ \.(css|js|woff2?|ttf|eot|png|jpe?g|gif|webp|ico|map)$         → bypass cfm.lua, proxy to origin
  └─ everything else                                               ↓
[ access_by_lua: cfm.lua ]
  ├─ POST resume handling
  ├─ Step 1   validate cfm_clearance → clearance_allow (no return yet)
  ├─ Step 2   run WAF (always, regardless of clearance)
  │            ├─ block            → exit 403
  │            ├─ challenge + clearance → convert via post_clearance_action
  │            │                       (high-risk → block; else → logonly)
  │            ├─ challenge no clearance → challenge flow
  │            └─ logonly          → log; refresh clearance if any; allow origin
  ├─ Step 2b  honour clearance_allow → refresh cookie, allow origin (return)
  ├─ Step 2.5 forced_challenge for marked locations
  └─ Step 3   bridge decision (Go side: ip/vhost/rule)
```

Key invariants:

1. **WAF runs even with valid clearance** for any request that reaches `cfm.lua`. No dynamic payload reaches origin without inspection.
2. **Post-clearance challenge cannot loop.** Conversion happens before the action switch; the `challenge` branch in the WAF hit handler is unreachable when `clearance_allow=true`.
3. **POST replays are safe.** `clearance_allow` is force-false on `cfm_resumed_post`; a re-challenged replay hits the `block_replayed` safety net.
4. **CFM control endpoints bypass `cfm.lua`.** `/__cfm_challenge`, `/__cfm_verify` are exact-match nginx locations — no WAF, no challenge, no origin.
5. **Static-asset URIs bypass `cfm.lua`** (`.css/.js/.woff2?/.ttf/.eot/.png/.jpe?g/.gif/.webp/.ico/.map`). The `location` block in `openresty.conf` / `angie.conf` skips the access phase and proxies straight to Apache. `.svg` is NOT in the bypass — it can carry script.

`X-CFM-Action` values for visibility:

| Value | Meaning |
|-------|---------|
| `allow_cookie` | No WAF hit, valid clearance, allowed |
| `logonly` | WAF logonly hit, no clearance involved |
| `logonly_pc` | challenge converted to logonly under clearance |
| `block` | Direct WAF block |
| `block_pc` | challenge converted to block under clearance + high-risk reason |
| `challenge` | WAF challenge, no clearance |
| `challenge_resume` | Challenge with POST-resume token |
| `block_replayed` | POST replay re-triggered WAF challenge → 403 |
| `challenge_forced` | nginx-marked location forced challenge |

---

## Configuration

| Var | Default | Allowed | Notes |
|-----|---------|---------|-------|
| `CFM_WAF_AFTER_CLEARANCE_CHALLENGE` | `logonly` | `block`, `logonly` | What a challenge becomes under clearance for noisy reasons. `challenge` is rejected. |
| `CFM_WAF_AFTER_CLEARANCE_HIGH_RISK` | `block` | `block`, `logonly` | What a challenge becomes under clearance for high-risk reasons. |
| `CFM_WAF_BODY_MAX_LEN` | `8192` | int bytes | Upstream body-read cap in `cfm.lua`. End-to-end ceiling for body-aware rules — see `body_scan_budget` below. Raise in lockstep with the json/multipart entries to fully exploit the per-Content-Type budget table. |

#### `CFG.body_scan_budget` (Content-Type-keyed body scan budget)

Body-aware detectors (`php_wrappers`, `ssrf_proto`, `js_proto`) consume a normalized `args & body` string built once per request by `get_norm_ab()` in `cfm_waf.lua`. Each request picks its byte budget from `CFG.body_scan_budget` based on the request's `Content-Type`:

| Key | Default | Matches |
|---|---|---|
| `urlencoded` | `8192`  | `application/x-www-form-urlencoded` |
| `json`       | `32768` | `application/json` (incl. `; charset=...`) |
| `multipart`  | `16384` | `multipart/form-data` |
| `xml`        | `16384` | `application/xml`, `text/xml` |
| `other`      | `2048`  | Everything else (incl. unset / unknown / `text/plain`) |

`CFG.max_scan_len` (default `2048`) is the legacy fallback used by callsites without header context — URI+args scans (`scan_str`) and body-only detectors invoked outside the engine's hot path. The 17+ standalone callsites in `cfm_waf_detectors.lua` still use it; only `get_norm_ab` is on the budget table today.

The `util.body_budget(headers)` helper is hardened against malformed user overrides (non-table values, missing keys, non-positive numbers, non-numeric values) — it falls back to `body_scan_budget.other`, then `CFG.max_scan_len`, then `2048`, so a bad `cfm_waf_config.lua` cannot crash the worker on every body-aware request.

High-risk reason families (matched by `:` prefix) live in `cfm_waf.lua` as `_M.WAF_HIGH_RISK_REASONS`:

```
WAF_RCE              WAF_PHP_WEBSHELL_BODY
WAF_UPLOAD_CONTENT   WAF_TRAVERSAL
WAF_UPLOAD_FNAME     WAF_XXE
WAF_UPLOAD_OBFUSCATION
WAF_CMD_PAYLOAD
WAF_B64_INJECT
WAF_SHELLSHOCK
WAF_WEBSHELL
WAF_CVE
```

A reason in this list, when fired with `challenge` action under valid clearance, gets converted to `block` instead of `logonly`. Matched against the prefix before the first `:` so `WAF_RCE:REVERSE_SHELL:BASH_TCP` still hits.

### `IGNORE_IPS` / `IGNORE_NETS` (global allowlist for the Lua self-bypass)

`cfm.lua`'s `is_self_origin(ip)` short-circuits the WAF (and the rest of `cfm.lua`) before any rule runs. It honours three sources:

1. **Loopback / link-local** (`127.0.0.0/8`, `::1`, `169.254.0.0/16`, `fe80::/10`) — hard-coded.
2. **Local interface IPs** of this box, written by `nft.go:writeSelfIPsLua()` to `/var/lib/cfm/lua/cfm_self_ips.lua`.
3. **`[global] IGNORE_IPS` / `IGNORE_NETS`** from `cfm.cfg`, written by `detectors.IPIgnore.WriteLuaCache()` to `/var/lib/cfm/lua/cfm_ignore_nets.lua`. Same allowlist the Go challenge engine uses via `SetBypassFunc(ipIgnore.ShouldIgnore)` — wiring them through to the Lua WAF closes the operator-expectation gap where "WAF runs on traffic from my own subnet."

File format (precomputed for fast Lua matching, refresh TTL 30s):

```lua
return {
  generated_at = "2026-05-19T...",
  ips = { ["1.2.3.4"] = true, ["::1"] = true },
  v4_ranges = {
    { 1412837632, 1412837887 },  -- 84.54.49.0/24 as uint32 [first, last]
  },
}
```

**IPv6 limitation:** `IGNORE_NETS` entries that are IPv6 CIDRs are silently skipped in `v4_ranges`. IPv6 *exact* IPs in `IGNORE_IPS` still work (they land in `ips`). Operators wanting IPv6 CIDR support need to list the specific addresses for now.

**Trigger:** the file is rewritten on every config reload that touches `[global]` (the same path that rebuilds `IPIgnore`), plus once on engine startup.

---

## Public API (cfm_waf module)

| Function | Purpose |
|----------|---------|
| `_M.check(ctx)` | Run all rules, return highest severity. 6-tuple (hit, reason, ttl, action, hits, waf_rule_id). |
| `_M.enabled()` | Module-level kill-switch. |
| `_M.should_push(shdict, ip, reason)` | Per-(reason,ip) push rate limit. |
| `_M.get_config()` | Snapshot of CFG (read-only copy). |
| `_M.set_rule(name, mode)` | Live rule-mode tuning. Per-worker. Used by tests and ops kill-switches. |
| `_M.get_rule_ids()` | Snapshot of the RULE_IDS table. |
| `_M.rule_id_for(name)` | Lookup a single rule's stable numeric ID. |
| `_M.is_high_risk_reason(reason)` | Prefix match against `WAF_HIGH_RISK_REASONS`. |
| `_M.post_clearance_action(action, reason, after_challenge, after_high_risk)` | Returns `(converted_action, did_convert)`. Pure. |

---

## Tests

`scripts/tests/cfm_waf_severity_test.lua` — 69 cases covering severity aggregation, post-clearance gating, rule-id stability + drift detection, per-vhost rule exclusion via `ctx.skip_rule_ids`, and per-detector positive + negative cases for every rule shipped during the rebuild. Run via `make test-lua`.

`scripts/tests/cfm_waf_post_clearance_test.lua` — `_M.post_clearance_action` matrix: prefix match for bare families and family:tag forms, conversion table, defaults, malformed input.

`scripts/tests/cfm_panel_forced_mode_test.lua` — panel dispatch decisions (challenge / origin pass-through / API SSO bypass / internal-endpoint deny). Asserts on captured side effects.

`scripts/tests/cfm_rules_race_test.lua` — `cfm_rules` shdict-state compatibility under concurrent mutation.

`internal/webdetector/waf_rule_ids_test.go` — `TestWAFRuleIDs_LuaParity` parses `cfm_waf.lua`'s `RULE_IDS` table at test time and diffs against the Go `wafRuleIDs` slice. Catches drift between the two source-of-truth lists.

`internal/webdetector/exclude_rule_ids_test.go` and `exclude_store_test.go` — rule-id-spec parsing (`N`, `Nxx`, `N-M`, mixed) and per-vhost rule-exclusion store semantics.

`internal/webdetector/challenge_server_xss_test.go` — `jsStringLiteral`'s HTML-script-context safety: dangerous bytes (`<`, `>`, `&`, U+2028, U+2029) absent from output for representative attack payloads.

---

## Known gaps

These are real and worth addressing, but not blocking:

1. **Body truncation.** `CFM_WAF_BODY_MAX_LEN=8192` (in `cfm.lua`) means uploads/payloads larger than 8 KB skip body-inspection rules silently. The Content-Type-keyed `body_scan_budget` (added in PR #764) raises the WAF-internal cap to 32 KB for JSON / 16 KB for multipart+XML / 8 KB for urlencoded, but the upstream env-var ceiling still bottlenecks effective inspection at 8 KB. Phase W2/W3/W4 won't deliver until `CFM_WAF_BODY_MAX_LEN` is raised in lockstep (or inspection is streamed) for upload endpoints.
2. **No multipart parser.** Polyglot upload detection (W4), upload context for W2/W3, and X1-in-body assume part-aware inspection. Today the WAF runs literal `has()` over raw bytes — works for finding `<?php` in image content, but can't distinguish multipart parts (claimed CT, filename, content).
3. ~~**No hit-rate measurement.**~~ DONE — see "Hit-rate measurement" above. `/api/v1/waf/hit-rates`, `cfm webtop waf hit-rates`, plus `cfm.waf.log` (one JSON record per trigger with UA/Referer/CT) for FP investigation.
4. **shdict pressure.** Auth-burst counters use shdict. Adding more counters scales contention. Per-rule benchmarks needed before Phase 5 lands.
5. **Per-rule kill-switch audit.** `set_rule()` exists; not every detector is reachable through a `rule_*` CFG key. Audit + fill gaps.
6. **Push payload uses post-conversion action.** `cfm.lua:1127` pushes `action=logonly` after challenge→logonly conversion. Probably correct (push the effective action) but confirm with Go-side consumers.
7. **Route log loses post-clearance signal.** The `waf_logonly` / `waf_block` log line at `cfm.lua:1131` after conversion doesn't say "from challenge". The separate `waf_post_clearance_convert` line at `cfm.lua:1089` carries it; correlation is by IP+timestamp. Could be folded into one line.
8. **Inspector-as-attack-surface follow-ups (2026-05-09 audit).** Quick sweep of the surface that reads attacker bytes (Lua WAF + challenge_server + nginx_bridge) showed strong defences in the high-risk places (no `ngx.re` → no PCRE ReDoS; bridge listener is unix-socket-only with token gate on every endpoint; body cap 8 KB; literal `string.find(s, pat, 1, true)` in the `util.has` hot helper; `cpanelUserExists` regex `^[a-z0-9][a-z0-9_]{0,15}$` blocks path traversal in `/var/cpanel/databases/<user>.json` reads) and one real reflected XSS that's now closed (#565). Items not fully audited: (a) caller traces for the remaining `os.Open`/`os.ReadFile` sites in `cpanel_api_handlers.go` and `challenge_server.go` outside the `cpanelUserExists`-gated path; (b) spot-check of the more exotic Lua patterns in `cfm_waf_detectors.lua` for polynomial-time backtracking (Lua patterns can't catastrophically backtrack but `(.-)*`-style patterns can be slow on crafted input); (c) per-field length bounds in bridge JSON handlers (the body is wrapped in `MaxBytesReader` but individual fields like `host` can still land 16 KB in memory); (d) `dispatchHook` channel-saturation behaviour under load. None block production; worth a dedicated `claude/inspector-audit-*` pass when there's space.

---

## Roadmap

Highest-value items first. S/M/L = ½–1 day / 2–3 days / multi-day.

| # | Item | Why now | Size |
|---|------|---------|------|
| 1 | **File split** of `cfm_waf.lua` into `cfm_waf_util.lua` + `cfm_waf_detectors.lua` + `cfm_waf.lua`. Pure refactor, zero behaviour change. | Foundation for Phases below; lets each new detector tag its surface (header / uri / body / multipart) at move time. | M |
| 2 | **C1+C2 (Log4Shell, Java deserialization)** | Cheapest CVE detectors, near-zero FP, scan headers + query + body. | S |
| 3 | **R1 (Reverse shell payloads)** | Exact literal match, near-zero FP, instant block-class. | S |
| 4 | **W1 (Known webshell paths)** as a hash-lookup table loaded from a data file. | Foundation for all path-based detectors. | S |
| 5 | **W4 (Polyglot upload detection)** | Highest-value upload defense. Needs a tiny multipart parser (also unblocks W2/W3 in upload context). | M |
| 7 | **B5 (POST + empty UA + CL:0 + .php)** combo fingerprint | Cheap, high-confidence webshell ping detector. | S |
| 8 | **Panel DNAT WAF profile** for cPanel/DirectAdmin file managers, backup restore, plugin/theme editors. | Hijacked panel sessions uploading webshells. | L |
| 9 | ~~**Hit-rate counter + sampled hit log**~~ DONE — see "Hit-rate measurement" section. | — | — |
| 10 | ~~**Stable rule IDs + per-vhost rule exclusions**~~ (ModSec `SecRuleRemoveById`-style). **PR A DONE** + **PR B DONE** — see "Rule IDs" and "Per-vhost rule exclusions" sections above. Solves the vitolighting/3xK Tech-style FP cleanly without disabling whole-host WAF. | — |

---

## Detector phases (proposed; not yet implemented)

Format: short ID, what it detects, target reason family, indicative score. Full literal lists live in git history of this doc and will move into the implementation when each detector lands.

### Phase 1 — webshell delivery

- **W1** known-bad webshell path names (`/c99.php`, `/r57.php`, …) → `WAF_WEBSHELL:PATH:<basename>` — **shipped at `logonly` (rule 410)**.
- **W2** webshell magic strings in body (`b374k`, `WSO 2.5`, `@eval(`, …) → `WAF_PHP_WEBSHELL_BODY:tag`, scored — **shipped inside rule 404 (`detect_php_webshell_body`)**, covers `b374k` / `c99shell` / `r57shell` / `wso 2./4./5.` / `weevelyshell` / `filesman`.
- **W3** PHP function obfuscation (`\x65val`, `chr().chr()…`, `hex2bin($_POST[`) → `WAF_SCRIPT_OBFUSCATION:tag`, `+5` — **shipped (rule 405)**.
- **W4** polyglot upload (image extension/CT + `<?php`/`<?=`/`<%`/`<script` in first 64 bytes) → `WAF_UPLOAD_CONTENT:POLYGLOT`, `+6` — **shipped at `logonly` (rule 412)**.

### Phase 2 — post-exploitation / RCE

- **R1** reverse shell strings (`bash -i >& /dev/tcp/`, `python -c 'import socket'`, `socat tcp-connect`) → `WAF_RCE:REVERSE_SHELL:<tag>` — **shipped at `logonly` (rule 322)**; planned promotion to `block` after one week of clean hit-rate evidence per the rollout playbook.
- **R2** cron/systemd persistence (`crontab -e`, `/etc/cron.d/`, `[Unit]…ExecStart=/`) → `WAF_RCE:PERSISTENCE`, `+6` — **shipped (rule 323)**.
- **R3** LD_PRELOAD / userspace rootkit artifacts → `WAF_RCE:ROOTKIT_ARTIFACT`, `+6` — **shipped (rule 324)**.
- **R4** LOLbins (`certutil -urlcache -split`, `iex(iwr`, `-EncodedCommand <b64>`) → `WAF_RCE:LOLBIN` / score combo with base64 detector — **shipped (rule 325)**.

### Phase 3 — known-CVE fingerprints

- **C1** Log4Shell — **split across two rules**: the bare `${jndi:` / `${j{n{d{i` / URL-encoded forms are caught by `detect_rce` (rule 320, default `block`); the lookup-syntax evasion variants (`${${::-j}…`, `${lower:j}…`, `${upper:j}…`, `${env:`, `${sys:`, `${main:`, `${date:`, `${base64:`, generic `${${` nesting) are **shipped at `logonly` as rule 328 (`rule_log4shell`)** with family `WAF_CVE:LOG4SHELL:<tag>`. Inspects normalized args+body plus every header value (UA / Referer / X-Forwarded-For / Authorization).
- **C2** Java deserialization (`rO0ABXNyAB`, `\xac\xed\x00\x05`) → `WAF_CVE:JAVA_DESERIALIZATION` — **shipped (rule 326)**.

### Phase 4 — C2 / exfiltration

- **X1** tunnel/paste services in body or upload (`pastebin.com/raw/`, `cdn.discordapp.com/attachments/`, `webhook.site`, `ngrok.io`) → `WAF_C2:TUNNEL`, `+5` body-only.
- **X2** coinminer URLs/tools (`xmrig --url`, `pool.minexmr.com`, `stratum+tcp://`) → `WAF_RCE:COINMINER`, `+5`.

### Phase 5 — behavioural / combined-signal

- **B1** Content-Length vs observed body mismatch → `WAF_HTTP_SMUGGLING:CONTENT_LENGTH_MISMATCH`, `+4`.
- **B2** Suspicious method outside expected location (CONNECT to non-proxy, PROPFIND/SEARCH to non-DAV) → fold into existing exploit-method check, `+2`.
- **B3** Single URL segment ≥ 256 chars → `WAF_LONG_PATH`, `+3`; raise if high-entropy.
- **B4** Header bag total > 16 KB without large `Cookie`/`Authorization` → `WAF_HEADER_FLOOD`, `+3`.
- **B5** POST + empty UA + Content-Length:0 + URI ends in `.php`/`.phtml`/`.phar` → `WAF_WEBSHELL:PING` — **shipped at `logonly` (rule 411)**.

---

## Rollout playbook

1. Land each new detector as a **score signal** with mode `logonly`.
2. Replay one week of sanitized `access.cfm.log` traffic against it.
3. Replay attack samples (webshell uploads, reverse shells, CVE probes, miners).
4. Promote to `challenge` only after the rule fires on `<0.01%` of legit traffic in production.
5. Promote to `block` only after `challenge` mode produces no operator complaints for at least a week.
6. Every detector ships with a `rule_*` knob so it can be live-disabled via `_M.set_rule`.
7. False positives become tuning data: adjust score, context, or family — don't only disable.
8. Prefer combinations for noisy signals over standalone blocking.

---

## Expected invariant

A solved `cfm_clearance` means: "do not repeatedly challenge this client for the same gate." It never means: "trust this request payload" or "skip WAF inspection before origin."

---

## Adding a new detector

Follow the existing patterns; new code should look like the rules already in the file.

| Layer | What | Where |
|---|---|---|
| Engine | Severity-aggregation `_M.check`, post-clearance conversion, kill-switches, `ctx.skip_rule_ids` gate | `configs/lua/cfm_waf.lua` |
| Detectors | 48 detector functions invoked from `_M.check` (39 base + W1/R1/B5 + W4 polyglot + range/header_flood/long_path + log4shell + bad_utf8) | `configs/lua/cfm_waf_detectors.lua` |
| Util | `scan_str`, `normalize` (no-`%` fast path), `url_decode_once`, `header_string`, `body_budget` (Content-Type-keyed scan cap), IP literal helpers | `configs/lua/cfm_waf_util.lua` |
| Rule IDs | Stable 3-digit IDs, log-line plumbing, `/api/v1/waf/rules`, CLI | `configs/lua/cfm_waf.lua` (`RULE_IDS`), `internal/webdetector/waf_rule_ids.go` |
| Hit-rate | Per-rule rate gating, `/api/v1/waf/hit-rates`, JSON hit log; flush runs in `ngx.timer.at` so the request path never pays RPC latency | `configs/lua/cfm.lua` (`waf_insp_incr` + `maybe_flush_waf_insp`), `internal/webdetector/waf_hit_rates_api_handler.go` |
| Per-vhost exclusions | `excludeEntry.RuleIDs []int`, `--rule N\|Nxx\|N-M` CLI, `rule_ids` API param, `ctx.skip_rule_ids` Lua gate, vhost-controls panel toggle ignores rule-scoped entries | `internal/webdetector/exclude_store.go`, `exclude_rule_ids.go`, `cli_exclude.go`, `configs/lua/cfm.lua` (`waf_skip_for`) |
| CI | `Build & Test` job in `.github/workflows/security.yml` runs `go vet`, `make lua`, `make test-lua`, `check_*` shell guards alongside `go build` and `go test -race`. luajit installed explicitly per matrix run. | `.github/workflows/security.yml` |
| Security audit | Critical+High CodeQL alerts triaged 2026-05-09 (1 real XSS fixed, 10 FPs documented at the call sites). Inspector-as-attack-surface sweep summary in "Known gaps" item 8. | `docs/security/code-scanning-triage-2026-05-09.md` |
| Tests | Severity, post-clearance, rule ID drift, hit-rate aggregation, rule-id parsing, exclude-store match, jsStringLiteral XSS, panel forced-mode dispatch | `scripts/tests/cfm_*_test.lua`, `internal/webdetector/*_test.go` |
| Production analysis | 2026-05-08 dataset findings + per-rule recommendations | `docs/waf-analysis-2026-05-08.md` |

### How to add a new detector — template

Follow the existing patterns; new code should look like the rules already in the file. Rough recipe:

1. **Pick a rule name + ID.** CFG key like `rule_<short>_<short>`, ID in the right group (1xx-8xx; see "Rule IDs"). Add the entry to:
   - `configs/lua/cfm_waf.lua` CFG table (default mode — almost always `"logonly"` for new rules; see Rollout playbook)
   - `configs/lua/cfm_waf.lua` `RULE_IDS` table (assign next free ID in the appropriate 100-block)
   - `internal/webdetector/waf_rule_ids.go` `wafRuleIDs` slice (mirror of the Lua table — drift is caught by `TestWAFRuleIDs_LuaParity`)

2. **Write the detector function** in `configs/lua/cfm_waf_detectors.lua`. Conventions:
   - Pure function: `function _M.detect_<name>(args ...)`. Returns a tag string on hit, `nil` on miss.
   - Use `util.has`, `util.scan_str`, `util.url_decode_once` for input normalisation.
   - For body-only detectors, the engine already gates on `body_inspect_ok` (POST + non-empty body).
   - Cap scan length: respect `CFG.max_scan_len` (default 2048) or set a per-rule `CFG.<rule>_max_scan_len`.
   - Tags `SCREAMING_SNAKE_CASE`, conveying which sub-pattern matched (e.g. `PHTML`, `BASE64_BLOB`, `JNDI_LDAP`).

3. **Wire it into `_M.check`** in `configs/lua/cfm_waf.lua`. Add a numbered `do … end` block:

   ```lua
   -- ── NN) <Name> ───────────────────────────────────────────────────────
   do
     local mode = rule_mode(CFG.rule_<name>, "logonly")
     if mode ~= "disabled" and body_inspect_ok then  -- gate as needed
       local tag = det.detect_<name>(body, headers)
       if tag then
         local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
         if record("WAF_<FAMILY>:" .. tag, ttl, mode, RULE_IDS.rule_<name>) then goto done end
       end
     end
   end
   ```

   Always pass `RULE_IDS.rule_<name>` as the 4th `record()` arg — the test `TestWAFRuleIDs_LuaParity` and the hit-rate aggregation depend on it.

4. **High-risk?** If the rule is "block-on-detection" class (RCE, webshell, LFI, deserialization), add the family prefix to `_M.WAF_HIGH_RISK_REASONS`. This routes post-clearance challenges to `block` instead of `logonly`.

5. **Tests.** Add positive + negative cases to `scripts/tests/cfm_waf_severity_test.lua`. Pattern:

   ```lua
   do
     disable_all_rules()
     waf.set_rule("rule_<name>", "<expected mode>")
     local hit, reason, _ttl, action, _hits, waf_rule_id = waf.check(fresh_ctx({
       <field that triggers it>
     }))
     check(hit == true, "<NN>: <name> — hit=true")
     check(reason and reason:find("WAF_<FAMILY>", 1, true), "<NN>: reason prefix")
     check(action == "<expected>", "<NN>: action")
     check(waf_rule_id == <id>, "<NN>: rule id")
   end
   ```

   Also add at least one negative case (input that *shouldn't* trigger).

6. **Rollout.** Default mode for new rules is **always `logonly`** until hit-rate data justifies promotion. See [Operating the WAF](#operating-the-waf).

### Files you'll edit

| File | Why |
|---|---|
| `configs/lua/cfm_waf.lua` | CFG entry, RULE_IDS entry, `_M.check` call site |
| `configs/lua/cfm_waf_detectors.lua` | Detector function |
| `configs/lua/cfm_waf_util.lua` | New shared helpers (only if reused across multiple detectors) |
| `internal/webdetector/waf_rule_ids.go` | Mirror entry — drift caught by `TestWAFRuleIDs_LuaParity` |
| `scripts/tests/cfm_waf_severity_test.lua` | Positive + negative test cases |
| `docs/waf.md` | Rule IDs table — append the new ID |

### Don't do these things

- Don't promote a rule to `block` without one full week at `challenge` first. Operator complaints in week 1 of `challenge` are how you find the false positives.
- Don't add new helpers to `cfm_waf.lua` — they belong in `cfm_waf_util.lua`. If they need CFG, expose them via `_M.init(cfg)`.
- Don't bypass `record()` to handle a hit specially. The severity-aggregation engine is load-bearing.
- Don't renumber existing rule IDs. Operators reference them in tickets, exclusion lists, and dashboards.
- Don't add detectors that match Apache's default `Reject` patterns (`../`, certain methods); the prod analysis showed those are already handled upstream.

---

## Production data references

- `docs/waf-analysis-2026-05-08.md` — Tier 1/2/3 analysis of three production servers. **Read before adding rules in any family already represented**, to avoid recreating known-FP patterns. Key takeaways: Facebook scrapers hit `/.../<path>` literals (handled in `detect_traversal`'s FB-skip); vitolighting/3xK Tech is the canonical "scraper triggers `WAF_PROXY_HDR`" pattern, solved by per-vhost exclusions; `WAF_BAD_UA` scoring covers most scanner UAs without explicit per-tool literals.
- `docs/security/code-scanning-triage-2026-05-09.md` — Critical+High CodeQL alert triage from 2026-05-09 (1 real XSS fixed, 10 FPs documented, inspector-audit follow-ups).
- `cfm.waf.log` on a running production server — one JSON record per trigger; replay representative attack samples through a new detector before promoting.

---

## Expected invariant

A solved `cfm_clearance` means: "do not repeatedly challenge this client for the same gate." It never means: "trust this request payload" or "skip WAF inspection before origin."

---

# External reference audit (2026-05)

Audit of every CFM WAF detector against six reference projects, with
keep/borrow/integrate classification and ready-to-apply patches.

**Scope:** `configs/lua/cfm_waf.lua`, `cfm_waf_detectors.lua`,
`cfm_waf_util.lua`.

**Constraint:** LuaJIT FFI is acceptable in the hot path; cgo is not.
Anything requiring a Go-in-request boundary is out of scope today.

## Reference projects compared

| Tag | Project | Why it's here |
|-----|---------|---------------|
| **A** | [`corazawaf/libinjection-go`](https://github.com/corazawaf/libinjection-go) | Pure-Go libinjection port (used by Coraza). |
| **B** | [`wasilibs/go-libinjection`](https://github.com/wasilibs/go-libinjection) | WASM-wrapped libinjection via wazero. |
| **C** | [`corazawaf/coraza`](https://github.com/corazawaf/coraza) | Full Go WAF. Reference for operator set + CRS integration. |
| **D** | [`p0pr0ck5/lua-resty-libinjection`](https://github.com/p0pr0ck5/lua-resty-libinjection) | LuaJIT FFI binding with context-specific variants. **Most relevant to CFM.** |
| **E** | [`bungle/lua-resty-injection`](https://github.com/bungle/lua-resty-injection) | Minimal LuaJIT FFI binding (Kong author). |
| **F** | OWASP CRS | Rule-family comparison, not per-rule. |

## Detector inventory

Implementation locations and techniques. For the operator-facing Rule IDs
table, see [§ Rule IDs](#rule-ids) above.

| # | Category | Technique | File:line |
|---|----------|-----------|-----------|
| 1 | Traversal | `../` + null + double-encode + sensitive-sink whitelist | `cfm_waf_detectors.lua:64` |
| 2 | RCE | Substring list (JNDI, `;wget`, `\|bash`, backticks, `base64,`) | `cfm_waf_detectors.lua:102` |
| 3 | Exploit methods | TRACE / TRACK / CONNECT | `cfm_waf_detectors.lua:127` |
| 4 | PHP wrappers | `php://`, `phar://`, `data://`, `zip://`, `expect://`, `glob://` | `cfm_waf_detectors.lua:148` |
| 5 | Control chars | `[\x01-\x08\x0b\x0c\x0e-\x1f]` in args/body with CT gating | `cfm_waf_detectors.lua:192` |
| 6 | PHP webshell body | Scored: `<?php`+superglobals+exec-family+dyn-include+webshell-names | `cfm_waf_detectors.lua:241` |
| 7 | Base64 body scan | Greedy `=([A-Za-z0-9+/]+=*)`, decode, scan decoded for shells/SQL/PHP | `cfm_waf_detectors.lua:401` |
| 8 | XSS | Substring: `<script`, `=javascript:`, `onerror=`/`onload=`/… with `%f[%w]` anchor | `cfm_waf_detectors.lua:457` |
| 9 | SQLi | Substring: `union select`, `information_schema`, `or 1=1`, `' or '1'='1` (post comment-strip) | `cfm_waf_detectors.lua:486` |
| 10 | Auth burst | Endpoint-tagged shdict counter window | `cfm_waf_detectors.lua:547` |
| 11 | WP login probe | HEAD-burst window + no-UA/Referer POST | `cfm_waf_detectors.lua:581` |
| 12 | XMLRPC multicall/pingback | Body substring | `cfm_waf_detectors.lua:726` |
| 13 | XMLRPC POST burst | shdict counter | `cfm_waf_detectors.lua:749` |
| 14 | cmd param key | `exec=`, `passthru=`, …; `cmd/system/command` value-aware shelly check | `cfm_waf_detectors.lua:880` |
| 15 | cmd payload | `;wget`, `\|bash`, backtick-cmd, with search-field / `filters=` carve-outs | `cfm_waf_detectors.lua:920` |
| 16 | Debug toggles | `xdebug` / `debug=1` / `trace=1` by key+value | `cfm_waf_detectors.lua:1045` |
| 17 | PHP serialize | `O:N:"`/`C:N:"` plain & URL-encoded | `cfm_waf_detectors.lua:1090` |
| 18 | Bad UA (scored) | INSTANT tool UAs + 6-signal score (UA / method / headers / URI risk) | `cfm_waf_detectors.lua:1123` |
| 19 | Shellshock | `() {` in any header value (URL-decode once) | `cfm_waf_detectors.lua:1315` |
| 20 | Header vulns | `Proxy`, `Lock-Token`, `If`, CVE-2025-24813 | `cfm_waf_detectors.lua:1342` |
| 21 | CT anomaly | Charset bypass (IBM037 etc.), boundary count, non-string CT | `cfm_waf_detectors.lua:1384` |
| 22 | Proxy header SQLi | `'` in XFF / X-Real-IP / Client-IP | `cfm_waf_detectors.lua:1445` |
| 23 | SSRF proto | `file://`, `gopher://`, `dict://`, `ldap[s]://`, `tftp://`, `stratum+*://`, `sftp/ftp://` + octal/hex/dword IP in `://` ctx | `cfm_waf_detectors.lua:1476` |
| 24 | JS proto pollution | `__proto__`, `constructor` + `.prototype` / `[prototype` | `cfm_waf_detectors.lua:1517` |
| 25 | XXE | DOCTYPE / ENTITY + SYSTEM / PUBLIC | `cfm_waf_detectors.lua:1537` |
| 26 | CRLF | Raw and URL-encoded CRLF + header-keyword | `cfm_waf_detectors.lua:1567` |
| 27 | HTTP smuggling (body) | VERB SP PATH SP HTTP/N | `cfm_waf_detectors.lua:1598` |
| 28 | Upload filename | Quoted/single/unquoted multipart `filename=` + ext patterns + special names | `cfm_waf_detectors.lua:1632` |
| 29 | Upload content | Body substring `<?php`, `<?=`, `<jsp:`, `$_*` superglobals, ImageMagick MVG | `cfm_waf_detectors.lua:1700` |
| 30 | Script obfuscation | Shared scorer (long-b64 / decode-helpers / eval / atob / XOR / chr-storm) | `cfm_waf_detectors.lua:1730` + `cfm_waf_util.lua:115` |
| 31 | Upload obfuscation | Same scorer on multipart | `cfm_waf_detectors.lua:1753` |
| 32 | Webshell path | URI basename ∈ 28-name set | `cfm_waf_detectors.lua:1817` |
| 33 | Reverse shell | 24 literal one-liner needles | `cfm_waf_detectors.lua:1897` |
| 34 | Persistence | crontab / cron.d / systemd / bashrc / authorized_keys with `>>`/`>` | `cfm_waf_detectors.lua:1981` |
| 35 | Rootkit | `LD_PRELOAD=/`, `/etc/ld.so.preload`, `insmod /tmp/`, `/dev/mem` | `cfm_waf_detectors.lua:2013` |
| 36 | LOLbin | certutil / bitsadmin, `-EncodedCommand`, IEX, `wget -o /tmp/` | `cfm_waf_detectors.lua:2049` |
| 37 | Java deserialize | `\xac\xed\x00\x05` raw + `rO0AB` b64 + `aced0005` hex (body/cookie/auth/xff) | `cfm_waf_detectors.lua:2073` |
| 38 | Webshell ping | POST + empty UA + CL:0 + `.php` / `.phtml` / `.phar` URI | `cfm_waf_detectors.lua:2124` |
| 39 | C2 tunnel | 21 hostnames (pastebin, ngrok, webhook.site, discord cdn, telegram) | `cfm_waf_detectors.lua:2168` |
| 40 | Coinminer | xmrig / xmr-stak flags + pool hostnames + monerod / ethminer | `cfm_waf_detectors.lua:2218` |
| 41 | Smuggling CL/TE | CL+TE coexist / multi-CL / malformed CL / multi-TE | `cfm_waf_detectors.lua:2267` |
| 42 | Long path segment | ≥ 800 B segment with `data:` URI artifact carve-out | `cfm_waf_detectors.lua:2347` |
| 43 | Header flood | > 16 KB excluding Cookie / Authorization | `cfm_waf_detectors.lua:2374` |
| 44 | Polyglot upload | Multipart parser → first 64 B of image-claimed parts checked vs PHP/ASP/JSP/script openers | `cfm_waf_detectors.lua:2423` |
| 45 | Range abuse | `Request-Range`, multi `Range`, oversized, ≥ 8 ranges | `cfm_waf_detectors.lua:2533` |
| 46 | IP host | Host header is bare IPv4 / IPv6 literal | `cfm_waf_detectors.lua:162` |
| 47 | Log4Shell evasion | `${${::-j}…`, `${lower:j}…`, `${env:` / `sys:` / `main:` / `date:` / `base64:` in args+body+headers | `cfm_waf_detectors.lua` (`detect_log4shell`) |
| 48 | Bad UTF-8 | Overlong / surrogate / truncated multibyte in normalized args+body (Coraza `validateUtf8Encoding` port) | `cfm_waf_detectors.lua` (`detect_bad_utf8`) |
| — | Body budget by CT | json=32K / multipart=16K / xml=16K / urlencoded=8K / other=2K | `cfm_waf_util.lua:249` |
| — | Normalize | `url_decode_once × 2` + `lower`, with no-`%` fast path. **No UTF-8 / unicode normalization.** | `cfm_waf_util.lua:211` |

## Coverage matrix vs external projects

Cell values: **stronger** / **equivalent** / **weaker** / **none** / **different-scope**.

| Category | A — libinjection-go | B — wasilibs | C — Coraza | D — p0pr0ck5 | E — bungle | F — CRS |
|----------|---------------------|--------------|------------|--------------|------------|---------|
| SQLi | stronger (tokenizer + fingerprint) | stronger (same via WASM) | stronger (wraps A + CRS regex) | **stronger (FFI tokenizer + context variants)** | stronger (FFI, minimal API) | stronger (REQUEST-942) |
| XSS | stronger (HTML5 state machine) | stronger | stronger | **stronger (context-aware variants)** | stronger | stronger (REQUEST-941) |
| Traversal | none | none | equivalent (CRS-930 + `validateUrlEncoding`) | none | none | stronger |
| RCE | none | none | equivalent | none | none | stronger (CRS-932) |
| PHP wrappers | none | none | equivalent | none | none | equivalent (CRS-933) |
| Bad UA scoring | none | none | none | none | none | weaker (flat UA lists) |
| Header vulns | none | none | none | none | none | equivalent (CRS-921 / 944) |
| CT anomaly | none | none | different-scope (`validateByteRange`, `validateUtf8Encoding`) | none | none | equivalent (CRS-920) |
| Upload filename/content | none | none | different-scope | none | none | equivalent (CRS-953 / 954) |
| Polyglot upload | none | none | none | none | none | weaker |
| Webshell path / ping | none | none | none | none | none | weaker |
| Reverse shell / persistence / rootkit / lolbin | none | none | none | none | none | equivalent (CRS-932 unix tokens) |
| Java deserialize | none | none | none | none | none | equivalent (CRS-944) |
| C2 tunnel / coinminer | none | none | none | none | none | none |
| HTTP smuggling (CL/TE + body) | none | none | weaker | none | none | weaker |
| CRLF | none | none | weaker | none | none | equivalent (CRS-921) |
| Auth / XMLRPC bursts | different-scope | different-scope | different-scope (Coraza has no rate logic) | none | none | different-scope (CRS-DoS plugin) |
| Long path / header flood / range | none | none | equivalent (partial) | none | none | equivalent (CRS-920) |
| Normalize / decoding | none | none | **stronger** (`validateUtf8Encoding`, `t:normalizePath`, `t:cmdLine`, `t:cssDecode`, `t:jsDecode`) | none | none | stronger |
| SSRF proto | none | none | weaker | none | none | weaker (CRS-934) |
| JS proto pollution | none | none | none | none | none | equivalent (CRS-934) |
| XXE | none | none | equivalent | none | none | equivalent (CRS-934) |
| Proxy header SQLi | none | none | none | none | none | none |

**Net read:** the only two columns where any reference is meaningfully
stronger across CFM's workloads are libinjection (D / E) for SQLi + XSS
and Coraza's normalization operators (C) for encoding anomalies. The
rest of CFM's surface is either at parity with CRS or covers categories
no reference project covers at all (bad-UA scoring, webshell-name set,
auth / XMLRPC burst logic, C2 tunnel / coinminer fingerprints).

## Classification

### Integrate (wrap)

| Detector | Library | Reason |
|----------|---------|--------|
| `detect_sqli` | libinjection via D or E | Tokenizer covers bypasses (`UN/**/ION`, encoded comparators, stacked) that no substring list can keep up with. |
| `detect_xss` | libinjection via D | HTML5 state machine covers attribute / SVG / data-URI / mutation XSS contexts. |

### Borrow logic

| Detector | Source | What to borrow |
|----------|--------|----------------|
| `detect_proxy_header_sqli` | libinjection | Replace bare-`'` heuristic with `libinjection.sqli(header_value)`. |
| `detect_b64_injection` decoded buffer | libinjection | Run decoded base64 through `libinjection.sqli` / `libinjection.xss` instead of 30 substring tags. |
| New `detect_bad_utf8` | Coraza `validateUtf8Encoding` | Port the ~40-line algorithm. No FFI, no dependency. Closes an encoding-bypass gap nothing in CFM flags today. |

### Replace category

*None.* No category in CFM is so weak that a wholesale replacement beats
the current implementation plus targeted borrows.

### Keep as-is

All other categories are at parity or better than every reference
project for the workloads CFM targets, **or** cover a category no
reference project covers:

> traversal · rce · php_wrappers · ctrl_chars · php_webshell_body ·
> script_obfuscation · upload_obfuscation · upload_filename · upload_content
> · polyglot_upload · xxe · crlf · http_smuggling · smuggling_cl ·
> header_vulns · ct_anomaly · ssrf_proto · js_proto · ip_host ·
> php_serialize · java_deserialize · webshell_path · webshell_ping ·
> reverse_shell · persistence · rootkit · lolbin · c2_tunnel · coinminer ·
> exploit_method · shellshock · bad_ua_scored · debug_toggles ·
> cmd_params · cmd_payload · auth_burst · wp_login_probe ·
> xmlrpc_probe · xmlrpc_post_burst · long_path_segment · header_flood ·
> range_abuse

## Recommended actions (impact-ordered)

Every action ships in `logonly` first per the
[rollout playbook](#rollout-playbook) above.

### Action 1 — Integrate libinjection for SQLi

**Impact: highest.** `detect_sqli` is 7 substrings against an attack
surface (`UN/**/ION SE/**/LECT`, hex comparators, stacked queries,
encoded `OR/**/0x31=0x31`, MySQL `#` comments) that no substring set
can keep up with. libinjection's tokenizer reduces all of those to a
canonical fingerprint.

| Field | Value |
|-------|-------|
| **Target** | `p0pr0ck5/lua-resty-libinjection` (`libinjection.lua`) or `bungle/lua-resty-injection` (`resty.injection`) |
| **API used** | `libinjection.sqli(buf)` → `(bool, fingerprint_string)` |
| **Effort** | +20 LOC in `cfm_waf_detectors.lua`, +1 `require`, 0 LOC in engine |
| **Runtime cost** | One FFI call per request on the same `scan_str()` buffer; ~1–3 µs on 1–4 KB inputs vs. ~7 `string.find`s today. Net cost ≈ unchanged. |
| **Allocations** | Returns one Lua string fingerprint (~10 bytes). |
| **Migration** | Add `CFG.rule_sqli_libinjection = "logonly"`; run both for one week; compare hit-rates per rule ID 301; drop the legacy branch once parity confirmed. |

**Patch** — top of `cfm_waf_detectors.lua`, after `local _M = {}`:

```lua
-- libinjection FFI binding (p0pr0ck5 or bungle). Optional dependency:
-- if the module isn't installed the WAF falls back to the substring path.
local libinjection_ok, libinjection = pcall(require, "resty.libinjection")
if not libinjection_ok then
  libinjection_ok, libinjection = pcall(require, "libinjection")
end
if not libinjection_ok then
  libinjection_ok, libinjection = pcall(require, "resty.injection")
end
if not libinjection_ok then libinjection = nil end
```

Replace `detect_sqli` at `cfm_waf_detectors.lua:486`:

```lua
function _M.detect_sqli(uri, args, _s)
  local s = _s or scan_str(uri, args)
  if s == "" then return false end

  if libinjection then
    local sqli_fn = libinjection.sqli or libinjection.sql
    if sqli_fn then
      local is_sqli, fp = sqli_fn(s)
      if is_sqli then
        if type(fp) == "string" and #fp > 0 then
          _M._last_sqli_fp = string.sub(fp, 1, 32)
        end
        return true
      end
    end
  end

  -- Fallback / belt-and-braces: catches second-order injections that
  -- arrive already-decoded inside JSON values and libinjection abstains on.
  local sc = strip_sql_comments(s)
  if has(sc, "union select")              then return true end
  if has(sc, "union%20select")            then return true end
  if has(sc, "information_schema")        then return true end
  if has(sc, " or 1=1")                   then return true end
  if has(sc, " or%201=1")                 then return true end
  if has(sc, "' or '1'='1")               then return true end
  if has(sc, "%27%20or%20%271%27%3d%271") then return true end

  return false
end
```

### Action 2 — Integrate libinjection for XSS

**Impact: high.** `detect_xss` has 7 substrings; the HTML5 attack
surface has hundreds of evasions (attribute states, SVG, data-URI,
polyglots, mutation XSS).

| Field | Value |
|-------|-------|
| **Target** | Same module as Action 1 |
| **API used** | `libinjection.xss(buf)` → `bool`. Context variants (`xss_data_state`, `xss_noquote`, `xss_singlequote`, `xss_doublequote`, `xss_backquote`) available for later per-context tuning. |
| **Effort** | +12 LOC |
| **Runtime cost** | One FFI call, sharing Action 1's buffer. |
| **Migration** | `CFG.rule_xss_libinjection = "logonly"` for one week. |

**Patch** — replace `detect_xss` at `cfm_waf_detectors.lua:457`:

```lua
function _M.detect_xss(uri, args, _s)
  local s = _s or scan_str(uri, args)
  if s == "" then return false end

  if libinjection then
    local xss_fn = libinjection.xss
    if xss_fn and xss_fn(s) then return true end
  end

  if has(s, "<script")        or has(s, "%3cscript")  then return true end
  if has(s, "=javascript:")                            then return true end
  if has(s, "=\"javascript:")                          then return true end
  if has(s, "='javascript:")                           then return true end
  if has(s, "onerror=")     and string.find(s, "%f[%w]onerror=",     1, false) then return true end
  if has(s, "onload=")      and string.find(s, "%f[%w]onload=",      1, false) then return true end
  if has(s, "onmouseover=") and string.find(s, "%f[%w]onmouseover=", 1, false) then return true end
  if has(s, "onfocus=")     and string.find(s, "%f[%w]onfocus=",     1, false) then return true end

  return false
end
```

### Action 3 — Borrow libinjection for `detect_proxy_header_sqli`

**Impact: medium.** The current `'`-in-XFF heuristic produces FPs on
legit Cyrillic vendor names in proxy headers and misses real header
SQLi that doesn't use a literal quote.

| Field | Value |
|-------|-------|
| **Target** | Same `libinjection.sqli` call as Action 1 |
| **Effort** | +6 LOC |
| **Runtime cost** | ≤ 4 FFI calls per request (one per proxy header present), each on a < 128-byte string — sub-microsecond. |
| **Migration** | New tag `PROXY_HDR_SQLI_LIBI:<hname>` for one week, then drop the bare-`'` fallback. |

**Patch** — replace `detect_proxy_header_sqli` body at `cfm_waf_detectors.lua:1445`:

```lua
function _M.detect_proxy_header_sqli(headers)
  headers = headers or {}
  local suspects = {
    ["x-forwarded-for"] = headers["x-forwarded-for"] or headers["X-Forwarded-For"],
    ["x-real-ip"]       = headers["x-real-ip"]       or headers["X-Real-IP"],
    ["client-ip"]       = headers["client-ip"]        or headers["Client-IP"],
    ["x-client-ip"]     = headers["x-client-ip"]      or headers["X-Client-IP"],
  }
  local sqli_fn = libinjection and (libinjection.sqli or libinjection.sql)
  for hname, hval in pairs(suspects) do
    if hval ~= nil then
      local s = header_string(hval)
      if s ~= "" then
        if sqli_fn then
          if sqli_fn(s) then return "PROXY_HDR_SQLI:" .. hname end
        else
          if has(s, "'") then return "PROXY_HDR_SQLI:" .. hname end
        end
      end
    end
  end
  return nil
end
```

### Action 4 — Borrow libinjection for `detect_b64_injection`

**Impact: medium.** Three existing tags (`B64_SQLI_UNION`,
`B64_SQLI_INSERT`, `B64_SQLI_SCHEMA`) reimplement what libinjection
does, while missing obfuscated-then-base64'd SQLi like `UN/**/ION`
inside the decoded buffer.

| Field | Value |
|-------|-------|
| **Target** | `libinjection.sqli` / `libinjection.xss` from Action 1 |
| **Effort** | +8 LOC; retains all PHP-callable branches (libinjection has no PHP semantics). |
| **Runtime cost** | Zero net — replaces three existing `has()` calls per decoded candidate. |
| **Migration** | New tags `B64_SQLI_LIBI` / `B64_XSS_LIBI`; keep existing tags as belt-and-braces; one-week observation. |

**Patch** — inside the loop at `cfm_waf_detectors.lua:409`, insert after
`local d = string.lower(decoded)` and before the existing SQL/XSS
substring branches:

```lua
        if libinjection then
          local sqli_fn = libinjection.sqli or libinjection.sql
          if sqli_fn and sqli_fn(d) then return "B64_SQLI_LIBI" end
          if libinjection.xss and libinjection.xss(d) then return "B64_XSS_LIBI" end
        end
```

Leave every other branch in place — they cover PHP-semantic markers
libinjection cannot judge.

### Action 5 — Port Coraza's `validateUtf8Encoding` as a new detector

**Impact: medium-low** (additive coverage, not improving an existing
detector). Malformed UTF-8 surviving `normalize()` (overlong sequences,
lone surrogates, truncated multibyte starters) is a classic encoding-
bypass primitive that no CFM rule flags today.

| Field | Value |
|-------|-------|
| **Target** | `corazawaf/coraza` → `internal/operators/validate_utf8_encoding.go` |
| **Effort** | New detector ≈ 35 LOC; new rule ID `rule_bad_utf8 = 611`; 1 callsite in engine. No FFI. |
| **Runtime cost** | One byte-walk over the normalized scan buffer — cheaper than `string.lower`. Allocates nothing. |
| **Migration** | `logonly` for ≥ 2 weeks (legacy ISO-8859-1 form encodings need to be observed first). |

**Patch — new function** in `cfm_waf_detectors.lua`:

```lua
-- Port of Coraza's validateUtf8Encoding operator (internal/operators/
-- validate_utf8_encoding.go). Returns tag on first invalid sequence,
-- nil if the buffer is clean UTF-8 (or pure ASCII).
--
-- Flags:
--   * Overlong 2/3/4-byte encoding of a codepoint that fits in fewer bytes
--   * Truncated multibyte sequence (high bit set, missing continuation)
--   * Lone or out-of-order continuation byte
--   * Codepoint > U+10FFFF or in the U+D800–U+DFFF surrogate range
function _M.detect_bad_utf8(args, body, _ns)
  local s = _ns or normalize(cap((args or "") .. "&" .. (body or ""), CFG.max_scan_len))
  local n = #s
  local i = 1
  while i <= n do
    local b = s:byte(i)
    if b < 0x80 then
      i = i + 1
    else
      local need, min_cp
      if     b >= 0xF0 and b <= 0xF4 then need, min_cp = 3, 0x10000
      elseif b >= 0xE0 and b <= 0xEF then need, min_cp = 2, 0x800
      elseif b >= 0xC2 and b <= 0xDF then need, min_cp = 1, 0x80
      else
        return "UTF8_BAD_LEAD"
      end
      if i + need > n then return "UTF8_TRUNC" end
      local cp
      if need == 1 then
        cp = (b - 0xC0) * 64
      elseif need == 2 then
        cp = (b - 0xE0) * 4096
      else
        cp = (b - 0xF0) * 262144
      end
      for k = 1, need do
        local c = s:byte(i + k)
        if not c or c < 0x80 or c > 0xBF then return "UTF8_BAD_CONT" end
        cp = cp + (c - 0x80) * (64 ^ (need - k))
      end
      if cp < min_cp then return "UTF8_OVERLONG" end
      if cp >= 0xD800 and cp <= 0xDFFF then return "UTF8_SURROGATE" end
      if cp > 0x10FFFF then return "UTF8_OUT_OF_RANGE" end
      i = i + need + 1
    end
  end
  return nil
end
```

**Engine wire-up** (`cfm_waf.lua`): add `rule_bad_utf8 = "logonly"` to
CFG, `rule_bad_utf8 = 611` to RULE_IDS, and insert after the existing
ctrl-chars block (~ line 695):

```lua
  -- ── 12a) Bad UTF-8 encoding (Coraza validateUtf8Encoding port) ───────────
  do
    local mode = rule_mode(CFG.rule_bad_utf8, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_bad_utf8(args, body, get_norm_ab())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BAD_UTF8:" .. tag, ttl, mode, RULE_IDS.rule_bad_utf8) then goto done end
      end
    end
  end
```

## Audit rollout checklist

1. [ ] **Action 1 — SQLi:** ship behind `rule_sqli_libinjection = "logonly"`. Compare hit-rates against rule 301 for ≥ 7 days. Promote and drop fallback once parity confirmed.
2. [ ] **Action 2 — XSS:** ship behind `rule_xss_libinjection = "logonly"`. Compare against rule 302 for ≥ 7 days. Promote.
3. [ ] **Action 3 — Proxy header SQLi:** new tag `PROXY_HDR_SQLI_LIBI:*`. Compare against `PROXY_HDR_SQLI:*` for ≥ 7 days. Drop fallback.
4. [ ] **Action 4 — Base64 decoded buffer:** new tags `B64_SQLI_LIBI` / `B64_XSS_LIBI`. Keep existing tags indefinitely; libinjection augments them, doesn't replace them.
5. [x] **Action 5 — Bad UTF-8:** **DONE** — `detect_bad_utf8` shipped as rule 611 at `logonly`. Coraza `validateUtf8Encoding` port; flags overlong / surrogate / truncated multibyte sequences in args+body. Promotion requires `cfm webtop waf hit-rates --hours 336` `ok_to_promote`.

## Audit — out of scope

- **Coraza as a runtime layer:** Go process + thousands of CRS regexes, large surface overlap with existing CFM detectors. Cost > benefit for CFM's workloads.
- **CRS rule import:** every category where CRS is "stronger" in the matrix is one where CFM already has a workload-tuned equivalent. Importing CRS rules would add FP load without closing a real gap.
- **`wasilibs/go-libinjection`:** WASM via wazero implies a Go boundary; CFM has no Go in the request path today.
- **Replacing curated lists** (webshell names, C2 hostnames, coinminer pools, reverse-shell one-liners) with CRS PM lists: CFM's lists are smaller, signal-confirmed, and FP-tested against actual mars / virgo / orion traffic samples.
