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
                                       421  rule_php_split_string_canary
                                       422  rule_php_dropper_wget_curl
                                       423  rule_php_dropper_markers
                                       424  rule_php_filesize_recon
                                       425  rule_php_touch_antiforensic

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
WAF_DROPPER
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

The original detector / engine roadmap is shipped end-to-end. Every item is now in production at the `logonly` → `challenge` → `block` stage documented per rule in the [Rule IDs](#rule-ids) table; the **Outstanding** list at the bottom is the only forward-looking work.

### Shipped

| Item | Rule(s) | Notes |
|---|---|---|
| File split of `cfm_waf.lua` into `cfm_waf_util.lua` + `cfm_waf_detectors.lua` + engine | — | foundation; lets each detector tag header/uri/body/multipart surface |
| **C1** Log4Shell (bare `${jndi:` + lookup-syntax evasions) | 320, 328 | bare forms in `detect_rce` at `block`; evasion variants (`${${::-j}…`, `${lower:j}`, `${env:` etc.) in `detect_log4shell` at `logonly` |
| **C2** Java deserialization (`rO0AB…`, `\xac\xed\x00\x05`) | 326 | scans body / Cookie / Authorization / X-Forwarded-* |
| **R1** Reverse-shell one-liners (`bash -i >& /dev/tcp/`, `python -c 'import socket'`, `socat tcp-connect`, …) | 322 | 24 literal needles |
| **R2** Persistence (cron / systemd / bashrc / authorized_keys) | 323 | |
| **R3** Rootkit artifacts (`LD_PRELOAD`, `/etc/ld.so.preload`, `/dev/mem`) | 324 | |
| **R4** LOLbins (`certutil -urlcache`, `bitsadmin /transfer`, `-EncodedCommand`, `iex(iwr`) | 325 | scores with base64 detector when combined |
| **W1** Known webshell path names (`/c99.php`, `/r57.php`, …) | 410 | 28-name set, URI basename match |
| **W2** Webshell magic strings in body (`b374k`, `WSO 2.5`, `@eval(`, …) | 404 | scored; covers `b374k` / `c99shell` / `r57shell` / `wso 2./4./5.` / `weevelyshell` / `filesman` |
| **W3** PHP function obfuscation (`\x65val`, `chr().chr()…`, `hex2bin($_POST[`) | 405 | shared scorer across body and upload paths |
| **W4** Polyglot upload (image CT/ext + `<?php`/`<?=`/`<%`/`<script` in first 64 B) | 412 | required a multipart parser; also unblocked W2/W3 in upload context |
| **X1** C2 tunnel hostnames (pastebin, ngrok, webhook.site, discord cdn, telegram) | 702 | 21 hostnames |
| **X2** Coinminer (`xmrig --url`, `pool.minexmr.com`, `stratum+tcp://`, monerod, ethminer) | 327 | |
| **B1** HTTP smuggling (CL+TE coexist / multi-CL / malformed CL / multi-TE) | 608 | header-shape detector |
| **B3** Single URL segment ≥ 800 B | 102 | with `data:` URI artifact carve-out |
| **B4** Header bag > 16 KB excluding Cookie / Authorization | 609 | |
| **B5** POST + empty UA + Content-Length:0 + `.php` / `.phtml` / `.phar` URI | 411 | cheap, high-confidence webshell-ping fingerprint |
| Bad UTF-8 encoding (Coraza `validateUtf8Encoding` port) | 611 | overlong / surrogate / truncated multibyte in args+body |
| Range abuse (Apache Killer / `Request-Range` / multi-Range) | 610 | |
| **PHP dropper / canary family** (split-string exec-probes, wget+curl fallback droppers, `!success!`/`!ended!` markers, `<fs>` filesize recon, `@touch()` mtime backdating) | 421-425 | new `WAF_DROPPER` reason family; source workload was a 2026-05-19 shared-hosting compromise |
| Hit-rate counter + sampled hit log | — | see [Hit-rate measurement](#hit-rate-measurement) |
| Stable rule IDs + per-vhost rule exclusions (`SecRuleRemoveById`-style) | — | see [Rule IDs](#rule-ids) and [Per-vhost rule exclusions](#per-vhost-rule-exclusions); solves the vitolighting/3xK Tech-style FP cleanly without disabling whole-host WAF |

### Outstanding

| Item | Why deferred | Size |
|---|---|---|
| **B2** Suspicious method outside expected location (CONNECT to non-proxy, PROPFIND/SEARCH to non-DAV) — fold into the existing exploit-method check, `+2` | Low absolute volume in production; existing `rule_exploit_methods` (607) already covers the common cases | S |
| **Panel DNAT WAF profile** for cPanel / DirectAdmin file managers, backup restore, plugin/theme editors | Needs panel-session context plumbing; primary trigger is hijacked-panel webshell uploads which are currently caught at the body-inspection layer (404 / 405 / 412) | L |

---

## Implementation map

Where each layer lives in the tree:

| Layer | What | Where |
|---|---|---|
| Engine | Severity-aggregation `_M.check`, post-clearance conversion, kill-switches, `ctx.skip_rule_ids` gate | `configs/lua/cfm_waf.lua` |
| Detectors | 48 detector functions invoked from `_M.check` (base set + W1/R1/B5 + W4 polyglot + range/header_flood/long_path + log4shell + bad_utf8) | `configs/lua/cfm_waf_detectors.lua` |
| Util | `scan_str`, `normalize` (no-`%` fast path), `url_decode_once`, `header_string`, `body_budget` (Content-Type-keyed scan cap), IP literal helpers | `configs/lua/cfm_waf_util.lua` |
| Rule IDs | Stable 3-digit IDs, log-line plumbing, `/api/v1/waf/rules`, CLI | `configs/lua/cfm_waf.lua` (`RULE_IDS`), `internal/webdetector/waf_rule_ids.go` |
| Hit-rate | Per-rule rate gating, `/api/v1/waf/hit-rates`, JSON hit log; flush runs in `ngx.timer.at` so the request path never pays RPC latency | `configs/lua/cfm.lua` (`waf_insp_incr` + `maybe_flush_waf_insp`), `internal/webdetector/waf_hit_rates_api_handler.go` |
| Per-vhost exclusions | `excludeEntry.RuleIDs []int`, `--rule N\|Nxx\|N-M` CLI, `rule_ids` API param, `ctx.skip_rule_ids` Lua gate, vhost-controls panel toggle ignores rule-scoped entries | `internal/webdetector/exclude_store.go`, `exclude_rule_ids.go`, `cli_exclude.go`, `configs/lua/cfm.lua` (`waf_skip_for`) |
| CI | `Build & Test` job in `.github/workflows/security.yml` runs `go vet`, `make lua`, `make test-lua`, `check_*` shell guards alongside `go build` and `go test -race`. luajit installed explicitly per matrix run. | `.github/workflows/security.yml` |
| Tests | Severity, post-clearance, rule ID drift, hit-rate aggregation, rule-id parsing, exclude-store match, jsStringLiteral XSS, panel forced-mode dispatch | `scripts/tests/cfm_*_test.lua`, `internal/webdetector/*_test.go` |

## Production data references

- `docs/waf-analysis-2026-05-08.md` — Tier 1/2/3 analysis of three production servers. **Read before adding rules in any family already represented**, to avoid recreating known-FP patterns. Key takeaways: Facebook scrapers hit `/.../<path>` literals (handled in `detect_traversal`'s FB-skip); vitolighting/3xK Tech is the canonical "scraper triggers `WAF_PROXY_HDR`" pattern, solved by per-vhost exclusions; `WAF_BAD_UA` scoring covers most scanner UAs without explicit per-tool literals.
- `docs/security/code-scanning-triage-2026-05-09.md` — Critical+High CodeQL alert triage from 2026-05-09 (1 real XSS fixed, 10 FPs documented, inspector-audit follow-ups).
- `cfm.waf.log` on a running production server — one JSON record per trigger; replay representative attack samples through a new detector before promoting.

---

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
| 49 | PHP split-string canary (421) | `<?php print "A"."B";exit;` exec-test probe; print/echo/die + quoted-string concat + whole-word `exit`/`die`, no control-flow disqualifiers | `cfm_waf_detectors.lua` (`detect_php_split_string_canary`) |
| 50 | PHP wget+curl dropper (422) | `wget -O` + `curl -o` fallback pair + `filesize()` integrity + `@touch(`/`file_exists(` | `cfm_waf_detectors.lua` (`detect_php_dropper_wget_curl`) |
| 51 | PHP dropper markers (423) | `'!success!'` + `'!ended!'` literals + `die(`/`exit(` framing | `cfm_waf_detectors.lua` (`detect_php_dropper_markers`) |
| 52 | PHP filesize recon (424) | `<fs>` literal tag + `filesize(` + `SCRIPT_FILENAME` reference | `cfm_waf_detectors.lua` (`detect_php_filesize_recon`) |
| 53 | PHP touch anti-forensic (425) | `@touch(<path>, <literal-unix-ts>)` mtime backdating + paired file-write primitive | `cfm_waf_detectors.lua` (`detect_php_touch_antiforensic`) |
| — | Body budget by CT | json=32K / multipart=16K / xml=16K / urlencoded=8K / other=2K | `cfm_waf_util.lua:249` |
| — | Normalize | `url_decode_once × 2` + `lower`, with no-`%` fast path. **No UTF-8 / unicode normalization.** | `cfm_waf_util.lua:211` |

## Coverage matrix vs external projects

Cell values: **stronger** / **equivalent** / **weaker** / **none** / **different-scope**.

Column key — **A** `corazawaf/libinjection-go` (pure-Go libinjection port) · **B** `wasilibs/go-libinjection` (WASM via wazero) · **C** `corazawaf/coraza` (full Go WAF) · **D** `p0pr0ck5/lua-resty-libinjection` (LuaJIT FFI binding, most relevant to CFM) · **E** `bungle/lua-resty-injection` (minimal LuaJIT FFI binding) · **F** OWASP CRS.

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

