# CFM WAF and Challenge-Clearance Boundary

## Status

The WAF rebuild is complete. **51 detectors across 9 rule-ID groups** (1xx-9xx)
inspect every dynamic request before it reaches origin. Severity-aggregation
returns the strongest rule's action; per-vhost exclusions let operators
whitelist specific rules on noisy hosts; hit-rate counters and a sampled hit
log give operators data-driven evidence before promoting any rule from
`logonly` to `challenge` to `block`.

Open follow-ups (none blocking):

- **C3 — CVE signature file infrastructure** (`/etc/cfm/cve_signatures.txt` with
  hot-reload). Deferred until there's a concrete CVE pipeline to feed it.
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
| `review` | 0.01% ≤ rate < 1% | Investigate FP candidates in `cfm.waf.sampled.log` before promoting. Tighten the rule or add per-vhost exclusions for noisy hosts. |
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
- **`review`/`noisy` rules** — feed real samples from `cfm.waf.sampled.log` to
  see what triggers them.
- **New detectors** — sanity-check before pushing to production.

### Investigating FPs in `cfm.waf.sampled.log`

Production-side, a configurable fraction of WAF hits (`CFM_WAF_SAMPLE_RATE`,
default `0.01` = 1%) gets a richer entry in `cfm.waf.sampled.log` carrying
UA, Referer, Content-Type, ASN, country. Format: one JSON object per line.

```bash
# Hits for a specific rule
grep '"waf_rule_id":410' /var/log/cfm/cfm.waf.sampled.log | jq

# Hits with a specific reason family
grep '"reason":"WAF_DYN_INCLUDE' /var/log/cfm/cfm.waf.sampled.log | jq

# Last 24h of hits on a specific vhost
grep '"host":"example.com"' /var/log/cfm/cfm.waf.sampled.log | jq
```

The compact `cfm.waf.log` is for high-volume monitoring. The sampled log is
for FP investigation — that's why the extra fields are there.

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
cfm webtop exclude add <host> <path> --rule N|Nxx|N-M[,…]
cfm webtop exclude add <host> <path>          # whole-WAF entry (no --rule flag)
cfm webtop exclude remove <host> <path> --rule …
```

Rule-ID spec accepts:

- Bare ID: `--rule 320`
- Wildcard: `--rule 3xx` → expanded to 300-399 at parse time
- Range: `--rule 310-317`
- List: `--rule 320,3xx,605` (deduped)

### API

`POST /api/v1/exclude` accepts `rule_ids` as a CSV string in the same spec format. Empty / missing → whole-WAF entry.

`GET /api/v1/exclude` returns each entry's `rule_ids` (sorted, deduped) when set; the field is omitted otherwise.

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

### Sampled hit log

A configurable fraction of WAF triggers (`CFM_WAF_SAMPLE_RATE`, default `0.01` = 1%) gets a richer entry in `cfm.waf.sampled.log`. Format: one JSON object per line.

```json
{"ip":"1.2.3.4","host":"example.com","uri":"/admin/upload",
 "method":"POST","action":"block","reason":"WAF_UPLOAD_FNAME:PHTML",
 "waf_rule_id":401,"ttl_sec":3600,
 "ua":"curl/7.81.0","referer":"","ct":"multipart/form-data; boundary=...",
 "asn":12345,"asn_name":"EXAMPLE-AS","country":"US"}
```

The compact `cfm.waf.log` stays for high-volume monitoring. Operators tail `cfm.waf.sampled.log` for FP investigation.

### Cost / regression notes

| Path | Cost | Notes |
|---|---|---|
| Per WAF check | ~3-5µs | Two shdict incr + one get-and-compare. <1% of WAF check cost. |
| Per flush (~1/min cluster-wide) | ~3µs on the lock winner | Snapshot+RPC runs in `ngx.timer.at(0, …)`; RPC latency is 100% off the request path. |
| Sampling (per request) | sub-µs | `math.random() < sr` and integer compare. |
| Sampled trigger (1% of triggers) | ~50µs | Three extra string fields in JSON + one file write. |
| `/api/v1/waf/hit-rates` | <100ms typical | `json_extract` is O(N events in window); operator-pulled, never on hot path. |

Backward compat: all new wire fields are `omitempty`; `CREATE TABLE IF NOT EXISTS` upgrades existing SQLite DBs silently.

Kill switches: `CFM_WAF_STATS_ENABLE=0` disables counters + flushing; `CFM_WAF_SAMPLE_RATE=0` disables sampled log.

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
| `CFM_WAF_BODY_MAX_LEN` | `8192` | int (bytes) | Body cap for inspection. Larger bodies skip body-content rules. |
| `CFM_WAF_STATS_ENABLE` | `1` | `0`, `1` | Per-rule hit-rate counters + flush. |
| `CFM_WAF_SAMPLE_RATE` | `0.01` | float in [0,1] | Fraction of WAF triggers that get a sampled-log entry. |

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
```

A reason in this list, when fired with `challenge` action under valid clearance, gets converted to `block` instead of `logonly`. Matched against the prefix before the first `:` so `WAF_RCE:REVERSE_SHELL:BASH_TCP` still hits.

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

1. **Body truncation.** `CFM_WAF_BODY_MAX_LEN=8192` means uploads/payloads larger than 8 KB skip body-inspection rules silently. Either raise the cap for upload endpoints or stream-inspect.
2. **shdict pressure.** Auth-burst and hit-rate counters use shdict. Per-rule benchmarks needed before scaling counter usage further.
3. **Per-rule kill-switch audit.** `set_rule()` exists; not every detector is reachable through a `rule_*` CFG key. Audit + fill gaps.
4. **Push payload uses post-conversion action.** `cfm.lua:1127` pushes `action=logonly` after challenge→logonly conversion. Probably correct (push the effective action) but confirm with Go-side consumers.
5. **Route log loses post-clearance signal.** The `waf_logonly` / `waf_block` log line at `cfm.lua:1131` after conversion doesn't say "from challenge". The separate `waf_post_clearance_convert` line at `cfm.lua:1089` carries it; correlation is by IP+timestamp.
6. **Inspector-as-attack-surface follow-ups (2026-05-09 audit).** Items not fully audited: (a) caller traces for the remaining `os.Open`/`os.ReadFile` sites in `cpanel_api_handlers.go` and `challenge_server.go` outside the `cpanelUserExists`-gated path; (b) spot-check of the more exotic Lua patterns in `cfm_waf_detectors.lua` for polynomial-time backtracking; (c) per-field length bounds in bridge JSON handlers (the body is wrapped in `MaxBytesReader` but individual fields like `host` can still land 16 KB in memory); (d) `dispatchHook` channel-saturation behaviour under load. None block production; worth a dedicated `claude/inspector-audit-*` pass when there's space.

---

## Adding a new detector

Follow the existing patterns; new code should look like the rules already in the file.

1. **Pick a rule name + ID.** CFG key like `rule_<short>_<short>`, ID in the right group (1xx-9xx; see [Rule IDs](#rule-ids)). Add the entry to:
   - `configs/lua/cfm_waf.lua` CFG table (default mode — almost always `"logonly"` for new rules)
   - `configs/lua/cfm_waf.lua` `RULE_IDS` table (next free ID in the appropriate 100-block)
   - `internal/webdetector/waf_rule_ids.go` `wafRuleIDs` slice — drift caught by `TestWAFRuleIDs_LuaParity`

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
- `cfm.waf.log` and `cfm.waf.sampled.log` on a running production server — replay representative attack samples through a new detector before promoting.

---

## Expected invariant

A solved `cfm_clearance` means: "do not repeatedly challenge this client for the same gate." It never means: "trust this request payload" or "skip WAF inspection before origin."
