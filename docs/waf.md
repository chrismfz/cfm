# CFM WAF and Challenge-Clearance Boundary

## Status

| Step | What | State |
|------|------|-------|
| 1 | `cfm_waf.lua` `_M.check` returns highest-severity match (was first-match) | DONE |
| 2 | `cfm.lua` runs WAF before honoring `cfm_clearance` | DONE |
| 3 | Post-clearance `challenge` is converted, never re-prompted | DONE |
| 4 | Lua unit tests for Steps 1-3 | DONE |
| 5 | Static-asset bypass at nginx layer | DONE |
| 6 | Production WAF log analysis + first-pass rule tuning | DONE — see `docs/waf-analysis-2026-05-08.md` |
| 7 | Split `cfm_waf.lua` into engine / detectors / util files | DONE |
| 8 | Stable numeric rule IDs (PR A of #10 below) — log line, `/api/v1/waf/rules`, CLI | DONE |
| 9 | Hit-rate counters + sampled hit log — per-rule rate gates promotions, sampled log carries UA/Referer/CT for FP investigation. `/api/v1/waf/hit-rates`, `cfm webtop waf hit-rates`, `cfm.waf.sampled.log`. | DONE |
| 10 | Per-vhost per-rule exclusions (PR B of #10) — `excludeEntry.RuleIDs []int`, `--rule N\|Nxx\|N-M` CLI flag, `rule_ids` API query param, `ctx.skip_rule_ids` gating inside `record()`. | DONE — see "Per-vhost rule exclusions" below |
| 11 | CI hardening — `Build & Test` job in `.github/workflows/security.yml` now installs `luajit`, then runs `check_cli_transport.sh`, `check_cfm_clearance_require.sh`, `make lua`, `make test-lua`, `go vet ./...`, `go build ./...`, `go test -race -v ./...`. Catches Lua syntax breakage, Lua-test regressions, mutex-copy / atomic-copy / duplicate-JSON-tag bugs at PR time. Four `go vet` issues that had sat in `main` were closed alongside (`unblock`, `telemetry`, `apiserver/detectors_api`, `cli/firewall_status`). | DONE |
| 12 | Code-scanning triage (Critical+High, 2026-05-09) — 11 CodeQL alerts triaged: one real reflected XSS in `jsStringLiteral` fixed (was `strconv.Quote` only, didn't escape `<`/`>`/`&`/U+2028/U+2029, allowed `?next=` payloads to break out of `<script>` context), one defence-in-depth `int32` clamp on `nftables.ChainPriority`, nine FPs documented inline at the call sites. See `docs/security/code-scanning-triage-2026-05-09.md`. | DONE |
| 13 | Phase 1 detectors at `logonly` — W1 (rule 410, `WAF_WEBSHELL:PATH:<basename>`), R1 (rule 322, `WAF_RCE:REVERSE_SHELL:<tag>`), B5 (rule 411, `WAF_WEBSHELL:PING`). All ship `logonly` per the rollout playbook; promote individually after `cfm webtop waf hit-rates --hours 168` shows `ok_to_promote`. `WAF_WEBSHELL` added to `WAF_HIGH_RISK_REASONS` so post-clearance routing is correct when promoted. | DONE |
| 14 | Cross-phase duplication audit — **C1 dropped** (Log4Shell `${jndi:` already covered by `detect_rce` rule 320), **W2/W3 reclassified as extensions** of rules 404/405, **B2 reclassified as a tightening** of rule 607, **R4 trimmed** to remove overlap with R1's REVERSE_SHELL table. | DONE |
| 15 | Phase 2 detectors at `logonly` — R2 (rule 323, `WAF_RCE:PERSISTENCE:<tag>`), R3 (rule 324, `WAF_RCE:ROOTKIT:<tag>`), R4 (rule 325, `WAF_RCE:LOLBIN:<tag>`). All emit family `WAF_RCE` so they share rule_rce's high-risk post-clearance routing. | DONE |
| 16 | Phase 3/4/5 cross-phase duplication audit — **C1 already dropped** (rule 320), **C2/C3 are genuinely new** (Java deserialize / signature file infra), **X1 new** (tunnel/paste hostnames not covered by `detect_ssrf_proto`), **X2 has a half-overlap** on `stratum+tcp://` with rule 701 (design call: add as a tag inside 701 instead of duplicating in X2), **B1/B3/B4 new** (length mismatch / segment length / header-bag size are not covered by existing rules), **B2 already reclassified** as extension of rule 607 (row 14). | DONE |
| 17 | Phase 3 detector at `logonly` — C2 (rule 326, `WAF_RCE:JAVA_DESERIALIZE:<tag>`). Detects Java ObjectOutputStream payloads via three wire forms: raw `0xAC 0xED 0x00 0x05` magic in body, base64 prefix `rO0AB` (case-insensitive), or `aced0005` hex literal. Searched in args, body, and the standard gadget-vector headers (Cookie, Authorization, X-Forwarded-For). Disjoint from PHP serialize (rule 306) — neither rule shadows the other. C3 (`/etc/cfm/cve_signatures.txt` hot-reload) is deferred to its own infra PR. | DONE |
| 18 | Roadmap-extension tweaks (no new rule IDs). **W2** webshell self-identifying literals (`b374k`, `c99shell`, `r57shell`, `indoxploit`, `0byt3m1n1`, `weevelyshell`, `wso 2./4./5.`, `<title>c99`, `<title>r57`) folded into rule 404 with `RAW_WS_<NAME>` sub-tags that outrank the generic `RAW_*` set. **W3** `hex2bin(` added to `score_obfuscation_blob` (rule 405) at +2 weight. **B2** `detect_exploit_method` (rule 607) refactored to emit method sub-tags: `WAF_EXPLOIT_METHOD:TRACE` / `:TRACK` / `:CONNECT_NOT_PROXY` / `:DAV_PROPFIND` / `:DAV_SEARCH`. **X2/rule-701 design call resolved**: `stratum+tcp://` and `stratum+ssl://` folded into `detect_ssrf_proto` as `SSRF_STRATUM`; future X2 rule will then cover only the tool/pool fingerprints. | DONE |
| 19 | Phase 4 + Phase 5 detectors at `logonly` — **X1** (rule 702, `WAF_C2:TUNNEL:<host>`) tunnel/paste hostnames in args+body (pastebin raw, gist raw, webhook.site, ngrok, transfer.sh, Discord/Telegram CDN, …); **X2** (rule 327, `WAF_RCE:COINMINER:<tag>`) coinminer tool/pool fingerprints (xmrig flags, public XMR pool hostnames, monerod / ethminer); **B1** (rule 608, `WAF_HTTP_SMUGGLING:<tag>`) CL/TE smuggling header pairs — `CL_AND_TE`, `MULTI_CL`, `MULTI_TE`, `CL_MALFORMED`; **B3** (rule 102, `WAF_LONG_PATH:SEG_<len>`) single URL path segment ≥ 256 chars; **B4** (rule 609, `WAF_HEADER_FLOOD:FLOOD:<bytes>`) total header bag > 16 KB excluding Cookie / Authorization volume. | DONE |
| 20 | Phase 1 W4 polyglot upload at `logonly` — **W4** (rule 412, `WAF_UPLOAD_CONTENT:POLYGLOT_<TYPE>`). Tiny multipart parser walks the body's parts, finds parts whose `Content-Type: image/*` or filename ends in an image extension (`.png/.jpg/.jpeg/.gif/.webp/.bmp/.svg/.ico/.tif/.tiff`), and checks the first 64 bytes of each such payload for an executable opener: `<?php` / `<?=` / `<%@` / `<jsp:` / `<%` / `<script`. Distinct from rule 402 (raw substring scan over the whole multipart body) — W4 is strictly narrower and higher-precision. Same family `WAF_UPLOAD_CONTENT` reuses the existing high-risk post-clearance routing. | DONE |
| 21 | Real-sample audit (2026-05-09). Replayed 4 PHP malware samples captured from hacked WordPress / shared-hosting sites: `forms.php` (in-memory loader, char-table+XOR), `index.php` (eval gadget with $func chains), `index2.php` (WP index spoof, multilingual identifiers, .htaccess writer), `user.php` (hex2bin loader). All four caught at upload time by rules 401+402 (block). At request time samples 2+3 were caught by 404/405. The audit's initial claim that samples 1+4 missed was wrong: they were already caught by rule 404 with the generic tag `RAW_SUPERGLOBAL` because the rule's old `;<?php` +1 score bonus pushed any `<?php + $_POST + multi-statement` body to exactly the 5-point threshold. The real finding was that **rule 404 had a broad pre-existing FP class**: legitimate `<?php $x=$_POST['m']; echo $x;` echo handlers, code-snippet plugin saves, and form helpers also fired with the same `RAW_SUPERGLOBAL` tag. Closed in row 22 — see that row for the FP-mitigation design. Other deferred items: gap B (request-time encoded-payload detector), gap D (string-fragment fname detector). | DONE |
| 22 | Rule 404 retune — drop the `;<?php` +1 score bonus that was producing FPs on legit `<?php + $_POST + multi-stmt` bodies, AND add a new `has_dynamic_include` matcher for `include`/`include_once`/`require`/`require_once` whose argument starts with `$` (the variable-form malicious shape used by sample 1+4 loaders). New tags `RAW_DYN_INCLUDE` / `RAW_DYN_INCLUDE_ONCE` / `RAW_DYN_REQUIRE` / `RAW_DYN_REQUIRE_ONCE`. Score now requires an actual exec-class signal — eval/system/exec/passthru/shell_exec/popen/proc_open callable, a webshell-name marker (RAW_WS_*), OR a dynamic include — to cross the 5-point threshold. Effects: legit `echo $_POST['m']` no longer FPs (score 4 vs old 5); legit `require_once 'app.php'` doesn't contribute score (literal-string skipped by has_dynamic_include); WordPress-bootstrap `include __DIR__.path` doesn't fire; sample 1 (`forms.php` with `include_once $_13`) and sample 4 (`user.php` with `include $_6`) still fire with the more specific tag `RAW_DYN_INCLUDE_ONCE` / `RAW_DYN_INCLUDE`. | DONE |
| 23 | C3 CVE-signature-file infrastructure (`/etc/cfm/cve_signatures.txt`, `reason<TAB>score<TAB>literal`, hot-reload via `refresh_*_if_needed`). Different shape from a single detector — file format + parser + reload mechanism + a generic `detect_cve_signature` runner. | TODO (deferred) |
| 24 | Data-driven promotion of the logonly rules. Walk `cfm webtop waf hit-rates --hours 168` after a week and promote well-behaved rules (`ok_to_promote`) one mode level at a time per the rollout playbook (logonly → challenge → block, never skipping levels). | TODO (operator review, not code) |

`make test-lua` runs everything under `scripts/tests/*_test.lua` (also wired into CI per row 11):

- `cfm_waf_severity_test.lua` — severity aggregation, post-clearance gating, rule-id stability, per-vhost rule exclusion (the `ctx.skip_rule_ids` set), Phase 1 detectors W1/R1/B5/W4 (including W4-vs-rule-402 disjoint test: a non-image text field carrying `<?php` text doesn't trigger W4), Phase 2 detectors R2/R3/R4 (including a non-overlap test that R4 doesn't double-count R1's IEX-WebClient pattern), Phase 3 detector C2 (including a disjoint-from-PHP-serialize test), W2/W3/B2/X2-stratum extensions to rules 404/405/607/701, Phase 4 detectors X1/X2 (including a "bare pastebin.com without /raw/" negative), Phase 5 detectors B1/B3/B4 (including a "large Cookie alone is session state" negative for B4), rule 404 retune (positive variable-form include with $_POST, positive sanitised loader-pattern body with variable include_once, negative WordPress-bootstrap with literal include, negative legit echo with $_POST, negative legit literal-require with $_POST, no-regression test for eval+$_POST) — 68 cases covering Steps 1, 8, 10, 13, 14, 15, 17, 18, 19, 20, 22.
- `cfm_waf_post_clearance_test.lua` — `_M.post_clearance_action` matrix — covers Step 3.
- `cfm_panel_forced_mode_test.lua` — panel dispatch decisions (challenge / origin pass-through / API SSO bypass / internal-endpoint deny). Asserts on side effects (captured `ngx.redirect` / `ngx.exit` calls) rather than chunk-return values, since `cfm_panel.lua`'s `main()` is wrapped in `xpcall` for fail-open hardening.
- `cfm_rules_race_test.lua` — `cfm_rules` shdict-state compatibility under concurrent mutation.

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

Return shape: `(hit, reason, ttl, action, hits, waf_rule_id)`. The first four are the original API; `hits` is per-rule diagnostics; `waf_rule_id` is the strongest rule's stable numeric ID (see "Rule IDs" below).

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
| 9xx | 900-999 | Reserved (future CVE detectors, behavioural rules) |

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

- **WAF log line** — `cfm.waf.log` events now carry `waf_rule_id=N` alongside the existing `reason=` field. Field is omitted when the source can't supply it (older Lua clients, internal triggers without a rule context).
- **History persistence** — stored in `HistoryEvent.Payload["waf_rule_id"]` for forensic queries. Schema unchanged (Payload is `map[string]any`).
- **API** — `GET /api/v1/waf/rules` returns the registry: `{rules: [{id, name, group, group_name, reason_family, default_mode}, …], groups: {"1": "path", …}}`. Sorted by ID. Used by the panel rule glossary and the per-vhost exclusion picker (see "Per-vhost rule exclusions" below).
- **CLI** — `cfm webtop waf rules` prints the table grouped by family. `--json` for scripts.
- **Public Lua API** — `_M.get_rule_ids()` returns a copy of the `RULE_IDS` table; `_M.rule_id_for("rule_traversal")` looks up a single ID. Both used by tests; available to in-process Lua callers.

The `rule_id` field returned by the bridge's `/nginx/decision` endpoint is a **separate** namespace (decision-engine traffic-rule IDs, not WAF rule IDs). The WAF path uses `waf_rule_id` everywhere to avoid collision.

---

## Per-vhost rule exclusions

Operators can suppress specific WAF rules on specific hosts/paths without disabling the whole WAF for that scope. This solves the canonical "scraper triggers `WAF_PROXY_HDR` on one site" pattern (3xK Tech / vitolighting from `docs/waf-analysis-2026-05-08.md`) — keep the rest of the ruleset hot, drop just the noisy rule on the affected host.

### Data model

`excludeEntry` (`internal/webdetector/exclude_store.go`) gains an optional `RuleIDs []int`:

- **`RuleIDs` empty/nil** → legacy whole-WAF skip (existing behaviour, on-disk back-compat).
- **`RuleIDs` non-empty** → entry only suppresses hits whose `waf_rule_id` is in the set; the WAF still runs and other rules can still fire.

The entry key includes the rule-ID set, so `(host=foo.com, RuleIDs=nil)` and `(host=foo.com, RuleIDs=[320])` are distinct entries. Two rule-scoped entries on the same host union their IDs at match time.

### CLI

```
cfm webtop waf exclude add example.com --rule 320              # single ID
cfm webtop waf exclude add example.com --rule 3xx              # whole 300..399 group
cfm webtop waf exclude add example.com --rule 310-317          # inclusive range
cfm webtop waf exclude add example.com --rule 320 --rule 401   # repeatable flag
cfm webtop waf exclude add example.com                         # bare = whole-WAF (legacy)
cfm webtop waf exclude remove example.com --rule 320           # exact-match remove
cfm webtop waf exclude list                                    # RULES column shows IDs (or *)
```

`--rule` is WAF-only; `cfm webtop challenge exclude` ignores the flag.

### API

`POST /api/v1/waf/exclude/add?type=host&value=example.com&rule_ids=320,3xx,310-317`

`rule_ids` accepts a comma-separated mix of bare ints, group prefixes, and ranges. Out-of-range IDs (outside 100..999) are rejected with HTTP 400. Empty/absent param means the legacy whole-WAF semantics. The `remove` endpoint takes the same `rule_ids` value and matches the entry exactly.

### Lua wiring

`/nginx/waf/excludes` already serves entries; `RuleIDs` flows through automatically via `rule_ids,omitempty`. `cfm.lua`'s exclude cache (`wxhosts` / `wxpaths` shdict snapshots) now carries `{v, rule_ids}` per entry. Per-request:

```
skip_all, skip_rule_ids = waf_skip_for(host, uri)
if skip_all then          -- whole-WAF entry matched: short-circuit, never call _M.check
  ...
else
  waf.check({ ..., skip_rule_ids = skip_rule_ids })  -- set { [101]=true, [320]=true, ... } or nil
end
```

`cfm_waf.lua`'s `_M.check` consumes `ctx.skip_rule_ids` inside the severity-aggregation `record()` closure: any hit whose `rule_id` is in the set is silently dropped — no severity, no log, no counters. Detectors still execute (their work is dominated by helpers shared across rules; per-rule short-circuiting at the call sites was rejected in favour of a single choke point).

When the `cfm_debug_headers` knob is on, `X-CFM-WAF-Skip-Rules` echoes the active set so operators can confirm the right rule IDs reach the request.

### Tests

- Go: `internal/webdetector/exclude_rule_ids_test.go` (parser: bare, `Nxx`, ranges, mixed, clipping, error cases) and `exclude_store_test.go` (rule-scoped entries don't trigger whole-WAF; whole-WAF wins on collision; union of multiple rule-scoped entries; persistence round-trip; remove distinguishes scoping).
- Lua: tests 17-18 in `scripts/tests/cfm_waf_severity_test.lua` (skip suppresses hit; non-excluded rules still fire).

---

## Hit-rate measurement

The rollout playbook below requires `<0.01%` FP rate before promoting `logonly → challenge → block`. Step 9 ships the data pipeline that makes this measurable.

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
     "hits": 75000, "rate_pct": 5.0, "promotion_hint": "noisy"},
    ...
  ]
}
```

`promotion_hint` maps the rate to an action label:

| Hint | Condition | Operator action |
|---|---|---|
| `ok_to_promote` | hits > 0 AND rate < 0.01% | Safe to promote one mode level |
| `silent` | inspected > 0 AND hits == 0 | Verify rule isn't broken before promoting |
| `review` | 0.01% ≤ rate < 1% | Investigate FP candidates before promoting |
| `noisy` | rate ≥ 1% | Demote, tighten, or add per-host exclusion |
| `n_a` | inspected == 0 | Insufficient data — wait for the flusher |

Per-rule precision uses `json_extract(payload_json, '$.waf_rule_id')` so families with multiple rules (e.g. all `WAF_AUTH_BURST` tags) are counted separately. Events from before the rule-IDs PR have NULL `waf_rule_id` and are excluded from the per-rule view (they still appear in the legacy `WAFByRule` reason-aggregation).

### CLI

```
cfm webtop waf hit-rates                      # last 24h, all hosts, grouped by family
cfm webtop waf hit-rates --hours 168          # last week
cfm webtop waf hit-rates --host example.com   # single vhost
cfm webtop waf hit-rates --hint ok_to_promote # filter to promotion candidates
cfm webtop waf hit-rates --json               # machine-readable
```

### Sampled hit log

A configurable fraction of WAF triggers (`CFM_WAF_SAMPLE_RATE`, default `0.01` = 1%) gets a richer entry written to `cfm.waf.sampled.log`. The fraction is chosen in Lua so the cost of capturing UA/Referer/Content-Type is paid only on sampled events.

Format: one JSON object per line.

```json
{"ip":"1.2.3.4","host":"example.com","uri":"/admin/upload",
 "method":"POST","action":"block","reason":"WAF_UPLOAD_FNAME:PHTML",
 "waf_rule_id":401,"ttl_sec":3600,
 "ua":"curl/7.81.0","referer":"","ct":"multipart/form-data; boundary=...",
 "asn":12345,"asn_name":"EXAMPLE-AS","country":"US"}
```

The main `cfm.waf.log` stays compact for high-volume monitoring. Operators tail `cfm.waf.sampled.log` for FP investigation.

### Cost / regression notes

| Path | Cost | Notes |
|---|---|---|
| Per WAF check | ~3-5µs | Two shdict incr + one get-and-compare. <1% of WAF check cost. |
| Per flush (~1/min cluster-wide) | ~3µs on the lock winner | The actual snapshot+RPC runs in a background light-thread via `ngx.timer.at(0, …)`; the request that wins the lock pays only the lock-claim + timer-schedule cost. RPC latency is 100% off the request path. |
| Sampling (per request) | sub-µs | `math.random() < sr` and integer compare. |
| Sampled trigger (1% of triggers) | ~50µs | Three extra string fields in JSON + one file write. |
| `/api/v1/waf/hit-rates` | <100ms typical | `json_extract` is O(N events in window); operator-pulled, never on hot path. |

Backward compat: all new wire fields are `omitempty`; `CREATE TABLE IF NOT EXISTS` upgrades existing SQLite DBs silently.

Kill switches: `CFM_WAF_STATS_ENABLE=0` disables counters + flushing; `CFM_WAF_SAMPLE_RATE=0` disables sampled log.

---

## Request flow (current)

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
5. **Static-asset URIs bypass `cfm.lua`** (`.css/.js/.woff2?/.ttf/.eot/.png/.jpe?g/.gif/.webp/.ico/.map`). The `location` block in `openresty.conf` / `angie.conf` skips the access phase and proxies straight to Apache via `http://$server_addr:80` (HTTP) or `https://$server_addr:443` (HTTPS). `.svg` is NOT in the bypass — it can carry script. The block has a commented `# FUTURE: proxy_cache cfm_static; ...` slot so caching can be enabled later as a pure nginx-side change.

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

Env vars added by Steps 2-3:

| Var | Default | Allowed | Notes |
|-----|---------|---------|-------|
| `CFM_WAF_AFTER_CLEARANCE_CHALLENGE` | `logonly` | `block`, `logonly` | What a challenge becomes under clearance for noisy reasons. `challenge` is rejected. |
| `CFM_WAF_AFTER_CLEARANCE_HIGH_RISK` | `block` | `block`, `logonly` | What a challenge becomes under clearance for high-risk reasons. |

High-risk reason families (matched by `:` prefix) live in `cfm_waf.lua` as `_M.WAF_HIGH_RISK_REASONS`:

```
WAF_RCE              WAF_PHP_WEBSHELL_BODY
WAF_UPLOAD_CONTENT   WAF_TRAVERSAL
WAF_UPLOAD_FNAME     WAF_XXE
WAF_UPLOAD_OBFUSCATION
WAF_CMD_PAYLOAD
WAF_B64_INJECT
WAF_SHELLSHOCK
```

---

## Public API (cfm_waf module)

| Function | Purpose |
|----------|---------|
| `_M.check(ctx)` | Run all rules, return highest severity. 5-tuple. |
| `_M.enabled()` | Module-level kill-switch. |
| `_M.should_push(shdict, ip, reason)` | Per-(reason,ip) push rate limit. |
| `_M.get_config()` | Snapshot of CFG (read-only copy). |
| `_M.set_rule(name, mode)` | Live rule-mode tuning. Per-worker. Used by tests and ops kill-switches. |
| `_M.is_high_risk_reason(reason)` | Prefix match against `WAF_HIGH_RISK_REASONS`. |
| `_M.post_clearance_action(action, reason, after_challenge, after_high_risk)` | Returns `(converted_action, did_convert)`. Pure. |

---

## Tests

`scripts/tests/cfm_waf_severity_test.lua` — 18 cases:

- single hit returns the configured action (block / challenge / logonly);
- logonly-then-block, challenge-then-block: severity wins;
- block short-circuits later detectors (XSS configured but never runs after RCE blocks);
- two logonly hits aggregate to logonly;
- disabled rule does nothing even with the trigger payload present;
- body-only detector skipped on GET, fires on POST (body_inspect_ok gating);
- 4-tuple return on no-hit, 5-tuple on hit, hits[] ordering and entry shape;
- `_M.get_rule_ids()` snapshot is a copy (caller mutation doesn't leak), `rule_id_for(name)` lookup;
- 6th return value (`waf_rule_id`) carries the strongest rule's ID; severity-wins picks the strongest's ID, not first-match;
- `cmd_payload` sub-rule IDs map per tag (per-tag override table);
- `ctx.skip_rule_ids` suppresses excluded IDs without affecting non-excluded rules — the per-vhost-rule-exclusion contract from row 10.

`scripts/tests/cfm_waf_post_clearance_test.lua` — covers:

- prefix matching for bare families and family:tag forms;
- empty / nil / malformed reasons return `false`;
- conversion table: challenge+high-risk → block, challenge+noisy → logonly;
- pass-through for `block` and `logonly` actions;
- custom defaults honoured; missing defaults fall back to safe values.

`internal/webdetector/challenge_server_xss_test.go` — covers `jsStringLiteral`'s HTML-script-context safety: the dangerous bytes (`<`, `>`, `&`, U+2028, U+2029) are absent from the output for representative attack payloads, and the rewritten bytes appear as the documented `\uXXXX` form. Pins the fix for CodeQL #565 (2026-05-09).

`internal/webdetector/exclude_rule_ids_test.go` and `exclude_store_test.go` — rule-id-spec parsing (`N`, `Nxx`, `N-M`, mixed) and per-vhost rule-exclusion store semantics (rule-scoped doesn't trigger whole-WAF skip; whole-WAF wins on collision; union of multiple rule-scoped entries; persistence round-trip; remove distinguishes scoping; vhost-controls panel filter drops rule-scoped from the WAF-toggle list).

---

## Known gaps

These are real and worth addressing, but not blocking:

1. **Body truncation.** `CFM_WAF_BODY_MAX_LEN=8192` (in `cfm.lua`) means uploads/payloads larger than 8 KB skip body-inspection rules silently. Phase W2/W3/W4 won't deliver until either the cap is raised for upload endpoints or inspection is streamed.
2. **No multipart parser.** Polyglot upload detection (W4), upload context for W2/W3, and X1-in-body assume part-aware inspection. Today the WAF runs literal `has()` over raw bytes — works for finding `<?php` in image content, but can't distinguish multipart parts (claimed CT, filename, content).
3. ~~**No hit-rate measurement.**~~ DONE — see "Hit-rate measurement" above. `/api/v1/waf/hit-rates`, `cfm webtop waf hit-rates`, plus `cfm.waf.sampled.log` for FP investigation.
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
| 6 | **CVE signature file** at `/etc/cfm/cve_signatures.txt` with hot-reload. | Needed before Phase 3 grows; ship updates without redeploying. | M |
| 7 | **B5 (POST + empty UA + CL:0 + .php)** combo fingerprint | Cheap, high-confidence webshell ping detector. | S |
| 8 | **Panel DNAT WAF profile** for cPanel/DirectAdmin file managers, backup restore, plugin/theme editors. | Hijacked panel sessions uploading webshells. | L |
| 9 | ~~**Hit-rate counter + sampled hit log**~~ DONE — see "Hit-rate measurement" section. | — | — |
| 10 | ~~**Stable rule IDs + per-vhost rule exclusions**~~ (ModSec `SecRuleRemoveById`-style). **PR A DONE** + **PR B DONE** — see "Rule IDs" and "Per-vhost rule exclusions" sections above. Solves the vitolighting/3xK Tech-style FP cleanly without disabling whole-host WAF. | — |

---

## Detector phases (proposed; not yet implemented)

Format: short ID, what it detects, target reason family, indicative score. Full literal lists live in git history of this doc and will move into the implementation when each detector lands.

### Phase 1 — webshell delivery

- **W1** known-bad webshell path names (`/c99.php`, `/r57.php`, …) → `WAF_WEBSHELL:PATH:<basename>` — **shipped at `logonly` (rule 410)**.
- **W2 (extension of rule 404)** — **DONE**. Added webshell self-identifying literals (`b374k`, `c99shell`, `r57shell`, `indoxploit`, `0byt3m1n1`, `weevelyshell`, `wso 2./4./5.`, `<title>c99`, `<title>r57`) to `detect_php_webshell_body` at +3 weight. Tag prefix `RAW_WS_<NAME>` outranks the generic `RAW_*` set so operators see *which* shell hit. Bare prose mention stays below `min_score=5` so a forum post can't trigger.
- **W3 (extension of rule 405)** — **DONE**. Added `hex2bin(` to `score_obfuscation_blob` at +2 weight (same as `base64_decode` and `gzinflate`). Tag `HEX2BIN`.
- **W4** polyglot upload — image Content-Type or image-extension filename + executable opener in first 64 bytes of the part payload → `WAF_UPLOAD_CONTENT:POLYGLOT_<TYPE>` — **shipped at `logonly` (rule 412)**. Tags: `POLYGLOT_PHP`, `POLYGLOT_PHP_SHORT` (`<?=`), `POLYGLOT_JSP_DIRECTIVE` (`<%@`), `POLYGLOT_JSP` (`<jsp:`), `POLYGLOT_ASP` (`<%`), `POLYGLOT_SCRIPT`. Image extensions covered: `.png/.jpg/.jpeg/.gif/.webp/.bmp/.svg/.ico/.tif/.tiff`. Rule is strictly narrower than rule 402 — same family `WAF_UPLOAD_CONTENT` so post-clearance routing is correct, distinct rule ID so hit-rate counters and per-vhost exclusions work independently.

### Phase 2 — post-exploitation / RCE

- **R1** reverse shell strings (`bash -i >& /dev/tcp/`, `python -c 'import socket'`, `socat tcp-connect`) → `WAF_RCE:REVERSE_SHELL:<tag>` — **shipped at `logonly` (rule 322)**.
- **R2** cron/systemd persistence (`crontab -e`, `(crontab -l;`, `>/etc/cron.d/`, `[Unit]\nExecStart=/`, `>> ~/.bashrc`, `>> ~/.ssh/authorized_keys`) → `WAF_RCE:PERSISTENCE:<tag>` — **shipped at `logonly` (rule 323)**.
- **R3** LD_PRELOAD / rootkit artifacts (`LD_PRELOAD=/`, `>/etc/ld.so.preload`, `insmod /tmp/`, `/dev/mem`) → `WAF_RCE:ROOTKIT:<tag>` — **shipped at `logonly` (rule 324)**.
- **R4** LOLbins (`certutil -urlcache -split`, `bitsadmin /transfer`, `-EncodedCommand `, `iex(iwr `, `wget -O /tmp/`) → `WAF_RCE:LOLBIN:<tag>` — **shipped at `logonly` (rule 325)**. The `iex(new-object net.webclient` and TcpClient variants are intentionally NOT in R4's table — they already fire under R1 (rule 322); R4 covers the *download/encoded-command* side, R1 covers the shell.

### Phase 3 — known-CVE fingerprints

- **C1 (DROPPED — already covered)**: Log4Shell `${jndi:`, `${j{n{d{i`, `$%7bjndi` are already detected by `detect_rce` (rule 320). Re-adding them as a separate rule would double-count hits. If a future Log4Shell variant slips past rule 320's three patterns, extend `detect_rce` rather than create a new rule.
- **C2** Java ObjectOutputStream deserialization — raw `0xAC 0xED 0x00 0x05` magic, base64 `rO0AB` prefix, `aced0005` hex literal. Searched in args, body, and the standard gadget-vector headers (Cookie, Authorization, X-Forwarded-For) → `WAF_RCE:JAVA_DESERIALIZE:<tag>` — **shipped at `logonly` (rule 326)**. Disjoint from PHP serialize (rule 306) — neither rule shadows the other. Family `WAF_RCE` reuses high-risk post-clearance routing.
- **C3 (DEFERRED — TODO / planning)**: signature file `/etc/cfm/cve_signatures.txt` (`reason<TAB>score<TAB>literal`), hot-reload via `refresh_*_if_needed` pattern. Different shape from a single detector — file format + parser + reload mechanism + a generic `detect_cve_signature` runner. Tracked as status row 21. Pick up when there's a concrete CVE pipeline to feed it (otherwise the framework is solving a problem that doesn't have urgent input).

### Phase 4 — C2 / exfiltration

- **X1** tunnel/paste services in body or args → `WAF_C2:TUNNEL:<host>` — **shipped at `logonly` (rule 702)**. Hostnames covered: `pastebin.com/raw/`, `paste.ee/r/`, `dpaste.com/`, `rentry.co/`, `0x0.st/`, `transfer.sh/`, `controlc.com/`, `ix.io/`, `gist.githubusercontent.com/`, `raw.githubusercontent.com/`, `webhook.site/`, `requestbin.net/`, `pipedream.com/`, `ngrok.io/`, `ngrok-free.app/`, `trycloudflare.com/`, `loca.lt/`, `serveo.net/`, `cdn.discordapp.com/attachments/`, `media.discordapp.net/attachments/`, `api.telegram.org/bot`. Family `WAF_C2` is distinct from `WAF_SSRF` (rule 701) — SSRF is about scheme abuse, C2 is about specific hostnames known to host attacker infrastructure.
- **X2** coinminer URLs/tools → `WAF_RCE:COINMINER:<tag>` — **shipped at `logonly` (rule 327)**. Patterns: `xmrig --url`, `xmrig -o `, `xmrig --pool`, `xmr-stak --url`, `xmr-stak -o `, public XMR pool hostnames (`pool.minexmr.com`, `supportxmr.com`, `xmrpool.eu`, `moneroocean.stream`, `nanopool.org`, `fr.minexmr.com`), `monerod -p `, `ethminer --pool`. The `stratum+tcp://` / `stratum+ssl://` schemes are intentionally NOT here — already in `detect_ssrf_proto` as `SSRF_STRATUM` (rule 701) per the design call in audit row 16.

### Phase 5 — behavioural / combined-signal

- **B1** HTTP smuggling header pairs → `WAF_HTTP_SMUGGLING:<tag>` — **shipped at `logonly` (rule 608)**. Tags: `CL_AND_TE` (Content-Length + Transfer-Encoding both present — RFC 7230 §3.3.3 forbids), `MULTI_CL` (Content-Length value contains a comma — multiple CLs joined by nginx), `MULTI_TE` (chunked appears in Transfer-Encoding but isn't the final element — CL.TE primitive), `CL_MALFORMED` (Content-Length isn't a non-negative integer). Operates on header presence/value shape only — does NOT do byte-level CL-vs-body comparison, which is unreliable through the cfm body cap.
- **B2 (extension of rule 607)** — **DONE**. `detect_exploit_method` now returns `(action, tag)` and the wire-up emits `WAF_EXPLOIT_METHOD:TRACE` / `:TRACK` / `:CONNECT_NOT_PROXY` / `:DAV_PROPFIND` / `:DAV_SEARCH`. Sub-tags are advisory log triage; the per-vhost mechanism (rule_id 607 in `--rule-ids`) is what operators use to whitelist a DAV-hosting vhost.
- **B3** Single URL path segment ≥ 256 chars → `WAF_LONG_PATH:SEG_<len>` — **shipped at `logonly` (rule 102)**. Indicator of token stuffing, base64 in path, or buffer-overflow probing. Tag carries the longest segment's length so log analysis can distinguish "just over 256" from "10 KB stuffed".
- **B4** Header bag total > 16 KB without large `Cookie`/`Authorization` → `WAF_HEADER_FLOOD:FLOOD:<bytes>` — **shipped at `logonly` (rule 609)**. Sums header byte volume excluding Cookie / Authorization (those are session-state, frequently legit-large on shared hosting with WordPress / cPanel sessions). Typical request headers are 1-3 KB total.
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

## Phase 1 starting context

This section is a self-contained briefing for picking up the next chunk of work without reading prior chat history. A fresh Claude session with this file plus `docs/waf-analysis-2026-05-08.md` should be able to scope, code, test, and ship a new detector.

**Shipped so far**: Phase 1 (W1/R1/B5/W4 — rules 410, 322, 411, 412), Phase 2 (R2/R3/R4 — rules 323, 324, 325), Phase 3 partial (C2 — rule 326; C3 deferred), W2/W3/B2/X2-stratum extensions (rules 404/405/607/701, no new IDs), Phase 4 (X1/X2 — rules 702, 327), Phase 5 (B1/B3/B4 — rules 608, 102, 609). All new behaviour at `logonly`. Two cross-phase audits closed (status rows 14 and 16) — **C1 dropped** (rule 320), **R4 trimmed** to avoid overlap with R1, **X2/rule-701 design call resolved** by folding `stratum+tcp://` into rule 701.

**Detector roadmap is essentially complete.** The two remaining items in the status table are:

- **C3 (TODO/planning, status row 21)** — CVE-signature-file infrastructure. Pick up when there's a concrete CVE pipeline to feed it; otherwise the framework is solving a problem with no urgent input.
- **Data-driven promotion (status row 22)** — walk `cfm webtop waf hit-rates --hours 168` after a week, promote well-behaved logonly rules → challenge → block per the playbook. Operator review, not code work.

### What's already done

| Layer | What | Where |
|---|---|---|
| Engine | Severity-aggregation `_M.check`, post-clearance conversion, kill-switches, `ctx.skip_rule_ids` gate | `configs/lua/cfm_waf.lua` |
| Detectors | 52 detector functions invoked from `_M.check` (39 base + W1/R1/B5 + R2/R3/R4 + C2 + X1/X2/B1/B3/B4 + W4) | `configs/lua/cfm_waf_detectors.lua` |
| Util | `scan_str`, `normalize`, `url_decode_once`, `header_string`, IP literal helpers | `configs/lua/cfm_waf_util.lua` |
| Rule IDs | Stable 3-digit IDs, log-line plumbing, `/api/v1/waf/rules`, CLI | `configs/lua/cfm_waf.lua` (`RULE_IDS`), `internal/webdetector/waf_rule_ids.go` |
| Hit-rate | Per-rule rate gating, `/api/v1/waf/hit-rates`, sampled log; flush runs in `ngx.timer.at` so the request path never pays RPC latency | `configs/lua/cfm.lua` (`waf_insp_incr` + `maybe_flush_waf_insp`), `internal/webdetector/waf_hit_rates_api_handler.go` |
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
   - Uses `util.has`, `util.scan_str`, `util.url_decode_once`, etc. for input normalisation. Avoid duplicating helpers.
   - For body-only detectors, the engine already gates on `body_inspect_ok` (POST + non-empty body).
   - Cap scan length: respect `CFG.max_scan_len` (default 2048) for URI/args; body detectors usually have their own limit (`CFG.<rule>_max_scan_len`).
   - Tags should be `SCREAMING_SNAKE_CASE` and convey *which sub-pattern* matched, e.g. `PHTML`, `BASE64_BLOB`, `JNDI_LDAP`.

3. **Wire it into `_M.check`** in `configs/lua/cfm_waf.lua`. Add a numbered `do … end` block in the existing flow. Pattern:
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

5. **Tests.** Add cases to `scripts/tests/cfm_waf_severity_test.lua`:
   ```lua
   do
     disable_all_rules()
     waf.set_rule("rule_<name>", "<expected mode>")
     local hit, reason, _ttl, action, _hits, waf_rule_id = waf.check(fresh_ctx({
       <field that triggers it>
     }))
     check(hit == true,                                "NN: <name> — hit=true")
     check(reason and reason:find("WAF_<FAMILY>", 1, true), "NN: reason prefix")
     check(action == "<expected>",                     "NN: action")
     check(waf_rule_id == <id>,                        "NN: rule id")
   end
   ```
   And one negative case (input that *shouldn't* trigger). For the most-affected rules also add a Go test that the hit appears in `/api/v1/waf/hit-rates`.

6. **Rollout** — see playbook below. Default mode for new rules is **always `logonly`** until hit-rate data justifies promotion.

### Rule modes & defaults

```
disabled (0) < logonly (1) < challenge (2) < block (3)
```

`record()` aggregates all hits and returns the strongest action. New rules that look high-confidence (CVE, webshell, RCE patterns) can ship `challenge` if production-validated; everything else starts at `logonly`. `block` is reserved for instant-block patterns with near-zero FP risk (Log4Shell, reverse shells, known webshell uploads on confirmed-vulnerable endpoints).

### Production data to consult before designing a new rule

- `docs/waf-analysis-2026-05-08.md` — the Tier 1/2/3 analysis of three production servers. **Read this before adding rules in any family already represented there**, to avoid recreating known-FP patterns. Key takeaways:
  - Facebook scrapers hit `/.../<path>` literals — already handled in `detect_traversal`'s FB-skip
  - Vitolighting/3xK Tech case is the canonical "scraper that triggers `WAF_PROXY_HDR` with no real attack" — solved by PR B (per-vhost exclusions), not by tightening the rule
  - `WAF_BAD_UA` scoring covers most scanner UAs without explicit per-tool literals
- `cfm.waf.log` and `cfm.waf.sampled.log` on a running production server — replay representative attack samples through the new detector before promoting.

### Promotion gate (use the data; don't eyeball)

After landing a new detector at `logonly` mode:

```
cfm webtop waf hit-rates --hours 168          # one week of evidence
```

Operator looks at the row for the new rule:

| `promotion_hint` | Action |
|---|---|
| `ok_to_promote` | Promote one mode level: `logonly → challenge` (or `challenge → block`). Rerun for another week. |
| `silent` | Verify the rule isn't broken — run a known-positive sample through it. If it fires, leave it at logonly and wait. If not, debug. |
| `review` | Investigate the hits in `cfm.waf.sampled.log` (look for FPs). Tighten the rule, then rerun. Don't promote yet. |
| `noisy` | Clear FP source. Either tighten the detector, or add a per-vhost exclusion when PR B lands. Don't promote. |
| `n_a` | Wait for the flusher (1 minute typical). |

Promote one mode level at a time. Never go `logonly → block` directly.

### Phase 1 specific guidance — webshell delivery (W1, W2, W3, W4)

Detailed sketch in "Detector phases" above. Concrete starting points:

- **W1 (known webshell paths)** — **shipped (rule 410, `logonly`)**. `WEBSHELL_NAMES` hash-set in `cfm_waf_detectors.lua`; basename-only match (path's final segment after the last `/`, before `?`). Add new entries by appending the lowered basename — don't include path prefixes.
- **W2 (webshell magic strings in body)** — extends `detect_php_webshell_body` with more literals (`b374k`, `WSO 2.5`, `c99shell`, `r57shell`, `mini.php`, `@eval(`, `@assert(`). Score-based to combine signals. Body-only (gated by `body_inspect_ok`). Already has a CFG knob (`rule_php_webshell_body`); maybe extend the existing rule rather than add a new one.
- **W3 (PHP function obfuscation)** — extends `detect_script_obfuscation`. Add patterns: `\x65val`, `chr(101).chr(118)…`, `hex2bin($_POST[`, `base64_decode($_GET[`. Already has CFG knob (`rule_script_obfuscation`).
- **W4 (polyglot upload)** — needs a tiny multipart parser (or settle for naïve raw-bytes scan of first 64 bytes after `Content-Type: image/*`). Reason `WAF_UPLOAD_CONTENT:POLYGLOT`. Foundational because W2/W3 in upload context also need this. New rule ID; suggest 411.

### Files you'll edit for any new detector

| File | Why |
|---|---|
| `configs/lua/cfm_waf.lua` | CFG entry, RULE_IDS entry, `_M.check` call site |
| `configs/lua/cfm_waf_detectors.lua` | Detector function |
| `configs/lua/cfm_waf_util.lua` | New shared helpers (only if reused across multiple detectors) |
| `internal/webdetector/waf_rule_ids.go` | Mirror entry — drift caught by `TestWAFRuleIDs_LuaParity` |
| `scripts/tests/cfm_waf_severity_test.lua` | Positive + negative test cases |
| `docs/waf.md` | Mark roadmap row done; mention the new rule in Rule IDs section if it's a new ID |

### Files you'll edit for the next infrastructure work

Item #10 (per-vhost rule exclusions, PR B) shipped — see "Per-vhost rule exclusions" section above for the deployed shape. Future infrastructure items (deferred) include the inspector-audit follow-ups noted in "Known gaps" item 8 and the Medium/Low code-scanning batch deferred from `docs/security/code-scanning-triage-2026-05-09.md`.

### Don't do these things

- Don't promote a rule to `block` without one full week at `challenge` first. Operator complaints in week 1 of `challenge` are how you find the false positives.
- Don't add new helpers to `cfm_waf.lua` — they belong in `cfm_waf_util.lua` (and need `_M.init(cfg)` exposure if they need CFG).
- Don't bypass `record()` to handle a hit specially. The severity-aggregation engine is load-bearing; one rule firing block must override another rule firing logonly on the same request.
- Don't renumber existing rule IDs. Operators reference them in tickets, exclusion lists, and dashboards.
- Don't add detectors that match Apache's default `Reject` patterns (`../`, certain methods); the prod analysis showed those are already handled upstream and CFM only matters when Apache is misconfigured.
