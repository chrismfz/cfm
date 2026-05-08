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
| 8+ | New detector phases (W/R/C/X/B series) | TODO |

`make test-lua` runs everything under `scripts/tests/*_test.lua`. The two new files (`cfm_waf_severity_test.lua`, `cfm_waf_post_clearance_test.lua`) cover Steps 1-3.

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

Return shape: `(hit, reason, ttl, action, hits)`. The first four are the original API; the fifth is for diagnostics and is currently unused by callers.

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

`scripts/tests/cfm_waf_severity_test.lua` — 12 cases:

- single hit returns the configured action (block / challenge / logonly);
- logonly-then-block, challenge-then-block: severity wins;
- block short-circuits later detectors (XSS configured but never runs after RCE blocks);
- two logonly hits aggregate to logonly;
- disabled rule does nothing even with the trigger payload present;
- body-only detector skipped on GET, fires on POST (body_inspect_ok gating);
- 4-tuple return on no-hit, 5-tuple on hit, hits[] ordering and entry shape.

`scripts/tests/cfm_waf_post_clearance_test.lua` — covers:

- prefix matching for bare families and family:tag forms;
- empty / nil / malformed reasons return `false`;
- conversion table: challenge+high-risk → block, challenge+noisy → logonly;
- pass-through for `block` and `logonly` actions;
- custom defaults honoured; missing defaults fall back to safe values.

---

## Known gaps

These are real and worth addressing, but not blocking:

1. **Body truncation.** `CFM_WAF_BODY_MAX_LEN=8192` (in `cfm.lua`) means uploads/payloads larger than 8 KB skip body-inspection rules silently. Phase W2/W3/W4 won't deliver until either the cap is raised for upload endpoints or inspection is streamed.
2. **No multipart parser.** Polyglot upload detection (W4), upload context for W2/W3, and X1-in-body assume part-aware inspection. Today the WAF runs literal `has()` over raw bytes — works for finding `<?php` in image content, but can't distinguish multipart parts (claimed CT, filename, content).
3. **No hit-rate measurement.** The rollout playbook below requires `<0.01%` FP rate before promoting `logonly → challenge → block`, but there's no tooling to measure that today. Need shdict counters or sampled hit log.
4. **shdict pressure.** Auth-burst counters use shdict. Adding more counters scales contention. Per-rule benchmarks needed before Phase 5 lands.
5. **Per-rule kill-switch audit.** `set_rule()` exists; not every detector is reachable through a `rule_*` CFG key. Audit + fill gaps.
6. **Push payload uses post-conversion action.** `cfm.lua:1127` pushes `action=logonly` after challenge→logonly conversion. Probably correct (push the effective action) but confirm with Go-side consumers.
7. **Route log loses post-clearance signal.** The `waf_logonly` / `waf_block` log line at `cfm.lua:1131` after conversion doesn't say "from challenge". The separate `waf_post_clearance_convert` line at `cfm.lua:1089` carries it; correlation is by IP+timestamp. Could be folded into one line.

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
| 9 | **Hit-rate counter + sampled hit log** | Required before promoting any rule from logonly upward. Enables data-driven rollout. | M |
| 10 | **Stable rule IDs + per-vhost rule exclusions** (ModSec `SecRuleRemoveById`-style). Three tiers: (a) assign 10-aligned numeric IDs to each `rule_*` CFG key (1010 = `rule_traversal`, 1240 = `rule_proxy_header_sqli`, …); include `rule_id=N` in `cfm.waf.log`. (b) Extend `excludeEntry` (`internal/webdetector/exclude_store.go`) with optional `rule_ids []int` — empty = whole-WAF skip (back-compat), populated = skip only those rules for the matched host/path. Lua reads via existing `/nginx/waf/excludes` RPC and gates per-detector via a small `ctx.skip_rule_ids` set. (c) `cfm webtop waf exclude add example.com --rule 1240` + `--rule 1010,1240` + `cfm webtop waf rules`; panel UI multi-select on the vhost edit screen; new `/api/v1/waf/rules` endpoint. Reuses the existing exclude store, RPC, host normalization, glob matching, persistence, CLI scaffold, and panel API — only adds a single optional field on `excludeEntry` plus per-rule gating in Lua. Solves the vitolighting/3xK Tech-style FP cleanly without disabling whole-host WAF. ~2 days total, ship as two PRs (Tier 1 alone, then Tier 2+3 bundled). | M |

---

## Detector phases (proposed; not yet implemented)

Format: short ID, what it detects, target reason family, indicative score. Full literal lists live in git history of this doc and will move into the implementation when each detector lands.

### Phase 1 — webshell delivery

- **W1** known-bad webshell path names (`/c99.php`, `/r57.php`, …) → `WAF_WEBSHELL:PATH`, `+6`.
- **W2** webshell magic strings in body (`b374k`, `WSO 2.5`, `@eval(`, …) → `WAF_PHP_WEBSHELL_BODY:tag`, scored.
- **W3** PHP function obfuscation (`\x65val`, `chr().chr()…`, `hex2bin($_POST[`) → `WAF_SCRIPT_OBFUSCATION:tag`, `+5`.
- **W4** polyglot upload (image extension/CT + `<?php`/`<?=`/`<%`/`<script` in first 64 bytes) → `WAF_UPLOAD_CONTENT:POLYGLOT`, `+6`.

### Phase 2 — post-exploitation / RCE

- **R1** reverse shell strings (`bash -i >& /dev/tcp/`, `python -c 'import socket'`, `socat tcp-connect`) → `WAF_RCE:REVERSE_SHELL`, instant block.
- **R2** cron/systemd persistence (`crontab -e`, `/etc/cron.d/`, `[Unit]…ExecStart=/`) → `WAF_RCE:PERSISTENCE`, `+6`.
- **R3** LD_PRELOAD / userspace rootkit artifacts → `WAF_RCE:ROOTKIT_ARTIFACT`, `+6`.
- **R4** LOLbins (`certutil -urlcache -split`, `iex(iwr`, `-EncodedCommand <b64>`) → `WAF_RCE:LOLBIN` / score combo with base64 detector.

### Phase 3 — known-CVE fingerprints

- **C1** Log4Shell (`${jndi:ldap://`, `${${::-j}…`, `${lower:j}…`, `${env:`) inspect headers/query/body → `WAF_CVE:LOG4SHELL`, instant block.
- **C2** Java deserialization (`rO0ABXNyAB`, `\xac\xed\x00\x05`) → `WAF_CVE:JAVA_DESERIALIZATION`.
- **C3** signature file `/etc/cfm/cve_signatures.txt` (`reason<TAB>score<TAB>literal`), hot-reload via `refresh_*_if_needed` pattern.

### Phase 4 — C2 / exfiltration

- **X1** tunnel/paste services in body or upload (`pastebin.com/raw/`, `cdn.discordapp.com/attachments/`, `webhook.site`, `ngrok.io`) → `WAF_C2:TUNNEL`, `+5` body-only.
- **X2** coinminer URLs/tools (`xmrig --url`, `pool.minexmr.com`, `stratum+tcp://`) → `WAF_RCE:COINMINER`, `+5`.

### Phase 5 — behavioural / combined-signal

- **B1** Content-Length vs observed body mismatch → `WAF_HTTP_SMUGGLING:CONTENT_LENGTH_MISMATCH`, `+4`.
- **B2** Suspicious method outside expected location (CONNECT to non-proxy, PROPFIND/SEARCH to non-DAV) → fold into existing exploit-method check, `+2`.
- **B3** Single URL segment ≥ 256 chars → `WAF_LONG_PATH`, `+3`; raise if high-entropy.
- **B4** Header bag total > 16 KB without large `Cookie`/`Authorization` → `WAF_HEADER_FLOOD`, `+3`.
- **B5** POST + empty UA + Content-Length:0 + URI ends in `.php` → `WAF_WEBSHELL:PING`, `+6`.

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
