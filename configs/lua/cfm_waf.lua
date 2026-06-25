-- /var/lib/cfm/lua/cfm_waf.lua (CFM-managed canonical location)
--
-- CFM inline WAF
--
-- Design goals:
--   1) Cheap request-side checks first
--   2) Unified rule modes: disabled | logonly | challenge | block
--   3) Easy to tune/promote rules without renaming config keys
--   4) Keep expensive body inspection narrow and conservative
--
-- Public API:
--   _M.enabled() -> bool
--   _M.check(ctx) -> hit(bool), reason(string), ttl_sec(int), action(string)
--   _M.should_push(shdict, ip, reason) -> bool
--
-- ctx fields expected from caller:
--   uri, args, method, host, ip, peer, cf_ip, cookie, shdict, headers, body

local _M = {}

-- Sub-modules. _M.init() chains init() into both.
local util = require("cfm_waf_util")
local det  = require("cfm_waf_detectors")

-- Util helpers used inline by _M.check below.
local lower         = util.lower
local cap           = util.cap
local normalize     = util.normalize
local scan_str      = util.scan_str
local header_string = util.header_string
local is_known_legit_php_upload_endpoint = util.is_known_legit_php_upload_endpoint

-- ─────────────────────────────────────────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────────────────────────────────────────
local CFG = {
  enabled = true,

  -- Rule modes:
  --   "disabled"  -> detector skipped
  --   "logonly"   -> log/push only, never challenge/block inline
  --   "challenge" -> send to challenge server
  --   "block"     -> return 403 immediately

  -- ── Core request-side protections ─────────────────────────────────────────
  rule_traversal       = "challenge",  -- ../, null bytes, basic traversal markers
                                       -- (signal-confirmed: encoded forms, null bytes,
                                       --  multi-hop, or single ../ paired with a
                                       --  sensitive sink — see detect_traversal)
  rule_rce             = "block",      -- strong RCE / shell / jndi markers
  rule_exploit_methods = "challenge",  -- TRACE/TRACK/CONNECT etc
  rule_xss             = "challenge",  -- cheap reflected-XSS style patterns
  rule_sqli            = "challenge",  -- cheap SQLi signatures (+ SQL comment bypass)

  -- ── Safer rollout / audit-first rules ─────────────────────────────────────
  rule_php_wrappers      = "challenge",  -- php:// phar:// data:// zip:// expect:// glob://
  rule_ip_host           = "challenge",  -- Host header is bare IPv4/IPv6 literal
                                         -- (promoted from logonly: 2026-05 hit analysis showed
                                         --  100% scanner traffic against raw IPv4 hosts —
                                         --  real users never set Host to a server IP literal)
  rule_ctrl_chars        = "challenge",  -- suspicious ASCII control chars in args/body
                                         -- (promoted from logonly: detector already excludes
                                         --  multipart/binary CTs; 0 hits over 6 weeks ×
                                         --  5 servers — no legit traffic produces these bytes)
  rule_php_webshell_body = "challenge",  -- raw POST-body PHP webshell scorer (<?php + exec/superglobals)
  rule_b64_injection     = "challenge",  -- POST-body base64 decode heuristic scanner

  -- ── Auth / brute / XML-RPC ────────────────────────────────────────────────
  rule_auth_burst         = "challenge", -- generic login endpoint burst
  rule_auth_wp_checks     = "challenge", -- HEAD wp-login (qualified/repeated), no UA+Referer POST wp-login
                                         -- rollout: start this rule in "logonly" to baseline HEAD noise,
                                         -- then promote to "challenge" after validating logs.
  rule_xmlrpc_multicall   = "challenge", -- system.multicall in XML-RPC body
  rule_xmlrpc_pingback    = "challenge", -- pingback.ping in XML-RPC body
  rule_xmlrpc_post_burst  = "challenge", -- generic repeated POST /xmlrpc.php

  -- ── Audit / payload rules ─────────────────────────────────────────────────
  rule_cmd_params       = "challenge",   -- suspicious parameter keys: exec= passthru= shell_exec= eval= assert= system= cmd= command=
                                         -- (cmd=/system=/command= are now value-aware: fires only
                                         --  when value contains shell metachars or known shell tokens —
                                         --  see detect_cmd_param_key in cfm_waf_detectors.lua)
  rule_cmd_payload      = "challenge", -- fallback/default mode for payload-y separators/tokens in args
                                       -- (every emitted tag has an explicit override below; this value
                                       --  is the safety net for any new tag added to detect_cmd_payload)
  rule_debug_toggles    = "challenge", -- xdebug, trace, debug, stacktrace
                                       -- (promoted from logonly: narrow value-equality match —
                                       --  debug=1|true, trace=1|true, etc. — 0 hits in 6 weeks)
  rule_serialize        = "challenge", -- PHP serialized object markers
                                       -- (promoted from logonly: serialized blobs in URL args are
                                       --  insecure-deserialization probes; legit apps carry these
                                       --  in cookies/POST bodies, not URL args — 0 hits in 6 weeks)

  -- Per-tag override modes for cmd payloads.
  -- Empty/nil means: fall back to rule_cmd_payload.
  rule_cmd_payload_semi_cmd  = "challenge",         -- PAY_SEMI_CMD
  rule_cmd_payload_pipe_wget = "challenge",         -- PAY_PIPE_WGET
  rule_cmd_payload_pipe_curl = "challenge",         -- PAY_PIPE_CURL
  rule_cmd_payload_pipe_bash = "challenge",         -- PAY_PIPE_BASH
  rule_cmd_payload_pipe_sh   = "challenge",         -- PAY_PIPE_SH
  rule_cmd_payload_backtick  = "challenge",       -- PAY_BACKTICK
                                                  -- (promoted from logonly: detector already
                                                  --  suppresses backticks in q/s/term/search/query
                                                  --  free-text params and only fires when the backtick
                                                  --  wraps a real shell command — 0 hits in 6 weeks)

  -- ── Research additions – all logonly for initial FP observation ────────────
  -- Sources: uusec-waf (BSD), ZhongKui (Apache2), anti_ddos_challenge (MIT),
  --          nginx_waf (MIT).  Promote individually after watching logs.

  -- [top-6]  Header vulnerability bundle
  rule_bad_ua           = "challenge",  -- empty UA; known scanner/bot UAs (sqlmap, nikto, …)
  rule_shellshock       = "challenge",  -- Shellshock CVE-2014-6271 () { pattern in headers (CGI env vars)
  rule_header_vulns     = "challenge",  -- httpoxy (Proxy:), CVE-2017-7269 (Lock-Token:/If:),
                                      -- CVE-2025-24813 (Tomcat PUT /session + Content-Range)

  -- [top-7]  Content-Type validation
  rule_content_type_anomaly = "challenge",  -- non-standard charset bypass; malformed multipart boundary
                                            -- (all observed hits POST `/` against webmail / MX hosts
                                            --  with non-string CT — never legitimate browser traffic)

  -- [top-8]  Proxy header integrity
  rule_proxy_header_sqli = "challenge",  -- single-quote / non-string in XFF, X-Real-IP, Client-IP

  -- [top-9]  SSRF + JS prototype pollution
  rule_ssrf             = "challenge", -- SSRF protocol schemes (file://, gopher://, …) + IP obfuscation
                                       -- (no legitimate browser/HTTP client sends these schemes)
  rule_js_proto         = "challenge",  -- JS __proto__ / constructor.prototype pollution

  -- [top-10] XXE + CRLF + HTTP request smuggling
  rule_xxe              = "challenge",  -- XXE DOCTYPE/ENTITY SYSTEM in request body
  rule_crlf_injection   = "challenge",  -- CRLF / HTTP response-splitting in args or body
  rule_http_smuggling   = "challenge", -- HTTP verb embedded in body / querystring (smuggling)
                                       -- (request-smuggling primitive; never benign)

  -- [top-4]  Upload controls
  rule_upload_filename    = "block",  -- webshell extension in multipart filename (.php, .jsp, user.ini …)
  rule_upload_content     = "block",  -- webshell bytes / PHP tags inside uploaded file content
  rule_script_obfuscation = "challenge",  -- raw POST-body PHP/JS obfuscation scorer
  rule_upload_obfuscation = "challenge",  -- multipart uploaded file content obfuscation scorer

  -- ── Phase 1 — webshell delivery + reverse shell (logonly rollout) ─────────
  -- Sources: docs/waf.md "Detector phases" §Phase 1 / §Phase 2 / §Phase 5 (B5).
  -- All three start at logonly per the rollout playbook; promote individually
  -- only after `cfm webtop waf hit-rates --hours 168` produces ok_to_promote.
  rule_webshell_path    = "challenge", -- URI basename matches a known webshell drop name (c99.php, r57.php, …)
                                       -- (scanner-only paths: /shell.php, /webshell.php, /x.php,
                                       --  /adminer.php — zero legitimate traffic observed)
  rule_reverse_shell    = "challenge", -- bash -i >& /dev/tcp/, python -c 'import socket', socat tcp-connect …
                                       -- (post-exploit primitive; no legitimate request shape)
  rule_webshell_ping    = "challenge", -- POST + empty UA + CL:0 + URI ends in .php — webshell C2 fingerprint
                                       -- (narrow 4-signal AND-match; no legit traffic fits all four)

  -- ── Phase 2 — post-exploitation / RCE markers (logonly rollout) ───────────
  -- Sources: docs/waf.md "Detector phases" §Phase 2 (R2/R3/R4). All three
  -- emit family WAF_RCE so they share high-risk post-clearance routing.
  -- C1 (Log4Shell) is NOT here — already covered by detect_rce (rule 320).
  rule_persistence       = "challenge", -- crontab -e, /etc/cron.d/, [Unit] ExecStart= …
                                        -- (post-exploit; never appears in legitimate HTTP)
  rule_rootkit_artifacts = "challenge", -- LD_PRELOAD=, /etc/ld.so.preload, insmod /tmp/
                                        -- (kernel/loader artifacts; not part of any web request)
  rule_lolbin            = "challenge", -- certutil -urlcache -split, bitsadmin /transfer, -EncodedCommand
                                        -- (LOLBin command-line fragments; web traffic doesn't carry these)

  -- ── Phase 3 — known-CVE fingerprints (logonly rollout) ───────────────────
  -- Java deserialization (CVE-2015-7501 / -2017-9805 / -2017-12149 / -2019-2725
  -- pattern). Family WAF_RCE so it shares high-risk post-clearance routing.
  -- rule_rce (320) already catches the bare "${jndi:" Log4Shell marker;
  -- rule_log4shell (328) extends C1 with evasion variants (${lower:j}…,
  -- ${env:X:-j}…, ${${::-j}…) that defeat substring matching on rule 320.
  rule_java_deserialize  = "challenge", -- rO0AB base64 prefix / 0xACED0005 magic / aced0005 hex
                                        -- (Java-serialization-specific marker; not in legit web traffic)
  rule_log4shell         = "logonly",   -- ${lower:j}…, ${env:X:-j}…, ${${::-j}${::-n}…, ${base64:…}
                                        -- (Log4Shell JNDI-lookup evasion forms not caught by rule 320)

  -- ── Phase 4 — C2 / exfiltration (logonly rollout) ────────────────────────
  -- Sources: docs/waf.md "Detector phases" §Phase 4. X1 covers tunnel/paste
  -- service hostnames; X2 covers coinminer tool/pool fingerprints (the
  -- stratum scheme is already folded into rule 701 per audit row 16).
  rule_c2_tunnel         = "challenge", -- pastebin.com/raw/, webhook.site, ngrok.io, transfer.sh, …
                                        -- (observed: POSTs to /wp-admin/admin-ajax.php from
                                        --  Tencent ASN referencing raw.githubusercontent.com)
  rule_coinminer         = "challenge", -- xmrig --url, pool.minexmr.com, supportxmr.com, nicehash, …
                                        -- (miner CLI / pool URLs; not part of legitimate HTTP)

  -- ── Phase 5 — behavioural / combined-signal (logonly rollout) ────────────
  -- Sources: docs/waf.md "Detector phases" §Phase 5. B2 was already absorbed
  -- as a tightening of rule 607 (status row 18); B5 was shipped earlier
  -- (rule 411). What's left: B1 (HTTP smuggling header pairs), B3 (long
  -- URL segments), B4 (oversized header bag).
  rule_smuggling_cl      = "challenge", -- Content-Length + Transfer-Encoding both present, multi-CL, malformed CL
                                        -- (RFC-violating header combos used for request smuggling)
  rule_long_path_segment = "challenge", -- single URL path segment ≥ 800 bytes (Greek/CJK
                                        -- slug-safe; observed abuse is base64 stuffing >1 KB)
  rule_header_flood      = "challenge", -- total header bag > 16 KB excluding Cookie/Authorization volume
                                        -- (promoted from logonly: 16 KB threshold sits well above
                                        --  typical 1-3 KB real-world headers; 0 hits in 6 weeks)
  rule_range_abuse       = "logonly",   -- Apache Killer (CVE-2011-3192) style multi-range floods,
                                        -- oversized Range: values, legacy Request-Range: header,
                                        -- duplicate Range: headers (slowhttp / smuggling fingerprints)
  rule_bad_utf8          = "logonly",   -- malformed UTF-8 in args+body (overlong / surrogate /
                                        -- truncated multibyte). Encoding-bypass primitive — overlong
                                        -- sequences encode "." / "/" / "<" in extra bytes that
                                        -- substring matchers miss. Port of Coraza validateUtf8Encoding.

  -- ── Phase 1 — W4 polyglot upload (logonly rollout) ───────────────────────
  -- Source: docs/waf.md "Detector phases" §Phase 1 (W4). Distinct from rule
  -- 402 (detect_upload_content) which substring-scans the entire raw
  -- multipart body — W4 parses parts and checks the first 64 bytes of any
  -- image-typed / image-extension part for PHP/ASP/JSP/script openers.
  -- Same family WAF_UPLOAD_CONTENT (high-risk) so post-clearance routing
  -- is correct when promoted.
  rule_polyglot_upload   = "challenge", -- image CT/ext + <?php/<%/<jsp:/<script in first 64 bytes
                                        -- (polyglot image upload; legit images never contain these openers)

  -- ── PHP dropper / canary family (421-425) ────────────────────────────────
  -- Source: 2026-05-19 production /tmp dump from a compromised shared host.
  -- All five start at logonly per the playbook; promote to challenge/block
  -- after one week of clean cfm.waf.log data.
  rule_php_split_string_canary = "logonly", -- <?php print "A"."B";exit; exec-test probe
  rule_php_dropper_wget_curl   = "logonly", -- wget -O + curl -o + filesize() fallback dropper
  rule_php_dropper_markers     = "logonly", -- `!success!` + `!ended!` automation framing
  rule_php_filesize_recon      = "logonly", -- <fs>…</fs> + filesize() + SCRIPT_FILENAME recon
  rule_php_touch_antiforensic  = "logonly", -- @touch($p, <literal-unix-ts>) mtime backdating

  -- ── Backdoor / obfuscation family (430-437) ──────────────────────────────
  -- Tier 1 (this batch) covers the highest-yield gaps observed in production:
  -- .htaccess poisoning, char-pool obfuscator output, deep polyglots, and the
  -- generic eval-loader shape. All ship at logonly per the playbook.
  rule_htaccess_poisoning         = "logonly", -- .htaccess / .user.ini directive injection in upload bodies
  rule_php_char_pool_obfuscation  = "logonly", -- $pool[N].$pool[N].$pool[N] function-name extraction
  rule_php_polyglot_full_body     = "logonly", -- image/PDF/ZIP magic + <?php anywhere in body
  rule_php_eval_loader_b64        = "logonly", -- variable-fed eval/assert/call_user_func + >=200-char b64 literal
  rule_php_superglobal_callable   = "logonly", -- $_GET[c]( / $_POST[c]( / $_SERVER[HTTP_X_…]( minimalist webshell
  rule_php_concat_funcname_eval   = "logonly", -- $a = "sys"."tem"; $a(); short-string funcname concat + invoke
  rule_php_decode_chain           = "logonly", -- 3+ decoder primitives (base64_decode/gzinflate/strrev/…) within 300 bytes
  rule_php_encoded_opener         = "challenge", -- encoded `<?php` opener (b64 PD9waHA / URL %3C%3Fphp / HTML entity / JS escape)
                                                 -- (promoted from logonly: 2026-06-25 five-server log review — strong `<?php`
                                                 --  openers were all real attacks (Bricks RCE render_element,
                                                 --  additional_webservices.php, Amasty uploadFile) with 0 FP. The weak `<?=`
                                                 --  short-opener variant (base64 "PD89") was 6/6 FP and has been REMOVED from
                                                 --  the detector, so this rule is safe at challenge.)


  -- ── Tuning ────────────────────────────────────────────────────────────────

  -- Generic auth burst tuning
  auth_window_sec      = 20,
  auth_burst_threshold = 8,
  auth_ttl_sec         = 600,

  -- WP login helper tuning
  auth_wp_login_head_window_sec = 20,
  auth_wp_login_head_threshold  = 3,
  auth_wp_login_head_ttl_sec = 600,
  auth_wp_login_noua_ttl_sec = 600,

  -- XML-RPC direct body signatures
  auth_xmlrpc_multicall_ttl_sec = 1800,
  auth_xmlrpc_pingback_ttl_sec  = 1800,

  -- Generic XML-RPC POST burst tuning
  xmlrpc_post_window_sec = 60,
  xmlrpc_post_threshold  = 6,
  xmlrpc_post_ttl_sec    = 1800,

  -- Generic defaults
  default_ttl_sec   = 600,
  -- Short IP-ban window after a hard `block` verdict. Deliberately small:
  -- the WAF inspects EVERY request independently, so each malicious payload
  -- is still blocked per-request regardless of any ban — the IP ban is only
  -- defense-in-depth, not the primary control. A long ban (was 3600s) does
  -- more harm than good on shared egress IPs (CGNAT / mobile carriers /
  -- Cloudflare WARP `104.28.154.x`), where it locks out many innocent users
  -- and turns a single false positive into an hour-long lockout for the
  -- whole IP. 10s lets a legitimate client recover almost immediately while
  -- still collapsing rapid multi-vector bursts from a true attacker.
  block_ttl_sec     = 10,
  push_cooldown_sec = 60,

  -- Body scan budget, keyed by request Content-Type. The merged args+body
  -- string fed to body-aware rules (traversal/rce/xss/sqli/php-wrappers/
  -- ssrf/proto-pollution via get_norm_ab() below) is capped to the entry
  -- that matches the request's Content-Type. cap() enforces the byte
  -- ceiling per call, so a single huge body cannot starve the worker —
  -- work scales with the budget, not the request size.
  body_scan_budget = {
    urlencoded = 8192,
    json       = 32768,
    multipart  = 16384,
    xml        = 16384,
    other      = 2048,
  },

  -- Legacy fallback scan cap. Used by callsites without request-headers
  -- context (URI+args scans in scan_str(), body-only detectors invoked
  -- outside the engine's hot path). Body-aware rules in the engine prefer
  -- body_scan_budget above via util.body_budget(headers).
  max_scan_len      = 2048,

  -- Raw PHP webshell body scanner tuning
  php_webshell_max_scan_len = 2048,
  php_webshell_min_score    = 5,

  -- Obfuscation scorers (script body + upload file content)
  script_obfuscation_max_scan_len = 8192,
  script_obfuscation_min_score    = 6,

  upload_obfuscation_max_scan_len = 8192,
  upload_obfuscation_min_score    = 6,

  -- Bad UA scorer tuning
  -- Signals and their point values (all accumulate):
  --   +2  empty / whitespace-only UA
  --   +2  generic HTTP library UA (python-requests, libwww-perl, winhttp, httrack)
  --   +1  HEAD method (scanners probe existence before fetching)
  --   +1  no Accept header (real browsers always send one)
  --   +1  no Referer on a non-root, non-asset URI
  --   +4  URI targets a sensitive file  (.env, .git/, wp-config.php, ...)
  --   +3  URI targets a credential / backup artifact (passwords.txt, *.sql, ...)
  --   instant  known scanner tool UA (sqlmap, nikto, masscan, ...) bypasses scoring
  --
  -- Threshold examples at default of 4:
  --   empty UA hitting a normal page        = 2  -> pass  (legit bots / your C++ agents)
  --   empty UA + HEAD + no Accept           = 4  -> trigger
  --   empty UA + .git/HEAD URI              = 6  -> trigger
  --   python-requests on any article page   = 2  -> pass  (scrapers, uptime monitors)
  --   python-requests + HEAD + no Accept    = 4  -> trigger
  --   any UA  + /backup/db.sql              = 3  -> pass  (score alone insufficient)
  --   empty UA + /backup/db.sql             = 5  -> trigger
  bad_ua_min_score = 4,
}

-- Optional user overrides from cfm_waf_config.lua
do
  local ok, usercfg = pcall(require, "cfm_waf_config")
  if ok and type(usercfg) == "table" then
    for k, v in pairs(usercfg) do
      CFG[k] = v
    end
  end
end


-- Initialise sub-modules now that CFG is fully populated.
util.init(CFG)
det.init(CFG, util)

-- ─────────────────────────────────────────────────────────────────────────────
-- RULE IDS
-- ─────────────────────────────────────────────────────────────────────────────
-- Stable numeric IDs grouped by first digit:
--   1xx path / traversal
--   2xx client identity (UA)
--   3xx injection (SQLi, XSS, RCE, b64, deserialization, XXE, shellshock, …)
--   4xx upload / malware / obfuscation
--   5xx auth abuse / brute force
--   6xx header / protocol anomaly
--   7xx SSRF / external interaction
--   8xx info disclosure / debug
--   9xx reserved (future CVE detectors, behavioural rules)
--
-- NEVER renumber an existing ID — operators reference these in per-vhost
-- exclusions, dashboards, and tickets. New rules get the next free slot in
-- their semantic group.
local RULE_IDS = {
  -- 1xx path / traversal
  rule_traversal               = 101,
  rule_long_path_segment       = 102,

  -- 2xx client identity
  rule_bad_ua                  = 201,

  -- 3xx injection
  rule_sqli                    = 301,
  rule_xss                     = 302,
  rule_js_proto                = 303,
  rule_b64_injection           = 304,
  rule_php_wrappers            = 305,
  rule_serialize               = 306,
  rule_xxe                     = 307,
  rule_shellshock              = 308,
  rule_cmd_params              = 310,
  rule_cmd_payload             = 311,  -- default tag
  rule_cmd_payload_semi_cmd    = 312,
  rule_cmd_payload_pipe_wget   = 313,
  rule_cmd_payload_pipe_curl   = 314,
  rule_cmd_payload_pipe_bash   = 315,
  rule_cmd_payload_pipe_sh     = 316,
  rule_cmd_payload_backtick    = 317,
  rule_rce                     = 320,
  rule_proxy_header_sqli       = 321,
  rule_reverse_shell           = 322,
  rule_persistence             = 323,
  rule_rootkit_artifacts       = 324,
  rule_lolbin                  = 325,
  rule_java_deserialize        = 326,
  rule_coinminer               = 327,
  rule_log4shell               = 328,

  -- 4xx upload / malware
  rule_upload_filename         = 401,
  rule_upload_content          = 402,
  rule_upload_obfuscation      = 403,
  rule_php_webshell_body       = 404,
  rule_script_obfuscation      = 405,
  rule_webshell_path           = 410,
  rule_webshell_ping           = 411,
  rule_polyglot_upload         = 412,
  rule_php_split_string_canary = 421,
  rule_php_dropper_wget_curl   = 422,
  rule_php_dropper_markers     = 423,
  rule_php_filesize_recon      = 424,
  rule_php_touch_antiforensic  = 425,
  rule_htaccess_poisoning         = 430,
  rule_php_char_pool_obfuscation  = 431,
  rule_php_polyglot_full_body     = 432,
  rule_php_eval_loader_b64        = 433,
  rule_php_superglobal_callable   = 434,
  rule_php_concat_funcname_eval   = 435,
  rule_php_decode_chain           = 436,
  rule_php_encoded_opener         = 437,

  -- 5xx auth abuse
  rule_auth_burst              = 501,
  rule_auth_wp_checks          = 502,
  rule_xmlrpc_multicall        = 510,
  rule_xmlrpc_pingback         = 511,
  rule_xmlrpc_post_burst       = 512,

  -- 6xx header / protocol anomaly
  rule_ctrl_chars              = 601,
  rule_ip_host                 = 602,
  rule_header_vulns            = 603,
  rule_content_type_anomaly    = 604,
  rule_crlf_injection          = 605,
  rule_http_smuggling          = 606,
  rule_exploit_methods         = 607,
  rule_smuggling_cl            = 608,
  rule_header_flood            = 609,
  rule_range_abuse             = 610,
  rule_bad_utf8                = 611,

  -- 7xx SSRF
  rule_ssrf                    = 701,
  rule_c2_tunnel               = 702,

  -- 8xx info disclosure / debug
  rule_debug_toggles           = 801,
}

-- Per-tag override for cmd_payload sub-rules. Falls back to the parent ID
-- (rule_cmd_payload = 311) when the tag isn't in the override set.
local function rule_id_for_cmd_payload(tag)
  if     tag == "PAY_SEMI_CMD"  then return RULE_IDS.rule_cmd_payload_semi_cmd
  elseif tag == "PAY_PIPE_WGET" then return RULE_IDS.rule_cmd_payload_pipe_wget
  elseif tag == "PAY_PIPE_CURL" then return RULE_IDS.rule_cmd_payload_pipe_curl
  elseif tag == "PAY_PIPE_BASH" then return RULE_IDS.rule_cmd_payload_pipe_bash
  elseif tag == "PAY_PIPE_SH"   then return RULE_IDS.rule_cmd_payload_pipe_sh
  elseif tag == "PAY_BACKTICK"  then return RULE_IDS.rule_cmd_payload_backtick
  end
  return RULE_IDS.rule_cmd_payload
end

-- ─────────────────────────────────────────────────────────────────────────────
-- MODE HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

-- Validate / normalize a rule mode.
-- Also supports legacy booleans:
--   true  -> default_mode
--   false -> disabled
local function rule_mode(v, default_mode)
  if v == "disabled" or v == "logonly" or v == "challenge" or v == "block" then
    return v
  end
  if v == true then
    return default_mode or "challenge"
  end
  return "disabled"
end

local function mode_ttl_action(mode, ttl)
  return ttl, mode
end

-- Severity ordering for highest-severity-wins WAF aggregation.
-- _M.check() records every rule hit and returns the strongest action,
-- so a low-severity logonly never suppresses a later block/challenge.
-- "disabled" stays at 0 so disabled rules never overwrite real findings.
local ACTION_SEVERITY = {
  disabled  = 0,
  logonly   = 1,
  challenge = 2,
  block     = 3,
}
local SEV_BLOCK = ACTION_SEVERITY.block

local function cmd_payload_mode(tag)
  local override = nil

  if tag == "PAY_SEMI_CMD" then
    override = CFG.rule_cmd_payload_semi_cmd
  elseif tag == "PAY_PIPE_WGET" then
    override = CFG.rule_cmd_payload_pipe_wget
  elseif tag == "PAY_PIPE_CURL" then
    override = CFG.rule_cmd_payload_pipe_curl
  elseif tag == "PAY_PIPE_BASH" then
    override = CFG.rule_cmd_payload_pipe_bash
  elseif tag == "PAY_PIPE_SH" then
    override = CFG.rule_cmd_payload_pipe_sh
  elseif tag == "PAY_BACKTICK" then
    override = CFG.rule_cmd_payload_backtick
  end

  if override == nil then
    return rule_mode(CFG.rule_cmd_payload, "logonly")
  end
  return rule_mode(override, rule_mode(CFG.rule_cmd_payload, "logonly"))
end

function _M.enabled()
  return CFG.enabled == true
end

-- ─────────────────────────────────────────────────────────────────────────────
-- MAIN CHECK
-- ─────────────────────────────────────────────────────────────────────────────

function _M.check(ctx)
  if not CFG.enabled then
    return false, nil, nil, nil
  end

  ctx = ctx or {}

  -- Self-origin bypass (defense-in-depth). cfm.lua's "Step 0a" already
  -- short-circuits self-origin requests before they reach the WAF
  -- (cfm.lua:1106), but any caller that invokes waf.check() directly —
  -- a future code path, a test harness, an admin tool — would otherwise
  -- still run every rule against cron / cpanel / monitoring traffic.
  -- ctx.self_origin is computed once by cfm.lua via is_self_origin(ip)
  -- (loopback + link-local + the self-IP set written by Go at
  -- /var/lib/cfm/lua/cfm_self_ips.lua); we just honour it here.
  if ctx.self_origin then
    return false, nil, nil, nil
  end

  local uri     = ctx.uri     or ""
  local args    = ctx.args    or ""
  local method  = ctx.method  or "GET"
  local ip      = ctx.ip      or ""
  local shdict  = ctx.shdict
  local headers = ctx.headers or {}
  local body    = ctx.body    or ""
  -- skip_rule_ids: optional set { [rule_id] = true } of IDs to suppress.
  -- Populated by cfm.lua from the per-vhost waf-excludes snapshot when the
  -- operator has marked specific rules as excluded for this host (e.g. to
  -- whitelist a noisy scraper while keeping the rest of the WAF active).
  -- Detectors still execute (their cost is dominated by helpers shared with
  -- other rules), but record() drops the hit so it never logs, never
  -- counts, and never affects severity.
  local skip_rule_ids = ctx.skip_rule_ids

  -- One-shot gating bools so body/upload rules don't each lower(method) again.
  -- body_inspect_ok is the existing "POST + non-empty body" gate, hoisted.
  local m_lower         = lower(method)
  local body_inspect_ok = (m_lower == "post" and body ~= "")
  -- Authenticated WP plugin/theme installer (and Code Snippets REST) carry
  -- PHP-bearing uploads by design — a plugin/theme archive *is* PHP, often
  -- obfuscated. Reused below to exempt the upload-malware / webshell-content
  -- scanners (401/402/403 and the 431-436 backdoor family) so they don't
  -- flag the PHP that is the upload's whole point. Declared up here (before
  -- any `goto done`) so those jumps don't cross its scope. (437 keeps its
  -- own broader /wp-admin/ carve-out.)
  local legit_archive_upload = is_known_legit_php_upload_endpoint(uri, args)

  -- Pre-computed normalized scan strings, lazily initialised on first use.
  -- scan_str(uri,args) is shared by traversal/rce/xss/sqli (4 rules).
  -- norm_args_body is shared by php_wrappers/ssrf/js_proto (3 rules).
  -- Without this, each rule independently calls normalize()+url_decode twice.
  local _scan_ua, _norm_ab

  local function get_scan_ua()
    if not _scan_ua then _scan_ua = scan_str(uri, args) end
    return _scan_ua
  end

  local function get_norm_ab()
    if not _norm_ab then
      local budget = util.body_budget(headers)
      local a = args or ""
      local b = body or ""
      -- Pre-cap body before concat: when body >> budget (e.g. 1MB body
      -- against the 32K json budget) the merged "args & body" string would
      -- materialise the full body in memory just to be truncated by cap()
      -- below. Capping body to the budget first bounds the concat
      -- transient at ~budget+#args+1 bytes. cap() still enforces the
      -- final ceiling, so semantics are identical to a single-cap merge.
      if #b > budget then b = string.sub(b, 1, budget) end
      _norm_ab = normalize(cap(a .. "&" .. b, budget))
    end
    return _norm_ab
  end

  -- ── Severity accumulator ───────────────────────────────────────────────
  -- Highest-severity-wins: every rule that matches calls record(); the
  -- strongest action is what cfm.lua enforces. record() returns true when
  -- it just stored a `block` hit, so the caller can `goto done` and skip
  -- remaining detectors (block is the cap, nothing can exceed it).
  local hits          = {}
  local final_sev     = 0
  local final_reason  = nil
  local final_ttl     = nil
  local final_action  = nil
  local final_rule_id = nil

  local function record(reason, ttl, action, rule_id)
    local sev = ACTION_SEVERITY[action] or 0
    if sev == 0 then return false end
    -- Per-vhost rule exclusion: drop hits whose rule_id is in the operator's
    -- skip set. The detector's work is wasted (its match cost was already
    -- paid) but the hit never leaks into severity/log/counters — exactly
    -- the semantic the operator asked for ("ignore rule N on this host").
    if skip_rule_ids and rule_id and skip_rule_ids[rule_id] then
      return false
    end
    hits[#hits + 1] = { reason = reason, ttl = ttl, action = action, waf_rule_id = rule_id }
    if sev > final_sev then
      final_sev     = sev
      final_reason  = reason
      final_ttl     = ttl
      final_action  = action
      final_rule_id = rule_id
    end
    return sev >= SEV_BLOCK
  end

  -- ── 1) Bad User-Agent (scored) ──────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_bad_ua, "logonly")
    if mode ~= "disabled" then
      local score, tag = det.detect_bad_ua_scored(headers, uri, method)
      local threshold = tonumber(CFG.bad_ua_min_score) or 4
      if score >= threshold then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BAD_UA:" .. tag .. ":score=" .. score, ttl, mode, RULE_IDS.rule_bad_ua) then goto done end
      end
    end
  end

  -- ── 2) Header vulnerabilities (httpoxy / CVE-2017-7269 / CVE-2025-24813) ─
  do
    local mode = rule_mode(CFG.rule_header_vulns, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_header_vulns(headers, uri, method)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_HEADER_VULN:" .. tag, ttl, mode, RULE_IDS.rule_header_vulns) then goto done end
      end
    end
  end

  -- ── 3) Proxy header SQLi / injection ─────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_proxy_header_sqli, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_proxy_header_sqli(headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_PROXY_HDR:" .. tag, ttl, mode, RULE_IDS.rule_proxy_header_sqli) then goto done end
      end
    end
  end

  -- ── 4) Content-Type anomaly (charset bypass / malformed boundary) ─────────
  do
    local mode = rule_mode(CFG.rule_content_type_anomaly, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_content_type_anomaly(headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CT_ANOMALY:" .. tag, ttl, mode, RULE_IDS.rule_content_type_anomaly) then goto done end
      end
    end
  end

  -- ── 5) Traversal ──────────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_traversal, "block")
    if mode ~= "disabled" and det.detect_traversal(uri, args, get_scan_ua()) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      ttl, mode = mode_ttl_action(mode, ttl)
      if record("WAF_TRAVERSAL", ttl, mode, RULE_IDS.rule_traversal) then goto done end
    end
  end

  -- ── 6) RCE ────────────────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_rce, "block")
    if mode ~= "disabled" and det.detect_rce(uri, args, get_scan_ua()) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      ttl, mode = mode_ttl_action(mode, ttl)
      if record("WAF_RCE", ttl, mode, RULE_IDS.rule_rce) then goto done end
    end
  end

  -- ── 6a) Log4Shell evasion variants (C1 extension; rule_rce 320 catches  ──
  --       the bare "${jndi:" forms — this rule covers the lookup-syntax
  --       tricks: ${${::-j}…, ${lower:j}…, ${env:X:-j}…, ${base64:…}).
  do
    local mode = rule_mode(CFG.rule_log4shell, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_log4shell(args, body, headers, get_norm_ab())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:LOG4SHELL:" .. tag, ttl, mode, RULE_IDS.rule_log4shell) then goto done end
      end
    end
  end

  -- ── 7) Shellshock (CVE-2014-6271) ────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_shellshock, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_shellshock(headers, uri)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_SHELLSHOCK:" .. tag, ttl, mode, RULE_IDS.rule_shellshock) then goto done end
      end
    end
  end

  -- ── 8) Exploit methods ────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_exploit_methods, "challenge")
    if mode ~= "disabled" then
      local maction, mtag = det.detect_exploit_method(method)
      local reason = mtag and ("WAF_EXPLOIT_METHOD:" .. mtag) or "WAF_EXPLOIT_METHOD"
      if maction == "block" then
        local final = (mode == "logonly") and "logonly" or "block"
        local ttl = (final == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record(reason, ttl, final, RULE_IDS.rule_exploit_methods) then goto done end
      elseif maction == "challenge" then
        local final = (mode == "block") and "block" or mode
        local ttl = (final == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record(reason, ttl, final, RULE_IDS.rule_exploit_methods) then goto done end
      end
    end
  end

  -- ── 9) PHP wrappers ───────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_wrappers, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_php_wrappers(args, body, get_norm_ab())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_PHP_WRAPPER:" .. tag, ttl, mode, RULE_IDS.rule_php_wrappers) then goto done end
      end
    end
  end

  -- ── 10) PHP double-extension in URI ──────────────────────────────────────

-- removed --

  -- ── 11) Bare IP Host ──────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_ip_host, "logonly")
    if mode ~= "disabled" and det.detect_ip_host(header_string(headers["Host"] or headers["host"])) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      if record("WAF_IP_HOST", ttl, mode, RULE_IDS.rule_ip_host) then goto done end
    end
  end

  -- ── 12) Control chars ─────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_ctrl_chars, "logonly")
    if mode ~= "disabled" and det.detect_ctrl_chars(args, body, headers, uri) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      if record("WAF_CTRL_CHARS", ttl, mode, RULE_IDS.rule_ctrl_chars) then goto done end
    end
  end

  -- ── 12a) Bad UTF-8 encoding (Coraza validateUtf8Encoding port) ───────────
  do
    local mode = rule_mode(CFG.rule_bad_utf8, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_bad_utf8(args, body, headers, uri)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BAD_UTF8:" .. tag, ttl, mode, RULE_IDS.rule_bad_utf8) then goto done end
      end
    end
  end

  -- ── 13) SSRF protocol schemes + IP obfuscation ───────────────────────────
  do
    local mode = rule_mode(CFG.rule_ssrf, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_ssrf_proto(args, body, get_norm_ab())
      -- WP All Import (`pmxi-*`), WPvivid, UpdraftPlus, BackWPup, and
      -- similar plugins legitimately store `ftp://` URLs as plugin
      -- configuration. The admin then revisits those settings pages and
      -- the saved URL is echoed in query strings / hidden form fields,
      -- which trips SSRF_FTP — but the FTP URL is plugin state, not an
      -- attacker-controlled fetch target. Suppress that one tag on
      -- /wp-admin/ paths; the other SSRF tags (FILE, GOPHER, DICT,
      -- LDAP, TFTP, STRATUM, SFTP, IP-obfuscation flavours) still fire
      -- because no benign WP plugin stores those.
      if tag == "SSRF_FTP" and uri:find("^/wp%-admin/", 1, false) then
        tag = nil
      end
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_SSRF:" .. tag, ttl, mode, RULE_IDS.rule_ssrf) then goto done end
      end
    end
  end

  -- ── 14) JS prototype pollution ────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_js_proto, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_js_proto(args, body, get_norm_ab())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_JS_PROTO:" .. tag, ttl, mode, RULE_IDS.rule_js_proto) then goto done end
      end
    end
  end

  -- ── 15) Raw PHP webshell body (scored) ───────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_webshell_body, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_php_webshell_body(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_PHP_WEBSHELL_BODY:" .. tag, ttl, mode, RULE_IDS.rule_php_webshell_body) then goto done end
      end
    end
  end

  -- ── 16) Script / JS obfuscation scorer (raw POST body) ───────────────────
  do
    local mode = rule_mode(CFG.rule_script_obfuscation, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_script_obfuscation(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_SCRIPT_OBFUSCATION:" .. tag, ttl, mode, RULE_IDS.rule_script_obfuscation) then goto done end
      end
    end
  end

  -- ── 17) Upload filename extension blacklist ───────────────────────────────
  do
    local mode = rule_mode(CFG.rule_upload_filename, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_upload_filename(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_UPLOAD_FNAME:" .. tag, ttl, mode, RULE_IDS.rule_upload_filename) then goto done end
      end
    end
  end

  -- ── 18) Upload content / webshell byte scan ───────────────────────────────
  do
    local mode = rule_mode(CFG.rule_upload_content, "logonly")
    if mode ~= "disabled"
       and body_inspect_ok
       and not legit_archive_upload then
      local tag = det.detect_upload_content(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_UPLOAD_CONTENT:" .. tag, ttl, mode, RULE_IDS.rule_upload_content) then goto done end
      end
    end
  end

  -- ── 19) Upload obfuscation scorer (multipart file content) ───────────────
  do
    local mode = rule_mode(CFG.rule_upload_obfuscation, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_upload_obfuscation(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_UPLOAD_OBFUSCATION:" .. tag, ttl, mode, RULE_IDS.rule_upload_obfuscation) then goto done end
      end
    end
  end

  -- ── 20) XSS ───────────────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_xss, "challenge")
    if mode ~= "disabled" and det.detect_xss(uri, args, get_scan_ua()) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      if record("WAF_XSS", ttl, mode, RULE_IDS.rule_xss) then goto done end
    end
  end

  -- ── 21) SQLi (+ SQL comment bypass) ──────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_sqli, "challenge")
    if mode ~= "disabled" and det.detect_sqli(uri, args, get_scan_ua()) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      if record("WAF_SQLI", ttl, mode, RULE_IDS.rule_sqli) then goto done end
    end
  end

  -- ── 22) XXE ───────────────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_xxe, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_xxe(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_XXE:" .. tag, ttl, mode, RULE_IDS.rule_xxe) then goto done end
      end
    end
  end

  -- ── 23) CRLF / HTTP response splitting ───────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_crlf_injection, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_crlf_injection(args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CRLF:" .. tag, ttl, mode, RULE_IDS.rule_crlf_injection) then goto done end
      end
    end
  end

  -- ── 24) HTTP request smuggling ────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_http_smuggling, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_http_smuggling(args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_HTTP_SMUGGLING:" .. tag, ttl, mode, RULE_IDS.rule_http_smuggling) then goto done end
      end
    end
  end

  -- ── 25) WP-specific auth checks ──────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_auth_wp_checks, "challenge")
    if mode ~= "disabled" then
      local tag = det.detect_wp_login_probe(uri, method, headers, ip, host, shdict)
      if tag == "AUTH_WP_LOGIN_HEAD" then
        local ttl = CFG.auth_wp_login_head_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        if record("WAF_AUTH_BURST:" .. tag, ttl, mode, RULE_IDS.rule_auth_wp_checks) then goto done end
      elseif tag == "AUTH_WP_LOGIN_NO_UA_REF" then
        local ttl = CFG.auth_wp_login_noua_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        if record("WAF_AUTH_BURST:" .. tag, ttl, mode, RULE_IDS.rule_auth_wp_checks) then goto done end
      end
    end
  end


  -- ── 26) XML-RPC strong body signatures ───────────────────────────────────
  do
    local xtag = nil
    if not det.is_known_legit_xmlrpc(uri, args, headers, body) then
      xtag = det.detect_xmlrpc_probe(uri, method, body)
    end

    if xtag == "AUTH_WP_XMLRPC_MULTICALL" then
      local mode = rule_mode(CFG.rule_xmlrpc_multicall, "challenge")
      if mode ~= "disabled" then
        local ttl = CFG.auth_xmlrpc_multicall_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        if record("WAF_AUTH_BURST:" .. xtag, ttl, mode, RULE_IDS.rule_xmlrpc_multicall) then goto done end
      end
    elseif xtag == "AUTH_WP_XMLRPC_PINGBACK" then
      local mode = rule_mode(CFG.rule_xmlrpc_pingback, "challenge")
      if mode ~= "disabled" then
        local ttl = CFG.auth_xmlrpc_pingback_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        if record("WAF_AUTH_BURST:" .. xtag, ttl, mode, RULE_IDS.rule_xmlrpc_pingback) then goto done end
      end
    end
  end


  -- ── 27) Generic XML-RPC POST burst ───────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_xmlrpc_post_burst, "challenge")
    if mode ~= "disabled" then
      local tag = det.detect_xmlrpc_post_burst(ip, host, uri, method, shdict, args, headers, body)
      if tag then
        local ttl = CFG.xmlrpc_post_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        if record("WAF_AUTH_BURST:" .. tag, ttl, mode, RULE_IDS.rule_xmlrpc_post_burst) then goto done end
      end
    end
  end

  -- ── 28) Generic auth endpoint burst ──────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_auth_burst, "challenge")
    if mode ~= "disabled" then
      local peer = ctx.peer or ""

      if not (peer ~= "" and ip ~= "" and ip == peer) then
        local tag = nil
        if not det.is_known_legit_xmlrpc(uri, args, headers, body) then
          tag = det.detect_auth_burst(ip, host, uri, method, shdict)
        end
        if tag then
          local ttl = CFG.auth_ttl_sec or CFG.default_ttl_sec
          if record("WAF_AUTH_BURST:" .. tag, ttl, mode, RULE_IDS.rule_auth_burst) then goto done end
        end
      end


    end
  end

  -- ── 29) Suspicious command parameter keys ─────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_cmd_params, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_cmd_param_key(args)
      if tag then
        if record("WAF_CMD_PARAM:" .. tag, CFG.default_ttl_sec, mode, RULE_IDS.rule_cmd_params) then goto done end
      end
    end
  end

  -- ── 30) Suspicious payload markers ───────────────────────────────────────
  do
    local tag = det.detect_cmd_payload(args)
    if tag then
      local mode = cmd_payload_mode(tag)
      if mode ~= "disabled" then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CMD_PAYLOAD:" .. tag, ttl, mode, rule_id_for_cmd_payload(tag)) then goto done end
      end
    end
  end

  -- ── 31) Debug toggles ─────────────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_debug_toggles, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_debug_toggles(args)
      if tag then
        if record("WAF_DEBUG_TOGGLE:" .. tag, CFG.default_ttl_sec, mode, RULE_IDS.rule_debug_toggles) then goto done end
      end
    end
  end

  -- ── 32) PHP serialize markers ─────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_serialize, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_php_serialize(args)
      if tag then
        if record("WAF_SERIALIZE:" .. tag, CFG.default_ttl_sec, mode, RULE_IDS.rule_serialize) then goto done end
      end
    end
  end

  -- ── 33) Base64 POST body scanner ──────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_b64_injection, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_b64_injection(body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_B64_INJECT:" .. tag, ttl, mode, RULE_IDS.rule_b64_injection) then goto done end
      end
    end
  end

  -- ── 34) Webshell drop path (W1) ──────────────────────────────────────────
  -- URI basename matches a known webshell name (c99.php, r57.php, p0wny.php …).
  -- Cheap (one lower(uri) + one hash-set lookup); near-zero legit traffic.
  do
    local mode = rule_mode(CFG.rule_webshell_path, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_webshell_path(uri)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_WEBSHELL:" .. tag, ttl, mode, RULE_IDS.rule_webshell_path) then goto done end
      end
    end
  end

  -- ── 35) Reverse shell payload (R1) ───────────────────────────────────────
  -- Literal reverse-shell strings in URI/args/body (bash -i >& /dev/tcp/,
  -- python -c 'import socket', socat tcp-connect …). Family WAF_RCE so it
  -- shares the high-risk routing of rule_rce; distinct rule_id 322 keeps
  -- hit-rate counters and per-vhost exclusions independent.
  do
    local mode = rule_mode(CFG.rule_reverse_shell, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_reverse_shell(uri, args, body, get_scan_ua())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_RCE:REVERSE_SHELL:" .. tag, ttl, mode, RULE_IDS.rule_reverse_shell) then goto done end
      end
    end
  end

  -- ── 36) Webshell ping fingerprint (B5) ───────────────────────────────────
  -- POST + empty UA + Content-Length:0 + URI ending in .php/.phtml/.phar.
  -- Pattern fingerprints C2 channels keeping a webshell warm; legit traffic
  -- almost never matches all four signals at once.
  do
    local mode = rule_mode(CFG.rule_webshell_ping, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_webshell_ping(method, headers, uri)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_WEBSHELL:" .. tag, ttl, mode, RULE_IDS.rule_webshell_ping) then goto done end
      end
    end
  end

  -- ── 37) Persistence markers (R2) ─────────────────────────────────────────
  -- Cron / systemd persistence one-liners (`crontab -e`, `/etc/cron.d/`,
  -- `[Unit]…ExecStart=/`). Family WAF_RCE shares high-risk routing.
  do
    local mode = rule_mode(CFG.rule_persistence, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_persistence(uri, args, body, get_scan_ua())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_RCE:PERSISTENCE:" .. tag, ttl, mode, RULE_IDS.rule_persistence) then goto done end
      end
    end
  end

  -- ── 38) Rootkit artifacts (R3) ───────────────────────────────────────────
  -- LD_PRELOAD / /etc/ld.so.preload / kernel-module insmod patterns.
  do
    local mode = rule_mode(CFG.rule_rootkit_artifacts, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_rootkit_artifacts(uri, args, body, get_scan_ua())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_RCE:ROOTKIT:" .. tag, ttl, mode, RULE_IDS.rule_rootkit_artifacts) then goto done end
      end
    end
  end

  -- ── 39) LOLbins (R4) ─────────────────────────────────────────────────────
  -- Living-off-the-land binary invocations: certutil/bitsadmin downloaders,
  -- powershell -EncodedCommand. The IEX-WebClient downloader and TcpClient
  -- variants are intentionally NOT here — already in R1's REVERSE_SHELL
  -- table to avoid double-counting on the same hit.
  do
    local mode = rule_mode(CFG.rule_lolbin, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_lolbin(uri, args, body, get_scan_ua())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_RCE:LOLBIN:" .. tag, ttl, mode, RULE_IDS.rule_lolbin) then goto done end
      end
    end
  end

  -- ── 40) Java deserialization (C2) ────────────────────────────────────────
  -- Detects ObjectOutputStream payloads by their stable wire-format prefix:
  -- raw bytes 0xAC 0xED 0x00 0x05, base64 prefix "rO0AB", or "aced0005" hex.
  -- These are how RCE chains (Commons Collections, Spring Framework, JBoss
  -- Richfaces — CVE-2015-7501 / -2017-9805 / -2017-12149 / -2019-2725)
  -- arrive over HTTP. PHP serialize is a separate rule (306).
  do
    local mode = rule_mode(CFG.rule_java_deserialize, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_java_deserialize(headers, args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_RCE:JAVA_DESERIALIZE:" .. tag, ttl, mode, RULE_IDS.rule_java_deserialize) then goto done end
      end
    end
  end

  -- ── 41) C2 / paste-tunnel hostnames (X1) ─────────────────────────────────
  -- Body or args carries an exfil-friendly hostname (pastebin.com/raw/,
  -- webhook.site, ngrok.io, transfer.sh, …). Family WAF_C2 is distinct from
  -- WAF_SSRF (rule 701) — SSRF is about scheme abuse, C2 is about specific
  -- hostnames known to host attacker infrastructure.
  do
    local mode = rule_mode(CFG.rule_c2_tunnel, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_c2_tunnel(args, body, get_norm_ab())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_C2:TUNNEL:" .. tag, ttl, mode, RULE_IDS.rule_c2_tunnel) then goto done end
      end
    end
  end

  -- ── 42) Coinminer tool/pool fingerprints (X2) ────────────────────────────
  -- xmrig invocation flags, public XMR pool hostnames, monerod etc. The
  -- stratum scheme is already covered by rule 701 (SSRF_STRATUM) — this
  -- rule covers the tool/pool side only.
  do
    local mode = rule_mode(CFG.rule_coinminer, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_coinminer(uri, args, body, get_scan_ua())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_RCE:COINMINER:" .. tag, ttl, mode, RULE_IDS.rule_coinminer) then goto done end
      end
    end
  end

  -- ── 43) Smuggling header pairs (B1) ──────────────────────────────────────
  -- Content-Length + Transfer-Encoding both present, multiple CL/TE values,
  -- malformed CL. Distinct from rule 606 (which catches embedded HTTP verbs
  -- in body/args); both share family WAF_HTTP_SMUGGLING for log triage.
  do
    local mode = rule_mode(CFG.rule_smuggling_cl, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_smuggling_cl(headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_HTTP_SMUGGLING:" .. tag, ttl, mode, RULE_IDS.rule_smuggling_cl) then goto done end
      end
    end
  end

  -- ── 44) Long URL path segment (B3) ───────────────────────────────────────
  -- Single path segment (between two `/`) ≥ 256 chars. Indicator of token
  -- stuffing, base64 in path, or buffer-overflow probing.
  do
    local mode = rule_mode(CFG.rule_long_path_segment, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_long_path_segment(uri)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_LONG_PATH:" .. tag, ttl, mode, RULE_IDS.rule_long_path_segment) then goto done end
      end
    end
  end

  -- ── 45) Header bag flood (B4) ────────────────────────────────────────────
  -- Total header bytes > 16 KB after subtracting Cookie / Authorization
  -- volume (those are session-state, not flood). Different mechanism from
  -- rule 603 (header_vulns) which checks specific CVE headers.
  do
    local mode = rule_mode(CFG.rule_header_flood, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_header_flood(headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_HEADER_FLOOD:" .. tag, ttl, mode, RULE_IDS.rule_header_flood) then goto done end
      end
    end
  end

  -- ── 45a) Range / Request-Range header abuse (slow-HTTP / Apache Killer) ──
  -- Multi-range Range: floods (CVE-2011-3192), oversized Range values, the
  -- deprecated Request-Range: header, and duplicate Range: headers. All
  -- four patterns are foreign to legitimate browser/CDN/uploader traffic
  -- but are common in slowhttptest range mode, RangeAmp variants, and
  -- exploit-kit probes. Starts at logonly per the playbook.
  do
    local mode = rule_mode(CFG.rule_range_abuse, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_range_abuse(headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_RANGE_ABUSE:" .. tag, ttl, mode, RULE_IDS.rule_range_abuse) then goto done end
      end
    end
  end

  -- ── 46) Polyglot upload (W4) ─────────────────────────────────────────────
  -- Multipart parts whose Content-Type / filename claim "image" but whose
  -- first 64 bytes start with an executable opener (`<?php`, `<%`, `<jsp:`,
  -- `<script`). Distinct from rule 402 (raw substring scan over the whole
  -- multipart body) — W4 parses parts and bounds the search so a legit form
  -- field containing `<?php` text can't trigger.
  do
    local mode = rule_mode(CFG.rule_polyglot_upload, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_polyglot_upload(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_UPLOAD_CONTENT:" .. tag, ttl, mode, RULE_IDS.rule_polyglot_upload) then goto done end
      end
    end
  end

  -- ── 47) PHP split-string canary (421) ────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_split_string_canary, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_php_split_string_canary(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_DROPPER:" .. tag, ttl, mode, RULE_IDS.rule_php_split_string_canary) then goto done end
      end
    end
  end

  -- ── 48) PHP wget+curl fallback dropper (422) ─────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_dropper_wget_curl, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_php_dropper_wget_curl(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_DROPPER:" .. tag, ttl, mode, RULE_IDS.rule_php_dropper_wget_curl) then goto done end
      end
    end
  end

  -- ── 49) PHP dropper success/ended markers (423) ──────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_dropper_markers, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_php_dropper_markers(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_DROPPER:" .. tag, ttl, mode, RULE_IDS.rule_php_dropper_markers) then goto done end
      end
    end
  end

  -- ── 50) PHP filesize / <fs>-tag recon (424) ──────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_filesize_recon, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_php_filesize_recon(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_DROPPER:" .. tag, ttl, mode, RULE_IDS.rule_php_filesize_recon) then goto done end
      end
    end
  end

  -- ── 51) PHP @touch() mtime backdating (425) ──────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_touch_antiforensic, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_php_touch_antiforensic(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_DROPPER:" .. tag, ttl, mode, RULE_IDS.rule_php_touch_antiforensic) then goto done end
      end
    end
  end

  -- ── 52) .htaccess / .user.ini poisoning (430) ────────────────────────────
  do
    local mode = rule_mode(CFG.rule_htaccess_poisoning, "logonly")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_htaccess_poisoning(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_htaccess_poisoning) then goto done end
      end
    end
  end

  -- ── 53) PHP char-pool function-name builder (431) ────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_char_pool_obfuscation, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_php_char_pool_obfuscation(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_php_char_pool_obfuscation) then goto done end
      end
    end
  end

  -- ── 54) PHP polyglot full-body (432) ─────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_polyglot_full_body, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_php_polyglot_full_body(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_php_polyglot_full_body) then goto done end
      end
    end
  end

  -- ── 55) PHP eval-loader with large b64 literal (433) ─────────────────────
  do
    local mode = rule_mode(CFG.rule_php_eval_loader_b64, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_php_eval_loader_b64(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_php_eval_loader_b64) then goto done end
      end
    end
  end

  -- ── 56) PHP superglobal-fed callable (434) ───────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_superglobal_callable, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_php_superglobal_callable(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_php_superglobal_callable) then goto done end
      end
    end
  end

  -- ── 57) PHP concat function-name eval (435) ──────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_concat_funcname_eval, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_php_concat_funcname_eval(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_php_concat_funcname_eval) then goto done end
      end
    end
  end

  -- ── 58) PHP multi-decode-chain proximity scorer (436) ────────────────────
  do
    local mode = rule_mode(CFG.rule_php_decode_chain, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_php_decode_chain(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_php_decode_chain) then goto done end
      end
    end
  end

  -- ── 59) PHP encoded `<?php` opener (437) ─────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_php_encoded_opener, "logonly")
    -- WPCode, Code Snippets, Insert PHP Code Snippet, and similar
    -- "save a PHP snippet" plugins POST encoded `<?php` bodies to
    -- /wp-admin/admin-ajax.php or /wp-admin/admin.php on every save.
    -- That's legitimate plugin behavior, not a backdoor upload —
    -- production data showed real Greek WP admins on Chrome 148
    -- residential IPs being challenged here. /wp-admin/ requests
    -- have already passed WP's cookie-auth gate before reaching us,
    -- so we suppress this detector on that path. Web shells delivered
    -- via theme/plugin file editors, upload exploits, or vulnerable
    -- public endpoints still arrive on non-/wp-admin/ paths where
    -- this rule remains active.
    local wp_admin = uri:find("^/wp%-admin/", 1, false) ~= nil
    if mode ~= "disabled" and body_inspect_ok and not wp_admin then
      local tag = det.detect_php_encoded_opener(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_php_encoded_opener) then goto done end
      end
    end
  end

  ::done::
  if final_sev == 0 then
    return false, nil, nil, nil
  end
  return true, final_reason, final_ttl, final_action, hits, final_rule_id
end

function _M.should_push(shdict, ip, reason)
  if not shdict or not ip or ip == "" then return true end
  local k  = "wafpush|" .. (reason or "WAF") .. "|" .. ip
  local ok = shdict:add(k, 1, CFG.push_cooldown_sec)
  return ok == true
end

-- WAF reason families that should escalate to block (instead of degrading to
-- logonly) when a "challenge"-mode rule fires under valid clearance. Match is
-- on the family prefix before the first ":" (so "WAF_RCE:REVERSE_SHELL" still
-- hits). Source of truth: docs/waf.md "High-risk reasons".
_M.WAF_HIGH_RISK_REASONS = {
  WAF_RCE                = true,
  WAF_UPLOAD_CONTENT     = true,
  WAF_UPLOAD_FNAME       = true,
  WAF_UPLOAD_OBFUSCATION = true,
  WAF_CMD_PAYLOAD        = true,
  WAF_B64_INJECT         = true,
  WAF_SHELLSHOCK         = true,
  WAF_PHP_WEBSHELL_BODY  = true,
  WAF_WEBSHELL           = true,
  WAF_TRAVERSAL          = true,
  WAF_XXE                = true,
  WAF_CVE                = true,
  WAF_DROPPER            = true,
  WAF_BACKDOOR           = true,
}

function _M.is_high_risk_reason(reason)
  if not reason or reason == "" then return false end
  local prefix = reason:match("^([^:]+)") or reason
  return _M.WAF_HIGH_RISK_REASONS[prefix] == true
end

-- Post-clearance challenge-loop converter. Returns (action, was_converted).
-- Only "challenge" actions are eligible for conversion; everything else
-- passes through unchanged. Defence in depth: if either default is itself
-- "challenge", coerce it to the safe value for that slot. The CFG sanitizer
-- in cfm.lua already rejects "challenge" as an env value, but a buggy
-- caller passing it raw must not reintroduce the loop.
function _M.post_clearance_action(action, reason, after_challenge, after_high_risk)
  if action ~= "challenge" then return action, false end
  if after_high_risk == "challenge" then after_high_risk = "block" end
  if after_challenge == "challenge" then after_challenge = "logonly" end
  if _M.is_high_risk_reason(reason) then
    return after_high_risk or "block", true
  end
  return after_challenge or "logonly", true
end

-- Live rule-mode tuning. Accepts the same values rule_mode() does:
-- "disabled" | "logonly" | "challenge" | "block". Returns true on success,
-- (false, err) on rejection. Per-worker only — changes do not survive
-- reload. Intended for ops kill-switches and tests.
--
-- Name must start with "rule_": this prevents typos like
-- set_rule("max_scan_len", "block") from silently overwriting unrelated
-- numeric tuning fields with a string mode value.
function _M.set_rule(name, mode)
  if type(name) ~= "string" or name:sub(1, 5) ~= "rule_" then
    return false, "invalid rule name"
  end
  if mode ~= "disabled" and mode ~= "logonly" and mode ~= "challenge" and mode ~= "block" then
    return false, "invalid mode"
  end
  CFG[name] = mode
  return true
end


-- This exposes the full CFG table (rule modes + tuning values) to cfm_stats.lua
-- without copying data or adding any runtime overhead to the hot path.
 
function _M.get_config()
  -- Return a shallow copy so callers cannot mutate the live CFG table.
  local snap = {}
  for k, v in pairs(CFG) do
    snap[k] = v
  end
  return snap
end

-- Return a shallow copy of the rule_id table so callers (Go-side mirror,
-- /api/v1/waf/rules endpoint, panel UI) can enumerate rules without being
-- able to mutate the live mapping.
function _M.get_rule_ids()
  local snap = {}
  for k, v in pairs(RULE_IDS) do
    snap[k] = v
  end
  return snap
end

-- Look up a single rule's stable numeric ID by its CFG key. Returns nil for
-- unknown keys.
function _M.rule_id_for(cfg_key)
  if type(cfg_key) ~= "string" then return nil end
  return RULE_IDS[cfg_key]
end

return _M
