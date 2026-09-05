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
--   _M.should_push(shdict, ip, reason, action) -> bool
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
local strip_data_uri = util.strip_data_uri
local header_string = util.header_string
local is_known_legit_php_upload_endpoint = util.is_known_legit_php_upload_endpoint
local is_php_hostile_asset_upload = util.is_php_hostile_asset_upload

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
  rule_traversal       = "block",      -- ../, null bytes, basic traversal markers
                                       -- (signal-confirmed: encoded forms, null bytes,
                                       --  multi-hop, or single ../ paired with a
                                       --  sensitive sink — see detect_traversal).
                                       -- Promoted challenge→block 2026-09-05 after a
                                       -- clean 6-server FP review: 11 507 hits/7 d,
                                       -- 0 from GR, every sampled hit a scanner
                                       -- payload (.env / /proc/self/environ / pearcmd
                                       -- / .git/config / /etc/passwd) — docs/waf.md.
  rule_rce             = "block",      -- strong RCE / shell / jndi markers
  rule_exploit_methods = "challenge",  -- TRACE/TRACK/CONNECT etc
  rule_xss             = "challenge",  -- cheap reflected-XSS style patterns
  rule_sqli            = "block",      -- cheap SQLi signatures + DBMS-unique blind primitives (promoted challenge→block 2026-07 after a clean 6-server FP review: 24/24 TP, 0 FP)
  rule_sqli_blind_lexical = "block", -- word/method-colliding blind tokens (extractvalue(/updatexml(/benchmark(/…); promoted challenge→block 2026-08-23 after expanded fleet burn-in; prior 188/188 TP, 0 FP review (docs/waf.md)
  rule_sqli_union_variant = "challenge",   -- obfuscated UNION (union all/distinct select, union(select, union/**/select) that rule 301's adjacent `union select` misses; promoted logonly→challenge 2026-08-23 after clean fleet review (docs/waf.md)
  rule_superglobal_override = "logonly", -- request param KEY named like a PHP superglobal (_GET/_SERVER/GLOBALS/…) = variable poisoning; observe-only pending FP review

  -- ── Safer rollout / audit-first rules ─────────────────────────────────────
  rule_php_wrappers      = "block",      -- php:// phar:// data:// zip:// expect:// glob:// (args/body only; edge-block + autoblock-armed since 2026-07-18)
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
  rule_xmlrpc_multicall   = "block", -- system.multicall in XML-RPC body
  rule_xmlrpc_pingback    = "block", -- pingback.ping in XML-RPC body
  rule_xmlrpc_post_burst  = "block", -- generic repeated POST /xmlrpc.php

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
  rule_php_object_injection = "block", -- UNAUTH PHP object injection O:N:"…"/C:N:"…" (deserialization->RCE)
                                       -- in args OR body, incl. base64 (Tzo/Qzo). Emits WAF_RCE (armed).
                                       -- Unauth-gated: legit serialized blobs ride authenticated
                                       -- admin-ajax; rule 306 keeps the auth'd case at challenge.

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
  rule_bad_ua           = "challenge",  -- mixed-mode: normal scored hits challenge; score >= 99 hard-blocks
  rule_shellshock       = "challenge",  -- Shellshock CVE-2014-6271 () { pattern in headers (CGI env vars)
  rule_header_vulns     = "challenge",  -- httpoxy (Proxy:), CVE-2017-7269 (Lock-Token:/If:),
                                      -- CVE-2025-24813 (Tomcat PUT /session + Content-Range)

  -- [top-7]  Content-Type validation
  rule_content_type_anomaly = "challenge",  -- non-standard charset bypass; malformed multipart boundary
                                            -- (all observed hits POST `/` against webmail / MX hosts
                                            --  with non-string CT — never legitimate browser traffic)

  -- Fetch-metadata missing (headless / automation tell) — logonly SHADOW.
  -- Fires ONLY when a UA CLAIMS a Sec-Fetch-capable browser (Chrome >= 76 /
  -- Firefox >= 90) yet a text/html GET|HEAD navigation carries NO Sec-Fetch-*
  -- AND NO Accept-Language — a stacked weak signal, categorical together, that a
  -- real browser normally never trips (Track-2 Stage 1b; docs/challenge-score.md).
  -- Honest curl/wget/python clients never claim a browser, so they never match;
  -- self-declared crawlers and infra paths are skipped in the detector, and the
  -- known real-browser exception (in-app WebViews of social apps, e.g. TikTok)
  -- is recorded under its own NO_FETCH_META_IN_APP tag so it stays separable,
  -- and that tag is CLAMPED to logonly at the record() call: a promotion here
  -- only ever escalates the tell proper (NO_FETCH_META_NO_ACCEPT_LANG), never
  -- the in-app pool. logonly-only for burn-in — promote past logonly only after
  -- watching waf_activity per tag, never on "no real browser trips it" alone.
  rule_fetch_metadata_missing = "logonly",

  -- [top-8]  Proxy header integrity
  rule_proxy_header_sqli = "challenge",  -- single-quote / non-string in XFF, X-Real-IP, Client-IP

  -- [top-9]  SSRF + JS prototype pollution
  rule_ssrf             = "challenge", -- SSRF protocol schemes (file://, gopher://, …) + IP obfuscation
                                       -- (no legitimate browser/HTTP client sends these schemes)
  rule_js_proto         = "challenge",  -- JS __proto__ / constructor.prototype pollution

  -- [top-10] XXE + CRLF + HTTP request smuggling
  rule_xxe              = "challenge",  -- XXE DOCTYPE/ENTITY SYSTEM in request body
  rule_crlf_injection   = "logonly",    -- CRLF / HTTP response-splitting in args or body.
                                        -- content-type/content-length are the FP-prone, low-impact tags:
                                        -- they appear legitimately in request BODIES (multipart part
                                        -- headers; page-builder/API/oEmbed save payloads embedding HTTP
                                        -- header text — a wp-admin/admin-ajax page-builder POST tripped
                                        -- CRLF_CONTENT_TYPE, a confirmed FP vs a logged-in admin). So
                                        -- detect_crlf_injection scopes content-type/content-length (raw AND
                                        -- URL-encoded) to the ARGS surface for ALL requests (generalises the
                                        -- old multipart-only carve-out); Set-Cookie/Location stay
                                        -- full-surface. Kept at logonly pending a fresh burn-in before
                                        -- promoting back to challenge (CLAUDE.md logonly->challenge->block).
  rule_http_smuggling   = "challenge", -- HTTP verb embedded in body / querystring (smuggling)
                                       -- (request-smuggling primitive; never benign)

  -- [CVE] Named-vulnerability detectors (family WAF_CVE, IDs 10000+; see
  -- WAF_CVE.md). Exact exploit shapes only. Shipping at `block` requires a
  -- near-zero-FP fingerprint. WAF_CVE is armed for autoblock by default
  -- (CVE=1), so a block here 403s the request AND nft-bans + Slack/mails as
  -- WAF/CVE-YYYY-NNNN; hold a lower-confidence CVE rule with RULE_<id>=0 in
  -- [waf_security] (not by un-arming the family). rule_log4shell (328) is also
  -- WAF_CVE (logonly).
  rule_cve_simple_file_list_upload = "block", -- CVE-2025-34085 / CVE-2020-36847: Simple File List (WP) unauth upload->rename RCE. Endpoints ee-upload-engine.php (PHP tag in upload) + ee-file-engine.php (rename target ->.php/.phtml/.php[0-9]); param names vary across PoCs so we key on endpoint + exec-ext/php-tag marker.
  rule_cve_joomla_jce_profile_import = "block", -- CVE-2026-48907: Joomla JCE (<2.9.99.5) unauth PHP upload->RCE. POST index.php?option=com_jce, JCE action value "profiles.import" (a multipart field, not a key=value pair), + php-executable multipart upload filename (double-ext .xml.php). Keyed on component+action-value+exec-ext, not the random filename/CSRF field.
  rule_cve_ninja_forms_fu_upload = "block", -- CVE-2026-0740: Ninja Forms File Uploads add-on unauth arbitrary file upload + path traversal. POST wp-admin/admin-ajax.php, action value "nf_fu_upload" + (php-executable upload filename OR image_jpg=../ traversal). Keyed on the specific action (NOT bare admin-ajax) + exploit marker.
  rule_cve_litespeed_hash_privesc = "block", -- CVE-2024-28000: LiteSpeed Cache (<6.4) unauth privesc. Request presents a litespeed_hash / litespeed_role COOKIE (weak 6-char crawler-simulation hash brute-forced to become admin). Cookie is internal-only; a real visitor never sets it (zero FP). Runs on all methods (cookie-based, not body-gated).
  rule_cve_revslider = "block", -- CVE-2015-1579 (+ classic upload RCE): Slider Revolution virtual-patch. Leg A LFI = action=revslider_show_image + ../ traversal in img. Leg B RCE = action=revslider_ajax_action + client_action=update_plugin (unauth only). Behavioural (shape-based), protects all versions, not just the vulnerable one.
  rule_cve_w3tc = "block", -- CVE-2026-5032 + CVE-2025-9501: W3 Total Cache mfunc RCE surface. Leg A = User-Agent contains "W3 Total Cache" (token-leak bypass, zero FP). Leg B = mfunc/mclude marker in a POST to wp-comments-post.php / wp-json/wp/v2/comments (dynamic-fragment eval RCE; substring match, not exact tag form).
  rule_cve_post_smtp = "block", -- CVE-2025-11833 (+ CVE-2023-6875): Post SMTP unauth email-log disclosure -> account takeover. UNAUTH request to the /wp-json/post-smtp/ REST namespace (get-log/connect-app) or the postman_email_log admin page. Gated on absence of the WP logged-in cookie so real admin usage is exempt.
  rule_cve_fusion_builder = "block", -- CVE-2026-6279 + CVE-2026-8713: Avada/Fusion Builder unauth admin-ajax. Leg A RCE = action=fusion_get_widget_markup + base64 render_logics decoding to a dangerous callable (call_user_func sink). Leg B file-delete = action=fusion_form_submit_ajax + privacy_expiration_action (server-only field).
  rule_cve_kirki_forgot_password = "block", -- CVE-2026-8206: Kirki (<=6.0.6) unauth account takeover. POST /wp-json/KirkiComponentLibrary/v1/kirki-forgot-password with a target username + attacker email (no email/username cross-check) -> reset link mailed to attacker. Keyed on endpoint + both params.
  rule_cve_gf_multi_uploader = "block", -- CVE-2025-23921: Multi Uploader for Gravity Forms (<=1.1.3) unauth arbitrary upload->RCE. POST gf_page=upload with gform_unique_id set to a ../ traversal ending in .phtml/.php (webshell). php-exec is in the FIELD VALUE not filename=, so rule 401 misses it. Actively exploited.
  rule_cve_wp2shell = "block", -- CVE-2026-63030 + CVE-2026-60137 ("wp2shell"): WordPress CORE unauth RCE chain (6.9–6.9.4 / 7.0–7.0.1; fixed 6.9.5/7.0.2), public PoC, actively exploited. Anon POST to the REST batch endpoint (/wp-json/batch/v1 or ?rest_route=/batch/v1); a nested-batch + "///" desync primer (63030 route confusion) smuggles a raw GET to /wp/v2/users?author_exclude=<SQLi> (60137 core SQLi, `0) OR SLEEP(n)-- -`). Gated on batch/v1; keyed on the "///" primer and SQL-breakout in the integer-only author_exclude param.
  rule_cve_woocommerce_payments = "block", -- CVE-2023-28121: WooCommerce Payments (4.8.0–5.6.1) unauth auth-bypass->privesc. The X-WCPAY-Platform-Checkout-User request header is trusted as the current user id with no validation; an attacker sets it to 1 and mints an admin (POST /wp-json/wp/v2/users roles=administrator). Header is server-set by WooPay only — a client never sends it (near-zero FP); keyed on header presence, all methods. Exempt genuine WooPay source nets via waf_security ALLOW_NETS.
  rule_cve_gravity_smtp = "block", -- CVE-2026-4020: Gravity SMTP (<=2.1.4) unauth sensitive-info exposure. REST route /gravitysmtp/v1/tests/mock-data has permission_callback=true and dumps the full System Report (PHP/DB/server versions, paths, plugins, API keys/tokens). Keyed on the plugin-unique route (both permalink forms) + UNAUTH gate — the only legit caller is the wp-admin settings screen, which carries the logged-in cookie.
  rule_cve_sppagebuilder_upload = "block", -- CVE-2026-48908: Joomla SP Page Builder (com_sppagebuilder) asset.upload* (uploadCustomIcon/uploadImage/uploadFont) — unauth arbitrary file upload->RCE ("ANTONKILL", actively exploited 2026-07). Runs before rules 401/414 for CVE attribution. Keyed on component+task + a php-exec payload (direct filename / php-in-zip / php content); reuses the hardened upload detectors. Near-zero FP (a legit icon/image/font upload never carries PHP). Body-budget caveat: a php entry past waf_body_max_len is ClamAV's backstop.
  rule_cve_elementor_pro_form_upload = "block", -- CVE-2026-32475: Elementor Pro (<4.2.2) Forms File Upload unauth arbitrary upload->RCE. validation() return-vs-continue mismatch on an empty (UPLOAD_ERR_NO_FILE) first part skips the extension blocklist for a following .php part, which process_field() still moves into public wp-content/uploads/elementor/forms/. POST admin-ajax.php action=elementor_pro_forms_send_form (nopriv) + php-exec upload filename (the surviving extension IS the vuln; content leg intentionally omitted — rule 402 covers php content). Runs before rule 401 for CVE attribution; reuses the hardened rule-401 detector. Near-zero FP (a legit Elementor form upload never carries a php-executable file). Body-budget caveat: a filename past waf_body_max_len is ClamAV's backstop.

  -- [top-4]  Upload controls
  rule_upload_filename    = "block",  -- webshell extension in multipart filename (.php, .jsp, user.ini …)
  rule_upload_content     = "block",  -- webshell bytes / PHP tags inside uploaded file content
  rule_upload_archive_php = "block",  -- PHP webshell compressed inside an uploaded .zip (ZIP entry name scan). Scoped to Joomla asset uploads (option=com_ + task=asset.upload), where a php-bearing zip is never legitimate → safe to block.
  rule_script_obfuscation = "challenge",  -- raw POST-body PHP/JS obfuscation scorer
  rule_upload_obfuscation = "challenge",  -- multipart uploaded file content obfuscation scorer

  -- ── Phase 1 — webshell delivery + reverse shell (logonly rollout) ─────────
  -- Sources: docs/waf.md "Detector phases" §Phase 1 / §Phase 2 / §Phase 5 (B5).
  -- Landed at logonly per the rollout playbook, then promoted on hit-rate data:
  -- the webshell drop-path split (410 ambiguous / 413 proper-noun) and ping now
  -- ship at challenge/block. NOTE: WAF_WEBSHELL is a high-risk reason, so for a
  -- client already holding a valid clearance cookie a rule-410 challenge is
  -- converted to block (post_clearance_action) — the challenge tier is only
  -- "recoverable" for as-yet-uncleared clients.
  rule_webshell_path    = "challenge", -- URI basename matches a generic/ambiguous webshell name (shell.php, x.php, adminer.php, alfa.php, …)
  rule_webshell_path_known = "block",  -- URI basename matches a proper-noun webshell (c99.php, r57.php, wso.php, b374k.php, …) — near-zero legit use
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

  -- ── Backdoor / obfuscation family (430-438) ──────────────────────────────
  -- Tier 1 covers the highest-yield gaps observed in production: .htaccess
  -- poisoning, char-pool obfuscator output, deep polyglots, and the generic
  -- eval-loader shape. The content-heuristic rules (430-436) ship at logonly;
  -- only the encoded-<?php openers 437/438 are at challenge (see their notes).
  rule_htaccess_poisoning         = "logonly", -- .htaccess / .user.ini directive injection in upload bodies (stays logonly: hand-written `AddType … x-httpd-php` is legit in shared hosting; needs prose-gating on the Apache-directive branches before promotion)
  rule_php_char_pool_obfuscation  = "logonly", -- $pool[N].$pool[N].$pool[N] function-name extraction
  rule_php_polyglot_full_body     = "logonly", -- image/PDF/ZIP magic + <?php anywhere in body. Stays logonly: WAF_BACKDOOR is high-risk, so a challenge here converts to block for cleared clients and (BACKDOOR being autoblock-armed) can 6h-ban a logged-in customer who uploads e.g. a PDF containing literal <?php via a raw-body endpoint. Promote only once post-clearance-converted hits are excluded from the autoblock feed.
  rule_php_eval_loader_b64        = "logonly", -- variable-fed eval/assert/call_user_func + >=200-char b64 literal
  rule_php_superglobal_callable   = "logonly", -- $_GET[c]( / $_POST[c]( / $_SERVER[HTTP_X_…]( minimalist webshell
  rule_php_concat_funcname_eval   = "logonly", -- $a = "sys"."tem"; $a(); short-string funcname concat + invoke
  rule_php_decode_chain           = "logonly", -- 3+ decoder primitives (base64_decode/gzinflate/strrev/…) within 300 bytes
  rule_php_numeric_xor_obfuscation = "logonly", -- phpfuck: a long tight [0-9().^] run with a paren/^/dot storm — arbitrary PHP built for a restricted-charset eval() sink (e.g. vBulletin runMaths / CVE-2026-61511). Best-effort visibility only; STAYS logonly (a block companion was removed for FP-banning spaced math posts).
  rule_php_encoded_opener         = "challenge", -- encoded `<?php` opener — JS `\x` hex-escape form only (`\x3c\x3fphp`).
                                                 -- Audit F16 REMOVED the URL (`%3C%3Fphp`), HTML-entity (`&lt;?php`) and
                                                 --  JS-unicode (`<…`) forms: they are the normal on-wire encodings of
                                                 --  legit content (a form body is url-encoded in its entirety; editors
                                                 --  HTML-escape; Go/JS JSON escapes `<`), so they FP-challenged real
                                                 --  comment/forum/API POSTs, and marker-bearing payloads in them are already
                                                 --  caught by the PHP webshell-body scorer (rule 404 detect_php_webshell_body),
                                                 --  which normalize()-url-decodes the body and scores <?php+exec-marker+
                                                 --  superglobal at challenge. `\x3c` is NOT a `%xx` escape so normalize() never
                                                 --  unwraps it — so 404 never sees a bare hex opener; 437 is its only coverage
                                                 --  for a MARKERLESS hex opener, attack-shaped with ~zero FP. `challenge`
                                                 --  preserves+replays the POST. (logonly→challenge 2026-06-25; narrowed F16.)
  rule_php_encoded_opener_b64     = "challenge", -- encoded `<?php` opener — base64 form (`PD9waHA` at a base64 value boundary).
                                                 -- Split out of rule 437 into its own id (438) on 2026-07-02 so its hit
                                                 --  stream is observable separately from the FP-prone URL form above. Unlike
                                                 --  URL-encoding, a browser NEVER base64-encodes a form field, and the match
                                                 --  is boundary-anchored + case-sensitive, so `PD9waHA` at a value boundary
                                                 --  (`p=PD9waHA…`) is payload-smuggling only (2026-07 six-server review:
                                                 --  16/16 base64 openers POSTed to /xmlrpc.php, botnet-distributed, 0 FP).
                                                 --  Candidate for `block` after a 1-2 week burn-in of this split telemetry.
                                                 --  The weak `<?=` base64 variant (PD89) was 6/6 FP and stays REMOVED from
                                                 --  the detector.


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
  --
  -- INVARIANT (audit F08): cfm.lua's `waf_body_max_len` — the cap on how many
  -- body bytes are read and handed to the WAF — must be >= the LARGEST value
  -- here, or that reader truncates the body before these budgets ever apply.
  -- If you raise any entry above 32768, raise waf_body_max_len to match.
  -- scripts/tests/cfm_waf_body_budget_test.lua asserts the relationship.
  body_scan_budget = {
    urlencoded = 8192,
    json       = 32768,
    multipart  = 16384,
    xml        = 16384,
    other      = 2048,
  },

  -- Legacy fallback scan cap. Used by the args-only / body-only callsites
  -- without request-headers context (get_norm_args, get_body_lc, and body
  -- detectors invoked outside the engine's hot path). Body-aware rules in the
  -- engine prefer body_scan_budget above via util.body_budget(headers); the
  -- URI+query surface (scan_str) uses uri_scan_len below.
  max_scan_len      = 2048,

  -- Request-line (URI + query string) scan budget for scan_str() — the surface
  -- shared by traversal/rce/xss/sqli. Capped PER SIDE (uri and query each) so a
  -- long path can't evict the query scan and query padding can't push a payload
  -- past the cap before any detector runs (audit F30). Set to the urlencoded
  -- POST-body budget: these same detectors already scan bodies to that depth, so
  -- this introduces no new false-positive class, and a normal short URI pays
  -- nothing (cap() only bounds; work scales with the actual length). Not raised
  -- to the full large_client_header_buffers ceiling (64k) on purpose: the extra
  -- coverage isn't worth the per-request CPU / FP surface on very large requests
  -- for a low-severity defence-in-depth gap. Safe to widen past 2048 only
  -- because strip_sql_comments is O(n) (F62).
  uri_scan_len      = 8192,

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
  rule_sqli_blind_lexical      = 309,
  rule_sqli_union_variant      = 319,
  rule_superglobal_override    = 318,
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
  rule_php_object_injection    = 329,

  -- 4xx upload / malware
  rule_upload_filename         = 401,
  rule_upload_content          = 402,
  rule_upload_archive_php      = 414,
  rule_upload_obfuscation      = 403,
  rule_php_webshell_body       = 404,
  rule_script_obfuscation      = 405,
  rule_webshell_path           = 410,
  rule_webshell_ping           = 411,
  rule_polyglot_upload         = 412,
  rule_webshell_path_known     = 413,
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
  rule_php_encoded_opener_b64     = 438,
  rule_php_numeric_xor_obfuscation = 439,

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
  rule_fetch_metadata_missing  = 612,

  -- 7xx SSRF
  rule_ssrf                    = 701,
  rule_c2_tunnel               = 702,

  -- 8xx info disclosure / debug
  rule_debug_toggles           = 801,

  -- 10xxx named-vulnerability (CVE) detectors — see WAF_CVE_PLAN.md. The 9xx
  -- band is too small for long-term CVE coverage, so CVE rules use 10000+.
  -- (rule_log4shell keeps its historical 328; new CVE rules start here.)
  rule_cve_simple_file_list_upload = 10001,
  rule_cve_joomla_jce_profile_import = 10002,
  rule_cve_ninja_forms_fu_upload = 10003,
  rule_cve_litespeed_hash_privesc = 10004,
  rule_cve_revslider = 10005,
  rule_cve_w3tc = 10006,
  rule_cve_post_smtp = 10007,
  rule_cve_fusion_builder = 10008,
  rule_cve_kirki_forgot_password = 10009,
  rule_cve_gf_multi_uploader = 10010,
  rule_cve_wp2shell = 10011,
  rule_cve_woocommerce_payments = 10012,
  rule_cve_gravity_smtp = 10013,
  rule_cve_sppagebuilder_upload = 10014,
  -- 10015 is intentionally skipped: it was the (never-released, then removed)
  -- vBulletin runMaths CVE-2026-61511 block rule — see WAF_CVE.md "Removed".
  rule_cve_elementor_pro_form_upload = 10016,
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
  local cookie  = ctx.cookie  or ""
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
  -- scanners (401/402/403 and the 431-436/439 backdoor family) so they don't
  -- flag the PHP that is the upload's whole point. Declared up here (before
  -- any `goto done`) so those jumps don't cross its scope. (437/438 keep
  -- their own broader /wp-admin/ carve-out, with 438's pre-auth admin-ajax/
  -- admin-post logonly exception — see rule 59 / audit F11.)
  local legit_archive_upload = is_known_legit_php_upload_endpoint(uri, args)
  -- Rule 414 (php-inside-zip) fires ONLY on media-asset upload endpoints (see
  -- is_php_hostile_asset_upload) — a positive allowlist, so legit plugin / theme
  -- / extension / backup `.zip` uploads (which contain PHP by design) are never
  -- matched. Computed once here alongside the other upload gates.
  local php_hostile_asset_upload = is_php_hostile_asset_upload(uri, args)

  -- Pre-computed normalized scan strings, lazily initialised on first use.
  -- scan_str(uri,args) is shared by traversal/rce/xss/sqli (4 rules).
  -- norm_args_body is shared by php_wrappers/ssrf/js_proto (3 rules).
  -- Without this, each rule independently calls normalize()+url_decode twice.
  local _scan_ua, _scan_ua_nodata, _norm_ab, _norm_args, _body_lc
  -- Comment-stripped SQLi scan pair (sc, scw), memoized PER SURFACE so the
  -- three SQLi rules share one strip_sql_comments + '+'-collapse pass instead
  -- of recomputing it each (uri+args and args+body surfaces) — audit F30b.
  local _sqli_ua_sc, _sqli_ua_scw, _sqli_ab_sc, _sqli_ab_scw

  local function get_scan_ua()
    if not _scan_ua then _scan_ua = scan_str(uri, args) end
    return _scan_ua
  end

  -- Same URI+args scan surface, but with an embedded `data:` URI in the PATH
  -- truncated at the scheme (strip_data_uri). Used ONLY by XSS (302): a data:
  -- payload's inline on…=/<script (incl. slashless/empty-mime data: URIs the
  -- detector's own uri_is_data_uri_path guard doesn't cover) would false-positive
  -- reflected-XSS. RCE (320) deliberately scans the RAW surface instead — its
  -- structural markers (${jndi:…}, ;wget/;curl) must stay full-surface so a data:
  -- prefix can't smuggle them past a block-tier rule, and its lone base64 FP is
  -- already paren-anchored + inline-gated. Structural rules (traversal/long-path)
  -- likewise keep get_scan_ua() (the RAW uri) so a data:-prefixed ../ can't slip.
  local function get_scan_ua_nodata()
    if not _scan_ua_nodata then
      local u = strip_data_uri(uri)
      -- No data: URI in the path (the overwhelming common case) → the stripped
      -- surface is byte-identical to the raw one, so reuse the memoized
      -- get_scan_ua() instead of paying a second normalize pass per request.
      if u == uri then
        _scan_ua_nodata = get_scan_ua()
      else
        _scan_ua_nodata = scan_str(u, args)
      end
    end
    return _scan_ua_nodata
  end

  -- args-only normalize, shared by cmd_param_key/cmd_payload/debug_toggles/
  -- php_serialize/bad_utf8 (audit F58) — each used to recompute it per request.
  -- Must use CFG.max_scan_len (the detectors' cap), which is the SAME CFG object
  -- passed to det.init, so the memoized string is byte-identical to theirs.
  local function get_norm_args()
    if not _norm_args then _norm_args = normalize(cap(args or "", CFG.max_scan_len)) end
    return _norm_args
  end

  -- lower(cap(body,max_scan_len)), shared by the five RCE-marker detectors
  -- (reverse_shell/persistence/rootkit/lolbin/coinminer) (audit F59).
  local function get_body_lc()
    if not _body_lc then _body_lc = lower(cap(body or "", CFG.max_scan_len)) end
    return _body_lc
  end

  local function get_norm_ab()
    if not _norm_ab then
      local budget = util.body_budget(headers)
      -- Cap args and body INDEPENDENTLY (each to the body budget) BEFORE the
      -- concat. The old code did cap(args .. "&" .. body, budget) — args first —
      -- so a query string padded to `budget` bytes evicted the POST body
      -- entirely from this shared scan surface, and every body-aware rule that
      -- reads it (php_wrappers, ssrf, js_proto, sqli, log4shell, superglobal,
      -- c2) then missed a body-borne payload (audit F09). Capping each side
      -- separately guarantees the body always gets its full budget; capping
      -- before the concat also bounds the transient to ~2*budget without
      -- materialising a large body first.
      _norm_ab = normalize(cap(args or "", budget) .. "&" .. cap(body or "", budget))
    end
    return _norm_ab
  end

  -- Comment-stripped SQLi scan pair for each surface, computed once and shared
  -- by detect_sqli / detect_sqli_blind_lexical / detect_sqli_union_variant.
  -- Each returns (sc, scw): the strip_sql_comments output and its '+'-collapsed
  -- variant (see det.sqli_scan_strings). Previously every one of the three
  -- rules recomputed this on the SAME string — 3x the strip + gsub per surface
  -- per request. Called via the `det` table so it stays interceptable in tests.
  local function get_sqli_ua()
    if not _sqli_ua_sc then
      _sqli_ua_sc, _sqli_ua_scw = det.sqli_scan_strings(get_scan_ua())
    end
    return _sqli_ua_sc, _sqli_ua_scw
  end
  local function get_sqli_ab()
    if not _sqli_ab_sc then
      _sqli_ab_sc, _sqli_ab_scw = det.sqli_scan_strings(get_norm_ab())
    end
    return _sqli_ab_sc, _sqli_ab_scw
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
        -- score >= 99 is reserved by detect_bad_ua_scored() for deterministic,
        -- high-confidence scanner / synthetic-client identities. A challenge
        -- has no security value for these hits, so challenge-tier rule 201
        -- promotes this hit only to block. Keep an explicit logonly override
        -- audit-only, and preserve an explicit block override for all scores.
        local action = mode
        if score >= 99 and mode ~= "logonly" then
          action = "block"
        end
        local ttl = (action == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BAD_UA:" .. tag .. ":score=" .. score, ttl, action, RULE_IDS.rule_bad_ua) then goto done end
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

  -- ── 3b) LiteSpeed Cache privesc (CVE-2024-28000): litespeed_hash/role cookie ─
  -- Cookie-based + all-methods (the brute-force is a GET to the REST API), so it
  -- runs here in the early header region, NOT in the POST-gated body block below.
  do
    local mode = rule_mode(CFG.rule_cve_litespeed_hash_privesc, "block")
    if mode ~= "disabled" and cookie ~= "" then
      local tag = det.detect_cve_litespeed_privesc(cookie)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2024_28000:LITESPEED_CACHE:" .. tag, ttl, mode, RULE_IDS.rule_cve_litespeed_hash_privesc) then goto done end
      end
    end
  end

  -- ── 3c) Slider Revolution virtual-patch (CVE-2015-1579 LFI + upload RCE) ────
  -- Runs before rule 5 (traversal) so the REVSLIDER:LFI attribution wins over a
  -- generic WAF_TRAVERSAL hit for the same request. Behavioural, all-methods.
  do
    local mode = rule_mode(CFG.rule_cve_revslider, "block")
    if mode ~= "disabled" then
      local tag = det.detect_cve_revslider(m_lower, args, body, cookie)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        local reason = (tag == "LFI")
          and "WAF_CVE:CVE_2015_1579:REVSLIDER:LFI"
          or  "WAF_CVE:REVSLIDER:PLUGIN_UPLOAD"
        if record(reason, ttl, mode, RULE_IDS.rule_cve_revslider) then goto done end
      end
    end
  end

  -- ── 3d) W3 Total Cache mfunc RCE surface (CVE-2026-5032 UA + CVE-2025-9501) ─
  -- UA leg is all-methods; the mfunc leg is a POST to the comment endpoints.
  do
    local mode = rule_mode(CFG.rule_cve_w3tc, "block")
    if mode ~= "disabled" then
      local tag = det.detect_cve_w3tc(uri, m_lower, headers, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        local reason = (tag == "UA_TOKEN_LEAK")
          and "WAF_CVE:CVE_2026_5032:W3TC:UA_TOKEN_LEAK"
          or  "WAF_CVE:CVE_2025_9501:W3TC:MFUNC"
        if record(reason, ttl, mode, RULE_IDS.rule_cve_w3tc) then goto done end
      end
    end
  end

  -- ── 3e) Post SMTP unauth email-log disclosure (CVE-2025-11833/CVE-2023-6875) ─
  -- UNAUTH-gated (the detector reads the cookie); all-methods.
  do
    local mode = rule_mode(CFG.rule_cve_post_smtp, "block")
    if mode ~= "disabled" then
      local tag = det.detect_cve_post_smtp(uri, args, cookie)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2025_11833:POST_SMTP:" .. tag, ttl, mode, RULE_IDS.rule_cve_post_smtp) then goto done end
      end
    end
  end

  -- ── 3f) Avada / Fusion Builder unauth admin-ajax (CVE-2026-6279 RCE + 8713) ─
  do
    local mode = rule_mode(CFG.rule_cve_fusion_builder, "block")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_cve_fusion_builder(uri, m_lower, args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        local reason = (tag == "RCE")
          and "WAF_CVE:CVE_2026_6279:FUSION_BUILDER:RCE"
          or  "WAF_CVE:CVE_2026_8713:FUSION_BUILDER:FILE_DELETE"
        if record(reason, ttl, mode, RULE_IDS.rule_cve_fusion_builder) then goto done end
      end
    end
  end

  -- ── 3g) Kirki unauth account takeover via password reset (CVE-2026-8206) ────
  do
    local mode = rule_mode(CFG.rule_cve_kirki_forgot_password, "block")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_cve_kirki_forgot_password(uri, m_lower, args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2026_8206:KIRKI:" .. tag, ttl, mode, RULE_IDS.rule_cve_kirki_forgot_password) then goto done end
      end
    end
  end

  -- ── 3h) Multi Uploader for Gravity Forms unauth upload->RCE (CVE-2025-23921) ─
  do
    local mode = rule_mode(CFG.rule_cve_gf_multi_uploader, "block")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_cve_gf_multi_uploader(uri, m_lower, args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2025_23921:GF_MULTI_UPLOADER:" .. tag, ttl, mode, RULE_IDS.rule_cve_gf_multi_uploader) then goto done end
      end
    end
  end

  -- ── 3i) WordPress core "wp2shell" unauth RCE chain (CVE-2026-63030 + -60137) ─
  -- Two chained core bugs: a REST batch route-confusion (63030) that smuggles a
  -- raw GET past sanitisation, carrying a core SQLi (60137) in author_exclude.
  -- Cheap-gated on the batch endpoint before materialising the normalized body;
  -- each leg attributes its own CVE id.
  do
    local mode = rule_mode(CFG.rule_cve_wp2shell, "block")
    if mode ~= "disabled" and body_inspect_ok and det.wp2shell_is_batch_endpoint(uri, args) then
      local tag = det.detect_cve_wp2shell(get_norm_ab())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        local reason = (tag == "SQLI")
          and "WAF_CVE:CVE_2026_60137:WP_CORE:BATCH_SQLI"
          or  "WAF_CVE:CVE_2026_63030:WP_CORE:BATCH_DESYNC"
        if record(reason, ttl, mode, RULE_IDS.rule_cve_wp2shell) then goto done end
      end
    end
  end

  -- ── 3j) WooCommerce Payments unauth auth-bypass -> privesc (CVE-2023-28121) ──
  -- Header-based (X-WCPAY-Platform-Checkout-User is trusted as the user id); all
  -- methods / all paths, so it runs here in the early header region.
  do
    local mode = rule_mode(CFG.rule_cve_woocommerce_payments, "block")
    if mode ~= "disabled" then
      local tag = det.detect_cve_woocommerce_payments(headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2023_28121:WOOCOMMERCE_PAYMENTS:" .. tag, ttl, mode, RULE_IDS.rule_cve_woocommerce_payments) then goto done end
      end
    end
  end

  -- ── 3k) Gravity SMTP unauth sensitive-info exposure (CVE-2026-4020) ──────────
  -- REST route + UNAUTH-gated (the detector reads the cookie); all methods.
  do
    local mode = rule_mode(CFG.rule_cve_gravity_smtp, "block")
    if mode ~= "disabled" then
      local tag = det.detect_cve_gravity_smtp(uri, args, cookie)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2026_4020:GRAVITY_SMTP:" .. tag, ttl, mode, RULE_IDS.rule_cve_gravity_smtp) then goto done end
      end
    end
  end

  -- ── 3l) SP Page Builder unauth arbitrary-upload -> RCE (CVE-2026-48908) ──────
  -- Joomla com_sppagebuilder asset.upload* (uploadCustomIcon/uploadImage/upload
  -- Font) has NO auth check and NO file-type restriction (the "ANTONKILL" vector,
  -- actively exploited 2026-07). Runs BEFORE the generic upload rules (401/414) so
  -- the hit is attributed to the CVE. Near-zero FP: a legit icon/image/font upload
  -- to this endpoint never carries a php-executable filename, a php entry inside a
  -- zip icon-pack, or raw php webshell content. (Body-budget caveat: a php entry
  -- past waf_body_max_len is ClamAV's backstop, not the WAF's — defence in depth.)
  do
    local mode = rule_mode(CFG.rule_cve_sppagebuilder_upload, "block")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_cve_sppagebuilder_upload(uri, m_lower, args, body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2026_48908:SPPAGEBUILDER:" .. tag, ttl, mode, RULE_IDS.rule_cve_sppagebuilder_upload) then goto done end
      end
    end
  end

  -- (A block-tier vBulletin runMaths CVE rule, CVE-2026-61511 / id 10015, was
  -- prototyped here and REMOVED: its phpfuck signature false-positive-banned
  -- legitimate spaced math forum posts on ajax/render routes — form-urlencoded
  -- spaces arrive as `+`, which bridged the run. The technique-level detector
  -- survives as the logonly rule 439 below with a tight run charset. See
  -- WAF_CVE.md and the 2026-08 red-team history.)

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

  -- ── 5) Traversal — moved to run after every armed block-tier family ────────
  -- (see "Traversal" just before the LAST step). Kept here as a signpost so the
  -- step numbering in the comments and docs still resolves.

  -- ── 6) RCE ────────────────────────────────────────────────────────────────
  -- RCE scans the RAW surface (get_scan_ua), NOT the data:-stripped one. Its
  -- structural markers (${jndi:…}, ;wget/;curl/|bash) are never valid inside a
  -- base64/image/JS data: payload, so they MUST stay full-surface — otherwise a
  -- data: path prefix (`/data:image/x,${jndi:…}`) evades this block-tier rule.
  -- detect_rce already suppresses the one real data: FP (a base64 blob whose
  -- letters spell eval/exec/system) surgically: that branch is paren-anchored
  -- (`eval(` can't occur in base64) AND inline-gated on uri_is_data_uri_path, so
  -- the raw surface needs no outer strip here.
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
      local tag = det.detect_bad_utf8(args, body, headers, uri, get_norm_args())
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BAD_UTF8:" .. tag, ttl, mode, RULE_IDS.rule_bad_utf8) then goto done end
      end
    end
  end

  -- ── 13) SSRF protocol schemes + IP obfuscation ───────────────────────────
  do
    local mode = rule_mode(CFG.rule_ssrf, "challenge")
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

  -- ── CVE) Named-vulnerability fingerprints ────────────────────────────────
  -- Run BEFORE the generic upload rules (17/18) so the CVE reason wins
  -- attribution over WAF_UPLOAD_* for the same request. Exact shapes only.
  do
    local mode = rule_mode(CFG.rule_cve_simple_file_list_upload, "block")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_cve_simple_file_list_upload(uri, m_lower, args, body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        -- One detector covers CVE-2025-34085 AND CVE-2020-36847 (same plugin/
        -- endpoints/exploit); the reason carries the campaign-primary CVE
        -- (2025-34085). Per-CVE metadata (WAFRule.CVEs) can carry both later.
        if record("WAF_CVE:CVE_2025_34085:SIMPLE_FILE_LIST:" .. tag, ttl, mode, RULE_IDS.rule_cve_simple_file_list_upload) then goto done end
      end
    end
  end

  do
    local mode = rule_mode(CFG.rule_cve_joomla_jce_profile_import, "block")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_cve_joomla_jce_profile_import(uri, m_lower, args, body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2026_48907:JOOMLA_JCE:" .. tag, ttl, mode, RULE_IDS.rule_cve_joomla_jce_profile_import) then goto done end
      end
    end
  end

  do
    local mode = rule_mode(CFG.rule_cve_ninja_forms_fu_upload, "block")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_cve_ninja_forms_fu_upload(uri, m_lower, args, body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2026_0740:NINJA_FORMS:" .. tag, ttl, mode, RULE_IDS.rule_cve_ninja_forms_fu_upload) then goto done end
      end
    end
  end

  -- Elementor Pro Forms unauth upload -> RCE (CVE-2026-32475). Runs BEFORE the
  -- generic upload rules (17/18) so the CVE reason wins attribution over
  -- WAF_UPLOAD_* for the same request.
  do
    local mode = rule_mode(CFG.rule_cve_elementor_pro_form_upload, "block")
    if mode ~= "disabled" and body_inspect_ok then
      local tag = det.detect_cve_elementor_pro_form_upload(uri, m_lower, args, body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_CVE:CVE_2026_32475:ELEMENTOR_PRO:" .. tag, ttl, mode, RULE_IDS.rule_cve_elementor_pro_form_upload) then goto done end
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

  -- ── 17b) Webshell PHP compressed inside an uploaded ZIP ───────────────────
  -- Same WAF_UPLOAD_FNAME family as rule 401 ("the upload's effective filename
  -- is a webshell"), but reads names out of the ZIP directory so a `.php` hidden
  -- inside an `ico*.zip` is caught. Scoped by a POSITIVE allowlist to JOOMLA
  -- media-asset uploads (option=com_ + task=asset.upload*): plugin/theme/
  -- extension/backup archives legitimately contain PHP and go elsewhere, and the
  -- option=com_ requirement means WordPress/OpenCart/Magento/PrestaShop/Drupal
  -- can't match. See is_php_hostile_asset_upload. Runs at `block` (CFG): on these
  -- endpoints a PHP-bearing zip is unambiguously a webshell drop.
  do
    local mode = rule_mode(CFG.rule_upload_archive_php, "logonly")
    if mode ~= "disabled" and body_inspect_ok and php_hostile_asset_upload then
      local tag = det.detect_upload_archive_php(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_UPLOAD_FNAME:" .. tag, ttl, mode, RULE_IDS.rule_upload_archive_php) then goto done end
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
    if mode ~= "disabled" and det.detect_xss(uri, args, get_scan_ua_nodata()) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      if record("WAF_XSS", ttl, mode, RULE_IDS.rule_xss) then goto done end
    end
  end

  -- ── 21) SQLi (+ SQL comment bypass) ──────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_sqli, "challenge")
    if mode ~= "disabled" then
      -- URI + query args (cheap, every request).
      local hit = det.detect_sqli(get_sqli_ua())
      -- Plus the POST body: form-field SQLi (e.g. a WHMCS ticket subject/
      -- message submitted as application/x-www-form-urlencoded) lands in
      -- the body, which uri+args does not cover. get_sqli_ab reuses the
      -- already-budgeted args+body scan string (get_norm_ab) and memoizes the
      -- comment-strip so the three SQLi rules share it (F30b).
      if not hit and body_inspect_ok then
        hit = det.detect_sqli(get_sqli_ab())
      end
      if hit then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_SQLI", ttl, mode, RULE_IDS.rule_sqli) then goto done end
      end
    end
  end

  -- ── 21b) SQLi blind-family lexical tokens (separate rule, block) ──────────
  -- benchmark( / extractvalue( / updatexml( / floor(rand( / randomblob( and
  -- "or sleep(" / "and sleep(" are valid SQLi primitives but also collide
  -- case-insensitively with legitimate code/content (XML parsers, PHP,
  -- minified JS, shell prose). The rule completed logonly + challenge burn-in
  -- cleanly and is block-tier as of 2026-08-23. Same uri+args then POST-body
  -- scan; per-vhost exclusions and explicit operator overrides still apply.
  do
    local mode = rule_mode(CFG.rule_sqli_blind_lexical, "block")
    if mode ~= "disabled" then
      local hit = det.detect_sqli_blind_lexical(get_sqli_ua())
      if not hit and body_inspect_ok then
        hit = det.detect_sqli_blind_lexical(get_sqli_ab())
      end
      if hit then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_SQLI_LEXICAL", ttl, mode, RULE_IDS.rule_sqli_blind_lexical) then goto done end
      end
    end
  end

  -- ── 21bb) Obfuscated UNION variants (separate rule, challenge) ────────────
  -- rule 301's `union select` signature requires the two keywords ADJACENT, so
  -- it misses `union all select` / `union distinct select` (keyword between),
  -- `union(select` (paren), and `union/**/select` (comment-collapsed to
  -- `unionselect`) — `UNION ALL SELECT` is at least as common as plain UNION
  -- SELECT. This distinct rule catches them under the SAME value-terminator FP
  -- guard. Its logonly burn-in completed cleanly, so it is challenge-tier as of
  -- 2026-08-23. Same uri+args then POST-body scan as the SQLi rules above.
  do
    local mode = rule_mode(CFG.rule_sqli_union_variant, "challenge")
    if mode ~= "disabled" then
      local hit = det.detect_sqli_union_variant(get_sqli_ua())
      if not hit and body_inspect_ok then
        hit = det.detect_sqli_union_variant(get_sqli_ab())
      end
      if hit then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_SQLI_UNION_VARIANT", ttl, mode, RULE_IDS.rule_sqli_union_variant) then goto done end
      end
    end
  end

  -- ── 21c) Superglobal / variable-override probe (logonly) ──────────────────
  -- A request param KEY named like a PHP superglobal (_GET/_POST/_SERVER/
  -- GLOBALS/…) is a PHP variable-poisoning attempt (extract()/register_globals
  -- patterns). Clean-room addition from the NinjaFirewall gap analysis; ships
  -- `logonly` so it surfaces in the WAF FP review before any enforcement.
  do
    local mode = rule_mode(CFG.rule_superglobal_override, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_superglobal_override(uri, args, get_scan_ua())
      if not tag and body_inspect_ok then
        tag = det.detect_superglobal_override(uri, args, get_norm_ab())
      end
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_SUPERGLOBAL:" .. tag, ttl, mode, RULE_IDS.rule_superglobal_override) then goto done end
      end
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
      local mode = rule_mode(CFG.rule_xmlrpc_multicall, "block")
      if mode ~= "disabled" then
        local ttl = CFG.auth_xmlrpc_multicall_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        if record("WAF_AUTH_BURST:" .. xtag, ttl, mode, RULE_IDS.rule_xmlrpc_multicall) then goto done end
      end
    elseif xtag == "AUTH_WP_XMLRPC_PINGBACK" then
      local mode = rule_mode(CFG.rule_xmlrpc_pingback, "block")
      if mode ~= "disabled" then
        local ttl = CFG.auth_xmlrpc_pingback_ttl_sec or CFG.auth_ttl_sec or CFG.default_ttl_sec
        if record("WAF_AUTH_BURST:" .. xtag, ttl, mode, RULE_IDS.rule_xmlrpc_pingback) then goto done end
      end
    end
  end


  -- ── 27) Generic XML-RPC POST burst ───────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_xmlrpc_post_burst, "block")
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
      local tag = det.detect_cmd_param_key(args, get_norm_args())
      if tag then
        if record("WAF_CMD_PARAM:" .. tag, CFG.default_ttl_sec, mode, RULE_IDS.rule_cmd_params) then goto done end
      end
    end
  end

  -- ── 30) Suspicious payload markers ───────────────────────────────────────
  do
    local tag = det.detect_cmd_payload(args, get_norm_args())
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
      local tag = det.detect_debug_toggles(args, get_norm_args())
      if tag then
        if record("WAF_DEBUG_TOGGLE:" .. tag, CFG.default_ttl_sec, mode, RULE_IDS.rule_debug_toggles) then goto done end
      end
    end
  end

  -- ── 31b) Unauth PHP object injection → WAF_RCE (armed block) ───────────────
  -- Runs BEFORE the serialize rule (32) so an UNAUTHENTICATED object marker gets
  -- the hard WAF_RCE block+ban; an AUTHENTICATED one falls through to rule 32's
  -- WAF_SERIALIZE challenge. Scans args AND body incl. base64 — wider than rule
  -- 32 (args-only). The unauth gate is HERE (not in the detector) so an
  -- authenticated request skips even the get_norm_ab() materialisation; legit
  -- serialized blobs (WooCommerce/Elementor/WPML) ride authenticated admin-ajax.
  -- Akeeba Restore endpoints (Joomla core update / Akeeba Backup restore) are
  -- excluded: they legitimately POST a base64 serialized `factory` object every
  -- extraction step, indistinguishable by shape from an attack (FP 2026-07-17).
  do
    local mode = rule_mode(CFG.rule_php_object_injection, "block")
    if mode ~= "disabled" and not lower(cookie):find("wordpress_logged_in_", 1, true)
       and not det.is_akeeba_restore_endpoint(uri) then
      local tag = det.detect_php_object_injection(get_norm_ab(), args, body)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_RCE:PHP_OBJECT_INJECTION:" .. tag, ttl, mode, RULE_IDS.rule_php_object_injection) then goto done end
      end
    end
  end

  -- ── 32) PHP serialize markers ─────────────────────────────────────────────
  do
    local mode = rule_mode(CFG.rule_serialize, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_php_serialize(args, get_norm_args())
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
        -- F13: the B64_OBJ_INJECT sub-rule was dead (a Lua `%b` balanced-match
        -- typo) until this release. Reviving a previously-silent sub-rule straight
        -- into the scanner's challenge tier could FP-challenge legit apps that
        -- base64(serialize($obj)) into a POST body, so this ONE tag burns in at
        -- logonly first (cap the effective mode at logonly). Promote to challenge
        -- after watching hit-rates. Mirrors the F11 rule-438 burn-in split.
        -- `mode ~= "disabled"` already gates the outer block, so disabling rule 304
        -- still silences this tag too. Safe against tier-downgrade: the detector
        -- returns B64_OBJ_INJECT only as a DEFERRED fallback (see
        -- detect_b64_injection), so a hostile sibling (eval/system/union-select)
        -- anywhere in the body always wins first and keeps the rule's real tier —
        -- an object marker can't be used to shadow it down to logonly.
        local eff_mode = mode
        if tag == "B64_OBJ_INJECT" then
          eff_mode = "logonly"
        end
        local ttl = (eff_mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_B64_INJECT:" .. tag, ttl, eff_mode, RULE_IDS.rule_b64_injection) then goto done end
      end
    end
  end

  -- ── 34) Webshell drop path (W1) ──────────────────────────────────────────
  -- URI basename matches a known webshell name. Two confidence tiers share one
  -- detector: proper-noun names (c99.php, r57.php, wso.php, b374k.php …) route to
  -- rule 413 (block, near-zero legit use); generic/ambiguous names (shell.php,
  -- x.php, adminer.php, alfa.php …) route to rule 410 (challenge for uncleared
  -- clients; a dropper is stopped). The rule_mode legacy-boolean fallback MUST
  -- match each rule's real default (block / challenge), or a `= true` config
  -- would silently downgrade the rule.
  do
    local mode_known = rule_mode(CFG.rule_webshell_path_known, "block")
    local mode_amb   = rule_mode(CFG.rule_webshell_path, "challenge")
    if mode_known ~= "disabled" or mode_amb ~= "disabled" then
      local tag, is_known = det.detect_webshell_path(uri)
      if tag then
        local mode = is_known and mode_known or mode_amb
        local rid  = is_known and RULE_IDS.rule_webshell_path_known or RULE_IDS.rule_webshell_path
        if mode ~= "disabled" then
          local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
          if record("WAF_WEBSHELL:" .. tag, ttl, mode, rid) then goto done end
        end
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
      local tag = det.detect_reverse_shell(uri, args, body, get_scan_ua(), get_body_lc())
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
      local tag = det.detect_persistence(uri, args, body, get_scan_ua(), get_body_lc())
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
      local tag = det.detect_rootkit_artifacts(uri, args, body, get_scan_ua(), get_body_lc())
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
      local tag = det.detect_lolbin(uri, args, body, get_scan_ua(), get_body_lc())
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
      local tag = det.detect_coinminer(uri, args, body, get_scan_ua(), get_body_lc())
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

  -- ── 59) PHP encoded `<?php` opener (437 JS `\x` hex-escape · 438 base64) ───
  do
    -- Two rule ids share one detector and the /wp-admin/ carve-out, differing
    -- only in id + mode. 437 = the JS `\x` hex-escape form (`\x3c\x3fphp`) —
    -- audit F16 REMOVED the FP-prone URL / HTML-entity / JS-unicode forms (they
    -- match the normal on-wire encoding of legit content and marker-bearing
    -- payloads in them are already caught by the PHP webshell-body scorer, rule
    -- 404 detect_php_webshell_body, on its normalize()-url-decoded body), leaving
    -- only this attack-shaped form; kept at `challenge`, which preserves+replays.
    -- 438 = the base64 form (`PD9waHA` at a value boundary), which a browser
    -- never emits for a form field → payload-smuggling only, tuned/observed
    -- independently (the block candidate). The detector checks base64 first, so
    -- a base64 opener is attributed to 438 and the hex-escape form to 437.
    local mode_enc = rule_mode(CFG.rule_php_encoded_opener, "logonly")
    local mode_b64 = rule_mode(CFG.rule_php_encoded_opener_b64, "logonly")
    -- WPCode, Code Snippets, Insert PHP Code Snippet, and similar
    -- "save a PHP snippet" plugins POST encoded `<?php` bodies to
    -- /wp-admin/admin-ajax.php or /wp-admin/admin.php on every save.
    -- That's legitimate plugin behavior, not a backdoor upload —
    -- production data showed real Greek WP admins on Chrome 148
    -- residential IPs being challenged here (docs/waf.md FP case 5).
    -- IMPORTANT: those legit saves use the base64 form too — the plugin's
    -- JS base64-encodes the snippet, so `PD9waHA…` (438) appears in a
    -- LEGIT admin-ajax.php save, not just in an attack; base64 is NOT
    -- "attack-only" on this path.
    --
    -- The old carve-out suppressed BOTH openers on ALL /wp-admin/ on the
    -- assumption "these already passed WP's cookie-auth gate." That is
    -- WRONG for admin-ajax.php / admin-post.php (audit F11): both serve
    -- `wp_ajax_nopriv_*` / unauthenticated admin-post actions and are
    -- reachable PRE-auth, so an unauthenticated attacker could smuggle a
    -- base64 `<?php` body there completely unseen. But the edge can't tell
    -- an authed WPCode save from a nopriv attack (both are base64 `<?php`
    -- on admin-ajax; the WP cookie is spoofable), so ENFORCING 438 there
    -- would re-run the FP-case-5 incident.
    --
    -- Compromise (F11, logonly-first): on the pre-auth admin-ajax.php /
    -- admin-post.php surface, keep 437 (url/entity form) fully suppressed
    -- and record the base64 opener (438) at LOGONLY only — visibility into
    -- pre-auth base64 smuggling with ZERO enforcement (no challenge, no
    -- block; and a logonly hit never reaches the autoblock feed — which
    -- ingests only action="block" (waf_security_register.go), and no
    -- WAF_BACKDOOR rule is block-tier — so no ban, even though the
    -- WAF_BACKDOOR family itself is autoblock-armed). Watch that
    -- logonly stream (rule 438 on an admin-ajax URI) to separate real
    -- attacks from WPCode noise before any promotion — deliberately logonly
    -- regardless of 438's global tier during this burn-in. The rest of
    -- /wp-admin/ (authed editors) keeps both openers carved out as before;
    -- non-/wp-admin/ paths are unaffected.
    local wp_admin = uri:find("^/wp%-admin/", 1, false) ~= nil
    local wp_preauth = wp_admin
      and (uri:find("admin%-ajax%.php", 1, false)
           or uri:find("admin%-post%.php", 1, false)) ~= nil
    if (mode_enc ~= "disabled" or mode_b64 ~= "disabled") and body_inspect_ok
       and (not wp_admin or wp_preauth) then
      local tag = det.detect_php_encoded_opener(body, headers)
      if tag then
        local is_b64 = (tag == "B64_PHP_OPENER")
        local mode, rid
        if wp_preauth then
          -- 437 stays suppressed here; 438 is logonly-only (burn-in).
          if is_b64 and mode_b64 ~= "disabled" then
            mode, rid = "logonly", RULE_IDS.rule_php_encoded_opener_b64
          end
        else
          mode = is_b64 and mode_b64 or mode_enc
          rid  = is_b64 and RULE_IDS.rule_php_encoded_opener_b64 or RULE_IDS.rule_php_encoded_opener
        end
        if mode and mode ~= "disabled" then
          local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
          if record("WAF_BACKDOOR:" .. tag, ttl, mode, rid) then goto done end
        end
      end
    end
  end

  -- ── 60) Generic phpfuck / numeric-XOR obfuscation blob (439) ─────────────
  -- Best-effort, technique-level visibility for a phpfuck payload built to
  -- survive ANY restricted-charset eval() sink (vBulletin runMaths /
  -- CVE-2026-61511, custom code, another CMS), keyed purely on the blob shape
  -- with no route to lean on. Ships logonly and STAYS logonly: an endpoint-
  -- anchored block companion was removed after it FP-banned spaced math forum
  -- posts (see detect_php_numeric_xor_obfuscation + WAF_CVE.md). WAF_BACKDOOR is
  -- autoblock-armed, but Phase-1 autoblock ingests edge-`block` hits only, so a
  -- logonly hit logs/alerts WITHOUT banning — the only safe posture here.
  do
    local mode = rule_mode(CFG.rule_php_numeric_xor_obfuscation, "logonly")
    if mode ~= "disabled" and body_inspect_ok and not legit_archive_upload then
      local tag = det.detect_php_numeric_xor_obfuscation(body, headers)
      if tag then
        local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_BACKDOOR:" .. tag, ttl, mode, RULE_IDS.rule_php_numeric_xor_obfuscation) then goto done end
      end
    end
  end

  -- ── Traversal (rule 101) — AFTER every armed block-tier family on purpose ──
  -- rule_traversal is block-tier since 2026-09-05, but its autoblock family
  -- (WAF_TRAVERSAL) is HELD un-armed for burn-in (waf_security_register.go).
  -- record() hands the headline reason to the FIRST block hit and `goto done`
  -- ends evaluation there, and cfm.lua pushes only that headline. Evaluated at
  -- its old position (step 5) a block-tier traversal hit would therefore
  -- SHADOW WAF_RCE / WAF_PHP_WRAPPER / WAF_SQLI / WAF_UPLOAD_* / WAF_CVE on any
  -- request that carries both a traversal marker and their payload (wrapper LFI
  -- `php://filter/...resource=../../etc/passwd`, LFI→RCE `../../proc/self/
  -- environ;wget …`, `${jndi:…}&f=../../etc/passwd`) — and because the
  -- traversal family is held, those requests would lose the 6h nft ban and the
  -- alert the armed family gave them. Running last, the armed family owns the
  -- headline and the ban; a traversal-only request still blocks at the edge.
  -- If WAF_TRAVERSAL is ever armed by default this ordering is merely harmless.
  do
    local mode = rule_mode(CFG.rule_traversal, "block")
    if mode ~= "disabled" and det.detect_traversal(uri, args, get_scan_ua()) then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      ttl, mode = mode_ttl_action(mode, ttl)
      if record("WAF_TRAVERSAL", ttl, mode, RULE_IDS.rule_traversal) then goto done end
    end
  end

  -- ── LAST) Fetch-metadata missing (headless / automation tell) — logonly ───
  -- Track-2 Stage 1b, the edge-only "Sec-Fetch tell": a UA that CLAIMS a modern
  -- Sec-Fetch-capable browser (Chrome >= 76 / Firefox >= 90) but sends a text/html
  -- GET|HEAD navigation with NO Sec-Fetch-* AND NO Accept-Language. Stacked weak
  -- signals — a real browser normally emits both — so honest CLI clients (they
  -- don't claim a browser) and self-declared crawlers (skipped in the detector)
  -- never match; the one real-browser exception, in-app WebViews of social apps,
  -- gets its own NO_FETCH_META_IN_APP tag, clamped to logonly below whatever the
  -- rule's mode is. Shadow-only for burn-in; feeds the per-client challenge
  -- score later, per tag.
  --
  -- Placed LAST on purpose: it is the WEAKEST signal here, so it must never become
  -- the headline `final_reason` ahead of a real finding. record() keeps the strongest
  -- action (highest severity wins) and, among equal-severity logonly hits, the FIRST
  -- to fire owns the headline — so running this after every other rule means it only
  -- surfaces as the primary reason when nothing stronger matched. All hits are still
  -- recorded in `hits`, so nothing is lost either way.
  do
    local mode = rule_mode(CFG.rule_fetch_metadata_missing, "logonly")
    if mode ~= "disabled" then
      local tag = det.detect_fetch_metadata_missing(headers, method, uri)
      if tag then
        -- The in-app tag (a real person inside TikTok & co., header-poor by the
        -- app's stack) is measurement-only: the rule's mode is per-rule, so a
        -- promotion of the tell proper would otherwise enforce on that known
        -- real-person pool exactly as on automation. Clamp it to logonly here —
        -- it is recorded, counted and separable, but never challenged/blocked
        -- whatever rule_fetch_metadata_missing is set to.
        local eff_mode = (tag == "NO_FETCH_META_IN_APP") and "logonly" or mode
        local ttl = (eff_mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
        if record("WAF_FETCH_METADATA:" .. tag, ttl, eff_mode, RULE_IDS.rule_fetch_metadata_missing) then goto done end
      end
    end
  end

  ::done::
  if final_sev == 0 then
    return false, nil, nil, nil
  end
  return true, final_reason, final_ttl, final_action, hits, final_rule_id
end

-- Reason families whose first ":"-tag stays in the should_push cooldown key —
-- see the comment inside should_push. Add a family here ONLY if its tag set is
-- fixed and small and the family has no block tier.
local PUSH_KEY_KEEPS_TAG = {
  WAF_FETCH_METADATA = true,
}

function _M.should_push(shdict, ip, reason, action)
  if not shdict or not ip or ip == "" then return true end
  -- Dedup on (ip, reason FAMILY, action tier).
  --   * FAMILY (the part before the first ":", the same identity
  --     WAF_HIGH_RISK_REASONS keys on) drops the volatile ":score=N" / per-hit
  --     tag that scored rules append — e.g. "WAF_BAD_UA:<tag>:score=6". Keying
  --     on the whole reason gave every hit a distinct key, so a scanner
  --     sweeping many URIs from one IP escaped the 60s cooldown entirely and
  --     emitted a cfm.waf.log record + ip_push RPC per hit (audit F31).
  --   * ACTION tier is essential and must NOT be dropped: WAF families mix
  --     enforcement tiers (e.g. WAF_RCE = block rule 320 + logonly 322-327),
  --     and the Go waf_security autoblock feeds on `action=block` pushes only.
  --     A family+ip-only key would let a cheap logonly recon hit consume the
  --     window and SUPPRESS the later block hit's push, so the IP is never
  --     autoblocked (a security under-report and an evasion primitive). Keying
  --     the action guarantees the first block hit of a family always pushes,
  --     while same-tier score/tag floods still collapse to one push per window.
  -- Caveat for future maintainers: this collapses distinct BLOCK sub-reasons of a
  -- family to one push/window, which is correct only while each armed family has a
  -- SINGLE block rule (the Go autoblock is family-keyed at threshold 1). If a
  -- family ever gains a 2nd block rule AND one is suppressed per-rule (RULE_<id>=0)
  -- while the family stays armed, a block hit of the suppressed rule could consume
  -- this window and mask the armed rule's push — revisit the key (add rule_id) then.
  local fam = (reason and reason:match("^([^:]+)")) or "WAF"
  local key_reason = fam
  if PUSH_KEY_KEEPS_TAG[fam] then
    -- Families whose tags are a FIXED, small set of categories that are meant to
    -- be compared against each other (not a volatile per-hit score/tag) keep the
    -- tag in the key: WAF_FETCH_METADATA's NO_FETCH_META_NO_ACCEPT_LANG vs
    -- NO_FETCH_META_IN_APP are two populations whose per-tag counts decide the
    -- in-app challenge-score weight, and they share CGNAT mobile IPs — a
    -- family-keyed window would drop whichever tag fires second per IP per
    -- minute and bias exactly that comparison. Safe here because the family is
    -- logonly-only (no block rule, no autoblock feed) and has two tags, so a
    -- per-IP flood still collapses to at most two pushes per window.
    key_reason = (reason and reason:match("^[^:]+:[^:]+")) or fam
  end
  local k  = "wafpush|" .. key_reason .. "|" .. (action or "na") .. "|" .. ip
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
