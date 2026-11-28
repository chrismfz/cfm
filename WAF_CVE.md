# WAF CVE detectors (`WAF_CVE`)

The one doc for CFM's named-vulnerability WAF rules: what ships (§1–§3), the
coverage decisions (§4), the backlog (§5), the design decisions behind the
framework (§6) and the recipe for adding the next rule (§7, "CVE hunting").
The code wins over this doc: `configs/lua/cfm_waf.lua` (`CFG` defaults,
`RULE_IDS`, `check()`), `configs/lua/cfm_waf_detectors.lua` (the
`detect_cve_*` functions), `internal/webdetector/waf_rule_ids.go` (the Go
mirror: `DefaultMode`, `HoldAutoblock`) and
`internal/detectors/wafsec/detector.go` (`cveFromReason`). Update this doc in
the same change that adds, promotes, holds or removes a CVE rule.

(The former design + backlog doc, `WAF_CVE_PLAN.md`, is folded in here: §5
and §6 keep what was still open or still decides something; git history
keeps the rest.)

---

## 1. Framework

### 1.1 Rule identity — the `10000+` band

- **Ids.** CVE detectors use stable ids from `10001`, kept out of the legacy
  `1xx–9xx` families (`9xx`, reserved for behavioural rules, is too small for
  long-term CVE coverage). **Never renumber** an id: operators reference them
  in excludes, `RULE_<id>` overrides, dashboards and tickets. `10015` is
  skipped for good (the removed vBulletin rule, §3).
- **Lua is canonical:** `RULE_IDS` in `configs/lua/cfm_waf.lua` (ids) and its
  `CFG` table (default modes). **Go mirror:** `wafRuleIDs` in
  `internal/webdetector/waf_rule_ids.go`, every entry
  `ReasonFamily: "WAF_CVE"`.
- **Parity tests** (`internal/webdetector/waf_rule_ids_test.go`):
  `TestWAFRuleIDs_LuaParity` (ids) and `TestWAFRuleIDs_DefaultModeLuaParity`
  (every Go `DefaultMode` equals the Lua `CFG` default; a promotion edits both
  in the same change).
- **Grouping:** `Group = id / 100`, and `wafRuleGroupNames[100] = "cve"`.
  `TestWAFRuleIDs_GroupingDigits` accepts ids in `10000–99999` **but also
  requires the group to be in `wafRuleGroupNames`, which only has `100`** — so
  as the code stands only `10000–10099` pass. The next free id is `10034`; an
  id `>= 10100` needs a `wafRuleGroupNames` change first.
- **`rule_log4shell` (id `328`)** predates the band, keeps its legacy id and
  also reports the `WAF_CVE` family (default `challenge_v2`, so its hits never
  reach autoblock; its reason has no `CVE_*` token, see 1.2).

### 1.2 Reason format

```
WAF_CVE:CVE_<year>_<suffix>:<PRODUCT>:<TAG>
```

e.g. `WAF_CVE:CVE_2025_34085:SIMPLE_FILE_LIST:RENAME_TO_PHP`. The `<TAG>`
names the exploit leg. The CVE segment uses underscores (Lua/log friendly).
A rule that covers several CVEs picks one per leg in `check()` (10006, 10008,
10011, 10030 do this); otherwise it reports the campaign-primary one.

Reasons with **no** `CVE_*` segment (the notification then reads plain
`WAF/CVE`): `WAF_CVE:REVSLIDER:PLUGIN_UPLOAD` (10005's upload leg) and
`WAF_CVE:LOG4SHELL:<tag>` (328).

### 1.3 CVE-named notifications

`cveFromReason` (`internal/detectors/wafsec/detector.go`) takes the second
colon segment and, if it starts with `CVE_`, dash-converts it
(`CVE_2025_34085` → `CVE-2025-34085`); otherwise it returns `""`. For a
`WAF_CVE` hit the alert `Kind` becomes `WAF/CVE-2025-34085` and
`Extra["cve"]` carries the id, so sinks never parse message text;
`Extra["rule_id"]` cross-references the registry. Nothing to write per rule:
get the reason format right.

### 1.4 waf_security autoblock — family armed, doubtful rules held

- **`WAF_CVE` arms to `1` by default** because it has edge-`block` rules
  (`wafSecurityFamilies` in `internal/detectors/waf_security_register.go`: a
  family defaults to `1` iff `WAFFamilyHasBlockRule`, unless it is in
  `heldAutoblockFamilies`, today only `WAF_TRAVERSAL`). The operator wants CVE
  hits to both nft-ban (6 h) and alert; an un-armed family is dropped by
  `wafsec` before the sink, so `CVE = 0` would notify nothing.
  `TestWAFSecurityFamilyCoverage` enforces "block rule ⇒ armed" for every
  family, `WAF_CVE` included.
- **The family is heterogeneous, so hold the doubtful RULE, not the family.**
  A block rule whose 403 is right but whose ban could land on a legitimate
  user ships with `HoldAutoblock: true` on its `WAFRule` in
  `waf_rule_ids.go`: that makes `RULE_<id> = 0` the code default
  (`wafSecurityRuleOverrides`), which reaches configs that predate the rule;
  an operator's `RULE_<id>` in `detectors.conf` still wins. Mention the hold
  in the `[waf_security]` comment block of `configs/detectors.conf`. Held
  today: **10020, 10022, 10026, 10028, 10034**.
- **A held block rule runs late in `check()`.** The first block hit owns the
  headline `record()` and `goto done` ends evaluation, so a held rule placed
  early would take the ban from an armed rule on the same request. Held CVE
  rules sit with traversal, after every armed block family (CLAUDE.md §6).
- Only edge-`block` hits feed autoblock (Phase 1); a tag recorded `logonly`
  (10024 `SAME_SITE`, 10028 `FILE_INFO_ELSEWHERE`, 10029 `EVAL_ZERO`) never
  bans. `DRY_RUN = 1` in `[waf_security]` alerts without banning.
- The edge action is per rule (`CFG.rule_cve_* = "block"` or a per-vhost
  override), independent of arming. Block tier is also what the panel-port
  gate (`cfm_panel.lua`, `:2083/:2087/:2096`) enforces, for rules that run
  there (the panel gate reads no body and passes no raw path).

### 1.5 Body burn-in

A large or chunked body on `location /` is read by cfm.lua in a burn-in pass,
where only the block rules in `BURNIN_ENFORCE_IDS` (`configs/lua/cfm.lua`)
are enforced: today **10021, 10024, 10027, 10028, 10030, 10031, 10033, 10034**. A rule whose
exploit arrives that way must be in that list and must run before any other
block rule that the same request can trip (the pass ends at the first block,
enforced or not). That is why 10021, 10024, 10027 and 10030 run first in
`check()`, and why 10028, 10034, then 10031 / 10033 run early in the burn-in second pass
(`ctx.burnin_pass`, after 10027 and 10030) but late otherwise.

---

## 2. Rules in code

Every rule below ships at edge default **`block`** (Lua `CFG` and Go
`DefaultMode` agree), except the logonly 10035 (and the tags 10032 / 10033 force to logonly, named in their rows). "Armed" = the `WAF_CVE` default applies (6 h nft ban +
`WAF/CVE-…` alert); "held" = `HoldAutoblock` (403 only).

| Id | `CFG` name | CVE(s) in the reason | Product | Keyed on | Autoblock |
|---|---|---|---|---|---|
| 10001 | `rule_cve_simple_file_list_upload` | CVE-2025-34085 (also covers CVE-2020-36847) | Simple File List (WP) | `ee-file-engine.php` rename to a PHP-exec ext; `ee-upload-engine.php` + PHP content (rule-402 scanner) | armed |
| 10002 | `rule_cve_joomla_jce_profile_import` | CVE-2026-48907 | Joomla JCE | `option=com_jce` + `profiles.import` + php-exec upload filename | armed |
| 10003 | `rule_cve_ninja_forms_fu_upload` | CVE-2026-0740 | Ninja Forms File Uploads | `action=nf_fu_upload` + (php-exec filename OR `image_jpg` traversal) | armed |
| 10004 | `rule_cve_litespeed_hash_privesc` | CVE-2024-28000 | LiteSpeed Cache | `litespeed_hash` / `litespeed_role` cookie, all methods | armed |
| 10005 | `rule_cve_revslider` | CVE-2015-1579 (LFI leg); upload leg has no CVE token | Slider Revolution | `revslider_show_image` + `../`; unauth `revslider_ajax_action` + `update_plugin` | armed |
| 10006 | `rule_cve_w3tc` | CVE-2026-5032 (UA leg), CVE-2025-9501 (mfunc leg) | W3 Total Cache | `User-Agent: W3 Total Cache`; `mfunc`/`mclude` in a comment POST | armed |
| 10007 | `rule_cve_post_smtp` | CVE-2025-11833 (also covers CVE-2023-6875) | Post SMTP | unauth `/wp-json/post-smtp/` or `postman_email_log` page | armed |
| 10008 | `rule_cve_fusion_builder` | CVE-2026-6279 (RCE), CVE-2026-8713 (file delete) | Avada / Fusion Builder | `fusion_get_widget_markup` + base64 `render_logics` → dangerous callable; `fusion_form_submit_ajax` + `privacy_expiration_action` | armed |
| 10009 | `rule_cve_kirki_forgot_password` | CVE-2026-8206 | Kirki | `POST /wp-json/KirkiComponentLibrary/v1/kirki-forgot-password` + `username` & `email` | armed |
| 10010 | `rule_cve_gf_multi_uploader` | CVE-2025-23921 | Multi Uploader for Gravity Forms | `gf_page=upload` + `gform_unique_id` traversal → `.phtml`/`.php` | armed |
| 10011 | `rule_cve_wp2shell` | CVE-2026-63030 (desync), CVE-2026-60137 (SQLi) | WordPress core | REST `batch/v1` POST: `"///"` primer; SQL breakout in `author_exclude`/`author_not_in` | armed |
| 10012 | `rule_cve_woocommerce_payments` | CVE-2023-28121 | WooCommerce Payments | `X-WCPAY-Platform-Checkout-User` header present, all methods | armed |
| 10013 | `rule_cve_gravity_smtp` | CVE-2026-4020 | Gravity SMTP | unauth `/gravitysmtp/v1/tests/mock-data` (both permalink forms) | armed |
| 10014 | `rule_cve_sppagebuilder_upload` | CVE-2026-48908 | SP Page Builder (Joomla) | `com_sppagebuilder` + `task=asset.upload*` + php-exec payload | armed |
| 10016 | `rule_cve_elementor_pro_form_upload` | CVE-2026-32475 | Elementor Pro Forms | `action=elementor_pro_forms_send_form` + php-exec upload filename | armed |
| 10017 | `rule_cve_wp_pagename_traversal` | CVE-2026-87902 | WordPress core | a `pagename` field (query / POST) with a `..` segment | armed |
| 10018 | `rule_cve_translatepress_reset_preview` | CVE-2026-19632 | TranslatePress | `trp-edit-translation` on a password-reset POST, no login cookie | armed |
| 10019 | `rule_cve_translatepress_id_lookup` | CVE-2026-19632 | TranslatePress | `action=trp_get_translations_regular` + non-empty `string_ids`, no login cookie | armed (since 2026-11-17) |
| 10020 | `rule_cve_translatepress_reset_preview_authed` | CVE-2026-19632 | TranslatePress | 10018's request WITH a login cookie | **held** |
| 10021 | `rule_cve_php_multipart_oom` | CVE-2026-109618 | PHP core | multipart body: `PART_HEADERS` / `EMPTY_FILES` / `NESTING` | armed |
| 10022 | `rule_cve_php_multipart_no_length` | CVE-2026-109618 | PHP core | multipart POST with no Content-Length the edge never read (`NO_CL`) | **held** |
| 10023 | `rule_cve_php2shell_tool` | CVE-2026-109619 | PHP core (PHP2Shell tool) | `php2shell-…` UA or a PoC boundary (header only) | armed |
| 10024 | `rule_cve_php_upload_progress` | CVE-2026-109619 | PHP core | `PHP_SESSION_UPLOAD_PROGRESS` part without same-site Referer/Origin + Fetch Metadata (`SAME_SITE` is logonly) | armed |
| 10025 | `rule_cve_pixelyoursite_xss` | CVE-2026-1844 (also covers -1841, -109987) | PixelYourSite / PRO | executable markup / attribute breakout / script URL in the plugin's own cookies | armed |
| 10026 | `rule_cve_pixelyoursite_session_xss` | CVE-2026-1844 | PixelYourSite / PRO | the same in the raw path, the Referer host, `utm_*` query fields | **held** |
| 10027 | `rule_cve_magento_polyshell` | CVE-2026-48356 | Magento / Adobe Commerce | cart-save request (REST / SOAP) carrying `custom_options` + `file_info` + `base64_encoded_data` | armed |
| 10028 | `rule_cve_magento_polyshell_unseen` | CVE-2026-48356 | Magento / Adobe Commerce | a cart-save request 10027 could not read (`OVERSIZE` / `XML_ENTITY` / `UNREADABLE`); `FILE_INFO_ELSEWHERE` logonly | **held** |
| 10029 | `rule_cve_fabrik_listfilter_eval` | CVE-2026-67282 | Fabrik (Joomla) | an `[eval]` index set on a Fabrik request field (`EVAL_ZERO` logonly) | armed (block since 2026-11-17) |
| 10030 | `rule_cve_drupal_render_callback` | CVE-2026-108097 (`#region_callback`), CVE-2018-7600 (the other keys) | Drupal core | a render-array callback key as a field NAME / JSON KEY | armed |
| 10031 | `rule_cve_php_fpm_smuggle` | CVE-2026-129289 | PHP core (FPM / LSAPI) | a FastCGI BEGIN_REQUEST + PARAMS record (`FCGI_BEGIN_REQUEST`) or a length-prefixed SCRIPT_FILENAME / PATH_TRANSLATED / PHP_ADMIN_VALUE / REMOTE_ADDR (`FCGI_PARAMS`) in a POST body | held (block since 2026-11-28) |
| 10032 | `rule_cve_php_oversized_auth` | CVE-2026-129496 | PHP core (ext/date) | an Authorization header line over nginx's default 8 KB buffer (`BASIC_OVERSIZE` blocks; `OVERSIZE`, any other scheme, stays logonly; `:len=N`) | held (block since 2026-11-28) |
| 10033 | `rule_cve_php_multipart_desync` | CVE-2026-129289 (first leg) | PHP core | a multipart POST that leaves bytes PHP never reads (`GARBLED_STOP` / `BOUNDARY_TOO_LARGE` block; `GARBLED_STOP_SMALL` / `NO_BOUNDARY` stay logonly) | held (block since 2026-11-28) |
| 10034 | `rule_cve_wp_rocket_beacon` | CVE-2026-125812 | WP Rocket < 3.24.2 | `POST` `action=rocket_beacon` (admin-ajax.php, any path) whose `results` JSON has a `preconnect_external_domain` entry that is not a bare origin (`NON_ORIGIN`), or a cut body that is not a real beacon's shape (`OVERSIZE`) | **held** (watch from 2026-11-28) |
| 10035 | `rule_cve_wp_rocket_beacon_unseen` | CVE-2026-125812 | WP Rocket | beacon JSON the edge could not decode (`UNPARSED`), or a body cut inside `results` (`OVERSIZE_RESULTS`) | **logonly** |

Lua tests: `scripts/tests/cfm_waf_cve_<slug>_test.lua` per product (plus
`*_e2e_test.lua` for 10021/10022, 10024, 10027/10028, 10030). 10023 is
tested in the `php_upload_progress` files, 10029 in
`cfm_waf_tier_review_2026_11_17_test.lua`. 10031–10033 share
`cfm_waf_cve_php_2611_test.lua`.

### 2.1 Rule notes (sources, residuals, decisions)

- **10031–10033, the php-src advisories of 2026-11-19** (fixed in 8.2.36 /
  8.3.37 / 8.4.28 / 8.5.13; no fix commit or PoC was published with them).
  That day's batch is larger than the eight triaged here (it also has, e.g.,
  a php-cgi and an FPM status-page advisory, outside what the fleet runs);
  the eight and their decision:
  - GHSA-qc49-hpvq-g2w6 / CVE-2026-129289, FPM request smuggling: **10031,
    10033** (block, ban held).
  - GHSA-gr4f-wgx5-jpfv / CVE-2026-129496, ext/date UAF: **10032** (block, ban held).
  - GHSA-658j-r8rw-q6mx / CVE-2026-115560, session upload progress +
    serializer mismatch: already blocked by **10024** (the same field).
  - GHSA-2fjv-p558-g82m / CVE-2026-129182, GHSA-8mjj-2r7p-4hg2 /
    CVE-2026-129474, GHSA-g3vh-838c-65v7 / CVE-2026-129481 (use-after-frees),
    GHSA-fm2m-fjf5-v3cp / CVE-2026-126714 (session TOCTOU),
    GHSA-jm4m-qfqx-967m / CVE-2026-129291 (local FPM escalation): no request
    shape a proxy sees (configuration, the application's own code, or a
    local foothold).

  Promotion (2026-11-28), after a 7-day logonly burn-in on all 8 cfm-edge
  nodes (~1.4 M WAF log records): 0 FCGI_*, 0 BASIC_OVERSIZE / OVERSIZE, 0
  GARBLED_STOP / _SMALL / BOUNDARY_TOO_LARGE, 0 305 / 201 hits on a
  multipart POST; 108 NO_BOUNDARY (99 from one site's broken client, 9
  one-off datacenter POSTs to `/`). No exploit attempt was seen, so the
  confidence is the spec's and the tests', not traffic's. Straight to block
  (none of these shapes comes from a browser, so a challenge proves
  nothing), the ban held per rule (`RULE_10031` / `RULE_10032` /
  `RULE_10033 = 0`): an edge 403, no nft ban, for a further watch at block.
  Forced logonly in code, as 10024's SAME_SITE: 10032's OVERSIZE (a rare
  legitimate large Bearer token), 10033's GARBLED_STOP_SMALL (PHP may still
  read a small rest) and NO_BOUNDARY (broken clients). 10031 / 10033 are in
  `BURNIN_ENFORCE_IDS` and run early in the body burn-in second pass (a
  chunked or > 1 MB `POST /` carrying them reached the origin otherwise; in
  that pass they also come before 305, so a chunked advisory request is
  theirs, a 403 without a ban). Elsewhere, as held block rules, all three run late, after every armed
  block rule (a held block evaluated earlier would take the headline and end
  the check before an armed rule's ban); so the advisory's own request,
  which also trips 305 (php://input in PHP_ADMIN_VALUE, an armed block), is
  305's, banned, and records no 10031 / 10033. 10032 also blocks on the
  panel ports (the panel gate denies block-tier hits; 0 panel hits in the
  burn-in). During the burn-in 10031 / 10033 ran early, in step 0, so the
  exploit would have been recorded behind 305. 10031 reads the FastCGI records as php-src's
  `fcgi_read_request` accepts them (any version >= 1, request id and
  reserved byte, role 1–3; a BEGIN_REQUEST counts only with a PARAMS record
  right after it; anchored on the plain `\0\8` of its content length, so a
  text body costs one find) and the parameter names `init_request_info` /
  the advisory use (SCRIPT_FILENAME, its fallback PATH_TRANSLATED,
  PHP_ADMIN_VALUE, REMOTE_ADDR; not PHP_VALUE, whose length byte is a TAB).
  10032: the advisory's FPM code-execution proof used an oversized HTTP
  Basic header, which this edge's 64 KB `large_client_header_buffers`
  admits; the tag carries the value's length. 10033, checked against PHP
  8.3.6: a part with a Content-Disposition but neither name nor filename
  ends the parse (a part with none, or bytes after the closing boundary, do
  not). What PHP then leaves unread depends on where its last 5120-byte
  refill started, so a rest over 5120 bytes (closing delimiter and
  whitespace ignored) is certainly unread (`GARBLED_STOP:rest=N`, or
  `:rest=trunc` when the edge holds only part of the body: the 32 KB cap
  reached, or Content-Length past it)
  and a smaller one may be (`GARBLED_STOP_SMALL:rest=N`). No boundary
  parameter (`NO_BOUNDARY`) and a boundary over 5116 bytes
  (`BOUNDARY_TOO_LARGE`) make PHP parse nothing. A body with no boundary line
  at all (an empty FormData, JSON labelled multipart) is read to its end and
  not tagged. Fleet (2026-11-20): fixed PHP everywhere (CloudLinux
  backported the EOL branches the day before), mostly LSAPI, no
  `enablereuse` / `fastcgi_keep_conn`, `session.upload_progress.enabled =
  0`, so the burn-in measures attempts, not exposure.

  Reading the burn-in (three reads, all 8 nodes; count distinct IPs and
  hosts, not lines — the push is de-duplicated per (ip, WAF_CVE, logonly)
  for `push_cooldown`, so counts are IP-minutes and one client's tag hides
  its other WAF_CVE logonly tags, 10024 SAME_SITE / 10028 / 10029 included):
  - count both the headline `reason` (`WAF_CVE:CVE_2026_129289:…`,
    `…129496:…`) and `also_rule_ids` holding 10031 / 10032 / 10033 (behind a
    block or challenge hit only the id survives, not the tag);
  - pull the 305 (`WAF_PHP_WRAPPER`) and 201 hits on multipart POSTs too: the
    real exploit lands there (with 10031 in `also_rule_ids` during the
    logonly burn-in; at block, late, it is 305's alone);
  - grep the edge error.log for `waf_body_burnin` lines with
    `CVE_2026_129289` (a body read in the burn-in second pass after a
    body-free first-pass hit logs there only) and for `[cfm_panel_waf]`
    lines with `CVE_2026_129496` (10032 on 2083 / 2087 / 2096; the panel gate
    reads no body, so 10031 / 10033 do not run there);
  - 10031: FP = a recurring upload endpoint (async-upload.php, media REST)
    from residential IPs with browser UAs (a probe of ~18 000 32 KB windows
    of real files found none; an uploaded pcap / core dump of FastCGI
    traffic is the one plausible source); attack = one-shot POSTs to `/`,
    `index.php` or random `.php` paths, tool UAs, hosting ASNs, many vhosts;
  - 10032: check the access-log status (Apache's LimitRequestFieldSize,
    8190, already refuses such a header with 400); FP = one stable
    integration on one host / uri; attack = BASIC_OVERSIZE on many hosts;
  - 10033: split by tag. NO_BOUNDARY mostly measures broken clients (a
    hand-set multipart header on a JSON / string body): group by (host, uri,
    ua) and treat it as a noise baseline, never a promotion case on its own.
    BOUNDARY_TOO_LARGE has no legitimate source. GARBLED_STOP together with
    10031 on one request is an attack; a single (host, uri) from a .NET or
    UA-less client (a nameless `Content-Disposition: form-data`) is a
    broken client.
  - 10031 reads the FastCGI form only. LSAPI, the handler on most of the
    fleet, frames requests in its own packets, so on an LSAPI node an
    LSAPI-shaped attempt leaves only 10033's trace (an LSAPI leg needs its
    format from lsapidef.h / lsapilib, never from memory).
  - The body burn-in second pass (a chunked or large body on `location /`)
    logs only its best hit, once per IP a minute, as a `waf_body_burnin`
    error-log line: a 10031 behind another body hit there leaves no record.
  - "0 hits" is not "no attacks": an earlier block that ends the check
    before step 0's end, a garbled part or record past the 32 KB window,
    PUT / PATCH bodies, bodies the edge never reads (off the read allowlist,
    HTTP/3 without Content-Length), excluded vhosts / rules and bypass
    prefixes, and the dedup window all hide hits.

  Known gaps for any promotion: only the first `waf_body_max_len` (32 KB)
  is read and the attacker chooses where PHP stops, so a garbled part or a
  FastCGI record past the window is not seen; POST only, while an app that
  half-reads php://input exposes PUT / PATCH bodies the same way. A
  promotion decides the autoblock intent in the same change and moves an
  armed rule early in `check()`.

- **10001 Simple File List** (unauth upload → rename → RCE). One detector for
  both CVEs (same plugin, endpoints, exploit). Rename leg: extension match
  `_cve_sfl_has_exec_ext` (`.php[0-9]?`, `.pht`, `.phtm`, `.phtml`, `.phar` at
  a value boundary), kept in step with `bad_fname()` (rule 401). Upload leg
  delegates to the hardened rule-402 scanner `_M.detect_upload_content`
  (multipart only, binary-safe short-echo check) rather than a naive `<?php`
  substring, which would bring back the rule-402 image-body FP. Sources:
  `0xGunrunner/CVE-2025-34085` and the CVE-2020-36847 upload/rename PoC.
- **10005 Slider Revolution** is a behavioural virtual-patch (§4.3): the
  shapes are malicious on any version. The `update_plugin` leg is unauth-gated.
- **10012 WooCommerce Payments.** The header is server-set by WooPay only;
  exempt genuine WooPay nets with `ALLOW_NETS`.
- **10013 Gravity SMTP.** The only legitimate caller is the wp-admin settings
  screen, which carries the login cookie (UNAUTH gate).
- **10014 SP Page Builder** ("ANTONKILL"). Runs before 401/414 for CVE
  attribution; payload = direct filename, php-in-zip or php content, reusing
  the upload detectors. A php entry past `waf_body_max_len` is ClamAV's
  backstop.
- **10016 Elementor Pro <4.2.2.** `validation()` `return`s on an empty first
  part, skipping the extension blocklist for a following `.php` part that
  `process_field()` still moves into `wp-content/uploads/elementor/forms/`.
  The surviving extension is the vuln, so there is deliberately no content leg
  (it would mis-attribute pasted PHP text; rule 402 covers raw PHP content).
  Runs before 401 for attribution.
- **10017 WordPress core page-template traversal** (GHSA-7hp8-65ch-5whp;
  4.7.0–7.1.1, fixed 7.1.2 and back to 4.7.37). `get_page_template()` builds
  `page-{$pagename}.php` from the url-decoded `pagename` without the `..`
  check (RCE via `pearcmd.php` with `register_argc_argv=On`; needs a top-level
  `page-*` theme dir). Source: the WordPress advisory + Wordfence entry
  (operator-supplied). Every duplicate field is checked; WP reads `$_POST`
  first. The pretty-permalink route (the path becomes `pagename`) was
  invisible because `ctx.uri` is nginx's decoded, dot-resolved `$uri`;
  **rule 103** (`rule_traversal_raw_path`, `WAF_TRAVERSAL`, block, family
  held) closes it generically from `ctx.raw_uri`. Web edge only.
- **10018 / 10019 / 10020 TranslatePress <= 3.3.1** (fixed 3.3.2), unauth
  account takeover. Source: the 3.3.1→3.3.2 diff and the titan capture
  (2026-10-08). `force_language_in_preview()` makes `wp_mail_filter()` store
  the reset mail, key included. 10020 is held because the editor preview
  (`trp-iframe-preview-script.js`) adds the parameter to every form a
  translator submits. 10019 was held against a translator whose login expired
  and is armed since 2026-11-17 (87 hits / 7 days / 8 nodes, all datacenter).
  `string_ids` of only whitespace and brackets does not count; the cookie
  gate is an FP filter (a junk cookie bypasses it). Fields are read as PHP
  reads them (`php_request_fields`). Residuals: a theme/plugin AJAX reset with
  the parameter in the Referer / `_wp_http_referer`; a field in a body the WAF
  does not see (a "body not seen" tag was tried and dropped: it would ban a
  translator's large form). An admin whose locale is a secondary language has
  the mail stored without the trick: update to 3.3.2+.
- **10021–10024 PHP core** (in scope because every WP/Joomla site runs on it).
  PHP < 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 unauth RCE: an OOM during the
  startup multipart parse leaves request memory half-initialised for
  shutdown. Sources: GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp (2026-10-21);
  for 10023/10024 Imunify360 ruleset 8.85 (77318849, 77866818, 77236259) and
  the fleet's edge logs (`ua="php2shell-scanner"`, `POST /`).
  - 10021: parts found by a line scan like `find_boundary` (three bypasses in
    two review rounds, checked against PHP 8.3.6). Nesting bar: a file part
    >16 levels, a plain field >32 (Drupal Paragraphs, axios/Inertia FormData).
    Fastest FP lever: a per-host/path exclude for 10021.
  - 10022: `NO_CL` per cfm.lua `no_body_length` (a body read in full first
    goes upstream with a real Content-Length). Off on an edge conf without
    `$cfm_body_buffered`. Held: chunked multipart clients (Go `io.Pipe`,
    `curl -F f=@-`, Java chunked mode) send the same shape.
  - 10023: User-Agent `php2shell-…` (`TOOL_UA`) or a PoC boundary
    (`TOOL_BOUNDARY`); header-only. A renamed tool passes.
  - 10024: blocks `NO_REFERER` / `XSITE` / `NO_FETCH_METADATA` (the scanner
    forged a same-site Referer, 2026-10-21); `SAME_SITE`, a `www.`/sibling
    host and `Origin: null` + same-origin are logonly. Name read from the
    multipart parse (PHP joins a split name). A browser without Fetch Metadata
    (Safari < 16.4) posting its own progress form is blocked. Removing 10024
    from `BURNIN_ENFORCE_IDS` reproduces the tool's pass
    (`cfm_waf_cve_php_upload_progress_e2e_test.lua`).
  - Residuals: only the first `waf_body_max_len` (32 KB) is seen; the panel
    ports read no body; nodes without the edge get nothing. A stopgap: update
    PHP and set `session.upload_progress.enabled = 0`.
- **10025 / 10026 PixelYourSite** (free < 11.4.3, PRO < 12.6.8), unauth stored
  XSS through the order "enrich" data. Source: the plugin code (PRO
  12.2.7.1, `class_enrich_order.php`, `views/html-order-meta-box.php`) and
  ~100 planted orders on 16 fleet shops (2026-02-13 → 2026-10-10; tophair.gr:
  fake plugin + two admins in 15 s). Both look for **executable markup** only
  (a script/iframe/frame/object/embed/meta/base element, or any element with
  an `on…=` handler, `srcdoc=` or `javascript:`); a bare `<`/`>` or a
  `<campaign_name>` placeholder is not. 10025 tags `COOKIE_MARKUP`,
  `COOKIE_ATTR_BREAKOUT`, `COOKIE_SCRIPT_URL`; 10026 `PATH_MARKUP`,
  `PATH_ATTR_BREAKOUT`, `REFERER_HOST_MARKUP`, `QUERY_UTM_MARKUP`. A 7-day
  replay (2026-10-27) found 10026 hits only from one XSS scanner. Protects new
  orders only: stored payloads need a DB clean-up.
- **10027 / 10028 Magento "PolyShell"**. A cart item's custom option
  `file_info` makes Magento write the decoded file, attacker's name and
  extension, to `pub/media/custom_options/quote/`. Sources: Sansec's write-up,
  Magento's own code (2.3.7 and 2.4-develop) and the 2026-10-29 attack on
  dabizasfoods.gr (orion; base64 inside JSON, which 401/402 do not decode).
  Names compared with `_` removed and lowercased, in JSON keys, XML
  element/attribute names and bracketed form/query keys. The edge reads a
  SOAP call's body (`waf_should_read_body_or_soap`); the edge and the
  detectors share one matcher (`magento_soap_call`). GraphQL is not
  vulnerable per Sansec. A shop whose own integration uploads a file option
  through the web API needs a per-vhost exclude of 10027 and 10028. Known
  limits: a legitimate bulk/quote-save call past 32 KB and an add-to-cart the
  edge could not read (HTTP/3, a PUT without Content-Length) get 10028's 403.
  Fixed in 2.4.9 and the APSB26-73 backports; keep
  `pub/media/custom_options/.htaccess` (`Deny from all`, `php_flag engine 0`).
- **10029 Fabrik for Joomla** 1.0.0–4.6.7 (fixed in 4.7.2), unauth RCE
  through the list filter (`<table>___<element>[value]` runs as PHP when the
  element carries `[eval]`). Source: the dmkomotinis.gr compromise (earth,
  2026-11-12) and its edge log. A Fabrik request = `option=com_fabrik`,
  `fabrik` in the path, or the element name's `___`. Promoted to block
  2026-11-17 after a 14-day read of all 8 nodes' `cfm.waf.log` (`EVAL_ZERO`
  only from real users, a set `[eval]` only from the attacker). Armed, so the
  first probe bans before a payload reaches rule 332.
- **10034 / 10035 WP Rocket beacon** (CVE-2026-125812,
  unauthenticated RCE, exploited from 2026-11-25). Sources: the CVE record
  (Patchstack; it publishes only `POST admin-ajax.php` +
  `action=rocket_beacon`), Patchstack's 2026-11-27 advisory (its detection
  hint: full URLs where bare domains are expected) and the
  `wp-media/wp-rocket` v3.24.1..v3.24.2 diff. The chain:
  `PreconnectExternalDomains\AJAX\Controller::add_data()` stored each
  `results.preconnect_external_domain` entry through `sanitize_url()` only;
  the page printed it as a `dns-prefetch` link; LazyLoad for CSS background
  images and Host Fonts Locally fetched that URL and wrote it to the cache
  under a name from its path (`wp-content/cache/background-css/…/*.php`). The
  fix (`OriginTrait::get_origin`) keeps only `scheme://host[:port]`, which is
  all the browser sends (`url.origin`). 10034 decodes `results` as
  `json_decode` does (escapes, duplicate keys, a string / list / object of
  entries) and accepts only `null`, `""` or `scheme://host[:port]/?`. It fires
  whether or not the site has either feature on. A cut body (past
  `waf_body_max_len`, 32 KB, or declared and unread): the browser's FormData
  has six fields with `results` last, and `results` is unbounded (every LCP
  candidate with srcset / sources, `data:` URIs included), so a large real
  beacon is cut inside `results`; that shape is 10035 `OVERSIZE_RESULTS`
  (logged): a single `results` that starts `{"` and runs to the end of the
  held body (or to a cut inside the closing delimiter right after it). Any other cut body is 10034 `OVERSIZE` (403): no `results` in
  view (padding in a file part, a nameless part or a part's headers hides
  the parts after it from the field reader), a second `results` (PHP keeps
  the last), a field the beacon never sends, a short field over 4 KB, or no
  body at all. Residuals, both seen in review:
  padding sent BEFORE `action` hides the action (nothing to key on), and
  padding inside `results` looks like the real large beacon. Edge 403, autoblock held
  per rule (`RULE_10034 = 0`) for a 2–3 day watch; `RULE_10034 = 1` in a
  node's `[waf_security]` arms it there, and dropping `HoldAutoblock` (Go)
  makes that the default once the hits read as attacks only. Keyed on the
  fields, not the path (a security plugin can rename admin-ajax.php), like
  10018; a renamed path off cfm.lua's body read list gets its body in the
  burn-in pass, so 10034 is in `BURNIN_ENFORCE_IDS` and runs early there. admin-ajax.php bodies are read (up to `waf_body_max_len`) by Step 2,
  never in the burn-in pass. 10035 (logonly) is `UNPARSED`: JSON the edge reader does not decode
  (a fuzz against PHP 8.3.6's `json_decode`, 30k documents, found no case
  PHP stores a non-origin entry that 10034 misses).
- **10030 Drupal render-array callbacks** (`#region_callback`,
  `#post_render`, `#pre_render`, `#lazy_builder`, `#access_callback`) as a
  field NAME (query, urlencoded, multipart), a JSON KEY (POST/PUT/PATCH,
  `#` decoded), `#region_callback` in a field value that is a JSON
  document, or in the query of Drupal 7's `destination`; words in a value
  never match. Sources: SA-CORE-2026-014 (fixed 2026-10-14 in 10.6.19 /
  11.3.19 / 11.4.10; exploit status "Theoretical") with the 0xABCD01 lab, and
  Drupalgeddon2's public payload. A first draft (a plain find) blocked 11
  legitimate requests in an FP review; they are negative tests now. Armed:
  the fleet's EOL Drupal sites cannot take the core patch.

---

## 3. Removed — vBulletin `runMaths()` (CVE-2026-61511), block rule 10015

A route-anchored, block-tier phpfuck detector was prototyped and, over three
adversarial review rounds, **removed** as too dangerous for a forum-hosting
fleet. The signature scores a dense run of parenthesised digit literals
joined by `.` and XORed with `^`. The fatal flaw was an FP **ban**: an
ordinary spaced math post (`(1.5)^2 + (2.5)^2 + …`) is sent form-urlencoded,
each space becomes `+`, `normalize` does not turn `+` back, so with `+` in the
run charset the expression bridged into one qualifying run → `block` →
`WAF_CVE` 6 h ban of a real user on the `ajax/render` preview route. Removing
`+` reopens a no-op-operator bypass, and projecting the payload as the sink
does re-merges legit code. The endpoint gate cannot separate a math post from
the attack at request time; the fix is **patching vBulletin (≥ 6.2.2)**.

What remains is rule **439** (`rule_php_numeric_xor_obfuscation`,
`WAF_BACKDOOR`, **logonly**, never to be promoted): body-only, tight charset,
best-effort visibility. There is no CVE-attributed block/ban for this vector.

---

## 4. Coverage decisions

### 4.1 Scope: what the fleet runs

A detector for software nobody on the fleet runs is pure FP surface and
maintenance for zero protection. The ACSC campaign shortlist's Craft CMS
(`CVE-2025-32432`), MaxSite CMS (`CVE-2026-3395`) and MetInfo CMS
(`CVE-2026-29014`) were dropped for that reason; revisit only if the hosting
mix changes. The rules in scope are WordPress / Joomla plugins and core, plus
products a fleet read or an incident showed are present: PHP core (every site
runs on it), Magento (the orion attack, 10027/10028) and Drupal (three
accounts, two past end of life, 10030).

### 4.2 Fleet-driven priority (2026-07)

The operator's plugin scan (1 473 critical-unauth installs across 495 sites)
produced a ranked worklist (R1–R9). Net-new detectors from it: R6 LiteSpeed
(10004), R1 W3TC (10006), R7 Post SMTP (10007), R4 Fusion Builder (10008).
R3 (upload) and R5 (`wp-config` traversal) are covered by the generic rules
401 / 101.

- **R2 (object injection) → rule 329** (`rule_php_object_injection`,
  `WAF_RCE`, armed block), not a `10xxx` rule: it is a vulnerability class,
  not one CVE. Rather than promote the broad rule 306 (`WAF_SERIALIZE`,
  `challenge_v2`, args only), which would ban legitimate authenticated
  serialized blobs (WooCommerce / Elementor / WPML), 329 is unauth-gated and
  reads an `O:N:"…"`/`C:N:"…"` marker in args or body (base64 included).
- **R8 (JetEngine SQLi) → skipped.** Rule 301 (`WAF_SQLI`, armed block)
  already catches the keyword markers; JetEngine's keyword-less operator /
  blind SQLi cannot be signatured without FPing legit filter traffic. The fix
  is upgrading JetEngine.

### 4.3 Behavioural virtual-patch is a valid `WAF_CVE` flavour

Rule 10005 keys on known-malicious request shapes, not on a version, so it
protects every install on the fleet. Use this pattern when a plugin has a long
history of the same abused endpoints and a version-specific match would
under-protect. Gate any leg whose action is also legitimate for an admin on
UNAUTH (no `wordpress_logged_in_*` cookie) — a forgeable FP filter, not a
security control.

---

## 5. Backlog

Candidates without a validated exact request shape. **None has a rule.** CVE
ids are as recorded in the original ACSC shortlist; confirm each against a
primary source (§7 step 0) before writing anything.

| Product | CVE | Note |
|---|---|---|
| WavePlayer (WP) | CVE-2025-12057 | exact endpoint/action/payload needed |
| BerqWP (WP) | CVE-2025-7443 | exact endpoint/action/payload needed |
| WPBookit (WP) | CVE-2025-7852 | exact endpoint/action/payload needed |
| ThemeREX Addons (WP) | CVE-2026-1969 | exact vulnerable action needed |
| Breeze Cache (WP) | CVE-2026-3844 | cache/admin endpoints: careful FP review |
| pay-uz (WP) | CVE-2026-31843 | exact exploit route needed |
| ACF Extended (WP) | CVE-2025-13486 | ACF admin traffic is common |
| Sneeit Framework (WP) | CVE-2025-6389 | exact framework endpoint needed |
| WPvivid Backup (WP) | CVE-2026-1357 | backup/restore endpoints: high FP risk |
| Gravity Forms (WP) | CVE-2025-12352 | form submissions are common: exploit-specific payload needed |
| GutenKit / Hunk Companion (WP) | likely CVE-2024-9234 | CVE mapping unconfirmed |
| Fabrik (Joomla) `ajax_calc` | CVE-2026-66915 | fixed with 10029's CVE in 4.7.2; no PoC yet |

Ranking: prefer KEV-listed / unauthenticated / RCE-upload-authbypass-SQLi /
public-PoC CVEs in software the fleet actually runs (the vulnerable-code list
in `docs/imunify360-gap-analysis.md` G4 is the exposure source). An
authenticated-admin-only issue or one with no stable request fingerprint is
not a WAF rule.

---

## 6. Design decisions (do not reopen without new evidence)

- **Internal ids are not CVE numbers.** One rule can cover several CVEs
  (10001, 10006, 10030) and one CVE can need several rules with different FP
  risk (10018/10019/10020, 10025/10026, 10027/10028); CVE suffix lengths vary;
  CVEs are external taxonomy, ids are an internal compatibility contract.
- **One `WAF_CVE` family**, not a `WAF_CMS_CVE` split. FP risk is handled per
  rule (`HoldAutoblock` / `RULE_<id>`), not by splitting families.
- **Arm the family, hold the doubtful rule.** The original plan said the
  opposite (family `CVE = 0`, opt in per CVE); it was reversed because an
  un-armed family notifies nothing (§1.4). Do not un-arm `WAF_CVE` for one
  rule.
- **Passive reconnaissance never blocks:** `GET …/plugins/<slug>/`,
  `readme.txt`, `/administrator/components/…`, `/vendor/…`, a login page, a
  bare `admin-ajax.php`, a generic multipart upload. A plugin slug is at most
  one constraint among several.
- **Rollout ladder** `logonly` → `challenge` → `block`. Direct-to-block only
  for an exact exploit shape with near-zero legitimate use (exact unauth
  endpoint + action, an upload of PHP to an exact endpoint, an exact
  injection payload on the vulnerable route, a header with no legitimate
  client use). Every rule in §2 ships at block on that basis, most after a
  fleet read (10031–10033 after a 7-day logonly burn-in).
- **Not built** (proposed in the original plan, no current need):
  per-rule CVE metadata on `WAFRule` (`CVEs`, `Product`, `ExploitClass`),
  `CVE_<year>_<suffix>` aliases in `[waf_security]`, and top-CVE summaries in
  `cfm webtop waf`. The reason string (§1.2) is the CVE carrier today.

---

## 7. "CVE hunting" — adding a new CVE detector

Every step is required.

### Step 0 — Get the *exact* exploit shape (never from memory)

The assistant's knowledge cutoff predates most target CVEs. **Do not invent
signatures.** Get the request shape from a primary source, in rough order of
confidence:

1. A **public PoC / exploit script** — read the HTTP request it builds:
   method, path, field names, marker payload.
2. The **vendor patch / diff** — the vulnerable endpoint and the input that
   reaches the sink.
3. **NVD → references**, followed to the advisory / PoC.
4. **Operator-supplied** PoC, capture, or edge / `cfm.waf.log` samples of the
   real attack.

Pin the **method**, the **endpoint** (prefer a product-unique path segment)
and a **marker** only the exploit carries. A parameter *name* legitimate
traffic also sends is not exact enough: keep it `logonly` or don't ship it.
Before shipping, read the fleet's edge logs for the marker (CFM MCP
`edge_error_tail` / `cfm_log_tail`, `node="all"`): the fleet reads in §2.1
are what justified block.

### Step 1 — Pick the id

Next free id (`10034` today). Never reuse `10015`. An id `>= 10100` needs a
`wafRuleGroupNames` entry first (§1.1).

### Step 2 — Lua detector (`configs/lua/cfm_waf_detectors.lua`)

Write `_M.detect_cve_<slug>(…)` taking what it needs (most take
`uri, method, args, body, headers`; cookie- or header-only rules take less)
and returning a `<TAG>` on a hit, `nil` otherwise.

- Gate on method and the exact endpoint first (cheap, and the main FP guard).
- **A rule keyed on a request field reads it through `php_request_fields`**,
  never a hand-rolled split: a field the edge reads differently from PHP is a
  bypass. Change that reader only with
  `scripts/tests/php_request_fields_oracle.py check` passing against a real
  PHP.
- **Reuse hardened helpers** (`_M.detect_upload_content`,
  `has_php_short_echo`, the rule-401 filename matcher) instead of re-rolling
  body scans; a naive `<?php` substring on a raw body is a known FP source.
- `cap(…, CFG.max_scan_len)` before lowercasing large bodies; `%f[%W]`
  frontier patterns for extension matches. Must parse under LuaJIT
  (`make lua`).

### Step 3 — Wire the check site (`configs/lua/cfm_waf.lua`)

Add the `CFG` default (with a comment carrying the CVE, source and why that
mode), the `RULE_IDS` entry, and a `check()` call site:

```lua
-- CFG
rule_cve_<slug> = "block",   -- CVE-…: source, keyed on …, why block

-- RULE_IDS
rule_cve_<slug> = 10031,

-- check()  (first block hit wins via `goto done`)
do
  local mode = rule_mode(CFG.rule_cve_<slug>, "block")
  if mode ~= "disabled" and body_inspect_ok then
    local tag = det.detect_cve_<slug>(uri, m_lower, args, body, headers)
    if tag then
      local ttl = (mode == "block") and CFG.block_ttl_sec or CFG.default_ttl_sec
      if record("WAF_CVE:CVE_<year>_<suffix>:<PRODUCT>:" .. tag, ttl, mode, RULE_IDS.rule_cve_<slug>) then goto done end
    end
  end
end
```

(`body_inspect_ok` is "POST with a non-empty body"; drop it for a rule that
reads headers, cookies or the query, or that must see PUT/PATCH.) Placement:

- an upload/RCE CVE goes before the generic upload rules (401/402/414) so the
  hit is attributed to the CVE;
- a rule whose ban is held goes late, with the other held rules (§1.4);
- a rule whose exploit is a large or chunked body joins
  `BURNIN_ENFORCE_IDS` in `configs/lua/cfm.lua` and runs in step 0 (§1.5).

### Step 4 — Go registry mirror (`internal/webdetector/waf_rule_ids.go`)

```go
{ID: 10031, Name: "rule_cve_<slug>", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
```

`DefaultMode` must equal the Lua `CFG` default
(`TestWAFRuleIDs_DefaultModeLuaParity`); a later promotion edits both.

### Step 5 — Decide autoblock intent in the same change

`WAF_CVE` is armed, so a new block rule bans the moment it lands.

- **Exact shape, no legitimate sender** → leave it armed (the common case).
- **Right to 403, but a ban could land on a legitimate user** → set
  `HoldAutoblock: true` on its Go entry, note it in the `[waf_security]`
  block of `configs/detectors.conf` (`RULE_<id> = 1` arms it), and place its
  check site late.
- Never un-arm the family for one rule.

### Step 6 — Tests

- **Lua** (`scripts/tests/cfm_waf_cve_<slug>_test.lua`): a positive per
  exploit leg / `<TAG>`, and negatives — wrong method, wrong endpoint,
  near-miss values, passive probes, legitimate traffic to the same product.
  Add an `_e2e_test.lua` through cfm.lua for a burn-in rule. `make test-lua`.
- **Go**: `go test ./internal/webdetector/ ./internal/detectors/...`
  (`TestWAFRuleIDs_LuaParity`, `TestWAFRuleIDs_DefaultModeLuaParity`,
  `TestWAFRuleIDs_GroupingDigits`, `TestWAFSecurityFamilyCoverage`, which
  needs no change: `WAF_CVE` stays armed).

### Step 7 — Notification

Nothing to write: `cveFromReason` names the alert `WAF/CVE-YYYY-NNNN` from a
`WAF_CVE:CVE_<year>_<suffix>:…` reason. A reason without that segment alerts
as plain `WAF/CVE`.

### Step 8 — Docs & changelog

- Add the rule to the §2 table and a note to §2.1 here; drop it from §5.
- `CHANGELOG.md` `[Unreleased]` → Added (operator-facing).
- If it is block-tier, check its panel-port behaviour (§1.4) and follow
  `docs/challenge-waf-release-checklist.md` for the edge reload gate.

### Safety checklist (every new CVE rule)

- [ ] Exact method **and** endpoint constraints.
- [ ] Exploit-specific marker (not a field name legitimate traffic shares);
      request fields read through `php_request_fields`.
- [ ] Passive version/plugin probes and legitimate product traffic are
      negative tests.
- [ ] Default edge mode justified in the `CFG` comment; Lua `CFG` = Go
      `DefaultMode`.
- [ ] Id stable, next free in the band; Go mirrors Lua.
- [ ] Reason is `WAF_CVE:CVE_YYYY_NNNN:PRODUCT:TAG`.
- [ ] Autoblock explicit: armed, or `HoldAutoblock` + late placement.
- [ ] Burn-in body rule listed in `BURNIN_ENFORCE_IDS` and run first.
- [ ] `make lua`, `make test-lua`, `go test ./internal/...` pass.
- [ ] PoC / patch / capture source recorded in the `CFG` comment and §2.1;
      **no signature written from memory**.
