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

### Added
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
