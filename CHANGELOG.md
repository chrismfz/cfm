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

### Security
- WAF: **promoted the encoded-`<?php` backdoor opener (rule 437,
  `WAF_BACKDOOR:*_PHP_OPENER`) `challenge` → `block`** after a second clean
  6-server FP review (2026-07). Two independent 0-FP reviews now agree: the
  2026-06-25 five-server sweep (Bricks RCE / Amasty upload real attacks) and a
  2026-07 six-server sweep (16/16 base64 `<?php` POSTed to `/xmlrpc.php`,
  botnet-distributed across 16 countries). The FP-prone weak `<?=` variant was
  already removed from the detector and legit snippet plugins (WPCode etc.) are
  carved out via the `/wp-admin/` suppression, so a non-`/wp-admin` encoded
  `<?php` body — which is never legitimate — is now 403'd in-path. Also fixes a
  stale `DefaultMode` in `waf_rule_ids.go` (437 read `logonly` while the live
  Lua CFG had been `challenge` since 2026-06-25). Operators who pinned this in
  `/etc/cfm/*` keep their setting; only the shipped default changes.
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
