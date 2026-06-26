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
