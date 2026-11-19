# CFM Roadmap

A single index of **where CFM is going**: what is open, in priority order
within each area. This file is a map, not a spec. Each item points at the doc
or PR that owns the detail, so this page never becomes a second copy that
drifts (CLAUDE.md §5). **When an item lands, delete it here** (the CHANGELOG
records it). Done items are not kept "for the record".

Tags: **[next]** queued and scoped · **[track]** larger effort, not yet broken
into PRs · **[idea]** not committed to · **[decided]** a standing "no", kept so
it is not reopened without new evidence. Discipline for everything here:
build → adversarial review until clean → PR → merge → next (small
single-concern PRs).

Last full review: 2026-11-18.

---

## 1. WAF tuning & coverage

Behaviour + FP runbooks: **`docs/waf.md`**, `docs/challenge-waf-release-checklist.md`.
WAF→autoblock: `docs/waf-autoblock-design.md`. CVE rules: **`WAF_CVE.md`**
(as-built, backlog, "CVE hunting" recipe). Pre-merge numbers: `make waf-corpus` (BlazeHTTP).

- **WAF false-positive tuning** — [track, never "done"]. Against real apps
  (Joomla K2/elFinder, `/.well-known/`, WP migration/backup imports). Promote
  `logonly` → `challenge` → `block`; operator-side rule-scoped excludes over
  code carve-outs.
- **WAF CVE detectors (`WAF_CVE`)** — [track]. Per-CVE rules in the `10000+`
  band. Never write a signature from memory.
- **libinjection SQLi / XSS tokenizer** — [decided] not adopted
  (2026-11-18). Run over ~8 days of query strings on all 8 nodes it caught
  ~200 attacks CFM let through, and would have broken ~170 legitimate
  requests (Jetpack, WooCommerce filters, search boxes). The attacks fell
  into a few shapes, now rules 301 / 332 (`docs/waf.md` "SQLi gaps,
  2026-11-18"). A shape that passes gets its own measured rule.
- **Decoding / normalization transforms** — [next]. `cmdLine`-style
  normalization for the RCE rules, unicode / fullwidth folding and
  `normalizePath` in `cfm_waf_util.lua` (today: `url_decode_once` × 2 + lower,
  no unicode normalization). Scope each to the variables it belongs to: the
  strict UTF-8 walker applied to the whole args+body buffer flagged legacy
  ISO-8859-7 Greek forms (`docs/waf.md`). Never as one more pass in the
  shared `normalize()`: that changes the input of every rule, block ones
  included, so it cannot ship `logonly`, and decoding `\uXXXX` / HTML
  entities there turns every JSON body and CMS post into an XSS/SQLi false
  positive (decided 2026-06-27). Each transform goes behind the one rule that
  needs it.
- **Login brute-force signals in the web detector** — [next]. The edge counts
  login *submissions* (rule 501: 8 per IP in 20 s), so a slow or distributed
  attack never trips it (vol2.gr, 2026-11-04: 2 787 failed `wp-login.php`
  posts from 1 121 IPs, none over 5 in 20 s). Phase 0 is built (the `auth`
  column, `auth_corpus` MCP tool); next the detector counts FAILED logins per
  IP across vhosts, per vhost, per /24, and flags a success from an IP that
  failed elsewhere. Design + fleet numbers: `docs/webdetector-signals-v2.md`.
- **Traffic rules: `match.asn_in` / `asn_not_in`** — [next]. Block /
  throttle / challenge a hosting ASN per vhost (the Singapore-datacenter shop
  case); cache-only ASN lookup on the hot path, fail-open on a miss.
  `traffic_rules.go` and `rules-model.js` in the same PR.
  `docs/traffic-rules-ux-proposal.md` §3a.
- **Traffic rules: simulate a draft with a `trace`** — [idea]. Why a rule
  did or did not match, before saving it.
- **cfm-admin WAF / ban UX** — [idea].
  - Hit-rates view: `/api/v1/waf/hit-rates` and its promotion hint
    (`ok_to_promote` / `silent` / `review` / `noisy`) are CLI/API only today.
  - Per-vhost protection presets (low / medium / high) that only WRITE the
    existing knobs (WAF modes, challenge tier, rate rules), never a second
    copy of the settings.
  - Ban evidence: every ban, not only `waf_security`'s, carries the requests
    that caused it in `detection_history`, shown beside the ban.
- **No Coraza / OWASP CRS in-path** — [decided 2026-11-18]. Its anomaly score
  has nothing to bind to (per-rule modes, autoblock families, scoped excludes,
  edge ban), it brings a second exclusion system and CRS's FP load on
  WordPress / Joomla / cPanel, and cPanel origins often run ModSecurity behind
  the edge already (the `modsec` detector reads it). UUSEC WAF, SafeLine and
  BunkerWeb were reviewed the same day: closed engines or CRS itself, so no
  rules to borrow; their usable ideas are the items above.
- **No plain loopback-IP / `DOCUMENT_ROOT`-in-params rule** — [decided
  2026-06-27]. The SSRF forms attackers use (non-http schemes, obfuscated
  IPs) are caught already; plain `127.0.0.1` in a parameter is heavy
  legitimate traffic, and the edge does not know a vhost's `DOCUMENT_ROOT`.
  If the fleet ever runs on cloud VMs, add a sharp `169.254.169.254`-only rule.
- **Payment-webhook IP allowlists (PayPal IPN, Stripe) only on demand** —
  [decided 2026-06-27]. Shipped only after a real gateway-callback false
  positive is seen.
- **WAF: unusual method outside its place** — [idea, low]. CONNECT to a
  non-proxy, PROPFIND / SEARCH to a non-DAV path, folded into
  `rule_exploit_methods` (607), which already covers the common cases.
- **Edge Lua residuals** — [idea, low]. `cfm_purge.lua` `purge_ip` scans the
  whole `cfm_decisions` dict under lock on a force-unblock (perf); `[...]`
  bracket-class globs in excludes match literally in Lua but as a class in Go
  (narrower in-path, so protective).

## 2. Panel enforcement (edge unification follow-up)

Edge unification is done (decisions + open items: `docs/edge-unification-plan.md`): panel
WAF + bridge decision enforce by default (`PANEL_WAF_MODE` /
`PANEL_DECISION_MODE`), the blanket panel challenge is kept on purpose.

- **Watch default-enforce on authenticated panel traffic** — [track,
  operator]. The burn-in behind it was scanner-dominated; per node, drop to
  `logonly` on a false positive.
- **Per-Content-Type body inspection on the panel ports** — [idea].

## 3. MCP telemetry surface

As-built: **`MCP.md`** (node tools) and the cfm-web fleet connector. Node MCP
stays read-only; writes live in cfm-web (blocklist, blackhole, notify) behind
per-ability tokens.

- **More read tools** — [idea]. MySQL governor history reads, analyze-ip /
  analyze-host, SSL collector stats, DNAT state, health time series, traffic
  rules, exclude lists (`MCP.md` §5 lists the endpoints not yet exposed and
  why).
- **Per-tenant scoped MCP tokens** — [idea]. Today `/mcp` is admin-only.
- **Revocable OAuth grants** — [idea]. Would also keep the used-nonce set
  across a restart.

## 4. Mail Monitor

- **MTA-agnostic mail tools** — [next]. Serve mail summaries from a
  detector-published snapshot instead of a per-request exec, so the tools work
  across exim/postfix without shelling out each call.

## 5. Health / observability correctness

- **Wire or drop the remaining `cfm_metrics`** — [next]. `active_blocks` /
  `challenge_queue` / `outbound_alerts` are still structural zeros
  (`internal/healthmodel/collector.go`). Populate them from the firewall block
  list / challenge engine / mail anomaly, or drop them.
- Watch item: any NEW consumer of edge-engine state must use
  `runtime.edge_service`.
- **CPU steal% in the `cpu_throttle` verdict** — [idea]. So the VM case gets a
  concrete answer, not just a pointer.
- **DirectAdmin host→owner in `panelmap`** — [idea]. `/etc/virtual/domainowners`,
  so `db_web_pressure` attribution works off cPanel too.

## 6. Control plane & operator housekeeping

- **Roll `ADMIN_TOKEN_IP_BINDING = enforce` per node** — [next, operator].
  Shipped default `off`; rollout + caveats: `docs/security/control-plane.md` §4.
- **Scoped embed cookie key off `AUTH_TOKEN`** — [next]. The scoped
  `cfm-embed-scope` cookie is still HMAC'd with an HKDF of `AUTH_TOKEN`
  (`embed_bootstrap.go`), so a cfm-web database leak can forge a scoped viewer
  cookie. Give it a random per-node key like the admin one
  (`embed_admin_cookie_key.go`); open cPanel iframe sessions re-login once.
- **Rotate `MCP_TOKEN` + remove `MCPGODEBUG`** — [next, operator].
  Post-rollout hygiene on the live nodes.
- **Retire `internal/apiserver/auth_autoblock.go`** — [next]. Still started
  in `apiserver.go`; the `cfm_endpoints` detector is meant to replace it.
  Remove only after showing the detector bans the same login brute force
  (keep the login throttle / account lock).
- **No CSP / frame policy / HSTS on the admin UI** — [decided 2026-08-25].
  Inline scripts, the cPanel iframe and per-host HSTS; reasons in
  `docs/security/control-plane.md` §7.
- **No PoW challenge in front of the `/cfm-admin/` login** — [decided
  2026-11-18]. `:6061` is nft-gated and `:6060` is loopback, so only the edge
  path is public, and its login already has MFA, the login throttle and the
  rate limiter. A challenge there risks the SSO / token flows. If one is ever
  wanted, a path challenge on `/cfm-admin/login` from cfm-admin does it.
- **Fleet `detectors.conf` fixes** — [next, operator]. Quote typos, missing
  panel `CHALLENGE_VHOST` patterns, `permanent` leniency, dead keys:
  `docs/detectors-config-unification.md` §7.

## 7. Detectors config unification

Design: `docs/detectors-config-unification.md`. Shipped: `srcresolve` (auto
source detection) and `detectors.d` overlays (`detconf` layering).

- **Global `[leniency]` fallback** — [next] (doc §8 PR 6; the persisted tokens
  shipped, `internal/hostsecrets`).
- **Stock `detectors.conf` converged defaults** — [next] (doc §8 PR 7). A
  behaviour change on hosts that inherit defaults: ships alone.
- **Fleet migration** — [track, operator]. Move each node's deltas to an
  overlay; `config_drift` reports a clean base.

## 8. Traffic classifier / abuse defense

**Plan of record: `docs/abuse-defense-master-plan.md`** (the one roadmap +
decision log for challenge / classifier / fingerprint reputation, both repos;
its §5 is the only live to-do list). Progress journal:
`docs/abuse-defense-progress.md`. Design: `docs/traffic-classifier.md`,
`docs/challenge-score.md`, `docs/under-attack-mode.md`,
`cfm-web:docs/fingerprint-reputation.md`. This section is only an index.

## 9. Webshell-drop safety net (cfm-lsm → ClamAV → edge attribution)

Design: `docs/lsm-php-drop-detection.md` (after the 2026-11-12 dmkomotinis.gr
compromise). `CFML-FS-009` watches the PHP tier write a PHP-executable file
under a docroot; the daemon scans that file with ClamAV and ties it to the
edge request so the IP can be banned.

- **P0 count-only** — [next, after the operator answers the doc's §11].
  `panelmap.Docroots()`, the BPF policy (own ringbuf, monitor-only) and the
  `php_drops` MCP aggregates. A fleet count gates every later phase; kernel
  deny is not planned.

## 9a. Site Cache follow-ups

Design + as-built: `docs/site-cache-design.md` (§14 lists every open item);
operating it: `docs/site-cache-runbook.md`.

- **Micro-cache on the clearance fast path** — [idea]. Exclude the edge-set
  `cfm_clearance` cookie from the store check first (design §5.5.1).
- **Per-URL purge** and a per-host purge under an admin wildcard — [idea].
- **`whats_wrong`: "armed but ~0 hits"** — [idea].
- **Durable stats** (history, per-tier split, bytes saved) — [idea].
- **Bypass on `Vary: Cookie`**, static TTL buckets, a per-vhost fill
  budget — [idea].

## 9b. cfm-lsm follow-ups

Reference: `docs/cfm-lsm.md`.

- **Allowlists that gate enforce** — [idea]. BPF-side allow maps keyed on
  the exe inode, so `allow_exe` can exempt in enforce mode for EXEC-006 and
  NET-002 (today the userspace allowlist only filters events).
- **FS-005: an `exe_file` inode check** — [idea]. Replaces the auth-helper
  comm gate, which a process can spoof with `prctl(PR_SET_NAME)`.
- **FS-006 enforce allowlist** — [idea], built from its monitor telemetry.
- **Ringbuf drop counter (or a larger ringbuf)** — [idea]. A full ringbuf
  drops events with no count today.
- **Hot policy reload without detaching** — [idea]. Mode changes go
  through `cfm lsm restart` now.
- **`kernel.modules_disabled` via a late unit in kernsec** — [idea].
- **kernsec `disable` / `rollback` should remove the `bpf` it merged into
  `lsm=`** — [idea]. `UnmergeLSMBPF` exists but nothing calls it; only
  unmerge when kernsec added it (an operator's own `bpf` must stay).

## 9c. Edge IPv6

The edge can listen on IPv6 where the host can and the origin trusts `::1`
(`docs/edge-ipv6.md`); for now only where `EDGE_LISTEN_V6 = on` allows it
(default off until the /64 item below), and the
origin hop brackets the address and binds `::1`.

- **Watch the first real IPv6 traffic through the live edge** — [track].
  The origin hop is verified with a scratch edge on speedhost (OpenResty
  1.31.8.1) and qualityweb (Angie 1.12.4), 2026-11-19: all four origin paths
  reached Apache from `::1` (200), and the old server-level
  `proxy_bind 127.0.0.1` failed as predicted (EINVAL). Not yet seen: an
  external IPv6 client through the DNAT into the live edge with the files
  rendered. A failed hop would be a 502 the browser does not retry on IPv4:
  check `edge_error_tail` for `bind(` / `set_current_peer` on the first nodes
  that turn IPv6 on.
- **A site with a dedicated IPv6 address through the edge** — [track]. The
  hop goes to the IPv6 address the visitor dialled (`[$server_addr]`, the
  DNAT keeps the destination), so a cPanel account with its own IPv6 (its
  vhost bound to that address) should reach its own vhost, as dedicated IPv4
  does today; no fleet site has one, so it is unproven. First real case: the
  operator node that reported the bug (AAAA records to the server). Check
  that the site (not the default vhost) answers over `curl -6`.
- **Per-IP counters and bans by /64, then IPv6 on by default** — [next].
  Every per-IP control keys on the full IPv6 address: nft `connlimit` /
  `pps_v6` / `syn_v6` / `new_v6` meters and `block_v6` bans, waf_security
  autoblock, webdetector scoring, login_bruteforce, 403_flood, challenge rate
  counters. A direct IPv6 client with a /64 (any VPS) gets a new identity per
  request. Behind Cloudflare that did not matter (nft never sees the client,
  Cloudflare absorbs the volume), but with the edge listening on IPv6 direct
  clients reach the nft per-IP layer. Group IPv6 by /64 there (and in the
  edge ban store), then flip `V6_DEFAULT` (scripts/cfm-edge-listen-v6.sh)
  and `edgeIPv6Default` (internal/originrealip) together to auto/true, and
  swap the reference cfm.conf's commented `# EDGE_LISTEN_V6 = on` for
  `# EDGE_LISTEN_V6 = off` (check_edge_listen_v6.sh checks all three).

- **IPv6 on the panel ports** — [open decision]. cpsrvd listens on IPv4
  only on the fleet; the panel listeners stay IPv4.

## 10. PHP runtime defense (CFM-managed Snuffleupagus)

Design: `docs/roadmaps/php-runtime-defense.md`. CFM renders Snuffleupagus
rules, monitor/enforce modes and per-vhost excludes, and never writes its own
PHP extension (decided 2026-11-18: one engine for one purpose). Pairs with §9
at the kernel boundary. `cfm php-inventory` is shipped.

- **P0b per-vhost PHP handler mapping (alt-php vs ea-php)** — [next]. It picks
  the beachhead adapter for P1 (monitor-only, one server).

## 11. Edge-added response headers per vhost

Proposal: `docs/roadmaps/security_headers.md`.

- **Shared-hosting-safe subset** — [idea]. Per vhost, opt-in, add only when
  the origin sent none: `Referrer-Policy`, `nosniff`, strip `X-Powered-By`.
- **No HSTS / CSP / frame policy / COOP-COEP / edge CORS on tenant vhosts** —
  [decided 2026-11-18]. They change how a tenant's site behaves, and HSTS
  cannot be taken back. Reasons in the proposal.

## 12. Other decided items

- **No per-tenant futex-PI seccomp filter (GhostLock, CVE-2026-43499)** —
  [decided 2026-11-18]. It could only apply to bare-metal / custom installs;
  on cPanel / DirectAdmin / CloudLinux tenant confinement is CageFS / LVE's
  job. Patched kernel or KernelCare is the fix; kernsec's
  `randomize_kstack_offset=on` and cfm-lsm `CFML-FS-008` are the shipped
  defence in depth.
- **NGM integration is done on the NGM side** — [decided]. NGM mints scoped
  tokens and admin SSO codes with `AUTH_TOKEN` and proxies `/cfm-admin/`
  itself; no `panelauth` provider or NGM metadata endpoint in CFM. NGM stays
  the TLS front door (2026-11-12), so its panel port is not in CFM's panel
  DNAT map (2026-09-09). As-built: `ngm/docs/cfm-integration-map.md`. CFM
  side: the `ngm_auth` detector (`docs/ngm-auth-detector.md`).

---

_Design docs live under `docs/`; this roadmap only indexes them. See
`CLAUDE.md` §6–§7 for the "where we historically lost the ball" areas and the
per-topic doc pointers._
