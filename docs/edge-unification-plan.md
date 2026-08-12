# Edge Unification Plan — one enforcement path, one clearance model

Status: **Phases 0–1 landed** (Phase 0: PR #1223 · 1a: #1224 · 1b: #1225 · 1c: #1226) · **Phase 2 in progress** (2a cookie isolation: #1227 · 2b panel tls-fp stamp: #1228 · 2d shared decision module + panel LOGONLY bridge decision: this PR) · Owner: operator + assistant
Date: 2026-08-11 · Origin: the orion challenge-loop incident (PR #1220/#1221/#1222)

---

## 1. Why this exists

On 2026-08-11 an endless "Checking your browser" loop on orion was root-caused to
**dual-path residue**: the `/verify` solve handler called the firewall backend's
`RemoveChallenge` (a DNAT-mode release) even in edge mode, before setting the
clearance cookie; a wedged nftlib netlink connection turned that no-op call into
a hang, and the cookie was never set (fixed in `f424af0` + `b2025b3`).

The bug class is architectural: CFM still carries **two challenge enforcement
paths** (in-path edge Lua vs nft-DNAT redirect) and **two panel policies**
(`cfm.lua` vs `cfm_panel.lua`), even though every production node has run
`OPENRESTY_MODE = 1` (full edge) for a long time. Dual paths drift; drift bites.
This plan retires the dead path and unifies the live ones.

Two full-surface scans ground this document:
- **Go-side scan**: OPENRESTY_MODE plumbing, challenge-DNAT machinery, `cfm dnat`
  semantics, dead-code inventory (summarised in §3/§7; file:line preserved there).
- **Edge-side scan**: openresty/angie configs, all `configs/lua/*` roles, panel
  listener architecture, cert/SNI mechanism, unification risk register (§4/§8).

---

## 2. Terminology — the two DNATs (do not confuse them)

| | What it is | Verdict |
|---|---|---|
| **Edge DNAT** (`cfm dnat on/off`) | Unconditional `:80/:443 → :9080/:9043` — how ALL web traffic enters the Angie/OpenResty edge. No source set involved (`dnatUnscopedWantedSpecs` has `sourceSet=""`). | **KEEP.** This *is* edge mode's traffic feed. |
| **Panel DNAT** (`cfm dnat cpanel on/off`) | `2082→12082 … 2222→12222` — puts cPanel/WHM/webmail/DA ports behind CFM's own panel listeners (`cfm-panel-listeners.conf.in`). `chain-imunify` only affects table priority selection; targets are always CFM's 1xxxx listeners. | **KEEP.** This is the existing panel fronting. |
| **Challenge DNAT** (`challenge_v4/v6` sets + `EnsureChallengeRedirect` + `challenge_guard` chain + daemon TLS interception on 9099) | Legacy per-IP enforcement: flagged IPs redirected to the daemon's own challenge listener. | **RETIRE.** Dead in edge mode; self-disabled at startup; nothing populates the sets. |

The `cfm dnat` CLI, intent persistence, failsafe/restore, and both bypass lists
(`cfm.dnat_bypass`, `cfm.dnat_cpanel_bypass`) all belong to the first two rows
and are untouched by this plan.

---

## 3. As-built findings (Go side)

### 3.1 OPENRESTY_MODE
- Parsed ad-hoc from `detectors.conf` in **four** places: the webdetector
  register (`webdetector_register.go:714`), `cfm status` bridge panel
  (`status.go:826`), edge diagnostics (`diagnostics/edge/probe.go:153`), and
  `cfm firewall-status` (`cli/firewall_status.go:412`). No central config
  registration.
- Shipped default is already `1` (`configs/detectors.conf:1466`); every fleet
  node runs `1`.
- `=1` branches: build NginxBridge + decision socket; disable pre-auth login
  challenge; force `SetChallengeRedirectEnabled(false)` + cleanup (twice:
  startup and the 10-min ensure tick); wire the challenge server to the bridge.
- `=0` branches are therefore **unexecuted anywhere** — untested code that still
  partially runs (the incident).

### 3.2 challenge_v4/v6 — provably dead in edge mode
- Only two writers exist: the autoblock sink (guarded `nginxBridge == nil`) and
  the pre-auth login enforcer (disabled in edge mode). **In edge mode nothing
  ever adds to the sets.**
- The nft backend only creates the sets when challenge-DNAT is enabled; nftlib
  creates them unconditionally (asymmetry).
- `challengeOKer` (`AddChallengeOK`/`RemoveChallengeOK`) has **no implementor**
  in either backend — already-dead interface.
- The daemon's TLS-interception listener (`CHALLENGE_HTTPS_LISTEN` = 9099, with
  its own `GetCertificate` hook) exists only for this path; the edge always
  proxies plain HTTP to 9098. It is also the source of the `tls_fp=-` blind
  spot on the legacy path.

### 3.3 Reporting mislabel (fixed in Phase 0)
`cfm firewall-status` derived `dnat_challenge` from "any `CHALLENGE_*=1` line"
AND `DNATStatus("inet","cfm")` — so an edge node reports `dnat_challenge=true`
purely because edge rules exist, while the daemon has explicitly disabled and
cleaned up challenge-DNAT.

---

## 4. As-built findings (edge side)

### 4.1 Panel fronting already exists and ships
`cfm-panel-listeners.conf.in` implements all seven ports with the hard parts
solved: SNI certs via the same `sslcollector.set_cert()` used on :9043;
websockets (`map $http_upgrade` + `Upgrade`/`Connection` on proxy locations);
the `/acctxfer(rsync|dsync)` **raw tunnel** (`cfm_panel_tunnel.lua`) for WHM
transfer streams; 24h timeouts + unbuffered bodies on `/acctxfer`,
`/cgi/transfer`, `/cgi/live_tail_log`; the 2083→2087 `xfercpanel` redirect
hop; the 497 friendly page; HTTP/1.1-only (websocket-compatible); trusted
`X-CFM-Panel-Port`/`X-Forwarded-Port` injection for panel-scoped clearance.

**Conclusion: "Option B" is not "build fronting" — it is "unify the panel
listeners' reduced policy with the full pipeline, then delete the dead path."**

### 4.2 The real gap: `cfm_panel.lua` is a reduced guard
- **No bridge decision**: `/__cfm_panel_decide` is declared in the config but
  never subrequested; the panel decision is purely local (human-entry URI +
  browser-like UA + clearance state). Per-IP/vhost/traffic-rule enforcement
  does not apply on panel ports.
- **No WAF** on panel ports (deliberate historically, but total).
- **No TLS-fingerprint stamping** on the panel `/__cfm_verify` (the
  `access_by_lua_block { return; }` skips `cfm_tlsfp`), hence 100% `tls_fp=-`
  for `scope=panel:*` in the audit.

### 4.3 Drift between the two Lua policies (Phase 0 targets)
| Drift | Where |
|---|---|
| Panel-host prefix lists diverge: `cfm.lua` has `cpanel/webmail/whm/mail`, `cfm_panel.lua` has `cpanel/whm/webmail/webdisk` | `cfm.lua` Step 0 vs `cfm_panel.lua has_panel_prefix` |
| Clearance-cookie TTL diverges three ways: Go mints `CHALLENGE_COOKIE_LIFE` (→`CHALLENGE_COOLDOWN`→60m floor); web Lua re-mints with `CFM_OK_TTL_SEC`-or-3600; panel Lua re-mints with a hardcoded 45m/2700 (its `$cfm_challenge_cookie_life` var is set by no config) | `challenge_server.go cookieTTL`, `cfm.lua CFG.ok_ttl_sec`, `cfm_panel.lua refresh_clearance_cookie` |
| `ngx.shared.cfm_panel_state` referenced but the dict is declared in no config → `trace_verify_success` is dead observability | `cfm_panel.lua` vs `openresty.conf`/`angie.conf` shdicts |
| `$cfm_panel_fail_mode` set in every listener block, read by nothing (real policy is the `CFM_PANEL_FAIL_OPEN` env) | `cfm-panel-listeners.conf.in` (7 blocks) |
| `dnat_challenge` status mislabel (see §3.3) | `cli/firewall_status.go` |

### 4.4 Why "just run cfm.lua on :2083" is wrong (unification must be by shared modules)
Twelve concrete breakages were catalogued; the load-bearing ones:
`origin_pass_for()` would proxy panel traffic to Apache instead of cpsrvd;
`clearance_scope` is hardcoded `"web"` (→ permanent `scope_mismatch` loop
against Go's `panel:<port>` mint); the web servers' `proxy_hide_header Upgrade`
kills panel websockets; WAF body buffering + POST-resume break 24h binary
transfer streams; the `$cfm_bypass_ip` geo bypass would become an
unauthenticated panel bypass; and **cookie clobber** — one `cfm_clearance`
cookie name on `Path=/` while browsers do not isolate cookies by port, so
web-scope and panel-scope tokens overwrite each other (the panel loop-breaker
currently masks this).

---

## 5. Decision

1. **Edge mode becomes the only mode.** `OPENRESTY_MODE` is deprecated
   (accepted-and-ignored with a warning when set to `0`), then removed.
2. **Challenge-DNAT machinery is deleted** (both backends), per the §7
   inventory.
3. **Panel listeners converge on the full pipeline via shared Lua modules**
   (bridge decision with `scope=panel:<port>`, reduced WAF, TLS-fp stamping,
   per-scope cookie isolation) — *not* by pointing them at `cfm.lua`.
4. **Edge DNAT and Panel DNAT (CLI, failsafe, bypasses) are untouched.** The
   emergency lever remains `cfm dnat [cpanel] off` (direct-to-origin, no
   pre-auth challenge) — there is no DNAT-challenge "fallback" to preserve,
   and keeping one would recreate the drift this plan removes.

---

## 6. Phases

### Phase 0 — drift fixes (landed, PR #1223; no behavior change beyond the noted nits)
1. **Shared panel-prefix module** `configs/lua/cfm_panel_hosts.lua` — canonical
   prefix set `{cpanel, whm, webmail, webdisk, mail}`; both `cfm.lua` and
   `cfm_panel.lua` consume it (pcall-require with their previous inline lists
   as fallback for deploy lag). Behavior notes: `cfm.lua`'s Step 0 gains
   `webdisk.` in panel-likeness (that bypass additionally requires the explicit
   trusted-bypass vars, so the widening is gated); `cfm_panel.lua` gains
   `mail.` (a no-op today — `is_human_panel_entry` ends `return true`).
2. **Publish the authoritative clearance-cookie TTL** to the edge:
   `cfm_bridge_config.lua` gains `cookie_life_sec` (resolved by the same
   `CHALLENGE_COOKIE_LIFE`→`CHALLENGE_COOLDOWN`→60m chain the challenge server
   uses, via one shared resolver — no second copy). `cfm.lua` and
   `cfm_panel.lua` prefer it for re-mint/refresh; previous fallbacks (3600 /
   2700) remain for upgrade lag only. This stops Lua re-mints from silently
   extending or shortening the operator-configured clearance lifetime.
3. **Declare `lua_shared_dict cfm_panel_state 1m`** in both engine configs —
   makes the existing panel verify-trace functional (it is exactly the debug
   instrument yesterday's incident needed).
4. **Remove the dead `$cfm_panel_fail_mode`** from the listener template
   (7 blocks). The challenge-mode rewrite regex matches only the
   `$cfm_panel_challenge_mode` statement, so in-place rewrites are unaffected.
5. **Fix the `dnat_challenge` status flag**: false when OPENRESTY_MODE is on
   (the daemon has disabled and cleaned up challenge-DNAT).

Gates: `make lua`, `make test-lua`, `check_cfm_clearance_require.sh`,
`go build/vet/test -race`, panel-listener config tests, logrotate/CLI-transport
guards. Deploy note: pure package upgrade; no config migration.

### Phase 1 — retire challenge-DNAT + the mode toggle (landed: 1a #1224, 1b #1225, 1c closes it)
- **PR 1a** (landed, #1224): make edge mode unconditional in the webdetector register (drop the
  `=0` branches, always wire the bridge); delete the pre-auth login-challenge
  enforcer path; deprecate `OPENRESTY_MODE` (parse, warn if `0`, ignore).
- **PR 1b** (landed, #1225): delete backend machinery per §7 — both backends' `AddChallenge` /
  `RemoveChallenge` / `SetChallengeRedirectEnabled` / `ChallengeRedirectEnabled`
  / `CleanupChallengeRedirect` / `EnsureChallengeRedirect`, the `challenge_guard`
  chain, the sets, the 9099 TLS listener + `CHALLENGE_HTTPS_LISTEN`, the
  `challengeRedirector`/`challengeOKer` interfaces, and `releaseSolvedIP`'s DNAT
  arm. **Pre-req check**: `dnatWantedSpecs` bundles `self_v4/self_v6` redirect
  specs into the challenge namespace — verify whether the self-IP redirects are
  load-bearing before wholesale namespace deletion, and rehome them if so.
- **PR 1c** (this PR): reporting/docs sweep — `printChallengeStatus`, firewall-status
  challenge probes, `setinventory`/`ipquery` rows, README §challenge,
  `docs/roadmaps/firewall_backend.md`. (The `challenge/list` endpoint +
  `challenge_ip_status` MCP tool retirement and the
  `endpoint_scope_inventory.md`/`MCP.md` updates, originally slated here,
  landed early with 1b.)

### Phase 2 — panel unification (the substance of "Option B")
- Extract the shared pipeline pieces `cfm.lua` and `cfm_panel.lua` both need
  (decision RPC, clearance refresh, tlsfp stamp) into modules; keep per-surface
  policy (origins, skip-lists, timeouts) in each entrypoint.
- **Bridge decision on panel ports** with `scope=panel:<port>` — **LOGONLY
  landed (PR 2d)**. The decision-RPC client is extracted to `cfm_decision.lua`
  (commit 1, zero web behaviour change) and `cfm_panel.lua` now consults
  `/nginx/decision` on human-entry with `scope=panel:<port>` and fires
  `/nginx/ok/touch` after a valid clearance (commit 2). It **records** what the
  bridge would do (`[cfm_panel_decision] logonly=would_enforce …`) but does
  **not** act on the verdict — the clearance-cookie challenge is unchanged, so
  there is zero panel-lockout risk while FP data is gathered. Everything is
  `pcall`'d + fail-open; the kill switch `CFM_PANEL_DECISION=0` (or a missing
  module on upgrade lag) disables the probe entirely. The Go bridge already
  accepts/stores panel scopes end-to-end (`okState` keyed by `(ip,host,scope)`).
  Enforcement (acting on the verdict) is a later opt-in phase after burn-in.
- **Reduced WAF on panel**: run on human-entry + generic paths; hard-skip the
  `is_panel_api_or_sso` allowlist, `/acctxfer*`, `/cgi/transfer`,
  `/cgi/live_tail_log`, `/cpsess…/websocket/`. No body buffering on streams;
  no POST-resume on panel.
- **TLS-fp stamping** on panel `/__cfm_verify` — **landed (PR 2b)**: the bare
  `access_by_lua_block { return; }` is replaced with the same clear-then-
  `cfm_tlsfp.stamp()` the web `/__cfm_verify` runs, so panel solves carry a
  fingerprint instead of `tls_fp=-`. Verify-only, matching the web edge — the
  `/__cfm_challenge` location records no solve, so it stays bare (stamping it
  would be dead work and would diverge from web). The plain-HTTP panel ports
  (2082/2086/2095) still resolve to no fingerprint, correctly: no TLS
  handshake to summarise.
- **Cookie isolation per scope** (Go + Lua together) — **landed (PR 2a)**:
  per-scope cookie name (`cfm_clearance` for web, `cfm_clearance_p<port>` for
  panel) so web/panel tokens stop clobbering each other. The panel accepts a
  panel-scoped token under the legacy shared name (upgrade lag) and migrates
  it to the scoped name on refresh; the loop-breaker is deliberately RETAINED
  as the safety net for the upgrade window and drops only after burn-in
  (Phase 2 cleanup, together with the legacy-name fallback and the inert
  shared-name `cfm_ok` marker — no Lua reads it anymore). Test the
  cPanel-plugin iframe cross-port flow (WHM :2087 iframing `/cfm-admin` on
  :443) under the new scheme.
- Never touch: acctxfer tunnel ordering (test-locked), DA-no-tunnel invariant,
  websocket headers, fixed `X-Forwarded-For` literals (no
  `$proxy_add_x_forwarded_for` on panel — client must not seed the chain).

### Phase 3 — burn-in + fleet
orion first (it has the MCP tooling), one release of burn-in for Phase 1+2,
then fleet. After burn-in: delete `cfm_panel.lua`'s superseded local policy and
the deprecated `OPENRESTY_MODE` key entirely; stamp CHANGELOG accordingly.

---

## 7. Retirement inventory (Phase 1 target; from the Go-side scan)

**Interfaces/impls**: `firewall.Backend.{AddChallenge,RemoveChallenge,
SetChallengeRedirectEnabled,CleanupChallengeRedirect,EnsureChallengeRedirect}`;
nft `nft.go` (constants `challengeV4/V6/challengeNatChain`, `challengeDNATEnabled`,
`EnsureChallengeRedirect` + `challenge_guard`, set creation branch in
`EnsureBase`, `SetChallengeDNATEnabled`/`CleanupChallengeDNAT` aliases); nftlib
(`setChalV4/V6`, `challengeRedirectEnabled`, `dnatOnScoped`, challenge namespace
constants + the `sourceSet` arm of the DNAT rule builder, set declarations in
`lifecycle.go`, `sets.go AddChallenge/RemoveChallenge`).

**Webdetector/detectors**: `ensureChallengeRedirect` + both call sites;
`SetChallengeRedirectEnabled(false)` blocks; pre-auth login enforcer
(`apiserver/login_challenge.go` path) + `SetPreAuthLoginChallengeEnabled`
plumbing; challenge server 9099 HTTPS listener + `maybeListenV6LoopbackFromV4Loopback`
+ `s.ssl`/`GetCertificate`; `challengeRedirector`/`challengeOKer` interfaces;
`releaseSolvedIP` DNAT arm; autoblock sink `else` arm.

**Config**: `CHALLENGE_HTTPS_LISTEN` (dead). `CHALLENGE_HTTP_LISTEN` **stays**
(it is the edge's `cfm_challenge` upstream) but loses its "is challenge
configured at all" double duty.

**Reporting**: `status.go printChallengeStatus`; `firewall_status.go` challenge
set probes / `challenge_runtime_mode` / `challengeRedirectConfigured`;
`setinventory` rows + `challenge_ips` alias; `ipquery/find.go` classification;
`apiserver/challenge_list_endpoint.go` + MCP `challenge_ip_status`; diag names.

**Survives regardless** (explicitly): all of §2's KEEP rows — edge DNAT +
panel DNAT CLI/machinery/bypasses/failsafe/restore, `EnsureDNATAccepts`,
challenge server on 9098 + token/abuse/access-log, NginxBridge + its config
keys, sslcollector (panel listeners + apiserver TLS still use it), manual
vhost-challenge API, all block/allow/ignore/feed sets.

**Known caveat**: rehome the `self_v4/self_v6` DNAT specs out of the challenge
namespace before deleting it (verify first whether they are load-bearing).

---

## 8. Risk register (carried into Phases 1–2)

| Risk | Mitigation |
|---|---|
| Cookie clobber web↔panel (until Phase 2's per-scope names) | Known-masked by panel loop-breaker; Phase 2 removes the cause, then the mask |
| Deleting challenge namespace also deletes `self_v4/v6` specs | Explicit pre-check + rehoming in PR 1b |
| WAF on panel ports = new FP surface | Reduced profile + `is_panel_api_or_sso` skip-list; `logonly` first per WAF discipline |
| Bridge RPC latency (300ms cap) added to panel human-entry | Only on human-entry paths; decision cache (90s clean-allow) applies |
| Plugin iframe cross-port clearance interplay | Dedicated test in Phase 2 before fleet |
| Upgrade lag (new Lua, old daemon or vice versa) | All new bridge-config fields optional with safe fallbacks; pcall-require with inline fallbacks for new modules |
| Imunify priority collision on panel DNAT | Untouched by this plan (priority selection logic stays) |

---

## 9. Verification per phase

- **Phase 0**: gates green; on a deployed node — panel solve still works
  (`webmail.<host>` full flow), `lua-stats` shows `cfm_panel_state`, panel
  re-mint Max-Age now follows `CHALLENGE_COOKIE_LIFE`, `cfm firewall-status`
  shows `dnat_challenge=false` on edge nodes.
- **Phase 1**: `nft list table inet cfm` has no `challenge_v4/v6`, no
  `challenge_guard`; grep proves no `OPENRESTY_MODE` branch remains; solve
  flow unchanged; `firewall_selftest` clean.
- **Phase 2**: panel port challenge honors bridge per-IP decisions; tls_fp
  populated for `scope=panel:*`; web↔panel navigation does not re-challenge;
  WHM transfer + Terminal + live-tail all pass under the fronted ports.
