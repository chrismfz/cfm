# Edge unification — one enforcement path, one clearance model

The plan this file carried is built: the per-IP challenge-DNAT is retired,
edge mode is the only mode, and the panel listeners run the web edge's
pipeline through shared Lua modules. What stays here are the decisions behind
that shape (so they are not reopened), the rules for the panel ports, and the
items still open. Phase-by-phase history is in git. Section numbers 6 and 10 are kept
because code comments cite them ("§6 Phase N", "§10").

Origin: the orion challenge-loop incident of 2026-08-11. The `/verify` solve
handler still called the firewall backend's DNAT-mode `RemoveChallenge` in
edge mode; a wedged nftlib netlink connection turned that no-op into a hang,
and the clearance cookie was never set. The bug class was two enforcement
paths (edge Lua vs nft DNAT redirect) and two panel policies (`cfm.lua` vs
`cfm_panel.lua`) drifting apart.

---

## 1. The three DNATs (do not confuse them)

| | What it is | Status |
|---|---|---|
| **Edge DNAT** (`cfm dnat on/off`) | Unconditional `:80/:443 → :9080/:9043`, how all web traffic enters the Angie/OpenResty edge (`internal/dnat/status.go:11-12`). | Kept: it is edge mode's traffic feed. |
| **Panel DNAT** (`cfm dnat cpanel on/off`) | `2082→12082 … 2222→12222` (`internal/firewall/panel_dnat.go:12`), putting cPanel/WHM/webmail/DA ports behind CFM's panel listeners (`configs/cfm-panel-listeners.conf.in`). | Kept. |
| **Challenge DNAT** (`challenge_v4/v6` sets, `challenge_guard` chain, the daemon's TLS listener on 9099) | Legacy per-IP enforcement: flagged IPs redirected to the daemon's own challenge listener. | **Retired.** |

The per-IP challenge-DNAT is gone from both backends. All that remains is a
cleanup that sheds leftover state on every `EnsureBase`
(`internal/firewall/nft/nft.go:182-201` `cleanupLegacyChallengeDNAT`;
`internal/firewall/nftlib/lifecycle.go:182-189`). `cfm firewall-status` no
longer publishes a `dnat_challenge` feature (`internal/cli/firewall_status.go:244-247`,
pinned by `firewall_status_test.go:74`). Challenges are served only in-path
by the edge Lua, which proxies plain HTTP to the challenge server on
`127.0.0.1:9098` (`configs/openresty.conf:882`). The edge clearance cookie is
the only clearance model.

---

## 2. Decisions

1. **Edge mode is the only mode.** There is no DNAT-challenge fallback to
   preserve: keeping one would recreate the drift this work removed. The
   emergency lever is `cfm dnat [cpanel] off` (direct to origin, no
   challenge). `OPENRESTY_MODE` is ignored. A live config that still sets it
   to `0` gets a one-line deprecation warning (`internal/detectors/webdetector_register.go:825-832`),
   kept on purpose so operators remove the key. The reference conf no longer
   carries it (`configs/detectors.conf:2249-2252`).
2. **The panel listeners converge on the web pipeline through shared
   modules, never by running `cfm.lua` on the panel ports.** Running
   `cfm.lua` there breaks things:
   - `origin_pass_for()` would proxy panel traffic to Apache instead of cpsrvd.
   - `clearance_scope` is `"web"`, a permanent `scope_mismatch` loop against
     the `panel:<port>` mint.
   - The web servers' `proxy_hide_header Upgrade` kills panel websockets.
   - WAF body buffering and POST-resume break 24 h binary transfer streams.
   - The `$cfm_bypass_ip` geo bypass would become an unauthenticated panel
     bypass.

   The shared modules are `cfm_panel_hosts` (the one panel-prefix list and
   the `is_panel_api_or_sso` matcher), `cfm_decision` (the bridge decision
   client), `cfm_selfip` (self-IP / `IGNORE_NETS` / loopback), `cfm_tlsfp`
   and `cfm_bridge_cfg`. Per-surface policy (origins, skip lists, timeouts)
   stays in each entrypoint.
3. **Clearance cookies are per scope**: `cfm_clearance` for web,
   `cfm_clearance_p<port>` for a panel port (`internal/webdetector/challenge_server.go:2397-2415`,
   mirrored in `configs/lua/cfm_panel.lua:849-858`). Browsers do not isolate
   cookies by port, so one shared name made web and panel tokens overwrite
   each other.
4. **The panel's blanket front-door challenge is kept (operator decision
   2026-08-12).** Every un-cleared browser on a panel human-entry URI is
   challenged once, then rides its per-scope cookie
   (`configs/lua/cfm_panel.lua:1332-1438`). It is an edge bot shield kept for
   defence in depth, not a leftover. The bridge decision adds the per-IP
   **block** tier on top. It does not replace the challenge.
5. **Panel WAF and panel bridge decision enforce the block tier only.**
   - **Challenge-tier hits:** never turned into a panel challenge. A solved
     clearance cookie clears neither the WAF match nor the bridge verdict, so
     the request would re-trip and loop. Non-browser clients would also get
     an unsolvable PoW.
   - **Logonly-tier hits:** observe-only.
   - **A `block` verdict:** a plain 403 with no redirect, so it cannot loop.
     The decision's deny comes before the clearance short-circuit, so an IP
     blocked mid-session is denied even with a valid cookie. This matches the
     web edge, where `cfm.lua`'s block ignores clearance
     (`configs/lua/cfm_panel.lua:1364-1386`).

   Challenge-tier enforcement driven by the bridge verdict is not planned:
   decision 4 already covers un-cleared browsers.
6. **The panel WAF has a reduced profile.** It reads header, URI, args and
   cookies, never the request body, so upload, rsync and websocket streams are
   never buffered. It runs no POST-resume. The `is_panel_api_or_sso` paths
   (`/acctxfer*`, `/cgi/transfer`, `/cgi/live_tail_log`, the websocket and
   JSON API paths) are hard-skipped before it
   (`configs/lua/cfm_panel.lua:1223-1227, 1240-1265, 352-358`).
7. **Panel enforcement is on by default, reversible per node.** The default is
   enforce because the fleet should get panel enforcement without editing
   every node's config. Fail-open keeps that safe: any WAF or bridge error
   falls through to the normal flow, so a fault cannot lock an admin out of
   WHM/cPanel. Only a real block verdict denies. Each mode resolves per request
   in this order:
   1. the env override, `CFM_PANEL_WAF` / `CFM_PANEL_DECISION` (emergency kill
      switch, wins);
   2. `detectors.conf [webdetector] PANEL_WAF_MODE` / `PANEL_DECISION_MODE`
      (`off | logonly | enforce`), published through `cfm_bridge_config.lua`
      so a change reaches the edge in about 10 s with no proxy reload;
   3. the default, `enforce`.

   Code: `configs/lua/cfm_panel.lua:97-128`,
   `internal/detectors/webdetector_bridge_config.go:38-39`,
   `configs/detectors.conf:1603-1604`. To silence one node, set it to
   `logonly` or `off` there.
8. **Never touch on the panel listeners**:
   - the acctxfer raw-tunnel location ordering (test-locked);
   - the DirectAdmin no-tunnel invariant;
   - the websocket `Upgrade` / `Connection` headers;
   - the fixed `X-Forwarded-For $remote_addr` literals. No
     `$proxy_add_x_forwarded_for` on the panel: a client must not seed the
     chain (`configs/cfm-panel-listeners.conf.in:93-95`).

---

## 6. Phases (what each one settled)



### Phase 0
Drift fixes:
- one panel-prefix list `{cpanel, whm, webmail, webdisk, mail}` in
  `configs/lua/cfm_panel_hosts.lua:27`;
- the authoritative clearance-cookie TTL (`CHALLENGE_COOKIE_LIFE` chain)
  published to the edge as `cookie_life_sec` (`configs/lua/cfm_bridge_cfg.lua:77`,
  used by `cfm.lua:185` and `cfm_panel.lua:964-971`);
- `lua_shared_dict cfm_panel_state` declared (`configs/openresty.conf:143`,
  `configs/angie.conf:137`);
- the dead `$cfm_panel_fail_mode` removed.

### Phase 1
Challenge-DNAT and the `OPENRESTY_MODE` toggle retired (§1, decision 1). The
pre-auth login challenge enforcer and the `challenge_ip_status` MCP tool went
with it (`MCP.md` "Removed tools").

### Phase 2
The panel listeners got the shared pieces of the web pipeline (decision 2):
- the bridge decision client extracted to `cfm_decision.lua`;
- the panel WAF;
- `cfm_tlsfp.stamp()` on the panel `/__cfm_verify`, so panel solves carry a
  fingerprint (`configs/cfm-panel-listeners.conf.in:93`). The plain-HTTP
  ports 2082/2086/2095 correctly have none;
- per-scope cookies (decision 3).

The cPanel-plugin iframe flow (WHM :2087 iframing `/cfm-admin` on :443) was
verified across ports under the per-scope scheme.

### Phase 3 — cookie-net cleanup
After burn-in, the legacy shared-cookie-name fallback and the panel
loop-breaker (`prior_attempts >= 3`) were dropped
(`configs/lua/cfm_panel.lua:860-870, 1429-1435`). A stale legacy-name cookie
now costs at most one re-challenge, never a lockout. The `validator_degraded`
fail-open, for a broken validator module, is a different net and stays
(`configs/lua/cfm_panel.lua:1388-1400`).

### Phase 4 — panel enforcement
The panel WAF (**Phase 4a**) and panel bridge decision (**Phase 4b**) enforce
the block tier, by default, under the mode ladder in decisions 5 and 7.

---

## 7. Open items

- **Watch default-enforce on authenticated panel traffic.** The burn-in that
  justified it was scanner-dominated: authenticated panel operations are
  hostname-based or hard-skipped by `is_panel_api_or_sso`. Tracked in
  `docs/ROADMAP.md` §2.
- **Panel body inspection.** Decide whether to add bounded per-Content-Type
  body reads, mirroring the web `get_req_body_for_waf` gate, or stay
  header/URI/args-only. Panel streams must never be buffered. Tracked in
  `docs/ROADMAP.md` §2.
- **Self-origin skip on the panel decision path.** The panel WAF and
  fingerprint policy skip self / `IGNORE_NETS` sources with
  `cfm_selfip.is_self_origin` (`configs/lua/cfm_panel.lua:303-310, 322, 1297`).
  `panel_decision_probe` does not (`configs/lua/cfm_panel.lua:211-237`). It
  relies on the bridge's own `IGNORE_IPS` bypass
  (`internal/webdetector/nginx_bridge.go:2283-2291`).
- **Decision enforcement beyond human entry.** The bridge decision is
  consulted only on human-entry URIs (section 3 of `cfm_panel.lua`), so an
  IP the bridge blocked still reaches generic passthrough paths. Full
  per-request parity needs its own burn-in.

---

## 10. Explicitly NOT planned

`cfm.lua` allocates small opts tables and transform closures for its
`cfm_filecache.get()` calls on every request, because `access_by_lua_file`
chunks re-execute per request. This is an accepted trade-off
(`configs/lua/cfm_filecache.lua:47-55`). A per-file accessor module would cost
more than the nursery-GC noise it saves next to the WAF and shdict work on
that path. Do not "fix" this without a measurement showing GC pressure from
the access phase.
