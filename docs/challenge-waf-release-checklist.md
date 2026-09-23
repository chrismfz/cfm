# Challenge/WAF release checklist

Use this checklist for challenge or WAF Lua/config updates before reloading Angie/OpenResty.

## Lua validation gate (required)

1. Ensure all shipped Lua files parse. Use **LuaJIT** (the edge runtime), not
   the system `luac`: distro `luac` is often Lua 5.1, which rejects `goto`/`::label::`
   and will falsely fail `cfm_waf.lua`. Prefer the project target:
   - `make lua`  (LuaJIT-based syntax check over `configs/lua/*.lua`)
   - or per file: `luajit -bl configs/lua/<file>.lua /dev/null`
2. Ensure rendered runtime artifacts parse (if generated in environment):
   - `for f in /var/lib/cfm/lua/*.lua; do luajit -bl "$f" /dev/null >/dev/null || echo "FAIL $f"; done`
3. Run the runtime load smoke test on an OpenResty node, with OpenResty's
   `resty` CLI. Plain `luajit` cannot run it: it has no `ngx` and no `cjson`,
   so several modules fail to load under it whatever their state.
   - `resty -I /var/lib/cfm/lua -e 'for _, m in ipairs({"cfm_clearance","cfm_rules","cfm_waf","cfm_stats","cfm_clamav","cfm_cache_log","cfm_cache","cfm_hostmatch","cfm_panel_hosts","cfm_selfip","cfm_filecache","cfm_bridge_cfg","cfm_origin_ka","cfm_tlsfp","cfm_decision","sslcollector"}) do local ok, err = pcall(require, m); if not ok then error(m .. ": " .. tostring(err)) end end'`
   - `cfm_panel` is not in the list: it is the panel ports' access script, not
     a module, so requiring it runs the request handler. Steps 1–2 cover its
     syntax; step 7 covers the rest.
   - Angie ships no `resty` CLI. On an Angie node, rely on steps 1–2 and 7.

## Site Cache (when the change touches it)

- `./scripts/tests/check_site_cache_config.sh` passes (CI runs it too): the
  bypass-by-default gate and every cache rail are still pinned in both confs.
- After the reload, on the box: an armed vhost still answers the debug stamp
  (`docs/site-cache-runbook.md` §4), its assets show `ucache="HIT"` after a
  second request, and `cfm webtop site-cache stats` still moves.
- Never set `MICRO_CACHE_ENFORCE = 1` as part of a release — per node, only
  after `docs/site-cache-design.md` §5.7.

## Deploy/reload guardrails (required)

4. Fail release/deploy on any Lua parse or module load failure.
5. Do **not** run `systemctl reload angie` (or restart) when Lua validation fails.
6. Keep previous active config/runtime in place until validation passes.
7. Right after the reload, check the edge `error.log` for Lua errors
   (`failed to load`, `attempt to`, `module '…' not found`), including after
   one request to a panel port (:2083) on a cPanel node.
