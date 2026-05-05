# Challenge/WAF release checklist

Use this checklist for challenge or WAF Lua/config updates before reloading Angie/OpenResty.

## Lua validation gate (required)

1. Ensure all shipped Lua files parse:
   - `luac -p configs/lua/*.lua`
2. Ensure rendered runtime artifacts parse (if generated in environment):
   - `luac -p /var/lib/cfm/lua/*.lua`
3. Run runtime load smoke-test with OpenResty-compatible LuaJIT:
   - `LUA_PATH="/var/lib/cfm/lua/?.lua;;" luajit -e 'assert(pcall(require,"cfm_clearance")); assert(pcall(require,"cfm_panel")); assert(pcall(require,"cfm_rules")); assert(pcall(require,"cfm_waf")); assert(pcall(require,"cfm_stats")); assert(pcall(require,"cfm_clamav")); assert(pcall(require,"cfm_cache_log")); assert(pcall(require,"sslcollector"))'`

## Deploy/reload guardrails (required)

4. Fail release/deploy on any Lua parse or module load failure.
5. Do **not** run `systemctl reload angie` (or restart) when Lua validation fails.
6. Keep previous active config/runtime in place until validation passes.
