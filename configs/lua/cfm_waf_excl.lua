-- /var/lib/cfm/lua/cfm_waf_excl.lua
--
-- Per-worker cache STATE for the WAF-excludes snapshot. Companion to
-- cfm.lua's `refresh_waf_excludes_if_needed` and
-- `load_waf_excludes_local_cache` functions, which still live inline in
-- cfm.lua because they call `rpc_call` (defined in cfm.lua too) and
-- moving them here would create a circular require.
--
-- WHY THIS FILE EXISTS
--
-- See the long-form pitfall block at the top of cfm.lua under
-- "PITFALL: access_by_lua_file top-level locals". Short version:
--
--   * cfm.lua is loaded via `access_by_lua_file`, which (with the
--     default lua_code_cache on) caches the compiled chunk per worker
--     but RE-EXECUTES it on every request. Top-level `local` statements
--     reset on every invocation.
--   * That defeats any "have I done this once" guard living in such a
--     local. The original symptom that surfaced this was a 13 GB
--     mmap leak in lua-resty-maxminddb (fixed in cfm_geo.lua).
--   * The same pattern affected this file's three pieces of cache state:
--     `wx_local_ts/hosts/paths`. They didn't leak (Lua tables are
--     properly GC'd, unlike FFI mmaps) but the timestamp comparison
--     `if ts == wx_local_ts then return end` was a permanent miss
--     because wx_local_ts always re-initialised to 0 — so every WAF-
--     eligible request paid an unnecessary cjson.decode of the shdict
--     snapshot.
--   * `package.loaded[name]` is the per-worker cache that DOES survive
--     across requests. Module-scope locals declared inside this file
--     persist between invocations of cfm.lua's chunk.
--
-- API
--
--   local wx = require "cfm_waf_excl"
--   wx.ts        -- number  : last shdict snapshot timestamp this worker decoded
--   wx.hosts     -- array   : decoded host-rule rows {v, rule_ids?}
--   wx.paths     -- array   : decoded path-rule rows {v, rule_ids?}
--
-- Mutated directly by load_waf_excludes_local_cache in cfm.lua. This
-- module deliberately exposes the state as plain table fields rather
-- than getter/setter methods — the call sites do at most one read and
-- one write per request, and the simpler shape keeps the diff in
-- cfm.lua small.

local _M = {}

-- Cache snapshot timestamp from the shdict (key `wxsnap_ts`). 0 means
-- this worker hasn't decoded any snapshot yet. Compared in
-- load_waf_excludes_local_cache against the live shdict ts to decide
-- whether to skip the cjson.decode.
_M.ts = 0

-- Decoded WAF-exclude entries from the shdict snapshot. Each row is
-- a table { v = <string>, rule_ids = <array of int>? }. The shape is
-- documented at refresh_waf_excludes_if_needed in cfm.lua.
_M.hosts = {}
_M.paths = {}

return _M
