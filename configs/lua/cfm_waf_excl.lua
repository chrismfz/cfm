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

-- ─────────────────────────────────────────────────────────────────────────────
-- EXCLUDE VALUE MATCHING
--
-- Lives here (not inline in cfm.lua) so it is unit-testable and so the boundary
-- semantics have one canonical home on the Lua side. It must stay consistent
-- with the Go enforcement matcher — internal/webdetector/exclude_store.go
-- `compiledValueMatcher` (the log-driven path) — or the in-path (Lua) and
-- log-driven (Go) engines would disagree about which requests an exclude covers.
-- ─────────────────────────────────────────────────────────────────────────────

local function lower(s)
  if type(s) ~= "string" then return "" end
  return string.lower(s)
end

-- Convert an operator glob (`*` = any run, `?` = one char) to an ANCHORED Lua
-- pattern, escaping every magic char first.
local function glob_to_lua_pattern(glob)
  local p = tostring(glob or "")
  p = p:gsub("([%^%$%(%)%%%.%[%]%+%-%*%?])", "%%%1")
  p = p:gsub("%%%*", ".*"); p = p:gsub("%%%?", ".")
  return "^" .. p .. "$"
end
_M.glob_to_lua_pattern = glob_to_lua_pattern

-- matches_rule(value, rule, kind): does the request's host/uri `value` match the
-- exclude `rule`? `kind` ("host"/"path") selects the non-glob boundary
-- semantics:
--   * host: exact, or a dot-boundary subdomain suffix — `shop.gr` matches
--     `shop.gr` and `www.shop.gr`, NOT `myshop.gr` / `shop.gr.evil.com`;
--   * path: exact, or a path-segment prefix — `/admin` matches `/admin` and
--     `/admin/x`, NOT `/administrator`. (Path rules carry a leading `/`.)
-- A glob rule (`*`/`?`) keeps anchored matching. The previous plain substring
-- (`value:find(rule)`) silently disabled the WAF on unintended vhosts/paths —
-- a `shop.gr` exclude also covered every `*shop.gr*` host. Mirrors the Go
-- compiledValueMatcher in internal/webdetector/exclude_store.go.
function _M.matches_rule(value, rule, kind)
  value = lower(tostring(value or "")); rule = lower(tostring(rule or ""))
  if value == "" or rule == "" then return false end
  if rule:find("*", 1, true) or rule:find("?", 1, true) then
    local ok, res = pcall(function() return value:match(glob_to_lua_pattern(rule)) ~= nil end)
    return ok and res or false
  end
  if value == rule then return true end
  if kind == "path" then
    if rule:sub(-1) == "/" then
      return value:sub(1, #rule) == rule
    end
    return value:sub(1, #rule + 1) == rule .. "/"
  end
  -- host (default): exact handled above, else a dot-boundary subdomain suffix.
  return value:sub(-(#rule + 1)) == "." .. rule
end

return _M
