-- Tests for the glob_to_lua_pattern per-rule cache (audit F32).
--
-- matches_rule rebuilt the anchored Lua pattern (two gsubs) for every glob rule
-- on every WAF-eligible request. glob_to_lua_pattern now caches the pattern in a
-- module-scope table keyed by the rule string. The conversion is a pure function
-- of the rule, so a cache hit returns a byte-identical pattern — behavior is
-- unchanged (the full matches_rule boundary/glob semantics are locked by
-- cfm_waf_excl_test.lua); this test proves the cache is actually USED.

package.path = "configs/lua/?.lua;" .. package.path
local wx = require("cfm_waf_excl")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- ── Behavior parity: the conversion output is unchanged ──────────────────────
check(wx.glob_to_lua_pattern("/wp-admin/*") == "^/wp%-admin/[^/]*$",
      "* -> [^/]* anchored, magic chars escaped")
check(wx.glob_to_lua_pattern("a?b") == "^a[^/]b$", "? -> [^/]")
check(wx.glob_to_lua_pattern("/admin") == "^/admin$", "literal rule anchored")
check(wx.glob_to_lua_pattern("shop.gr") == "^shop%.gr$", "dot escaped")
-- Bracket-glob (F10b literal path) and a heavy-magic rule: every magic char is
-- escaped, wildcards expand, so the pattern is unchanged by the cache.
check(wx.glob_to_lua_pattern("/foo[abc]/*") == "^/foo%[abc%]/[^/]*$",
      "bracket glob is matched literally (F10b), * still -> [^/]*")
check(wx.glob_to_lua_pattern("a.b+c(d)$") == "^a%.b%+c%(d%)%$$",
      "heavy-magic rule fully escaped")

-- Reach the module-scope cache (an upvalue of glob_to_lua_pattern) to prove the
-- second call reads from it rather than recomputing.
local function cache_ref()
  local i = 1
  while true do
    local n, v = debug.getupvalue(wx.glob_to_lua_pattern, i)
    if not n then break end
    if n == "_glob_pat_cache" then return v end
    i = i + 1
  end
  return nil
end

local cache = cache_ref()
check(cache ~= nil, "F32: found the _glob_pat_cache upvalue (cache exists)")

if cache then
  -- First call populates the cache with the real pattern.
  local RULE = "/api/v?/*"
  local first = wx.glob_to_lua_pattern(RULE)
  check(cache[RULE] == first, "F32: first call populates the cache entry")

  -- Poison the entry: a cache HIT must return the poisoned value (i.e. the second
  -- call did NOT recompute). Without the cache this would return the real pattern.
  cache[RULE] = "^POISONED$"
  check(wx.glob_to_lua_pattern(RULE) == "^POISONED$",
        "F32: second call returns the cached value (cache hit, no recompute)")

  -- The cache is keyed per rule: a different rule is unaffected by the poison.
  check(wx.glob_to_lua_pattern("/other/*") == "^/other/[^/]*$",
        "a different rule is computed independently (not the poisoned entry)")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_excl_globcache_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: glob_to_lua_pattern per-rule cache (F32)\n")
