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
--   wx.hosts     -- array   : decoded host-rule rows {v, rule_ids?, scope?}
--   wx.paths     -- array   : decoded path-rule rows {v, rule_ids?, scope?}
--   wx.rows_from_entries(entries) -> hosts, paths   (the /nginx/waf/excludes rows)
--   wx.skip_for(hosts, paths, host, uri) -> skip_all, skip_ids
--   wx.scope_takes(host, scope) / wx.normalize_scope(list)
--
-- Mutated directly by load_waf_excludes_local_cache in cfm.lua. This
-- module deliberately exposes the state as plain table fields rather
-- than getter/setter methods — the call sites do at most one read and
-- one write per request, and the simpler shape keeps the diff in
-- cfm.lua small.

local _M = {}

-- Cache snapshot timestamp from the shdict (key `wxsnap2_ts`). 0 means
-- this worker hasn't decoded any snapshot yet. Compared in
-- load_waf_excludes_local_cache against the live shdict ts to decide
-- whether to skip the cjson.decode.
_M.ts = 0

-- Decoded WAF-exclude entries from the shdict snapshot. Each row is
-- a table { v = <string>, rule_ids = <array of int>?, scope = <array of
-- string>? } built by rows_from_entries below. An absent scope means every
-- host (an entry written without scope_hosts, and every row an older Lua
-- cached, which never carried one).
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

-- Convert an operator glob to an ANCHORED Lua pattern, escaping every magic
-- char first, then re-expanding the two wildcards to their Go equivalents:
--   `*` -> `[^/]*`  (a run of non-'/' chars)
--   `?` -> `[^/]`   (exactly one non-'/' char)
-- The wildcards MUST NOT cross a path-segment separator, to match the Go
-- enforcement matcher globToRegex (internal/webdetector/exclude_store.go),
-- which uses `[^/]*`/`[^/]`. The old `*`->`.*` / `?`->`.` crossed `/`, so an
-- exclude like `/wp-admin/*` switched the WAF off for `/wp-admin/a/b/c` in-path
-- while the Go log-driven matcher did not — a silent, one-sided widening of the
-- WAF-off region. (For hosts there is no `/`, so this is a no-op there.)
--
-- NOTE (audit F10 residual, tracked as F10b): `[...]` bracket-class globs are
-- NOT yet ported. Go treats a rule containing `[`/`]` as a character class;
-- this matcher does not glob-detect brackets, so such a rule is matched
-- LITERALLY (exact / path-segment-prefix / host-suffix). For the intended class
-- meaning Lua is narrower (more protective in-path). The one case where Lua is
-- WIDER than Go: a request whose value literally contains the bracket text
-- (rule `/foo[abc]`, request `/foo[abc]`) matches here but not Go's anchored
-- class regex — contrived (needs literal, usually percent-encoded, brackets in
-- both the rule and the live URL). A full port closes both directions.
-- Anchored-pattern cache, keyed by the rule string (F32). matches_rule ran the
-- two gsubs below once per glob rule on every WAF-eligible request; Go compiles
-- its regexp once at rebuild. The keys are exclude RULES (a bounded operator
-- list), never request values, so this cannot grow with traffic; it persists per
-- worker via package.loaded and is naturally superseded when a rule string
-- changes (a changed rule is a new key). The conversion is a pure function of the
-- rule, so a cache hit returns a byte-identical pattern.
local _glob_pat_cache = {}
local function glob_to_lua_pattern(glob)
  local key = tostring(glob or "")
  local hit = _glob_pat_cache[key]
  if hit then return hit end
  local p = key:gsub("([%^%$%(%)%%%.%[%]%+%-%*%?])", "%%%1")
  p = p:gsub("%%%*", "[^/]*"); p = p:gsub("%%%?", "[^/]")
  p = "^" .. p .. "$"
  _glob_pat_cache[key] = p
  return p
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

-- ─────────────────────────────────────────────────────────────────────────────
-- EXCLUDE SCOPE (scope_hosts)
--
-- An admin `--scope <host>` / `scope_hosts=` (and every scoped cPanel token's
-- write, pinned to the token's vhosts) narrows an exclude to the hosts it
-- lists. Before this, the edge kept only the value and rule_ids of each row,
-- so a path exclude an admin narrowed to one vhost switched those rules (or
-- the whole WAF) off on that path of EVERY vhost, and a host exclude covered
-- sub-hosts its scope did not list: a silent WAF bypass across tenants.
--
-- Same semantics as the Go compiledScopeMatcher (internal/webdetector/
-- exclude_store.go), pinned by scripts/tests/fixtures/waf_exclude_scope.txt,
-- which both sides run:
--   * no scope (absent / empty after normalisation) = every host;
--   * a scope host without `* ? [ ]` matches that exact host only (no
--     subdomain suffix: `shop.gr` does NOT take `www.shop.gr`);
--   * one with them is an anchored glob (compileGlob): `*` = `[^/]*`,
--     `?` = `[^/]` (a host has no `/`, so `*` crosses dots), `[...]` a class;
--   * a scope whose every host is an unusable glob takes NO host.
-- Bracket classes are ported for the characters a host name holds (letters,
-- digits, `.`, `-`, ranges, a leading `!`/`^`); anything else in a class
-- makes that scope host match nothing here (narrower than Go = the WAF runs,
-- the fail-safe direction).
-- ─────────────────────────────────────────────────────────────────────────────

local function trim(s) return (s:gsub("^%s+", ""):gsub("%s+$", "")) end

-- normalize_scope(list): the scope_hosts array of a bridge entry -> a list of
-- lowercased, trimmed, de-duplicated host strings, or nil (= every host).
-- Mirrors Go normalizeScopeHosts. Anything but a table (absent, cjson.null)
-- is nil: an entry without scope_hosts is global, as Go stores it.
function _M.normalize_scope(list)
  if type(list) ~= "table" then return nil end
  local out, seen = {}, {}
  for _, h in ipairs(list) do
    if type(h) == "string" then
      h = trim(lower(h))
      if h ~= "" and not seen[h] then seen[h] = true; out[#out+1] = h end
    end
  end
  if #out == 0 then return nil end
  return out
end

local function lit(c)
  -- A literal char in a Lua pattern: alphanumerics as is (`%a` etc. would be
  -- classes), everything else escaped.
  if c:match("^%w$") then return c end
  return "%" .. c
end

-- Anchored-pattern cache for scope globs; `false` caches an unusable glob.
-- Keys are operator scope strings (a bounded list), never request values.
local _scope_pat_cache = {}
local function scope_glob_to_lua_pattern(glob)
  local hit = _scope_pat_cache[glob]
  if hit ~= nil then return hit or nil end
  local out, i, n = { "^" }, 1, #glob
  local bad = false
  while i <= n and not bad do
    local c = glob:sub(i, i)
    if c == "*" then
      out[#out+1] = "[^/]*"
    elseif c == "?" then
      out[#out+1] = "[^/]"
    elseif c == "\\" then
      -- Go: `\x` is a literal x; a trailing `\` fails compileGlob.
      if i == n then bad = true else i = i + 1; out[#out+1] = lit(glob:sub(i, i)) end
    elseif c == "[" then
      local cls = { "[" }
      i = i + 1
      local nc = glob:sub(i, i)
      if nc == "!" or nc == "^" then cls[#cls+1] = "^"; i = i + 1 end
      local closed, members = false, 0
      while i <= n do
        local d = glob:sub(i, i)
        if d == "]" then closed = true; break end
        if not d:match("^[%w%.%-]$") then break end
        cls[#cls+1] = d; members = members + 1
        i = i + 1
      end
      -- Unterminated (Go fails it too), empty, or holding a char not ported.
      if not closed or members == 0 then bad = true else cls[#cls+1] = "]"; out[#out+1] = table.concat(cls) end
    else
      out[#out+1] = lit(c)
    end
    i = i + 1
  end
  local p = false
  if not bad then p = table.concat(out) .. "$" end
  _scope_pat_cache[glob] = p
  return p or nil
end
_M.scope_glob_to_lua_pattern = scope_glob_to_lua_pattern

-- scope_takes(host, scope): does an exclude whose normalised scope is `scope`
-- apply to a request on `host`? nil / empty scope = every host.
function _M.scope_takes(host, scope)
  if type(scope) ~= "table" or #scope == 0 then return true end
  host = lower(tostring(host or ""))
  for _, h in ipairs(scope) do
    if type(h) == "string" then
      if h:find("[%*%?%[%]]") then
        local p = scope_glob_to_lua_pattern(h)
        if p then
          local ok, res = pcall(string.match, host, p)
          if ok and res ~= nil then return true end
        end
      elseif h == host then
        return true
      end
    end
  end
  return false
end

-- rows_from_entries(entries): the `entries` array of /nginx/waf/excludes
-- (NginxBridge.handleWAFExcludes: {type, value, scope_hosts?, rule_ids?}) ->
-- the host and path row lists cfm.lua caches in the shdict.
function _M.rows_from_entries(entries)
  local hosts, paths = {}, {}
  if type(entries) ~= "table" then return hosts, paths end
  for _, e in ipairs(entries) do
    if type(e) == "table" and type(e.value) == "string" then
      local t = lower(e.type); local v = lower(e.value)
      if v ~= "" then
        local row = { v = v, scope = _M.normalize_scope(e.scope_hosts) }
        if type(e.rule_ids) == "table" then row.rule_ids = e.rule_ids end
        if t == "host" then hosts[#hosts+1] = row
        elseif t == "path" then paths[#paths+1] = row end
      end
    end
  end
  return hosts, paths
end

-- skip_for(hosts, paths, host, uri) returns:
--   skip_all (bool)   true if a matching exclude whose scope takes host is
--                     whole-WAF (no rule_ids)
--   skip_ids (table)  set of waf_rule_id integers to suppress when the WAF
--                     runs; nil if no rule-scoped exclude applies
-- Mirrors Go excludeStore.MatchWAFRules: the scope first, then the value
-- (the host for a host row, the uri for a path row); no host, no exclude.
function _M.skip_for(hosts, paths, host, uri)
  host = lower(tostring(host or "")); uri = lower(tostring(uri or "/"))
  if host == "" then return false, nil end
  local skip_ids = nil
  local function consider(target, row, kind)
    -- Back-compat: Lua before rule_ids cached this list as bare strings. The
    -- snapshot now lives under keys of its own (cfm.lua "wxhosts2"), so an
    -- older Lua's rows are not read, but a string row keeps its old meaning
    -- if one ever reaches here: a whole-WAF exclude on every host. A table
    -- row without `scope` is global too (an entry without scope_hosts).
    if type(row) == "string" then row = { v = row } end
    if type(row) ~= "table" then return false end
    if not _M.scope_takes(host, row.scope) then return false end
    if not _M.matches_rule(target, row.v, kind) then return false end
    if type(row.rule_ids) ~= "table" or #row.rule_ids == 0 then
      return true -- whole-WAF skip; signal caller to short-circuit
    end
    if not skip_ids then skip_ids = {} end
    for _, id in ipairs(row.rule_ids) do
      local n = tonumber(id)
      if n then skip_ids[n] = true end
    end
    return false
  end
  for _, r in ipairs(hosts or {}) do
    if consider(host, r, "host") then return true, nil end
  end
  for _, r in ipairs(paths or {}) do
    if consider(uri, r, "path") then return true, nil end
  end
  return false, skip_ids
end

return _M
