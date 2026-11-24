-- WAF-exclude scope (scope_hosts) on the in-path WAF.
-- Run via `make test-lua` (luajit scripts/tests/cfm_waf_excl_scope_test.lua).
--
-- An admin `--scope <host>` (and every scoped cPanel token's write) narrows an
-- exclude to the vhosts it lists, and the Go matcher (exclude_store.go
-- MatchWAFRules) honours it. The edge used to keep only {v, rule_ids} per row,
-- so a path exclude narrowed to one vhost switched those rules (or the whole
-- WAF) off on that path of EVERY vhost: a WAF bypass across tenants.
--
-- 1. scripts/tests/fixtures/waf_exclude_scope.txt, which the Go side runs too
--    (TestWAFExcludeScope_EdgeParity), through scope_takes and skip_for.
-- 2. rows_from_entries + skip_for: positive and negative cases, back-compat.
-- 3. The real cfm.lua: refresh -> shdict -> per-worker cache -> waf_skip_for.

package.path = "configs/lua/?.lua;" .. package.path
local wx = require("cfm_waf_excl")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function split(s)
  local t = {}
  for part in (s .. ","):gmatch("([^,]*),") do t[#t+1] = part end
  return t
end

-- ── 1. the shared fixture ─────────────────────────────────────────────────────
do
  local n = 0
  for line in io.lines("scripts/tests/fixtures/waf_exclude_scope.txt") do
    line = line:gsub("^%s+", ""):gsub("%s+$", "")
    if line ~= "" and line:sub(1, 1) ~= "#" then
      local scope_s, host, want = line:match("^(%S+)%s+(%S+)%s+([01])$")
      assert(scope_s, "bad fixture line: " .. line)
      local raw = scope_s ~= "-" and split(scope_s) or nil
      want = want == "1"
      local got = wx.scope_takes(host, wx.normalize_scope(raw))
      check(got == want, ("scope %s host %s: scope_takes = %s, want %s"):format(scope_s, host, tostring(got), tostring(want)))
      -- The whole per-request path: a whole-WAF and a rule-scoped path exclude.
      local hosts, paths = wx.rows_from_entries({
        { type = "path", value = "/import/", scope_hosts = raw },
      })
      local all = wx.skip_for(hosts, paths, host, "/import/x")
      check(all == want, ("scope %s host %s: whole-WAF skip_all = %s, want %s"):format(scope_s, host, tostring(all), tostring(want)))
      hosts, paths = wx.rows_from_entries({
        { type = "path", value = "/import/", scope_hosts = raw, rule_ids = { 402 } },
      })
      local all2, ids = wx.skip_for(hosts, paths, host, "/import/x")
      local has = ids ~= nil and ids[402] == true
      check(not all2 and has == want, ("scope %s host %s: rule-scoped skip_all=%s 402=%s, want 402=%s"):format(
        scope_s, host, tostring(all2), tostring(has), tostring(want)))
      n = n + 1
    end
  end
  check(n >= 40, "fixture read " .. n .. " cases")
end

-- ── 2. rows_from_entries + skip_for ───────────────────────────────────────────
do
  local hosts, paths = wx.rows_from_entries({
    -- admin: rule 402 off on /wp-admin/admin-ajax.php for shop.gr only
    { type = "path", value = "/wp-admin/admin-ajax.php", scope_hosts = { "Shop.GR " }, rule_ids = { 402 } },
    -- a scoped cPanel token's whole-WAF host exclude, pinned to its vhosts
    { type = "host", value = "tenant.gr", scope_hosts = { "tenant.gr", "www.tenant.gr" } },
    -- admin-global path exclude, no scope
    { type = "path", value = "/healthz", rule_ids = { 7 } },
  })
  check(#hosts == 1 and #paths == 2, "rows: 1 host, 2 path")
  check(paths[1].scope and paths[1].scope[1] == "shop.gr", "scope normalised (lowercase, trimmed)")
  check(paths[2].scope == nil, "an entry without scope_hosts carries no scope (global)")

  local all, ids = wx.skip_for(hosts, paths, "shop.gr", "/wp-admin/admin-ajax.php")
  check(not all and ids and ids[402], "positive: rule 402 skipped on the scoped vhost")
  all, ids = wx.skip_for(hosts, paths, "victim.gr", "/wp-admin/admin-ajax.php")
  check(not all and ids == nil, "negative: the same path on another vhost keeps rule 402")
  all, ids = wx.skip_for(hosts, paths, "www.shop.gr", "/wp-admin/admin-ajax.php")
  check(not all and ids == nil, "negative: an exact scope host does not take its subdomain")

  check(wx.skip_for(hosts, paths, "tenant.gr", "/") == true, "positive: host exclude on a host in its scope")
  check(wx.skip_for(hosts, paths, "www.tenant.gr", "/") == true, "positive: second scope host")
  check(wx.skip_for(hosts, paths, "shop.tenant.gr", "/") == false,
    "negative: a sub-host the value covers but the scope does not list")

  all, ids = wx.skip_for(hosts, paths, "any.example", "/healthz")
  check(not all and ids and ids[7], "an unscoped path exclude still applies on every vhost")

  -- Absent / null / empty scope_hosts: global (cjson.null decodes to a
  -- lightuserdata; false stands in for any non-table).
  for _, sh in ipairs({ false, "shop.gr", {}, { "", "  " } }) do
    local h = wx.rows_from_entries({ { type = "host", value = "shop.gr", scope_hosts = sh } })
    check(h[1].scope == nil and wx.skip_for(h, {}, "www.shop.gr", "/") == true,
      "scope_hosts " .. tostring(sh) .. " reads as no scope")
  end

  -- Malformed entries are dropped, not fatal.
  hosts, paths = wx.rows_from_entries({ "x", { type = "path" }, { type = "path", value = "" }, { type = "nope", value = "/a" } })
  check(#hosts == 0 and #paths == 0, "malformed entries dropped")
  hosts, paths = wx.rows_from_entries(nil)
  check(#hosts == 0 and #paths == 0, "no entries")
end

-- ── back-compat: rows cached by an older Lua (still in the shdict after a
-- reload, until the next refresh) ─────────────────────────────────────────────
do
  -- Bare strings (before rule_ids): a whole-WAF exclude on every host.
  check(wx.skip_for({ "shop.gr" }, {}, "www.shop.gr", "/") == true, "string host row = whole-WAF, every host")
  check(wx.skip_for({}, { "/import" }, "other.gr", "/import/x") == true, "string path row = whole-WAF, every host")
  -- {v, rule_ids} without scope (before scope_hosts reached the edge): global.
  local all, ids = wx.skip_for({}, { { v = "/import", rule_ids = { 402 } } }, "other.gr", "/import/x")
  check(not all and ids and ids[402], "a cached row without scope stays global")
  check(wx.skip_for({}, { { v = "/import" } }, "other.gr", "/import/x") == true, "a cached row without rule_ids is whole-WAF")
end

-- ── 3. the real cfm.lua ──────────────────────────────────────────────────────
-- A codec that hands tables through a registry stands in for cjson, so the
-- rows go through refresh_waf_excludes_if_needed -> the shdict ->
-- load_waf_excludes_local_cache -> waf_skip_for as on a node.
do
  local H = dofile("scripts/tests/cfm_lua_harness.lua")
  local reg, nreg = {}, 0
  local codec = {
    encode = function(t) nreg = nreg + 1; local k = "#" .. nreg; reg[k] = t; return k end,
    decode = function(s) return reg[s] end,
  }
  local excludes = { entries = {
    { type = "path", value = "/import/", scope_hosts = { "shop.gr" } },
    { type = "path", value = "/api/", scope_hosts = { "shop.gr" }, rule_ids = { 402 } },
  } }
  reg["EXCL"] = excludes
  local function run(host, uri)
    wx.ts = 0 -- every run gets a fresh shdict; drop the worker's cached snapshot
    local seen = { calls = 0 }
    local fake = {
      enabled = function() return true end,
      check = function(ctx) seen.calls = seen.calls + 1; seen.skip = ctx.skip_rule_ids; return false end,
      should_push = function() return false end,
      also_rule_ids = function() return {} end,
      post_clearance_action = function(a) return a, false end,
    }
    local r = H.run{ host = host, uri = uri, waf_fake = fake, cjson = codec,
      rpc_body = function(kind) if kind == "waf_excludes" then return "EXCL" end end }
    return r, seen
  end
  local r, seen = run("shop.gr", "/import/x")
  check(r.ok and seen.calls == 0, "cfm.lua: a whole-WAF exclude skips the WAF on its scope host (calls=" .. seen.calls .. ", err=" .. tostring(r.err) .. ")")
  r, seen = run("victim.gr", "/import/x")
  check(r.ok and seen.calls == 1, "cfm.lua: the same path on another vhost meets the WAF (calls=" .. seen.calls .. ", err=" .. tostring(r.err) .. ")")
  r, seen = run("shop.gr", "/api/x")
  check(seen.calls == 1 and seen.skip and seen.skip[402], "cfm.lua: rule 402 skipped on the scope host")
  r, seen = run("victim.gr", "/api/x")
  check(seen.calls == 1 and seen.skip == nil, "cfm.lua: no rule skipped on another vhost")

  -- A reload: the shdict still holds an older Lua's fresh, scope-less snapshot
  -- (and an old worker draining connections keeps rewriting it). The new code
  -- must not read it: it refreshes under its own keys.
  local store = {}
  local SH = {
    get = function(_, k) return store[k] end,
    set = function(_, k, v) store[k] = v; return true end,
    add = function(_, k, v) if store[k] ~= nil then return false end store[k] = v; return true end,
    delete = function(_, k) store[k] = nil end,
    incr = function(_, k, n) if store[k] == nil then return nil, "not found" end store[k] = store[k] + n; return store[k] end,
    get_keys = function() local t = {} for k in pairs(store) do t[#t+1] = k end return t end,
  }
  reg["OLDP"] = { { v = "/import/" } }
  store.wxsnap_ts, store.wxhosts, store.wxpaths = 1000, "OLDH", "OLDP"
  reg["OLDH"] = {}
  wx.ts = 0
  local calls = 0
  local fake = {
    enabled = function() return true end,
    check = function() calls = calls + 1; return false end,
    should_push = function() return false end,
    also_rule_ids = function() return {} end,
    post_clearance_action = function(a) return a, false end,
  }
  r = H.run{ host = "victim.gr", uri = "/import/x", waf_fake = fake, cjson = codec, SH = SH,
    rpc_body = function(kind) if kind == "waf_excludes" then return "EXCL" end end }
  check(r.ok and calls == 1, "cfm.lua: an older Lua's scope-less snapshot is not read after a reload (calls=" .. calls .. ")")
  check(r.rpcs:find("waf_excludes", 1, true) ~= nil, "cfm.lua: refreshes under its own keys at once: " .. r.rpcs)
end

if fails > 0 then
  io.stderr:write(("%d failure(s)\n"):format(fails))
  os.exit(1)
end
print("ok: cfm_waf_excl scope_hosts (fixture parity, skip_for, back-compat, cfm.lua)")
