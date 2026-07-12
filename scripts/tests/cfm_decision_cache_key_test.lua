-- Tests for the cfm_decisions cache key (audit F38).
--
-- The per-URL key used uri:sub(1, 64), so two paths sharing a 64-byte prefix
-- mapped to the SAME cfm_decisions entry. Since only clean allows are cached,
-- an attacker could warm the cache with a benign same-prefix request and reuse
-- the "allow" for a longer path whose per-path bridge rule would challenge/block
-- (the bridge is never consulted for the second path). Fix: hash the FULL path
-- with ngx.md5 so distinct paths never collide.
--
-- cfm.lua is an access_by_lua_file (running main() on require), so we extract
-- decision_cache_key from the source and load() it — exercising the PRODUCTION
-- function. Its two free names, is_static_asset_uri and ngx.md5, are provided as
-- globals in the loaded chunk.

local path = "configs/lua/cfm.lua"
local f = assert(io.open(path, "r"), "cannot open " .. path)
local src = f:read("*a"); f:close()

local start = src:find("local function decision_cache_key%(")
assert(start, "decision_cache_key() not found in " .. path .. " (renamed/moved?)")
local body = src:sub(start)
local stop = body:find("\nend\n")
assert(stop, "could not delimit decision_cache_key() body")
local fnsrc = body:sub(1, stop + 4)

-- Deterministic stand-ins. md5 is modelled as a function of the FULL input, so
-- the key depends on the whole path (the real ngx.md5 also bounds it to 32 hex).
_G.ngx = { md5 = function(s) return "md5(" .. tostring(s) .. ")" end }
_G.is_static_asset_uri = function(uri)
  local ext = tostring(uri):match("%.([%w]+)$")
  return ext ~= nil and ({ css = true, js = true, png = true, woff = true })[ext:lower()] == true
end

local decision_cache_key = assert(load(fnsrc .. "\nreturn decision_cache_key"))()
assert(type(decision_cache_key) == "function", "extracted decision_cache_key is not a function")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local IP, HOST, SCOPE = "203.0.113.7", "shop.example.com", "web"
local function dk(uri, opt)
  opt = opt or {}
  return decision_cache_key(opt.ip or IP, opt.host or HOST, opt.method or "GET",
                            opt.scheme or "https", uri, opt.scope or SCOPE)
end

-- ── F38: two paths sharing a 64-byte prefix get DISTINCT keys ────────────────
local base = string.rep("/a", 32)        -- exactly 64 bytes
local uriA = base                        -- 64 bytes
local uriB = base .. "/admin/secret"     -- first 64 bytes identical, suffix differs
check(#base == 64, "sanity: base prefix is 64 bytes (got " .. #base .. ")")
check(dk(uriA) ~= dk(uriB),
      "F38: paths sharing a 64-byte prefix map to DISTINCT cache keys")
-- A far-past-64 divergence too.
check(dk("/wp-content/" .. string.rep("x", 80) .. "/a") ~=
      dk("/wp-content/" .. string.rep("x", 80) .. "/b"),
      "F38: divergence beyond 64 bytes still distinguishes keys")

-- ── Determinism & the other key dimensions still matter ─────────────────────
check(dk(uriB) == dk(uriB), "same request -> same key (deterministic)")
check(dk(uriB) ~= dk(uriB, { method = "POST" }),   "different method -> different key")
check(dk(uriB) ~= dk(uriB, { scheme = "http" }),   "different scheme -> different key")
check(dk(uriB) ~= dk(uriB, { host = "other.com" }), "different host -> different key")
check(dk(uriB) ~= dk(uriB, { ip = "198.51.100.9" }), "different ip -> different key")
check(dk(uriB) ~= dk(uriB, { scope = "panel:2087" }), "different scope -> different key (non-static keyed on scope too)")
check(dk(uriB):sub(1, 2) == "d|", "non-static key uses the 'd|' namespace")

-- ── Static assets: one coalesced entry per (ip, host, scope), path-independent ─
local ks1 = dk("/assets/app.css")
local ks2 = dk("/assets/vendor/huge/" .. string.rep("z", 100) .. ".js")
check(ks1 == ks2, "static assets from same (ip,host,scope) share one coalesced key")
check(ks1:sub(1, 3) == "ds|", "static key uses the 'ds|' namespace")
check(ks1 ~= dk("/assets/app.css", { scope = "panel:2087" }),
      "static key varies by scope")
check(ks1 ~= dk("/assets/app.css", { host = "other.com" }),
      "static key varies by host")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_decision_cache_key_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm decision_cache_key full-path hashing (F38)\n")
