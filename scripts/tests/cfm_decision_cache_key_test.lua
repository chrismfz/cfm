-- Tests for the cfm_decisions cache key (audit F38).
--
-- The per-URL key used uri:sub(1, 64), so two paths sharing a 64-byte prefix
-- mapped to the SAME cfm_decisions entry. Since only clean allows are cached,
-- an attacker could warm the cache with a benign same-prefix request and reuse
-- the "allow" for a longer path whose per-path bridge rule would challenge/block
-- (the bridge is never consulted for the second path). Fix: hash the FULL path
-- with ngx.md5 so distinct paths never collide.
--
-- The key builder now lives in cfm_decision.lua as Client:cache_key (extracted
-- from cfm.lua in edge-unification Phase 2). We require the module and exercise
-- the PRODUCTION method; its free names are ngx.md5 and the injected is_static
-- hook.

-- cfm_decision requires cjson.safe at load; stub it (unused by cache_key).
package.loaded["cjson.safe"] = { decode = function() return nil end, encode = function() return "" end }
package.path = package.path .. ";configs/lua/?.lua;./?.lua"

-- Deterministic stand-ins. md5 is modelled as a function of the FULL input, so
-- the key depends on the whole path (the real ngx.md5 also bounds it to 32 hex).
_G.ngx = { md5 = function(s) return "md5(" .. tostring(s) .. ")" end }

local cfm_decision = require("cfm_decision")
local client = cfm_decision.new({}, {
  is_static = function(uri)
    local ext = tostring(uri):match("%.([%w]+)$")
    return ext ~= nil and ({ css = true, js = true, png = true, woff = true })[ext:lower()] == true
  end,
})
assert(type(client.cache_key) == "function", "Client:cache_key missing")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local IP, HOST, SCOPE = "203.0.113.7", "shop.example.com", "web"
local function dk(uri, opt)
  opt = opt or {}
  return client:cache_key(opt.ip or IP, opt.host or HOST, opt.method or "GET",
                          opt.scheme or "https", uri, opt.qs or "", opt.scope or SCOPE)
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

-- ── Query dimension: query is folded into the non-static key ─────────────────
-- A query-less request must hash exactly the path (== the pre-query key), so
-- no-query traffic keeps its previous cache entry.
check(dk(uriB) == dk(uriB, { qs = "" }), "empty qs == no qs (unchanged key)")
check(dk(uriB):find("md5(" .. uriB .. ")", 1, true) ~= nil,
      "query-less key hashes the bare path (no '?query' appended)")
check(dk(uriB) ~= dk(uriB, { qs = "mode=register" }),
      "a query-scoped request gets a DISTINCT key from the query-less one")
check(dk(uriB, { qs = "mode=register" }) ~= dk(uriB, { qs = "mode=login" }),
      "different query -> different key")
check(dk(uriB, { qs = "mode=register" }):find("md5(" .. uriB .. ")md5(mode=register)", 1, true) ~= nil,
      "query key hashes path and query INDEPENDENTLY (md5(uri)..md5(qs))")

-- Regression: '?' can appear in a DECODED path (from %3F), so hashing
-- "uri..'?'..qs" once would collide "/p?q" (no query) with "/p" (query "q") and
-- let an attacker warm a clean-allow under the former to bypass a query-scoped
-- rule on the latter. Independent hashing must keep them DISTINCT.
check(dk("/forum/ucp.php?mode=register", { qs = "" }) ~=
      dk("/forum/ucp.php", { qs = "mode=register" }),
      "literal-'?' path must NOT collide with path+query (cache-bypass guard)")

-- ── Static assets: one coalesced entry per (ip, host, scope), path-independent ─
local ks1 = dk("/assets/app.css")
local ks2 = dk("/assets/vendor/huge/" .. string.rep("z", 100) .. ".js")
check(ks1 == ks2, "static assets from same (ip,host,scope) share one coalesced key")
check(ks1 == dk("/assets/app.css", { qs = "v=123" }),
      "static assets coalesce regardless of query (cache-buster ?v= ignored)")
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
