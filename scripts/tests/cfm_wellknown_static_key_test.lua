-- Two carve-outs that let a request skip what they were never meant to
-- (edge Lua sweep 2026-10-09, PR 6):
--   * Step 0a1 sent the WHOLE /.well-known/ prefix to the origin with no WAF,
--     no IP block and no challenge. A front-controller app (WordPress routes
--     any missing path to index.php) was reachable whole under
--     `/.well-known/x?rest_route=…` or a POST, and a shell dropped in
--     `.well-known/` too. Only a plain fetch is exempted now: GET / HEAD, no
--     query string, no script extension (ACME / CA DCV / security.txt /
--     mta-sts / apple-app-site-association keep working).
--   * The bridge-decision cache coalesces static assets to one allow per
--     (ip, host): `/xmlrpc.php/x.css` (PATH_INFO, the edge conf sends it to
--     cfm.lua) reused it, so its traffic rules and throttles never ran.

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local H = dofile("scripts/tests/cfm_lua_harness.lua")
local function desc(r)
  return ("ok=%s action=%s up=%s exit=%s rpcs=%s err=%s"):format(tostring(r.ok), tostring(r.action),
    tostring(r.upstream), tostring(r.exited), r.rpcs, tostring(r.err))
end
local function bypassed(r) return r.ok and r.upstream == "cfm_apache" and r.rpcs == "" end

-- ── .well-known: a plain fetch is exempted, nothing else ──────────────────────
do
  for _, t in ipairs({
    { uri = "/.well-known/acme-challenge/Xy_9-AbC" },
    { uri = "/.well-known/pki-validation/ABCDEF0123.txt" },
    { uri = "/.well-known/security.txt", method = "HEAD" },
    { uri = "/.well-known/mta-sts.txt" },
    { uri = "/.WELL-KNOWN/apple-app-site-association" },
    { uri = "/.well-known/caldav", method = "PROPFIND" },
  }) do
    local r = H.run{ uri = t.uri, method = t.method }
    check(bypassed(r), t.uri .. " (" .. (t.method or "GET") .. ") still bypasses: " .. desc(r))
  end
  for _, t in ipairs({
    { uri = "/.well-known/x", args = "rest_route=/x/v1/upload", why = "a query string" },
    { uri = "/.well-known/x", method = "POST", why = "a POST" },
    { uri = "/.well-known/acme-challenge/sh.php", why = "a .php file" },
    { uri = "/.well-known/acme-challenge/sh.PHP7", why = "a .php7 file" },
    { uri = "/.well-known/x.phtml/y.txt", why = "PATH_INFO behind a script" },
    { uri = "/.well-known/webfinger", args = "resource=acct:a@b", why = "webfinger with its query" },
    -- nginx sends the RAW target upstream: it must be the decoded path itself.
    { uri = "/.well-known/x", request_uri = "/%73earch/%27%29%20UNION%20SELECT%201--%20/%2e%2e/%2e%2e/%2ewell-known/x",
      why = "a raw target that normalises into the prefix" },
    { uri = "/.well-known/x", request_uri = "/.well-known/x#payload", why = "a raw fragment" },
    { uri = "/.well-known/a.txt", request_uri = "/.well-known/a%2etxt", why = "an escaped byte" },
    -- A directory runs its index.php (DirectoryIndex).
    { uri = "/.well-known/acme-challenge/", why = "a directory" },
    { uri = "/.well-known/", why = "the prefix itself" },
  }) do
    local r = H.run{ uri = t.uri, args = t.args, method = t.method, request_uri = t.request_uri }
    -- The WAF or the bridge decides it (a bare POST can be challenged by
    -- the WAF before the bridge is asked).
    check(not bypassed(r) and (r.rpcs:find("decision", 1, true) or r.rpcs:find("waf_excludes", 1, true)),
          t.uri .. " with " .. t.why .. ": takes the normal pipeline: " .. desc(r))
  end
  -- And the WAF sees it: a SQLi in the query is blocked.
  local r = H.run{ uri = "/.well-known/x", args = "id=1'%20OR%20'1'='1" }
  check(r.exited == 403 or r.action == "block", "a SQLi under /.well-known/ is blocked: " .. desc(r))
end

-- ── well_known_plain against the fixture the Go engine runs too ─────────────
do
  local src = io.open("configs/lua/cfm.lua"):read("*a")
  local chunk = src:match("(local SCRIPT_EXT = %b{}.-\nlocal function well_known_plain%(m, path, args, raw%).-\nend\n)")
  check(chunk ~= nil, "well_known_plain found in cfm.lua")
  if chunk then
    local plain = assert(loadstring(chunk .. "\nreturn well_known_plain"))()
    local n = 0
    for line in io.lines("scripts/tests/fixtures/wellknown_exempt.txt") do
      local m, path, q, want = line:match("^(%u+)%s+(%S+)%s+(%S+)%s+([01])%s*$")
      if m then
        n = n + 1
        local got = plain(m, path, q ~= "-" and q or "", path)
        check(got == (want == "1"), ("well_known_plain(%s %s ?%s) = %s, want %s"):format(m, path, q, tostring(got), want))
      end
    end
    check(n >= 25, "fixture read (" .. n .. " cases)")
  end
end

-- ── The static decision key: never for a script behind PATH_INFO ─────────────
do
  local src = io.open("configs/lua/cfm.lua"):read("*a")
  local chunk = src:match("(local STATIC_ASSET_EXT = %b{}.-\nlocal function is_static_asset_uri%(uri%).-\nend\n)")
  -- (the chunk spans SCRIPT_EXT, path_has_script_ext and well_known_plain too)
  check(chunk ~= nil, "is_static_asset_uri found in cfm.lua")
  if chunk then
    local is_static = assert(loadstring(chunk .. "\nreturn is_static_asset_uri"))()
    for _, u in ipairs({ "/a/b.css", "/x.svg", "/bootstrap-4.6.0/css/x.css", "/img/a.PNG" }) do
      check(is_static(u), u .. " is a static asset")
    end
    for _, u in ipairs({ "/xmlrpc.php/x.css", "/forum/ucp.php/a.svg", "/x.PHP5/y.png", "/a.phtml/b.js",
                         "/cgi-bin/x.cgi/y.css", "/up/x.php.svg", "/x.php", "/a.css.php/x.png",
                         "/up/a.svg#.php", "/up/a.svg?.php", "/x.plx/y.svg" }) do
      check(not is_static(u), u .. " is not a static asset")
    end

    -- Through the real cfm_decision cache: a warmed static allow is not reused.
    local store = {}
    local SH = { get = function(_, k) return store[k] end, set = function(_, k, v) store[k] = v; return true end,
                 add = function(_, k, v) if store[k] then return false end store[k] = v; return true end,
                 delete = function(_, k) store[k] = nil end }
    local saved = _G.ngx
    _G.ngx = { md5 = function(s) return "M(" .. s .. ")" end, now = function() return 1 end,
               escape_uri = function(s) return s end, var = {}, ctx = {}, header = {}, log = function() end,
               WARN = 1, ERR = 0 }
    package.loaded["cfm_decision"] = nil
    local D = require("cfm_decision")
    local c = D.new({ token = "t" }, { shdict = SH, is_static = is_static })
    local k1 = c:cache_key("1.2.3.4", "ex.com", "GET", "https", "/logo.svg", "", "web")
    local k2 = c:cache_key("1.2.3.4", "ex.com", "POST", "https", "/xmlrpc.php/x.css", "", "web")
    check(k1:sub(1, 3) == "ds|", "a static asset coalesces: " .. k1)
    check(k2 ~= k1 and k2:sub(1, 2) == "d|", "/xmlrpc.php/x.css gets its own per-URL key: " .. k2)
    _G.ngx = saved
  end
end

-- ── Site Cache: the prefix that now reaches Step 4 is never micro-cached ─────
do
  local src = io.open("configs/lua/cfm_cache.lua"):read("*a")
  local chunk = src:match("(local MICRO_PATH_PREFIX = %b{}.-\nlocal function micro_path_blocked%(uri%).-\nend\n)")
  check(chunk ~= nil, "micro_path_blocked found in cfm_cache.lua")
  if chunk then
    local blocked = assert(loadstring(chunk .. "\nreturn micro_path_blocked"))()
    check(blocked("/.well-known/webfinger"), "/.well-known/webfinger is never micro-cached")
    check(blocked("/.well-known/x"), "/.well-known/x is never micro-cached")
    check(not blocked("/blog/post"), "an ordinary page still can be")
  end
end

if fails > 0 then
  io.stderr:write(("well-known / static-key tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: /.well-known/ plain-fetch carve-out and the static decision key")
