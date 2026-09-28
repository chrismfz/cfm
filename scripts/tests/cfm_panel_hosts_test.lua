-- Tests for cfm_panel_hosts.lua: the proxy-host set and the shared
-- is_panel_api_or_sso matcher that both edges use (cfm_panel.lua step 1 on the
-- panel listeners, cfm.lua Step 0a2 for cpanel./whm./webmail. on 80/443).
--
-- Also pins:
--   * cfm_panel.lua's upgrade-lag fallback copy (legacy_is_panel_api_or_sso)
--     to the module over a URI corpus, so the two cannot drift;
--   * cfm.lua Step 0a2 runs before the WAF, the challenge and the rules, and
--     keys on the proxy-host set + the shared matcher.

package.path = "configs/lua/?.lua;" .. package.path
local ph = require("cfm_panel_hosts")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function read(path)
  local f = assert(io.open(path, "r"))
  local s = f:read("*a"); f:close()
  return s
end

-- ── proxy-host set ───────────────────────────────────────────────────────────
for _, h in ipairs({ "cpanel.example.gr", "whm.example.gr", "webmail.example.gr",
                     "CPANEL.Example.GR", "cpanel.sub.example.gr" }) do
  check(ph.is_proxy_panel_host(h) == true, "proxy host: " .. h)
end
for _, h in ipairs({ "mail.example.gr", "webdisk.example.gr", "example.gr",
                     "mycpanel.example.gr", "www.cpanel.example.gr", "cpanel",
                     "", "cpanelx.example.gr" }) do
  check(ph.is_proxy_panel_host(h) == false, "not a proxy host: " .. h)
end
check(ph.is_proxy_panel_host(nil) == false, "nil host is not a proxy host")
-- The proxy set is a subset of the panel set (Site Cache etc. still treat
-- every proxy host as a panel host).
for _, p in ipairs(ph.PROXY_PREFIXES) do
  check(ph.is_panel_prefix(p), "proxy prefix is also a panel prefix: " .. p)
end

-- ── is_panel_api_or_sso ──────────────────────────────────────────────────────
local YES = {
  "/cpsess4305700936/json-api/cpanel",                      -- File Manager save
  "/cpsess4305700936/execute/Fileman/upload_files",         -- File Manager upload
  "/cpsess4305700936/execute/Fileman/save_file_content",
  "/cpsess1/xml-api/listaccts",
  "/cpsess1/login/",
  "/cpsess1/websocket/Shell",
  "/json-api/cpanel", "/json-api/listaccts", "/execute/Email/list_pops",
  "/xml-api/version", "/cpanelwebcall/abc", "/openid_connect/cpanelid",
  "/session", "/session/x", "/xfercpanel", "/xfercpsess", "/api", "/api/v1/x",
  "/acctxfer/x", "/cgi/transfer/x", "/cgi/live_tail_log",
}
local NO = {
  "/", "/login", "/login/", "/cpanel", "/whm", "/webmail",
  "/cpsess4305700936/frontend/jupiter/filemanager/index.html",
  "/cpsess4305700936/frontend/jupiter/filemanager/editit.html",
  "/cpsess4305700936/download",
  "/cpsessX/json-api/cpanel",            -- the token is digits only
  "/cpsess/json-api/cpanel",
  "/x/cpsess1/json-api/cpanel",          -- anchored at the start
  "/wp-json/wp/v2/posts", "/apix", "/sessions", "/json-apix",
  "/.well-known/acme-challenge/t", "",
}
for _, u in ipairs(YES) do check(ph.is_panel_api_or_sso(u) == true, "api/sso: " .. u) end
for _, u in ipairs(NO)  do check(ph.is_panel_api_or_sso(u) == false, "not api/sso: " .. u) end
check(ph.is_panel_api_or_sso(nil) == false, "nil uri is not api/sso")

-- ── cfm_panel.lua fallback copy == module ────────────────────────────────────
do
  local src = read("configs/lua/cfm_panel.lua")
  local block = src:match("%-%- BEGIN legacy_is_panel_api_or_sso\n(.-)%-%- END legacy_is_panel_api_or_sso")
  check(block ~= nil, "cfm_panel.lua carries the marked legacy_is_panel_api_or_sso block")
  if block then
    local chunk = "local function starts_with(s, p) return s and p and s:sub(1, #p) == p end\n"
      .. block .. "\nreturn legacy_is_panel_api_or_sso"
    local fn = assert(loadstring(chunk))()
    local corpus = {}
    for _, u in ipairs(YES) do corpus[#corpus + 1] = u end
    for _, u in ipairs(NO)  do corpus[#corpus + 1] = u end
    for _, u in ipairs(corpus) do
      check((fn(u) and true or false) == ph.is_panel_api_or_sso(u),
            "cfm_panel.lua fallback agrees with cfm_panel_hosts for " .. u)
    end
  end
  check(src:find("local is_panel_api_or_sso = (panel_hosts_mod and panel_hosts_mod.is_panel_api_or_sso)", 1, true) ~= nil,
        "cfm_panel.lua prefers the shared matcher")
end

-- ── cfm.lua Step 0a2: placement and keys ─────────────────────────────────────
do
  local src = read("configs/lua/cfm.lua")
  local s0a2 = src:find("-- ── Step 0a2: cPanel proxy-subdomain API passthrough", 1, true)
  check(s0a2 ~= nil, "cfm.lua has Step 0a2")
  if s0a2 then
    local wk   = src:find("-- ── Step 0a1:", 1, true)
    local s0c  = src:find("-- ── Step 0c", 1, true)
    local waf  = src:find("-- ── Step 2: Inline WAF", 1, true)
    check(wk and wk < s0a2, "Step 0a2 follows Step 0a1")
    check(s0c and s0a2 < s0c, "Step 0a2 runs before Step 0c (fingerprint policy)")
    check(waf and s0a2 < waf, "Step 0a2 runs before the inline WAF")
    local body = src:sub(s0a2, src:find("\nend\n", s0a2, true) or #src)
    check(body:find("panel_hosts.is_proxy_panel_host(host)", 1, true) ~= nil,
          "Step 0a2 keys on the proxy-host set")
    check(body:find("panel_hosts.is_panel_api_or_sso(uri)", 1, true) ~= nil,
          "Step 0a2 keys on the shared api/sso matcher")
  end
end

if fails > 0 then
  io.stderr:write(string.format("\n%d cfm_panel_hosts test(s) failed\n", fails))
  os.exit(1)
end
print("ok: cfm_panel_hosts tests")
