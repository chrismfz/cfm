-- Tests for cfm_panel_hosts.lua: the proxy-host set and the shared
-- is_panel_api_or_sso matcher that both edges use (cfm_panel.lua step 1 on the
-- panel listeners, cfm.lua Step 0d for cpanel./whm./webmail. on 80/443).
--
-- Also pins:
--   * proxy_hosts_reach_panel: only an explicit `proxysubdomains=1` AND
--     `proxysubdomainsoverride=0` in cpanel.config arm the web-edge
--     passthrough (fail closed otherwise);
--   * cfm_panel.lua keeps NO inline copy of the matcher (CLAUDE.md §5);
--   * cfm.lua Step 0d runs after Steps 0b/0c (UA emergency, fingerprint deny)
--     and before the WAF, and requires all three gates.

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
                     "", "cpanelx.example.gr",
                     -- two labels: only a tenant's own domain is named like that
                     "webmail.gr", "cpanel.gr", "cpanel.gr.", "cpanel..gr", "cpanel." }) do
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

-- ── proxy_hosts_reach_panel ──────────────────────────────────────────────────
do
  local tmp = os.tmpname()
  local function with_cfg(content, now)
    if content then
      local f = assert(io.open(tmp, "w")); f:write(content); f:close()
    else
      os.remove(tmp)
    end
    ph.CPANEL_CONFIG = tmp
    ph._reset_proxy_cfg()
    return ph.proxy_hosts_reach_panel(now or 1000)
  end
  check(with_cfg("a=1\nproxysubdomains=1\nproxysubdomainsoverride=0\n") == true,
        "proxysubdomains=1 + override=0 → on (orion's settings)")
  check(with_cfg("proxysubdomainsoverride=0\r\nproxysubdomains=1\r\n") == true, "CRLF line ends, any key order → on")
  check(with_cfg("proxysubdomains=1\nproxysubdomainsoverride=1\n") == false,
        "override=1 (tenant may own webmail.x) → off")
  check(with_cfg("proxysubdomains=1\n") == false, "override key absent = cPanel default 1 → off")
  check(with_cfg("proxysubdomains=0\nproxysubdomainsoverride=0\n") == false, "proxysubdomains=0 → off")
  check(with_cfg("proxysubdomainsoverride=0\n") == false, "proxysubdomains key absent → off")
  check(with_cfg("") == false, "empty file → off")
  check(with_cfg(nil) == false, "missing file (DirectAdmin / no panel) → off")
  -- Cached per TTL: a flip is seen only after the window.
  with_cfg("proxysubdomains=1\nproxysubdomainsoverride=0\n", 1000)
  local f = assert(io.open(tmp, "w")); f:write("proxysubdomains=1\nproxysubdomainsoverride=1\n"); f:close()
  check(ph.proxy_hosts_reach_panel(1000 + ph.PROXY_CFG_TTL - 1) == true, "cached within TTL")
  check(ph.proxy_hosts_reach_panel(1000 + ph.PROXY_CFG_TTL) == false, "re-read after TTL")
  os.remove(tmp)
  ph.CPANEL_CONFIG = "/var/cpanel/cpanel.config"
  ph._reset_proxy_cfg()
end

-- ── shared dict: one worker reads, the others read the dict ──────────────────
do
  local store = {}
  local sh = {
    get = function(_, k) return store[k] end,
    set = function(_, k, v) store[k] = v; return true end,
  }
  local tmp = os.tmpname()
  local f = assert(io.open(tmp, "w")); f:write("proxysubdomains=1\nproxysubdomainsoverride=0\n"); f:close()
  ph.CPANEL_CONFIG = tmp
  ph._reset_proxy_cfg()
  check(ph.proxy_hosts_reach_panel(1000, sh) == true, "shared dict: first read from the file")
  check(store["cfm_cpanel_proxy_reach"] == "1|1000", "shared dict: answer + read time published for the other workers")
  -- Another worker (fresh module cache) with the file gone reads the dict.
  os.remove(tmp)
  ph._reset_proxy_cfg()
  check(ph.proxy_hosts_reach_panel(1000, sh) == true, "shared dict: another worker reads the dict, not the file")
  store = {}
  ph._reset_proxy_cfg()
  check(ph.proxy_hosts_reach_panel(1000, sh) == false, "shared dict expired + file gone → off")
  check(store["cfm_cpanel_proxy_reach"] == "0|1000", "shared dict: off is published too")
  -- No stacked TTLs: a worker reading a 50 s old dict value trusts it only
  -- for the remaining 10 s, then reads the file itself.
  local g = assert(io.open(tmp, "w")); g:write("proxysubdomains=1\nproxysubdomainsoverride=0\n"); g:close()
  store = { cfm_cpanel_proxy_reach = "0|1000" }
  ph._reset_proxy_cfg()
  check(ph.proxy_hosts_reach_panel(1050, sh) == false, "stacked TTL: dict value still fresh at +50 s")
  check(ph.proxy_hosts_reach_panel(1059, sh) == false, "stacked TTL: cached until the dict value's own expiry")
  store = { cfm_cpanel_proxy_reach = "0|1000" } -- nginx may still hold an expired-by-age value
  check(ph.proxy_hosts_reach_panel(1060, sh) == true, "stacked TTL: re-read at read time + TTL, not +2×TTL")
  os.remove(tmp)
  ph.CPANEL_CONFIG = "/var/cpanel/cpanel.config"
  ph._reset_proxy_cfg()
end

-- ── Step 0d host + path gates: the vectors the Go engine also runs ────────────
do
  local n = 0
  for line in io.lines("scripts/tests/fixtures/panel_session_api.txt") do
    if line ~= "" and line:sub(1, 1) ~= "#" then
      local host, path, want = line:match("^([^\t]*)\t([^\t]*)\t([^\t]*)$")
      check(host ~= nil, "malformed vector: " .. line)
      if host then
        local got = ph.is_proxy_panel_host(host) and ph.is_session_api(path)
        check(got == (want == "yes"), string.format("vector %s %s → %s", host, path, want))
        n = n + 1
      end
    end
  end
  check(n >= 20, "shared vectors read (" .. n .. ")")
  -- is_session_api is a subset of the panel ports' list.
  for _, k in ipairs(ph.SESSION_KINDS) do
    local u = "/cpsess1/" .. k .. "/x"
    check(ph.is_session_api(u) and ph.is_panel_api_or_sso(u), "session kind is on the ports' list: " .. k)
  end
end

-- ── cfm_panel.lua uses the module, with no inline copy ───────────────────────
do
  local src = read("configs/lua/cfm_panel.lua")
  check(src:find("is_panel_api_or_sso = panel_hosts_mod.is_panel_api_or_sso", 1, true) ~= nil,
        "cfm_panel.lua takes the matcher from cfm_panel_hosts")
  for _, marker in ipairs({ '"/cgi/live_tail_log"', '"/xfercpsess"', '"/openid_connect/"', "json%-api/" }) do
    check(src:find(marker, 1, true) == nil,
          "cfm_panel.lua carries no inline copy of the api/sso list (" .. marker .. ")")
  end
end

-- ── cfm.lua Step 0d: placement and gates ─────────────────────────────────────
do
  local src = read("configs/lua/cfm.lua")
  local s0d = src:find("-- ── Step 0d: cPanel proxy-subdomain API passthrough", 1, true)
  check(s0d ~= nil, "cfm.lua has Step 0d")
  if s0d then
    local s0b = src:find("-- ── Step 0b:", 1, true)
    local s0c = src:find("-- ── Step 0c", 1, true)
    local waf = src:find("-- ── Step 2: Inline WAF", 1, true)
    local res = s0c and src:find("\ntry_apply_post_resume(ip, host)", s0c, true)
    local clr = src:find("-- ── Step 1: Validate clearance", 1, true)
    check(s0b and s0b < s0d, "Step 0d follows Step 0b (UA emergency still applies)")
    check(s0c and s0c < s0d, "Step 0d follows Step 0c (fingerprint deny still applies)")
    check(res and res < s0d, "Step 0d follows the POST resume (a resumed save keeps its body)")
    check(clr and s0d < clr, "Step 0d runs before clearance validation")
    check(waf and s0d < waf, "Step 0d runs before the inline WAF")
    local stop = src:find("\nend\n", s0d, true) or #src
    local body = src:sub(s0d, stop + 4)
    for _, gate in ipairs({
      "panel_hosts.is_proxy_panel_host(host)",
      "panel_hosts.is_session_api(uri)",
      "panel_hosts.proxy_hosts_reach_panel(nil, SH)",
    }) do
      check(body:find(gate, 1, true) ~= nil, "Step 0d requires " .. gate)
    end
    -- The web edge passes the /cpsess<N>/ subset only, never the ports' full list.
    check(body:find("is_panel_api_or_sso(uri)", 1, true) == nil,
          "Step 0d must not pass the ports' full api/sso list on the web edge")
    -- The action: origin upstream, origin pass, and an immediate return.
    local cond_end = body:find(" then\n", 1, true)
    local action = cond_end and body:sub(cond_end) or ""
    check(action:find('ngx.var.cfm_upstream = "cfm_apache"; ngx.var.cfm_pass = origin_pass_for(scheme)\n  return\nend', 1, true) ~= nil,
          "Step 0d routes to the origin and returns at once")
    check(action:find("cfm_challenge", 1, true) == nil and action:find("cfm_block", 1, true) == nil,
          "Step 0d never routes to the challenge or block upstream")
  end
end

if fails > 0 then
  io.stderr:write(string.format("\n%d cfm_panel_hosts test(s) failed\n", fails))
  os.exit(1)
end
print("ok: cfm_panel_hosts tests")
