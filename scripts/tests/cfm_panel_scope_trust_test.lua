-- Tests that the panel challenge scope is derived from the TRUSTED per-listener
-- origin port, not client-suppliable headers (audit F41).
--
-- cfm_panel.lua's main() computed panel_scope from ngx.var.http_x_cfm_panel_port /
-- http_x_forwarded_port (client headers) with priority over the trusted
-- $cfm_panel_origin port. On the main panel request those headers are attacker-
-- supplied, so a clearance solved on one panel port (e.g. panel:2083) could be
-- replayed on another listener (2087) by sending `X-CFM-Panel-Port: 2083`, voiding
-- per-port isolation. The fix drops the client-header args from the panel_scope()
-- call, so the scope follows the trusted $cfm_panel_origin port.

-- cjson stub so cfm_clearance loads (panel_scope itself is pure string logic).
package.loaded["cjson.safe"] = { encode = function() end, decode = function() end }
package.loaded["cjson"] = package.loaded["cjson.safe"]
_G.ngx = _G.ngx or {}
package.path = "configs/lua/?.lua;" .. package.path
local cl = require("cfm_clearance")
local panel_scope = cl.panel_scope

local fails = 0
local function check(cond, msg) if cond then return end fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end

-- ── 1) Call-site guard: cfm_panel.lua must NOT feed the client headers in ──────
do
  local src = assert(io.open("configs/lua/cfm_panel.lua")):read("*a")
  local callarg = src:match("clearance_validator%.panel_scope(%b())")
  check(callarg ~= nil, "found the panel_scope() call in cfm_panel.lua")
  if callarg then
    check(not callarg:find("http_x_cfm_panel_port", 1, true),
          "F41: panel_scope() call no longer passes client X-CFM-Panel-Port")
    check(not callarg:find("http_x_forwarded_port", 1, true),
          "F41: panel_scope() call no longer passes client X-Forwarded-Port")
    check(callarg:find("origin", 1, true) ~= nil,
          "panel_scope() call still uses the trusted origin")
  end
end

-- ── 2) Behaviour: the trusted origin port wins; a client value can't sneak in ──
do
  local ORIGIN_2087 = "https://127.0.0.1:2087"
  -- New (fixed) call pattern: client-header args are nil -> origin decides.
  check(panel_scope(nil, nil, ORIGIN_2087, "9999") == "panel:2087",
        "fixed pattern: scope follows the trusted origin port (2087)")
  -- The vulnerability, on panel_scope itself: had the client port been passed it
  -- would have won — this is exactly what the call-site fix stops feeding in.
  check(panel_scope("2083", nil, ORIGIN_2087, "2087") == "panel:2083",
        "old pattern (client port passed) WOULD win -> panel:2083 (why the fix drops it)")
  check(panel_scope(nil, "2083", ORIGIN_2087, "2087") == "panel:2083",
        "old pattern (client X-Forwarded-Port passed) WOULD win -> panel:2083")
  -- The concrete replay: on the 2087 listener, a forged 2083 header must NOT
  -- reduce the scope to panel:2083 under the fixed (nil) pattern.
  check(panel_scope(nil, nil, ORIGIN_2087, "2087") ~= "panel:2083",
        "F41 repro closed: forged 2083 header can't make the 2087 listener validate a panel:2083 clearance")
end

-- ── 3) Guardrail: the mint/validate invariant the fix relies on ───────────────
-- The Go challenge server mints the scope from the injected X-CFM-Panel-Port; the
-- edge validates from $cfm_panel_origin's port. They agree only if, per listener
-- block, the origin port == the injected X-CFM-Panel-Port. Assert that here so a
-- future config edit can't silently break panel clearance validation.
do
  local conf = assert(io.open("configs/cfm-panel-listeners.conf.in")):read("*a")
  local origins, checked = {}, 0
  for port in conf:gmatch('cfm_panel_origin "[^"]*:(%d+)"') do origins[#origins + 1] = port end
  -- For each origin occurrence, scan the window up to the NEXT origin and assert
  -- every injected X-CFM-Panel-Port in that block equals this block's origin port.
  local pos = 1
  for idx = 1, #origins do
    local s = conf:find('cfm_panel_origin "', pos, true)
    if not s then break end
    local window = conf:sub(s)
    local nexto = window:find('cfm_panel_origin "', 20, true)
    if nexto then window = window:sub(1, nexto - 1) end
    for p in window:gmatch("X%-CFM%-Panel%-Port (%d+)") do
      checked = checked + 1
      check(p == origins[idx],
            "invariant: block origin :" .. origins[idx] .. " must inject X-CFM-Panel-Port " ..
            origins[idx] .. " (found " .. p .. ")")
    end
    pos = s + 18
  end
  check(#origins >= 7, "all known panel listener blocks carry a $cfm_panel_origin (got " .. #origins .. ")")
  check(checked >= #origins,
        "every listener block's X-CFM-Panel-Port injection was checked (blocks=" .. #origins ..
        " injections=" .. checked .. ")")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_panel_scope_trust_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: panel scope derived from the trusted listener origin port, not client headers (F41)\n")
