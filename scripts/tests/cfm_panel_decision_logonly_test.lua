-- Tests cfm_panel.lua's LOGONLY bridge-decision probe (edge-unification 2d).
--
-- The panel consults /nginx/decision (scope=panel:<port>) via the shared
-- cfm_decision module and RECORDS what the bridge would do, but must NOT act on
-- the verdict. This test injects a FAKE cfm_decision whose get() returns a
-- configurable verdict and pins the two safety properties:
--   1) a would-enforce verdict emits a `logonly=would_enforce` log line but does
--      NOT change control flow (a no-clearance browser is still challenged; it
--      is never blocked/allowed BECAUSE of the verdict);
--   2) a clean-allow verdict emits no such line;
--   3) a valid clearance still fires ok/touch (the bypass hint);
--   4) the CFM_PANEL_DECISION=0 kill switch disables the probe entirely.

local panel_path = "configs/lua/cfm_panel.lua"

-- Shared harness state, reset per load.
local verdict, probe_gets, rpc_kinds, log_lines, clearance_valid

local function install_fakes()
  package.loaded["cjson.safe"] = { encode = function(_) return "{}" end, decode = function() return nil end }
  package.loaded["cfm_decision"] = {
    classify_bridge_err = function() return "unknown" end,
    new = function(_, _)
      return {
        get = function(_, ip, host, uri, _qs, _m, scheme, _ua, _c, scope)
          probe_gets[#probe_gets + 1] = { ip = ip, host = host, uri = uri, scope = scope, scheme = scheme }
          return verdict
        end,
        rpc = function(_, kind) rpc_kinds[#rpc_kinds + 1] = kind; return "", nil end,
      }
    end,
  }
  package.loaded["cfm_bridge_cfg"] = {
    get = function() return { clearance_refresh = true, cookie_life_sec = 2700 } end,
    token = function() return "test-bridge-secret" end,
    refresh_token_throttled = function() return nil end,
    TOKEN_PATH = "/var/lib/cfm/lua/cfm_bridge_token.lua",
  }
  package.loaded["cfm_clearance"] = {
    validate = function(token) if clearance_valid and token and token ~= "" then return true, "ok" end return false, "scope_mismatch" end,
    mint = function(_, _, scope) return "MINTED_" .. tostring(scope) end,
    normalize_host = function(h) return tostring(h or ""):lower() end,
    panel_scope = function(_, _, origin, sp)
      local port = tostring(origin or ""):match(":(%d+)") or tostring(sp or "")
      return "panel:" .. (port ~= "" and port or "unknown")
    end,
  }
end

local function run(opts)
  opts = opts or {}
  verdict = opts.verdict or { ip_action = "allow", vhost_action = "allow" }
  clearance_valid = opts.clearance_valid or false
  probe_gets, rpc_kinds, log_lines = {}, {}, {}

  local actions = {}
  local ngx = {
    INFO = 1, WARN = 2, DEBUG = 3, ERR = 0, NOTICE = 5,
    HTTP_TEMPORARY_REDIRECT = 307, HTTP_FORBIDDEN = 403, HTTP_NOT_FOUND = 404, HTTP_INTERNAL_SERVER_ERROR = 500,
    header = {}, ctx = {},
    var = {
      uri = "/", request_uri = "/", host = "cpanel.example.com",
      remote_addr = "203.0.113.9", http_authorization = "",
      http_user_agent = opts.ua or "Mozilla/5.0", http_cookie = "",
      cookie_cfm_ok = "", cookie_cfm_clearance = opts.clearance_valid and "TOK" or "",
      cfm_panel_origin = "https://127.0.0.1:2087", cfm_panel_challenge_mode = "forced",
      cfm_panel_challenge_location = "/__cfm_challenge", server_port = "12087",
      scheme = "https", args = "",
    },
    req = { get_method = function() return "GET" end, get_uri_args = function() return {} end, is_internal = function() return false end },
    shared = { cfm_decisions = { get = function() return nil end, set = function() end, add = function() return true end, delete = function() end },
               cfm_stats = { get = function() return nil end, set = function() end } },
    now = function() return 1000 end, time = function() return 1000 end,
    log = function(_, ...)
      local p = {}
      for i = 1, select("#", ...) do p[i] = tostring((select(i, ...))) end
      log_lines[#log_lines + 1] = table.concat(p)
    end,
    location = { capture = function() return { status = 200, body = "c", header = {} } end },
    redirect = function(loc, code) actions[#actions + 1] = { action = "redirect", location = loc, code = code } end,
    exit = function(code) actions[#actions + 1] = { action = "exit", code = code } end,
    decode_base64 = function(s) return s end, unescape_uri = function(v) return v end,
    escape_uri = function(v) return tostring(v):gsub("/", "%%2F") end,
  }
  _G.ngx = ngx
  install_fakes()
  assert(loadfile(panel_path))()
  package.loaded["cfm_decision"] = nil
  package.loaded["cjson.safe"] = nil
  package.loaded["cfm_bridge_cfg"] = nil
  package.loaded["cfm_clearance"] = nil
  return ngx, actions[#actions]
end

local function assert_true(c, m) if not c then error(m, 2) end end
local function has_would_enforce(ngx)
  for _, l in ipairs(log_lines) do if l:find("logonly=would_enforce", 1, true) then return true end end
  return false
end
local function count(t, v) local n = 0 for _, x in ipairs(t) do if x == v then n = n + 1 end end return n end

-- 1) would-enforce verdict on a no-clearance browser: probe logs, but the flow
--    is UNCHANGED — the request is still challenged (redirect 307), never
--    blocked/allowed because of the verdict.
do
  local ngx, last = run({ verdict = { ip_action = "block", vhost_action = "allow" }, clearance_valid = false })
  assert_true(#probe_gets == 1, "probe called once on human-entry (got " .. #probe_gets .. ")")
  assert_true(probe_gets[1].scope == "panel:2087", "probe uses panel:<port> scope (got " .. tostring(probe_gets[1].scope) .. ")")
  assert_true(has_would_enforce(ngx), "would-enforce verdict emits the logonly line")
  assert_true(last and last.action == "redirect" and last.code == 307,
              "control flow UNCHANGED: no-clearance browser is still challenged (not blocked by the verdict)")
end

-- 2) clean-allow verdict: probe runs, but no would-enforce line.
do
  local ngx = run({ verdict = { ip_action = "allow", vhost_action = "allow" }, clearance_valid = false })
  assert_true(#probe_gets == 1, "probe still called on clean verdict")
  assert_true(not has_would_enforce(ngx), "clean-allow verdict emits NO would-enforce line")
end

-- 3) valid clearance: request is allowed AND ok/touch fires (bypass hint).
do
  local ngx, last = run({ verdict = { ip_action = "allow", vhost_action = "allow" }, clearance_valid = true })
  assert_true(last == nil or last.action ~= "redirect", "valid clearance is not challenged")
  assert_true(ngx.var.cfm_upstream == "cfm_panel_origin", "valid clearance passes to origin")
  assert_true(count(rpc_kinds, "ok_touch") == 1, "valid clearance fires exactly one ok_touch (got " .. count(rpc_kinds, "ok_touch") .. ")")
end

-- 4) kill switch CFM_PANEL_DECISION=0: the fake module IS present, but the
--    switch is off, so construction is skipped and no probe fires. luajit has
--    no os.setenv, so we wrap os.getenv for the load (which reads the env at
--    module top level) and restore it after. This is the REAL switch path, not
--    a proxy. (In production the switch also needs `env CFM_PANEL_DECISION;` in
--    the engine conf so workers see it — asserted at the end of this file.)
do
  local verdict_local = { ip_action = "block", vhost_action = "allow" }
  local real_getenv = os.getenv
  os.getenv = function(k) if k == "CFM_PANEL_DECISION" then return "0" end return real_getenv(k) end
  local ok_run, ngx_off, last_off = pcall(run, { verdict = verdict_local, clearance_valid = false })
  os.getenv = real_getenv
  assert_true(ok_run, "kill-switch load did not raise")
  assert_true(#probe_gets == 0, "CFM_PANEL_DECISION=0: no probe fired (got " .. #probe_gets .. ")")
  assert_true(#rpc_kinds == 0, "CFM_PANEL_DECISION=0: no ok/touch fired")
  assert_true(last_off and last_off.action == "redirect",
              "CFM_PANEL_DECISION=0: panel still challenges normally (probe off, flow intact)")
end

-- 5) module ABSENT (upgrade lag: new cfm_panel.lua, old /var/lib/cfm/lua without
--    cfm_decision): pcall(require) fails, panel_decision stays nil, probe is a
--    no-op, and the panel challenges exactly as before.
do
  verdict = { ip_action = "block", vhost_action = "allow" }
  clearance_valid = false
  probe_gets, rpc_kinds, log_lines = {}, {}, {}
  local actions = {}
  local ngx = {
    INFO = 1, WARN = 2, DEBUG = 3, ERR = 0, NOTICE = 5,
    HTTP_TEMPORARY_REDIRECT = 307, HTTP_FORBIDDEN = 403, HTTP_NOT_FOUND = 404, HTTP_INTERNAL_SERVER_ERROR = 500,
    header = {}, ctx = {},
    var = { uri = "/", request_uri = "/", host = "cpanel.example.com", remote_addr = "203.0.113.9",
            http_authorization = "", http_user_agent = "Mozilla/5.0", http_cookie = "", cookie_cfm_ok = "",
            cookie_cfm_clearance = "", cfm_panel_origin = "https://127.0.0.1:2087",
            cfm_panel_challenge_mode = "forced", cfm_panel_challenge_location = "/__cfm_challenge",
            server_port = "12087", scheme = "https", args = "" },
    req = { get_method = function() return "GET" end, get_uri_args = function() return {} end, is_internal = function() return false end },
    shared = { cfm_decisions = { get = function() return nil end, set = function() end, add = function() return true end, delete = function() end },
               cfm_stats = { get = function() return nil end, set = function() end } },
    now = function() return 1000 end, time = function() return 1000 end, log = function() end,
    location = { capture = function() return { status = 200, body = "c", header = {} } end },
    redirect = function(loc, code) actions[#actions + 1] = { action = "redirect", location = loc, code = code } end,
    exit = function(code) actions[#actions + 1] = { action = "exit", code = code } end,
    decode_base64 = function(s) return s end, unescape_uri = function(v) return v end,
    escape_uri = function(v) return tostring(v):gsub("/", "%%2F") end,
  }
  _G.ngx = ngx
  -- cfm_decision ABSENT (upgrade lag / kill switch equivalent): pcall(require) fails.
  package.loaded["cfm_decision"] = nil
  package.preload["cfm_decision"] = function() error("absent") end
  package.loaded["cjson.safe"] = { encode = function() return "{}" end, decode = function() return nil end }
  package.loaded["cfm_bridge_cfg"] = { get = function() return {} end, token = function() return "s" end }
  package.loaded["cfm_clearance"] = package.loaded["cfm_clearance"] or {
    validate = function() return false, "x" end, mint = function() return "m" end,
    normalize_host = function(h) return tostring(h or ""):lower() end,
    panel_scope = function() return "panel:2087" end,
  }
  assert(loadfile(panel_path))()
  package.preload["cfm_decision"] = nil
  package.loaded["cjson.safe"] = nil; package.loaded["cfm_bridge_cfg"] = nil; package.loaded["cfm_clearance"] = nil
  assert_true(#probe_gets == 0, "module absent (kill-switch-equivalent): no probe fired")
  assert_true(actions[#actions] and actions[#actions].action == "redirect",
              "module absent: panel still challenges normally (no dependency on the probe)")
  local _ = prev
end

-- 6) Production kill-switch wiring: nginx/OpenResty workers only see an env var
--    if it is re-exported with an `env` directive. The CFM_PANEL_DECISION switch
--    is inert without it, so assert both engine confs declare it (regression
--    guard for the exact "advertised-but-dead switch" bug this replaces).
do
  for _, conf in ipairs({ "configs/openresty.conf", "configs/angie.conf" }) do
    local fh = assert(io.open(conf, "r"), "cannot open " .. conf)
    local src = fh:read("*a"); fh:close()
    assert_true(src:find("env%s+CFM_PANEL_DECISION%s*;") ~= nil,
      conf .. " must declare `env CFM_PANEL_DECISION;` or the kill switch is inert in workers")
  end
end

print("ok: cfm_panel logonly bridge decision — records, never enforces")
