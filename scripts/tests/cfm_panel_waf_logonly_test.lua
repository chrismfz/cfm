-- Tests cfm_panel.lua's LOGONLY panel WAF probe (edge-unification 2e).
--
-- The panel runs the SAME cfm_waf ruleset the web edge uses against human-entry
-- + generic requests and RECORDS what it WOULD do, but must NOT act on the
-- verdict. This test injects a FAKE cfm_waf whose check() returns a configurable
-- hit and pins the safety properties:
--   1) a WAF hit emits a `[cfm_panel_waf] logonly=would_<action>` line but does
--      NOT change control flow (a no-clearance browser is still challenged; it
--      is never blocked/allowed BECAUSE of the WAF);
--   2) a clean request (no hit) emits no such line;
--   3) the probe reads NO request body (reduced profile: ctx.body == "");
--   4) api/sso/allowlisted paths are hard-skipped BEFORE the probe (never seen);
--   5) loopback/self traffic is skipped;
--   6) the CFM_PANEL_WAF=0 kill switch disables the probe entirely;
--   7) both engine confs declare `env CFM_PANEL_WAF;` (else the switch is inert).

local panel_path = "configs/lua/cfm_panel.lua"

-- Shared harness state, reset per load.
local waf_hit, waf_ctx, checks, log_lines

local function install_fakes()
  package.loaded["cjson.safe"] = { encode = function(_) return "{}" end, decode = function() return nil end }
  -- FAKE cfm_waf: records each ctx and returns the configured verdict.
  package.loaded["cfm_waf"] = {
    enabled = function() return true end,
    check = function(ctx)
      checks[#checks + 1] = ctx
      waf_ctx = ctx
      if waf_hit then
        -- hit, reason, ttl, action, hits, rule_id
        return true, waf_hit.reason or "WAF_SQLI:TEST", waf_hit.ttl or 600,
               waf_hit.action or "block", 1, waf_hit.rule_id or 320
      end
      return false, nil, nil, nil
    end,
  }
  -- cfm_decision ABSENT for this test: the decision probe is a no-op so it can
  -- never emit lines that confuse the WAF assertions.
  package.preload["cfm_decision"] = function() error("absent for waf test") end
  package.loaded["cfm_bridge_cfg"] = {
    get = function() return { clearance_refresh = true, cookie_life_sec = 2700 } end,
    token = function() return "test-bridge-secret" end,
    refresh_token_throttled = function() return nil end,
    TOKEN_PATH = "/var/lib/cfm/lua/cfm_bridge_token.lua",
  }
  package.loaded["cfm_clearance"] = {
    validate = function(_) return false, "scope_mismatch" end,
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
  waf_hit = opts.waf_hit  -- nil = clean
  checks, log_lines, waf_ctx = {}, {}, nil

  local actions = {}
  local ngx = {
    INFO = 1, WARN = 2, DEBUG = 3, ERR = 0, NOTICE = 5,
    HTTP_TEMPORARY_REDIRECT = 307, HTTP_FORBIDDEN = 403, HTTP_NOT_FOUND = 404, HTTP_INTERNAL_SERVER_ERROR = 500,
    header = {}, ctx = {},
    var = {
      uri = opts.uri or "/", request_uri = opts.uri or "/",
      host = "cpanel.example.com",
      remote_addr = opts.ip or "203.0.113.9", http_authorization = "",
      http_user_agent = opts.ua or "Mozilla/5.0", http_cookie = "",
      cookie_cfm_ok = "", cookie_cfm_clearance = "",
      cfm_panel_origin = "https://127.0.0.1:2087", cfm_panel_challenge_mode = "forced",
      cfm_panel_challenge_location = "/__cfm_challenge", server_port = "12087",
      scheme = "https", args = opts.args or "",
    },
    req = {
      get_method = function() return opts.method or "GET" end,
      get_uri_args = function() return {} end,
      get_headers = function() return {} end,
      is_internal = function() return false end,
    },
    shared = { cfm_decisions = { get = function() return nil end, set = function() end, add = function() return true end, delete = function() end } },
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
  package.preload["cfm_decision"] = nil
  package.loaded["cfm_waf"] = nil
  package.loaded["cjson.safe"] = nil
  package.loaded["cfm_bridge_cfg"] = nil
  package.loaded["cfm_clearance"] = nil
  return ngx, actions[#actions]
end

local function assert_true(c, m) if not c then error(m, 2) end end
local function has_waf_line(kind)
  for _, l in ipairs(log_lines) do
    if l:find("[cfm_panel_waf] logonly=would_" .. kind, 1, true) then return true end
  end
  return false
end
local function any_waf_line()
  for _, l in ipairs(log_lines) do if l:find("[cfm_panel_waf]", 1, true) then return true end end
  return false
end

-- 1) WAF hit on a no-clearance browser: probe logs would_block, but the flow is
--    UNCHANGED — the request is still challenged (redirect 307), never blocked.
do
  local _, last = run({ waf_hit = { action = "block", reason = "WAF_SQLI:TEST", rule_id = 320 } })
  assert_true(#checks == 1, "waf.check called once on human-entry (got " .. #checks .. ")")
  assert_true(has_waf_line("block"), "WAF hit emits `[cfm_panel_waf] logonly=would_block`")
  assert_true(last and last.action == "redirect" and last.code == 307,
              "control flow UNCHANGED: no-clearance browser is still challenged (not blocked by the WAF)")
end

-- 2) clean request: probe runs, no line.
do
  run({ waf_hit = nil })
  assert_true(#checks == 1, "waf.check still called on a clean request")
  assert_true(not any_waf_line(), "clean request emits NO [cfm_panel_waf] line")
end

-- 3) reduced profile: the probe reads NO body.
do
  run({ waf_hit = { action = "logonly", reason = "WAF_XSS:TEST", rule_id = 210 } })
  assert_true(waf_ctx ~= nil and waf_ctx.body == "", "panel WAF probe passes an EMPTY body (never buffers the panel body)")
  assert_true(has_waf_line("logonly"), "a logonly hit is recorded as would_logonly")
end

-- 4) api/sso path is hard-skipped BEFORE the probe.
do
  run({ uri = "/execute/Foo/bar", waf_hit = { action = "block", reason = "WAF_RCE:TEST" } })
  assert_true(#checks == 0, "api/sso path (/execute/...) is hard-skipped: waf.check never runs")
  assert_true(not any_waf_line(), "api/sso path emits no WAF line")
end

-- 5) loopback/self traffic is skipped.
do
  run({ ip = "127.0.0.1", waf_hit = { action = "block", reason = "WAF_SQLI:TEST" } })
  assert_true(#checks == 0, "loopback self-IP is skipped: waf.check never runs")
  assert_true(not any_waf_line(), "loopback self-IP emits no WAF line")
end

-- 6) kill switch CFM_PANEL_WAF=0: construction is skipped, no probe fires, panel
--    challenges normally. luajit has no os.setenv, so wrap os.getenv for the load
--    (read at module top level) and restore it after.
do
  local real_getenv = os.getenv
  os.getenv = function(k) if k == "CFM_PANEL_WAF" then return "0" end return real_getenv(k) end
  local ok_run, _, last_off = pcall(run, { waf_hit = { action = "block", reason = "WAF_SQLI:TEST" } })
  os.getenv = real_getenv
  assert_true(ok_run, "kill-switch load did not raise")
  assert_true(#checks == 0, "CFM_PANEL_WAF=0: waf.check never runs (got " .. #checks .. ")")
  assert_true(not any_waf_line(), "CFM_PANEL_WAF=0: no WAF line")
  assert_true(last_off and last_off.action == "redirect",
              "CFM_PANEL_WAF=0: panel still challenges normally (probe off, flow intact)")
end

-- 7) Production kill-switch wiring: workers only see an env var if it is
--    re-exported with an `env` directive. Assert both engine confs declare it.
do
  for _, conf in ipairs({ "configs/openresty.conf", "configs/angie.conf" }) do
    local fh = assert(io.open(conf, "r"), "cannot open " .. conf)
    local src = fh:read("*a"); fh:close()
    assert_true(src:find("env%s+CFM_PANEL_WAF%s*;") ~= nil,
      conf .. " must declare `env CFM_PANEL_WAF;` or the kill switch is inert in workers")
  end
end

print("ok: cfm_panel logonly WAF probe — records, never enforces")
