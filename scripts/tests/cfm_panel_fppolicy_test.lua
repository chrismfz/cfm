-- Tests cfm_panel.lua's step 2f: the panel-port consult of the fleet-armed
-- fingerprint policy (master plan item — an operator-armed fp `deny` covers
-- :2083/:2087/:2096 too). Fakes cfm_tlsfp + cfm_fppolicy and pins:
--   1) enforce + armed deny → hard 403 BEFORE the human-entry challenge;
--   2) logonly + armed deny → `logonly=would_deny` line, flow unchanged;
--   3) challenge/challenge_v2 fingerprints are OBSERVE-ONLY on panel ports
--      (logged, never enforced, never challenged from the policy) in BOTH modes;
--   4) mode off → the lookup never runs;
--   5) the global fp_policy=false kill gates the step even under enforce;
--   6) loopback/self traffic never reaches the lookup;
--   7) an ABSENT mode resolves to the enforce default;
--   8) no-policy answers change nothing and log nothing.

local panel_path = "configs/lua/cfm_panel.lua"

local lookups, log_lines
local fp_answer        -- { action=..., id=... } or nil for "no policy"
local bridge_fp_mode   -- panel_fp_policy_mode the fake bridge cfg publishes
local bridge_fp_kill   -- fp_policy boolean the fake bridge cfg publishes

local function install_fakes()
  package.loaded["cjson.safe"] = { encode = function(_) return "{}" end, decode = function() return nil end }
  package.loaded["cfm_tlsfp"] = {
    value = function() return "771,4865-4866,23-65281,29-23-24,0" end,
  }
  package.loaded["cfm_fppolicy"] = {
    lookup = function(deps)
      lookups[#lookups + 1] = deps
      if fp_answer then return fp_answer.action, fp_answer.id end
      return "", nil
    end,
  }
  -- cfm_waf ABSENT: 2e never runs, so its lines can't confuse assertions.
  package.preload["cfm_waf"] = function() error("absent for fppolicy test") end
  -- cfm_decision ABSENT: step 2f's rpc closure is unused (cfm_fppolicy is
  -- faked wholesale) and the decision probe stays a no-op.
  package.preload["cfm_decision"] = function() error("absent for fppolicy test") end
  package.loaded["cfm_bridge_cfg"] = {
    get = function()
      return {
        clearance_refresh = true, cookie_life_sec = 2700,
        panel_fp_policy_mode = bridge_fp_mode,
        fp_policy = bridge_fp_kill,
      }
    end,
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
  fp_answer = opts.fp_answer
  if opts.mode == "__absent__" then
    bridge_fp_mode = nil
  else
    bridge_fp_mode = opts.mode or "logonly"
  end
  if opts.fp_kill == nil then bridge_fp_kill = true else bridge_fp_kill = opts.fp_kill end
  lookups, log_lines = {}, {}

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
  package.preload["cfm_waf"] = nil
  package.preload["cfm_decision"] = nil
  package.loaded["cfm_tlsfp"] = nil
  package.loaded["cfm_fppolicy"] = nil
  package.loaded["cjson.safe"] = nil
  package.loaded["cfm_bridge_cfg"] = nil
  package.loaded["cfm_clearance"] = nil
  return ngx, actions[#actions]
end

local function assert_true(c, m) if not c then error(m, 2) end end
local function has_line(marker)
  for _, l in ipairs(log_lines) do
    if l:find(marker, 1, true) then return true end
  end
  return false
end

-- 1) enforce + armed deny → hard 403 before the challenge flow.
do
  local _, last = run({ mode = "enforce", fp_answer = { action = "deny", id = "c28caa00" } })
  assert_true(#lookups == 1, "enforce: lookup ran once (got " .. #lookups .. ")")
  assert_true(has_line("[cfm_panel_fppolicy] enforce=deny"), "enforce deny logged")
  assert_true(last and last.action == "exit" and last.code == 403,
              "enforce + armed deny must 403 (got " .. tostring(last and last.action) .. "/" .. tostring(last and last.code) .. ")")
end

-- 2) logonly + armed deny → would_deny line, flow unchanged (still challenged).
do
  local _, last = run({ mode = "logonly", fp_answer = { action = "deny", id = "c28caa00" } })
  assert_true(has_line("[cfm_panel_fppolicy] logonly=would_deny"), "logonly deny recorded")
  assert_true(last and last.action == "redirect" and last.code == 307,
              "logonly: no-clearance browser still challenged, never fp-denied")
end

-- 3) challenge-tier fingerprints are observe-only in BOTH modes.
for _, m in ipairs({ "enforce", "logonly" }) do
  for _, tier in ipairs({ "challenge", "challenge_v2" }) do
    local _, last = run({ mode = m, fp_answer = { action = tier, id = "c28caa00" } })
    assert_true(has_line("[cfm_panel_fppolicy] observe=" .. tier),
                m .. "/" .. tier .. ": observe line present")
    assert_true(last and last.action == "redirect" and last.code == 307,
                m .. "/" .. tier .. ": flow unchanged (challenge-tier never enforced on panel)")
  end
end

-- 4) mode off → the lookup never runs.
do
  run({ mode = "off", fp_answer = { action = "deny", id = "c28caa00" } })
  assert_true(#lookups == 0, "off: lookup never runs (got " .. #lookups .. ")")
  assert_true(not has_line("[cfm_panel_fppolicy]"), "off: no fppolicy line")
end

-- 5) global fp_policy=false kill gates the step even under enforce.
do
  run({ mode = "enforce", fp_kill = false, fp_answer = { action = "deny", id = "c28caa00" } })
  assert_true(#lookups == 0, "fp_policy=false: lookup never runs")
  assert_true(not has_line("[cfm_panel_fppolicy]"), "fp_policy=false: no fppolicy line")
end

-- 6) loopback/self traffic never reaches the lookup.
do
  run({ mode = "enforce", ip = "127.0.0.1", fp_answer = { action = "deny", id = "c28caa00" } })
  assert_true(#lookups == 0, "loopback self-IP: lookup never runs")
end

-- 7) an ABSENT mode resolves to the enforce default.
do
  local _, last = run({ mode = "__absent__", fp_answer = { action = "deny", id = "c28caa00" } })
  assert_true(last and last.action == "exit" and last.code == 403,
              "absent mode → enforce default: armed deny must 403")
end

-- 8) no-policy answer: nothing logged, flow unchanged.
do
  local _, last = run({ mode = "enforce", fp_answer = nil })
  assert_true(#lookups == 1, "no-policy: lookup still ran")
  assert_true(not has_line("[cfm_panel_fppolicy]"), "no-policy: no fppolicy line")
  assert_true(last and last.action == "redirect" and last.code == 307,
              "no-policy: normal challenge flow")
end

print("ok: cfm_panel fp-policy consult (step 2f) — deny enforce/logonly, observe-only challenge tiers, kills, self-skip")
