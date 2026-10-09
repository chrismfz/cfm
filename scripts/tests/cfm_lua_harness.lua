-- Shared harness for the Lua tests that run the real configs/lua/cfm.lua (an
-- access-phase script, not a module) under a mocked ngx. Not a test itself:
-- `make test-lua` runs *_test.lua only. Usage:
--   local H = dofile("scripts/tests/cfm_lua_harness.lua")
--   local r = H.run{ headers = {...}, verdict = {...}, vars = {...}, ... }
-- The bridge, clearance, decision and selfip modules are fakes; cfm_waf is the
-- real module unless req.waf_fake replaces it. See H.run for every knob.

package.path = "configs/lua/?.lua;" .. package.path

local function newdict()
  local d = { store = {} }
  function d:get(k) return self.store[k] end
  function d:set(k, v) self.store[k] = v; return true end
  function d:add(k, v) if self.store[k] ~= nil then return false end self.store[k] = v; return true end
  function d:delete(k) self.store[k] = nil end
  function d:incr(k, n) if self.store[k] == nil then return nil, "not found" end self.store[k] = self.store[k] + n; return self.store[k] end
  function d:get_keys() local t = {} for k in pairs(self.store) do t[#t+1] = k end return t end
  return d
end

local H = {}


function H.run(req)
  -- fresh module state for things cfm.lua require()s each request
  local exited, redirected, execd
  local reads = 0  -- ngx.req.read_body calls
  local logs = {}
  local headers_out = {}
  local vars = {
    remote_addr = req.ip or "203.0.113.9",
    realip_remote_addr = req.peer or req.ip or "203.0.113.9",
    host = req.host or "example.com",
    uri = req.uri or "/",
    request_uri = req.request_uri or req.uri or "/",
    args = req.args or "",
    scheme = req.scheme or "https",
    server_addr = "198.51.100.1",
    http_user_agent = req.ua or "Mozilla/5.0",
    http_cookie = req.cookie or "",
    cfm_upstream = "", cfm_pass = "",
    request_id = "rid",
  }
  for k, v in pairs(req.vars or {}) do vars[k] = v end
  local SH = req.SH or newdict()
  local rpcs = {}
  _G.ngx = {
    var = vars,
    ctx = (function() local c = {}; if req.ctx_init then req.ctx_init(c) end; return c end)(),
    header = headers_out,
    shared = { cfm_decisions = SH },
    ERR = 0, WARN = 1, INFO = 2, DEBUG = 3,
    HTTP_SEE_OTHER = 303, HTTP_POST = 8, HTTP_INTERNAL_SERVER_ERROR = 500,
    log = function(lvl, ...) logs[#logs+1] = table.concat({...}) end,
    now = function() return 1000 end,
    time = function() return 1000 end,
    req = {
      get_method = function() return req.method or "GET" end,
      start_time = function() return 999 end,
      get_headers = function() return req.headers or {} end,
      read_body = function()
        reads = reads + 1
        if req.read_body_error then error(req.read_body_error) end
      end,
      get_body_data = function() return req.body end,
      get_body_file = function() return nil end,
      get_uri_args = function() return {} end,
      set_method = function() end, set_header = function() end,
      set_body_data = function() end, set_uri = function() end, set_uri_args = function() end,
    },
    exit = function(c) exited = c; return c end,
    redirect = function(u, c) redirected = u; return c end,
    exec = function(t) execd = t end,
    md5 = function(s) return ("%032x"):format(#s) end,
    escape_uri = function(s) return s end,
    encode_base64 = function(s) return s end,
    decode_base64 = function(s) return s end,
    worker = { pid = function() return 1 end },
    timer = { at = function() return true end },
    re = { find = function() return nil end, match = function() return nil end },
  }
  -- fakes
  package.loaded["cjson.safe"] = { encode = function() return "{}" end, decode = function() return nil end }
  package.loaded["cfm_bridge_cfg"] = {
    get = function() return { clearance_refresh = true, cookie_life_sec = 2700, fp_policy = (req.fp_action ~= nil) } end,
    token = function() return "tok" end,
    refresh_token_throttled = function() end,
    TOKEN_PATH = "/x",
  }
  package.loaded["cfm_clearance"] = {
    validate = function(tok) if req.clearance and tok == "good" then return true, "ok" end return false, "missing" end,
    mint = function() return "minted" end,
    normalize_host = function(h) return h end,
    panel_scope = function() return "web" end,
  }
  package.loaded["cfm_decision"] = {
    new = function() return {
      get = function(_, ...) rpcs[#rpcs+1] = "decision"; return req.verdict or { ip_action = "allow", vhost_action = "allow" } end,
      rpc = function(_, kind) rpcs[#rpcs+1] = kind; return nil end,
    } end,
  }
  package.loaded["cfm_selfip"] = req.selfip or {
    normalize_ip = function(s) return s end,
    is_self_origin = function() return false end,
  }
  package.loaded["cfm_clamav"] = nil
  package.preload["cfm_clamav"] = function() error("no clamav in harness") end
  package.preload["cfm_rules"] = function() error("no") end
  package.preload["cfm_ua_emergency"] = function() error("no") end
  package.preload["cfm_pcw"] = function() error("no") end
  package.loaded["cfm_cache"] = nil
  if req.micro then
    package.preload["cfm_cache"] = function() return { micro_gate = function() return "@cfm_micro_5s" end } end
  else
    package.preload["cfm_cache"] = function() error("no") end
  end
  package.preload["cfm_geo"] = function() error("no") end
  package.loaded["cfm_tlsfp"] = { value = function() return req.fp_action and "fpraw" or nil end }
  package.loaded["cfm_fppolicy"] = { lookup = function() return req.fp_action or "", "fp1" end }
  package.loaded["cfm_cfg"] = nil
  local real_getenv = os.getenv
  os.getenv = function(k)
    if k == "CFM_FAIL_OPEN" and req.fail_open ~= nil then return req.fail_open and "1" or "0" end
    if req.env and req.env[k] ~= nil then return req.env[k] end
    return real_getenv(k)
  end
  package.loaded["cfm_waf"] = req.waf_fake or H.real_waf()
  local chunk = assert(loadfile("configs/lua/cfm.lua"))
  local ok, err = pcall(chunk)
  os.getenv = real_getenv
  return {
    ok = ok, err = err, exited = exited, redirected = redirected, execd = execd,
    upstream = vars.cfm_upstream, pass = vars.cfm_pass, action = headers_out["X-CFM-Action"],
    rpcs = table.concat(rpcs, ","), logs = logs, SH = SH, reads = reads,
  }
end

-- The real WAF, loaded once (under a minimal ngx) and reused by every run.
local REAL
function H.real_waf()
  if not REAL then
    local saved = _G.ngx
    _G.ngx = { now = function() return 1000 end, decode_base64 = function() return nil end,
               log = function() end, ERR = 0, WARN = 1, INFO = 2 }
    REAL = require("cfm_waf")
    _G.ngx = saved
  end
  return REAL
end

return H
