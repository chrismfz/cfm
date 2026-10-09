-- A logonly WAF hit used to route the request to the origin on the spot, so
-- everything after the WAF never ran for it: the forced challenge (Step 2.5),
-- the bridge decision (Step 3: IP block, vhost challenge / under-attack,
-- traffic rules, throttles) and the fingerprint challenge floor. Any request
-- could buy that by tripping a logonly rule on purpose (a header
-- `X-A: ${date:}` trips rule_log4shell). It now records the hit and goes on
-- through Steps 2b-4 like a clean request.
--
-- And waf.check() runs under pcall: a rule that raised took the request into
-- the request_failure handler, which under fail_open skipped the same steps.
-- Under fail_open the request now goes on without the WAF; under fail_closed
-- the error still reaches that handler (500).
--
-- Runs the real configs/lua/cfm.lua under a mocked ngx (the bridge, clearance
-- and decision modules are fakes; cfm_waf is real unless a case swaps it).

package.path = "configs/lua/?.lua;" .. package.path

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

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
      read_body = function() end,
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
    return real_getenv(k)
  end
  package.loaded["cfm_waf"] = req.waf_fake or REAL_WAF
  local chunk = assert(loadfile("configs/lua/cfm.lua"))
  local ok, err = pcall(chunk)
  os.getenv = real_getenv
  return {
    ok = ok, err = err, exited = exited, redirected = redirected, execd = execd,
    upstream = vars.cfm_upstream, pass = vars.cfm_pass, action = headers_out["X-CFM-Action"],
    rpcs = table.concat(rpcs, ","), logs = logs, SH = SH,
  }
end


-- The real WAF, loaded once (under a minimal ngx) and reused by every run.
_G.ngx = { now = function() return 1000 end, decode_base64 = function() return nil end,
           log = function() end, ERR = 0, WARN = 1, INFO = 2 }
REAL_WAF = require("cfm_waf")

local LOG4 = { ["x-a"] = "${date:}" }  -- trips rule_log4shell (logonly)
local function desc(r)
  return ("ok=%s action=%s up=%s exit=%s rpcs=%s err=%s"):format(tostring(r.ok), tostring(r.action),
    tostring(r.upstream), tostring(r.exited), r.rpcs, tostring(r.err))
end

-- ── The real WAF: a logonly hit no longer skips the steps after it ─────────
do
  local r = H.run{ headers = LOG4 }
  check(r.ok and r.action == "logonly" and r.upstream == "cfm_apache" and r.exited == nil,
        "logonly hit, nothing else: allowed, reported as logonly (" .. desc(r) .. ")")
  check(r.rpcs:find("ip_push", 1, true) and r.rpcs:find("decision", 1, true),
        "logonly hit: pushed AND the bridge decision consulted (" .. desc(r) .. ")")

  r = H.run{ headers = LOG4, verdict = { ip_action = "block", vhost_action = "allow" } }
  check(r.ok and r.action == "block" and r.exited == 403, "logonly hit + IP block → 403 (" .. desc(r) .. ")")
  check(r.rpcs:find("ip_push", 1, true), "the blocked logonly hit is still pushed (" .. desc(r) .. ")")

  r = H.run{ headers = LOG4, verdict = { ip_action = "allow", vhost_action = "challenge" } }
  check(r.ok and r.action == "challenge" and r.upstream == "cfm_challenge",
        "logonly hit + vhost challenge → challenge (" .. desc(r) .. ")")

  r = H.run{ headers = LOG4, verdict = { ip_action = "allow", vhost_action = "allow", rule_action = "block", rule_id = "r1" } }
  check(r.ok and r.exited == 403, "logonly hit + traffic-rule block → 403 (" .. desc(r) .. ")")

  r = H.run{ headers = LOG4, verdict = { ip_action = "allow", vhost_action = "allow", rule_action = "throttle", rule_id = "r2" } }
  check(r.ok and r.exited == 429 and r.action == "throttle", "logonly hit + throttle rule → 429 (" .. desc(r) .. ")")

  -- An uncleared resumed POST with a logonly hit on a challenged vhost ends
  -- like a clean uncleared replay there: block_replayed (the loop guard).
  local function resumed(ctx) ctx.cfm_resumed_post = true end
  r = H.run{ headers = LOG4, method = "POST", ctx_init = resumed, verdict = { ip_action = "allow", vhost_action = "challenge" } }
  local clean = H.run{ method = "POST", ctx_init = resumed, verdict = { ip_action = "allow", vhost_action = "challenge" } }
  check(r.ok and r.action == "block_replayed" and clean.action == "block_replayed",
        "uncleared resumed POST + logonly hit on a challenged vhost: block_replayed, as a clean one (" .. desc(r) .. ")")
  -- A cleared one reaches the origin, as before.
  r = H.run{ headers = LOG4, method = "POST", ctx_init = resumed, clearance = true,
             vars = { cookie_cfm_clearance = "good" }, verdict = { ip_action = "allow", vhost_action = "challenge" } }
  check(r.ok and r.action == "logonly" and r.upstream == "cfm_apache",
        "cleared resumed POST + logonly hit: origin (" .. desc(r) .. ")")

  r = H.run{ headers = LOG4, fp_action = "challenge" }
  check(r.ok and r.action == "challenge", "logonly hit + fingerprint challenge floor → challenge (" .. desc(r) .. ")")

  r = H.run{ headers = LOG4, vars = { cfm_force_challenge = "1" } }
  check(r.ok and r.action == "challenge_forced", "logonly hit on a forced-challenge location → challenge (" .. desc(r) .. ")")

  -- A cleared client with a logonly hit takes the clearance fast path (2b),
  -- as before: reported logonly, origin, no bridge decision.
  r = H.run{ headers = LOG4, clearance = true, cookie = "cfm_clearance=good",
             vars = { cookie_cfm_clearance = "good" }, verdict = { ip_action = "block" } }
  check(r.ok and r.action == "logonly" and r.upstream == "cfm_apache" and not r.rpcs:find("decision", 1, true),
        "cleared logonly hit: Step 2b fast path, as before (" .. desc(r) .. ")")

  -- No hit: unchanged.
  r = H.run{}
  check(r.ok and r.action == "allow" and r.upstream == "cfm_apache", "clean request: allow (" .. desc(r) .. ")")
end

-- ── A fake WAF: logonly_pc, block, and a WAF that raises ────────────────────
local function fake_waf(check_fn)
  return {
    enabled = function() return true end,
    check = check_fn,
    should_push = function() return true end,
    also_rule_ids = function() return {} end,
    post_clearance_action = function(a) if a == "challenge" then return "logonly", true end return a, false end,
  }
end
do
  local challenge = fake_waf(function() return true, "WAF_X:T", 600, "challenge", {}, 999 end)
  local r = H.run{ waf_fake = challenge, clearance = true, vars = { cookie_cfm_clearance = "good" } }
  check(r.ok and r.action == "logonly_pc" and r.upstream == "cfm_apache",
        "cleared challenge-tier hit converted to logonly: reported logonly_pc (" .. desc(r) .. ")")

  local block = fake_waf(function() return true, "WAF_X:T", 600, "block", {}, 999 end)
  r = H.run{ waf_fake = block }
  check(r.ok and r.exited == 403 and not r.rpcs:find("decision", 1, true),
        "block hit: 403 at once, no bridge decision, as before (" .. desc(r) .. ")")

  local boom = fake_waf(function() error("rule exploded") end)
  r = H.run{ waf_fake = boom, fail_open = true, verdict = { ip_action = "block" } }
  check(r.ok and r.exited == 403 and r.action == "block",
        "WAF error under fail_open: the bridge's IP block still applies (" .. desc(r) .. ")")
  local logged = false
  for _, l in ipairs(r.logs) do
    if l:find("waf_error", 1, true) and l:find("rule exploded", 1, true) and l:find("traceback", 1, true) then logged = true end
  end
  check(logged, "WAF error under fail_open is logged, with the rule's stack")
  r = H.run{ waf_fake = boom, fail_open = true }
  check(r.ok and r.action == "waf_error" and r.upstream == "cfm_apache",
        "WAF error under fail_open, nothing else: allowed, reported waf_error (" .. desc(r) .. ")")
  r = H.run{ waf_fake = boom, fail_open = false }
  check(r.ok and r.exited == 500, "WAF error under fail_closed: 500, as before (" .. desc(r) .. ")")
end

-- ── A logonly hit is never micro-cached ─────────────────────────────────────
do
  local r = H.run{ micro = true }
  check(r.ok and r.execd == "@cfm_micro_5s", "clean allow with micro armed: micro cache (" .. desc(r) .. ")")
  r = H.run{ micro = true, headers = LOG4 }
  check(r.ok and r.execd == nil and r.action == "logonly" and r.upstream == "cfm_apache",
        "logonly hit with micro armed: origin, not the micro cache (" .. desc(r) .. ")")
  local boom = { enabled = function() return true end, check = function() error("rule exploded") end }
  r = H.run{ micro = true, waf_fake = boom, fail_open = true }
  check(r.ok and r.execd == nil and r.action == "waf_error" and r.upstream == "cfm_apache",
        "WAF error with micro armed: origin, not the micro cache (" .. desc(r) .. ")")
end
do
  local f = assert(io.open("configs/lua/cfm.lua", "r"))
  local src = f:read("*a"); f:close()
  check(src:find("local function micro_cache_target()\n  if ngx.ctx.cfm_no_micro then return nil end", 1, true) ~= nil,
        "micro_cache_target refuses a flagged request")
end

if fails > 0 then
  io.stderr:write(("cfm logonly fall-through tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: a logonly WAF hit goes on through Steps 2b-4; a WAF error keeps them")
