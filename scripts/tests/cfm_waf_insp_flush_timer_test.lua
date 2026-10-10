-- The waf_insp flush timer must not close over cfm.lua's chunk locals (edge
-- Lua sweep 2026-10-09). cfm.lua runs per request (access_by_lua_file), so
-- SH / decision / cjson are locals on the request coroutine's stack when the
-- timer is created; as upvalues the callback read that stack after the
-- request had finished and its coroutine had been reset, and about once a
-- day per node the flush died with "attempt to index upvalue 'SH' (a nil
-- value)". The callback now takes them as timer arguments.
--
-- Extracts the production maybe_flush_waf_insp() (and its callback) from the
-- source and runs them with the chunk's names as globals, then drops those
-- globals before the timer fires: the old closure reads them and fails.

local f = assert(io.open("configs/lua/cfm.lua", "r"))
local src = f:read("*a"); f:close()

local function extract(head)
  local a = src:find(head, 1, true)
  if not a then return nil end
  local body = src:sub(a)
  local b = assert(body:find("\nend\n"), "cannot delimit " .. head)
  return body:sub(1, b + 4)
end

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local function new_dict()
  local d = { v = { ["waf_insp:hr=3600|host=a.gr"] = 5, ["waf_insp:hr=3600|host="] = 5, other = 1 } }
  function d:get(k) return self.v[k] end
  function d:set(k, v) self.v[k] = v; return true end
  function d:add(k, v) if self.v[k] ~= nil then return false, "exists" end self.v[k] = v; return true end
  function d:get_keys() local t = {} for k in pairs(self.v) do t[#t + 1] = k end return t end
  return d
end

local timer_fn, timer_args
_G.ngx = {
  now = function() return 10000 end,
  timer = { at = function(_, fn, ...) timer_fn, timer_args = fn, { ... }; return true end },
  log = function() end, WARN = 1,
}
local pushed
_G.SH = new_dict()
_G.CFG = { waf_stats_enable = true, waf_stats_flush_sec = 60, debug = false }
_G.decision = { rpc = function(_, kind, _, _, body) pushed = { kind = kind, body = body } end }
_G.cjson = { encode = function(t) return "rows=" .. #t.rows end }

local cb_src = extract("local function waf_insp_flush_cb(") or ""
local fl_src = assert(extract("local function maybe_flush_waf_insp("), "maybe_flush_waf_insp() not found")
local maybe_flush = assert(load(cb_src .. fl_src .. "\nreturn maybe_flush_waf_insp"))()

maybe_flush()
check(type(timer_fn) == "function", "the flush schedules a timer")
-- The request is over: its chunk locals are gone by the time the timer runs.
_G.SH, _G.decision, _G.cjson = nil, nil, nil
local ok, err = pcall(timer_fn, false, unpack(timer_args or {}))
check(ok, "the timer runs with the request's locals gone (" .. tostring(err) .. ")")
check(pushed and pushed.kind == "waf_stats" and pushed.body == "rows=2", "the flush pushes the two waf_insp rows (" ..
      tostring(pushed and pushed.body) .. ")")
-- No upvalue may reach the per-request chunk: none at all.
check(debug.getupvalue(timer_fn, 1) == nil, "the timer callback closes over nothing (upvalue 1: " ..
      tostring((debug.getupvalue(timer_fn, 1))) .. ")")
-- premature (worker exiting): no push.
pushed = nil
ok = pcall(timer_fn, true, unpack(timer_args or {}))
check(ok and pushed == nil, "a premature timer pushes nothing")

if fails > 0 then
  io.stderr:write(("waf_insp flush timer tests: %d FAILED\n"):format(fails))
  os.exit(1)
end
print("ok: waf_insp flush timer takes its state as arguments")
