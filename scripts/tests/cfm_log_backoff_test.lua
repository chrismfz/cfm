-- Tests for log-cfm.lua's ingest-socket connect backoff (audit round-2).
--
-- The backoff/error-throttle helpers key on ngx.shared.cfm_metrics. That dict was
-- never declared in any nginx conf, so the whole subsystem silently no-op'd: no
-- exponential backoff when the ingest socket is degraded, and connect failures
-- were 100% silent. The fix declares `lua_shared_dict cfm_metrics` in both confs.
-- This test proves (a) with the dict present the backoff arms/disarms correctly
-- and logs the first failures, and (b) with the dict ABSENT it's a pure no-op
-- (the dead-code state the fix removes).
--
-- log-cfm.lua runs in log_by_lua; extract the local helpers from source and
-- load() them with their free names (ngx, math) as globals.

package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local f = assert(io.open("configs/lua/log-cfm.lua", "r"))
local src = f:read("*a"); f:close()

local a = src:find("local RETRY_MIN_SECS", 1, true)
local b = src:find("\n-- Sanitize a field", a, true)
assert(a and b, "could not delimit the retry-helper block")
local block = src:sub(a, b)

local fails = 0
local function check(cond, msg)
  if not cond then fails = fails + 1; io.stderr:write("FAIL: " .. tostring(msg) .. "\n") end
end

-- Controllable clock + log capture.
local _now = 1000.0
local logs = 0
_G.ngx = { now = function() return _now end, log = function() logs = logs + 1 end, WARN = 1 }

-- Faithful-enough shdict stub (values stored directly; incr with init).
local function new_dict()
  local store = {}
  return {
    get    = function(_, k) return store[k] end,
    set    = function(_, k, v, _ttl) store[k] = v end,
    incr   = function(_, k, v, init) store[k] = (store[k] or init or 0) + v; return store[k] end,
    delete = function(_, k) store[k] = nil end,
  }
end

local loader = assert(load(block .. "\nreturn should_skip_connect, record_connect_failure, record_connect_success"))
local should_skip_connect, record_connect_failure, record_connect_success = loader()
assert(type(should_skip_connect) == "function", "extraction failed")

-- ── dict PRESENT: a failure arms backoff; it clears when the window passes ────
do
  _G.ngx.shared = { cfm_metrics = new_dict() }
  _now = 1000.0; logs = 0

  check(should_skip_connect() == false, "no failure yet → do not skip connect")

  record_connect_failure("connection refused")
  check(should_skip_connect() == true, "after a failure, backoff is armed → skip connect")
  check(logs == 1, "the first failure logs (got " .. logs .. ")")

  -- Within the backoff window, still skipping.
  _now = 1000.05
  check(should_skip_connect() == true, "still within the backoff window → skip")

  -- Past the backoff window (first backoff = 0.1s), stop skipping.
  _now = 1000.2
  check(should_skip_connect() == false, "past the backoff window → attempt connect again")

  -- A success clears the counters entirely.
  record_connect_failure("refused")   -- arm again
  record_connect_success()
  _now = _now + 10
  check(should_skip_connect() == false, "a success disarms backoff")
end

-- ── failure logging is throttled to the first 3 ──────────────────────────────
do
  _G.ngx.shared = { cfm_metrics = new_dict() }
  _now = 2000.0; logs = 0
  for _ = 1, 6 do record_connect_failure("e") end
  check(logs == 3, "only the first 3 consecutive failures log (got " .. logs .. ")")
end

-- ── dict ABSENT: the whole subsystem is a no-op (the pre-fix dead-code state) ─
do
  _G.ngx.shared = { cfm_metrics = nil }
  _now = 3000.0; logs = 0
  check(should_skip_connect() == false, "no dict → never skips (unthrottled retries)")
  record_connect_failure("e")   -- must not error, must not log
  record_connect_success()      -- must not error
  check(logs == 0, "no dict → connect failures are 100% silent (the dead-code bug the fix removes)")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_log_backoff_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: log-cfm ingest-socket connect backoff arms/disarms with cfm_metrics; no-op without it (round-2)\n")
