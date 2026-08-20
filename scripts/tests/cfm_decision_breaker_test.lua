-- Tests for cfm_decision.lua's circuit breaker.
--
-- A HUNG cfm daemon (accepts the unix connection but never replies) makes every
-- uncached request pay the full decision_timeout_ms before failing open. The
-- breaker trips after BREAKER_FAIL_THRESHOLD (3) daemon-unreachable failures
-- in a CONSECUTIVE run (a success resets the count), then SKIPS the RPC for
-- BREAKER_COOLDOWN_SEC (3s), failing fast, and self-heals. Covered here:
--   * trip on timeout/connect; skip (no http) while open
--   * fixed-window DECAY — sparse blips don't accumulate (review finding 1)
--   * only the `decision` kind trips it — telemetry never does (finding 2)
--   * persistent hang: after the cooldown, probes re-accumulate a fresh 3-run
--   * http_4xx/5xx/json never trip it; no-shdict = inert
--   * throttled OPEN/CLOSED ngx.log lines on the transitions (MCP-observable)

package.loaded["cjson.safe"] = { decode = function() return nil end, encode = function() return "{}" end }
package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local NOW = 1000
local LOGS = {}   -- captured ngx.log lines (for the observability test)
_G.ngx = { WARN = 1, ERR = 2, INFO = 3, ctx = {}, header = {}, var = {},
           now = function() return NOW end,
           log = function(_, ...) LOGS[#LOGS + 1] = table.concat({ ... }) end,
           escape_uri = function(s) return tostring(s or "") end }
local function log_has(substr)
  for _, l in ipairs(LOGS) do if l:find(substr, 1, true) then return true end end
  return false
end
local function log_count(substr)
  local n = 0
  for _, l in ipairs(LOGS) do if l:find(substr, 1, true) then n = n + 1 end end
  return n
end

local cfm_decision = require("cfm_decision")

local fails = 0
local function check(cond, msg) if cond then return end fails = fails + 1; io.stderr:write("FAIL: " .. msg .. "\n") end

-- TTL-aware shdict stub keyed off the controllable NOW clock (get/set/incr with
-- init_ttl / add / delete), so fixed-window expiry is actually exercised.
local function new_sh()
  local store = {}   -- k -> { v=, exp= }  (exp=nil → no expiry)
  local function alive(k)
    local e = store[k]
    if not e then return nil end
    if e.exp and NOW >= e.exp then store[k] = nil; return nil end
    return e
  end
  local function ttl_exp(ttl) return (ttl and ttl > 0) and (NOW + ttl) or nil end
  local sh = {
    get    = function(_, k) local e = alive(k); return e and e.v or nil end,
    set    = function(_, k, v, ttl) store[k] = { v = v, exp = ttl_exp(ttl) } end,
    delete = function(_, k) store[k] = nil end,
    add    = function(_, k, v, ttl) if alive(k) then return false, "exists" end
                                    store[k] = { v = v, exp = ttl_exp(ttl) }; return true end,
    incr   = function(_, k, v, init, init_ttl)
      local e = alive(k)
      if not e then store[k] = { v = (init or 0) + v, exp = ttl_exp(init_ttl) }
      else e.v = e.v + v end
      return store[k].v
    end,
  }
  return store, sh, alive
end

local function new_client()
  local store, sh, alive = new_sh()
  local c = cfm_decision.new({ debug = false, debug_headers = false }, { shdict = sh })
  local state = { calls = 0, result = { nil, "timeout" } }
  c.http = function() state.calls = state.calls + 1; return state.result[1], state.result[2] end
  return c, store, state, alive
end

local BRK_UNTIL, BRK_FAILS = "cfm_dec_brk_until", "cfm_dec_brk_fails"
local function val(alive, k) local e = alive(k); return e and e.v or nil end

-- ── 1) hung daemon: trip after 3, then fast-fail without calling http ─────────
do
  NOW = 1000
  local c, _, st, alive = new_client()
  st.result = { nil, "timeout" }
  for i = 1, 3 do
    local resp, err = c:rpc("decision", "GET", "/x")
    check(resp == nil and err == "timeout", "call " .. i .. " returns timeout")
  end
  check(st.calls == 3, "first 3 calls hit http, got " .. st.calls)
  check(type(val(alive, BRK_UNTIL)) == "number", "breaker opened after 3 failures")
  local resp, err = c:rpc("decision", "GET", "/x")
  check(resp == nil and err == "breaker_open", "open → breaker_open")
  check(st.calls == 3, "open breaker SKIPS http, got " .. st.calls)
end

-- ── 2) fixed-window DECAY: sparse failures don't accumulate (finding 1) ─────
do
  NOW = 1000
  local c, _, st, alive = new_client()
  st.result = { nil, "timeout" }
  c:rpc("decision", "GET", "/x"); c:rpc("decision", "GET", "/x")   -- 2 failures at t=1000
  check(val(alive, BRK_FAILS) == 2, "2 failures counted")
  NOW = 1011                                                       -- past the 10s window
  check(val(alive, BRK_FAILS) == nil, "counter decayed after the window")
  c:rpc("decision", "GET", "/x")                                  -- 1 fresh failure
  check(val(alive, BRK_UNTIL) == nil, "sparse blips (2 old + 1 new) do NOT trip a healthy daemon")
  check(val(alive, BRK_FAILS) == 1, "counter restarted at 1 in the new window")
end

-- ── 3) only the `decision` kind trips it; an open breaker never silences telemetry
do
  NOW = 2000
  local c, _, st, alive = new_client()
  st.result = { nil, "timeout" }
  for _ = 1, 6 do c:rpc("observe", "POST", "/nginx/observe") end   -- telemetry hangs
  check(val(alive, BRK_UNTIL) == nil, "telemetry timeouts must NOT trip the breaker")
  check(st.calls == 6, "telemetry still hits http (no skip), got " .. st.calls)

  -- Trip the breaker via the decision path, THEN a telemetry RPC must still run
  -- (decision-only skip): a decision-only trip must not drop autoblock pushes.
  for _ = 1, 3 do c:rpc("decision", "GET", "/x") end
  check(type(val(alive, BRK_UNTIL)) == "number" and val(alive, BRK_UNTIL) > NOW, "breaker open (decision)")
  local before = st.calls
  local _, err = c:rpc("ip_push", "POST", "/nginx/ip")
  check(st.calls == before + 1 and err == "timeout", "open breaker does NOT skip a telemetry RPC")
  -- ...but it DOES skip a decision RPC.
  local _, derr = c:rpc("decision", "GET", "/x")
  check(derr == "breaker_open" and st.calls == before + 1, "open breaker DOES skip the decision RPC")
end

-- ── 3b) CONSECUTIVE semantics: a success resets the count (finding 2) ─────────
-- A busy healthy node with occasional timeouts interleaved with successes must
-- NOT trip — only an unbroken run of failures does.
do
  NOW = 2500
  local c, _, st, alive = new_client()
  for _ = 1, 5 do
    st.result = { nil, "timeout" }; c:rpc("decision", "GET", "/x")   -- fail
    check(val(alive, BRK_FAILS) == 1, "failure counts to 1")
    st.result = { "BODY", nil };    c:rpc("decision", "GET", "/x")   -- success resets
    check(val(alive, BRK_FAILS) == nil, "success reset the consecutive-failure count")
  end
  check(val(alive, BRK_UNTIL) == nil, "interleaved fail/success never trips a healthy daemon")
end

-- ── 4) persistent hang: after the cooldown, probes re-accumulate a FRESH run ──
-- No presence-based re-arm — a single post-cooldown probe timeout must NOT
-- re-open on one blip; it takes a fresh 3-consecutive run to re-trip.
do
  NOW = 3000
  local c, _, st, alive = new_client()
  st.result = { nil, "timeout" }
  for _ = 1, 3 do c:rpc("decision", "GET", "/x") end   -- open the breaker
  check(type(val(alive, BRK_UNTIL)) == "number" and val(alive, BRK_UNTIL) > NOW, "breaker open")
  check(val(alive, BRK_FAILS) == nil, "counter dropped on trip")

  NOW = 3005                                           -- past the short open-TTL (cooldown+1=4s)
  check(val(alive, BRK_UNTIL) == nil, "open key lapsed")
  c:rpc("decision", "GET", "/x")                       -- one probe timeout
  check(val(alive, BRK_UNTIL) == nil, "ONE post-cooldown timeout does NOT re-open")
  check(val(alive, BRK_FAILS) == 1, "it starts a fresh consecutive count")
  c:rpc("decision", "GET", "/x"); c:rpc("decision", "GET", "/x")   -- 2 more = 3 fresh
  check(type(val(alive, BRK_UNTIL)) == "number" and val(alive, BRK_UNTIL) > NOW, "a fresh 3-run re-trips")
end

-- ── 5) self-heal: a probe success clears the breaker ──────────────────────────
do
  NOW = 4000
  local c, _, st, alive = new_client()
  st.result = { nil, "timeout" }
  for _ = 1, 3 do c:rpc("decision", "GET", "/x") end
  NOW = 4003
  st.result = { "BODY", nil }
  local resp = c:rpc("decision", "GET", "/x")           -- probe succeeds
  check(resp == "BODY", "probe hit http and succeeded")
  check(val(alive, BRK_UNTIL) == nil and val(alive, BRK_FAILS) == nil, "success cleared the breaker")
end

-- ── 6) http_4xx/5xx/json never trip; no-shdict inert ──────────────────────────
do
  NOW = 5000
  local c, _, st, alive = new_client()
  for _, e in ipairs({ "http 403 body=x", "http 500 body=y", "decode failed" }) do
    st.result = { nil, e }
    for _ = 1, 5 do c:rpc("decision", "GET", "/x") end
    check(val(alive, BRK_UNTIL) == nil, "'" .. e .. "' must NOT open the breaker")
  end

  local c2 = cfm_decision.new({ debug = false }, { shdict = nil })
  local calls = 0
  c2.http = function() calls = calls + 1; return nil, "timeout" end
  for _ = 1, 10 do local _, err = c2:rpc("decision", "GET", "/x"); check(err == "timeout", "no shdict: real error, never breaker_open") end
  check(calls == 10, "no shdict: every call hits http (breaker inert), got " .. calls)
end

-- ── 7) a telemetry SUCCESS must NOT clear the decision breaker (finding 1) ────
-- The daemon deadlocks in /nginx/decision but still answers telemetry; a
-- telemetry success must not keep resetting the breaker and re-expose the cliff.
do
  NOW = 6000
  local c, _, st, alive = new_client()
  st.result = { nil, "timeout" }
  for _ = 1, 3 do c:rpc("decision", "GET", "/x") end   -- trip via decision
  check(type(val(alive, BRK_UNTIL)) == "number" and val(alive, BRK_UNTIL) > NOW, "breaker open")
  st.result = { "BODY", nil }
  c:rpc("observe", "POST", "/nginx/observe")            -- telemetry SUCCESS
  check(val(alive, BRK_UNTIL) ~= nil and val(alive, BRK_UNTIL) > NOW,
        "a telemetry success does NOT clear the decision breaker")
  -- ...and a decision request is still skipped.
  local _, err = c:rpc("decision", "GET", "/x")
  check(err == "breaker_open", "decision still skipped after the telemetry success")
end

-- ── 8) a lone timeout after the window lapses must NOT re-trip (finding 2) ─────
do
  NOW = 7000
  local c, _, st, alive = new_client()
  st.result = { nil, "timeout" }
  for _ = 1, 3 do c:rpc("decision", "GET", "/x") end   -- trip; counter deleted on trip
  check(val(alive, BRK_FAILS) == nil, "counter dropped on trip")
  NOW = 7000 + 9                                        -- past the short open-TTL (cooldown+1=4s)
  check(val(alive, BRK_UNTIL) == nil, "breaker key lapsed after the short open-TTL")
  c:rpc("decision", "GET", "/x")                        -- one ISOLATED timeout
  check(val(alive, BRK_UNTIL) == nil, "a single stray timeout after the window does NOT re-trip")
  check(val(alive, BRK_FAILS) == 1, "it just starts a fresh consecutive count")
end

-- ── 9) observability: throttled OPEN/CLOSED logs on the transitions ───────────
-- The breaker writes a greppable ngx.log line to the edge error.log so an
-- operator can watch it via the MCP edge_error_tail tool.
do
  NOW = 8000
  for i = #LOGS, 1, -1 do LOGS[i] = nil end            -- clear capture
  local c, _, st, alive = new_client()
  st.result = { nil, "timeout" }
  for _ = 1, 3 do c:rpc("decision", "GET", "/x") end   -- trip → OPEN log
  check(log_has("decision breaker OPEN"), "trip emits an OPEN log line")
  check(log_count("decision breaker OPEN") == 1, "exactly one OPEN log on the transition")

  -- Recovery clears + emits CLOSED.
  NOW = 8003
  st.result = { "BODY", nil }
  c:rpc("decision", "GET", "/x")                        -- success → CLOSED log
  check(log_has("decision breaker CLOSED"), "recovery emits a CLOSED log line")

  -- Throttle (independent per type, no cross-reset): a re-trip within the 60s
  -- window must NOT emit another OPEN line — the first OPEN's marker is still live.
  for i = #LOGS, 1, -1 do LOGS[i] = nil end
  st.result = { nil, "timeout" }
  for _ = 1, 3 do c:rpc("decision", "GET", "/x") end   -- re-trip, still within 60s
  check(type(val(alive, BRK_UNTIL)) == "number", "breaker did re-open (state)")
  check(log_count("decision breaker OPEN") == 0, "re-trip within the window emits NO repeat OPEN log (throttled)")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_decision_breaker_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: cfm_decision circuit breaker (consecutive trip, decision-only, no-stray-retrip, self-heal)\n")
