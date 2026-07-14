-- Tests for the lock-free cfm_rules traffic throttle (audit F21).
--
-- throttle_hit was a per-(profile,host,ip) spin-lock + read-modify-write token
-- bucket; on lock-acquisition TIMEOUT it returned a 429 regardless of token
-- availability, so legit bursts from a shared/NAT IP 429'd each other on lock
-- contention (the false-positive F21 fixes). It is now a LOCK-FREE fixed-window
-- counter: one atomic SH:incr per request, keyed (profile,host,window,ip). No
-- lock means no contention to mis-handle — a full burst is counted exactly.

local function new_dict()
  local store, incr_fail = {}, false
  local dict = {}
  function dict:get(key) local e = store[key]; return e and e.v or nil end
  function dict:set(key, v, ttl) store[key] = { v = v, ttl = ttl }; return true end
  function dict:add(key, v, ttl)
    if store[key] ~= nil then return false, "exists" end
    store[key] = { v = v, ttl = ttl }; return true
  end
  function dict:delete(key) store[key] = nil end
  -- incr models OpenResty's 4-arg incr(key, value, init, init_ttl).
  function dict:incr(key, value, init, ttl)
    if incr_fail then return nil, "no memory" end
    local e = store[key]
    if not e then
      if init == nil then return nil, "not found" end
      store[key] = { v = init + value, ttl = ttl }
      return init + value
    end
    e.v = e.v + value
    return e.v
  end
  function dict:_dump() return store end
  function dict:_set_incr_fail(b) incr_fail = b end
  return dict
end

local dict = new_dict()
local now = 1000.0

_G.ngx = {
  now    = function() return now end,
  sleep  = function(_) error("throttle must be LOCK-FREE: ngx.sleep must not be called") end,
  log    = function() end,
  ERR = 2, WARN = 1, INFO = 3,
  shared = { cfm_decisions = dict },
}

local rules = dofile("configs/lua/cfm_rules.lua")
rules.init({})

-- Read the hard_bot profile from source so LIMIT/WINDOW track the real values.
local src
do local f = assert(io.open("configs/lua/cfm_rules.lua", "r")); src = f:read("*a"); f:close() end
local HRATE  = tonumber(src:match("hard_bot%s*=%s*{%s*rate%s*=%s*([%d%.]+)"))
local HBURST = tonumber(src:match("hard_bot%s*=%s*{%s*rate%s*=%s*[%d%.]+,%s*burst%s*=%s*(%d+)"))
assert(HRATE and HBURST, "could not read hard_bot rate/burst from cfm_rules.lua")
local WINDOW = math.max(1, math.floor(HBURST / HRATE))
local LIMIT  = HBURST

local function assert_eq(actual, expected, msg)
  if actual ~= expected then
    error((msg or "assert_eq failed") .. ": expected=" .. tostring(expected) .. " actual=" .. tostring(actual))
  end
end
local function throttle(ip)
  return rules.apply({ rule_action = "throttle", throttle_profile = "hard_bot" }, { host = "h", ip = ip })
end

-- ── passthrough actions unchanged ────────────────────────────────────────────
do
  assert_eq(rules.apply({ rule_action = "allow" }, {}).action, "allow", "allow passthrough")
  assert_eq(rules.apply({ rule_action = "challenge" }, {}).action, "challenge", "challenge passthrough")
  assert_eq(rules.apply({ rule_action = "block" }, {}).action, "block", "block passthrough")
  assert_eq(rules.apply({ rule_action = "drop" }, {}).action, "allow", "unsupported action fails open to allow")
end

-- ── a full LIMIT burst is admitted, then throttled — NO false throttle (F21) ──
-- (Every call is an independent atomic incr; the old lock would have 429'd the
-- "concurrent" lock-losers here even though budget remained.)
do
  now = 1000
  for i = 1, LIMIT do
    assert_eq(throttle("5.6.7.8").action, "allow", "request " .. i .. "/" .. LIMIT .. " within budget must be allowed")
  end
  local r = throttle("5.6.7.8")
  assert_eq(r.action, "throttle", "request LIMIT+1 must be throttled")
  assert(type(r.retry_after) == "number" and r.retry_after >= 1 and r.retry_after == math.floor(r.retry_after),
    "retry_after must be an integer >= 1, got " .. tostring(r.retry_after))
end

-- ── the next window resets the budget ────────────────────────────────────────
do
  now = 1000 + WINDOW
  assert_eq(throttle("5.6.7.8").action, "allow", "a new window resets the budget")
end

-- ── distinct IPs have independent budgets ────────────────────────────────────
do
  now = 3000
  for _ = 1, LIMIT do throttle("10.0.0.1") end
  assert_eq(throttle("10.0.0.1").action, "throttle", "10.0.0.1 throttled after LIMIT")
  assert_eq(throttle("10.0.0.2").action, "allow", "10.0.0.2 has its own budget")
end

-- ── host is part of the key: same IP, different hosts have independent budgets ─
do
  now = 5500
  local function t(host)
    return rules.apply({ rule_action = "throttle", throttle_profile = "hard_bot" }, { host = host, ip = "7.7.7.7" }).action
  end
  for _ = 1, LIMIT do t("a.example") end
  assert_eq(t("a.example"), "throttle", "same IP, host a.example throttled after LIMIT")
  assert_eq(t("b.example"), "allow", "same IP, host b.example has its own budget")
end

-- ── a different profile (soft_bot) enforces its OWN larger limit ──────────────
do
  now = 5700
  local SRATE  = tonumber(src:match("soft_bot%s*=%s*{%s*rate%s*=%s*([%d%.]+)"))
  local SBURST = tonumber(src:match("soft_bot%s*=%s*{%s*rate%s*=%s*[%d%.]+,%s*burst%s*=%s*(%d+)"))
  assert(SRATE and SBURST, "could not read soft_bot rate/burst")
  local SLIMIT = SBURST
  assert(SLIMIT > LIMIT, "sanity: soft_bot limit (" .. SLIMIT .. ") should exceed hard_bot limit (" .. LIMIT .. ")")
  local function s(ip)
    return rules.apply({ rule_action = "throttle", throttle_profile = "soft_bot" }, { host = "h", ip = ip }).action
  end
  for i = 1, SLIMIT do
    assert_eq(s("8.8.4.4"), "allow", "soft_bot request " .. i .. "/" .. SLIMIT .. " within its budget")
  end
  assert_eq(s("8.8.4.4"), "throttle", "soft_bot throttled only after its own larger limit (" .. SLIMIT .. ")")
end

-- ── incr failure fails OPEN (F21: was fail-CLOSED/429 on lock timeout) ────────
do
  now = 4000
  dict:_set_incr_fail(true)
  assert_eq(throttle("9.9.9.9").action, "allow", "an incr failure fails OPEN (admit, not 429)")
  dict:_set_incr_fail(false)
end

-- ── key format: IP is the LAST field so cfm_purge.purge_ip still matches ──────
do
  now = 5000
  local IP = "203.0.113.77"
  throttle(IP)
  local found
  for k in pairs(dict:_dump()) do
    if k:sub(1, 3) == "tr|" and k:find(IP, 1, true) then found = k end
  end
  assert(found, "a tr| throttle key was written for " .. IP)
  assert_eq(found:match("([^|]+)$"), IP, "F21/purge: IP must be the LAST pipe-field of the tr key")
end

-- ── SH missing → fail open (unchanged) ───────────────────────────────────────
do
  _G.ngx.shared.cfm_decisions = nil
  rules.init({})
  assert_eq(throttle("2.2.2.2").action, "allow", "missing cfm_decisions dict → throttle fails open")
  _G.ngx.shared.cfm_decisions = dict
  rules.init({})
end

print("ok: cfm_rules lock-free fixed-window throttle — " .. LIMIT .. "/" .. WINDOW .. "s, fails open, ip-last key (F21)")
