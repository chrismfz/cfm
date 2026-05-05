local function new_dict()
  local store = {}
  local dict = {}

  function dict:get(key)
    local e = store[key]
    if not e then return nil end
    return e.v
  end

  function dict:set(key, v, ttl)
    store[key] = { v = v, ttl = ttl }
    return true
  end

  function dict:add(key, v, ttl)
    if store[key] ~= nil then
      return false, "exists"
    end
    store[key] = { v = v, ttl = ttl }
    return true
  end

  function dict:delete(key)
    store[key] = nil
  end

  function dict:_dump()
    return store
  end

  return dict
end

local dict = new_dict()
local now = 1000.0

_G.ngx = {
  now = function() return now end,
  sleep = function(_)
    coroutine.yield()
  end,
  shared = {
    cfm_decisions = dict,
  },
}

local rules = dofile("configs/lua/cfm_rules.lua")
rules.init({})

local function assert_eq(actual, expected, msg)
  if actual ~= expected then
    error((msg or "assert_eq failed") .. ": expected=" .. tostring(expected) .. " actual=" .. tostring(actual))
  end
end

local function run_concurrent(fn1, fn2)
  local c1 = coroutine.create(fn1)
  local c2 = coroutine.create(fn2)
  local alive = true
  while alive do
    alive = false
    if coroutine.status(c1) ~= "dead" then
      alive = true
      local ok, err = coroutine.resume(c1)
      if not ok then error(err) end
    end
    if coroutine.status(c2) ~= "dead" then
      alive = true
      local ok, err = coroutine.resume(c2)
      if not ok then error(err) end
    end
  end
end

-- Test 1: legacy split keys are read and migrated to unified key.
do
  local k = "tr|hard_bot|example.com|1.2.3.4"
  dict:set(k .. ":tok", "1", 30)
  dict:set(k .. ":ts", tostring(now), 30)

  local out = rules.apply({ rule_action = "throttle", throttle_profile = "hard_bot" }, { host = "example.com", ip = "1.2.3.4" })
  assert_eq(out.action, "allow", "legacy state should allow one consume")

  local state = dict:get(k)
  if not state or not tostring(state):match("^[^:]+:[^:]+$") then
    error("expected migrated unified state format")
  end
end

-- Test 2: non-throttle actions are normalized passthrough.
do
  local allow = rules.apply({ rule_action = "allow" }, { host = "example.com", ip = "1.1.1.1" })
  local challenge = rules.apply({ rule_action = "challenge" }, { host = "example.com", ip = "1.1.1.1" })
  local block = rules.apply({ rule_action = "block" }, { host = "example.com", ip = "1.1.1.1" })
  local unknown = rules.apply({ rule_action = "drop" }, { host = "example.com", ip = "1.1.1.1" })

  assert_eq(allow.action, "allow", "allow passthrough")
  assert_eq(challenge.action, "challenge", "challenge passthrough")
  assert_eq(block.action, "block", "block passthrough")
  assert_eq(unknown.action, "allow", "unsupported actions fail open to allow")
end

-- Test 3: concurrent same-IP requests must not double-consume a single token.
do
  local k = "tr|hard_bot|example.org|5.6.7.8"
  dict:set(k, "1:" .. tostring(now), 30)

  local r1, r2
  run_concurrent(
    function()
      r1 = rules.apply({ rule_action = "throttle", throttle_profile = "hard_bot" }, { host = "example.org", ip = "5.6.7.8" })
    end,
    function()
      r2 = rules.apply({ rule_action = "throttle", throttle_profile = "hard_bot" }, { host = "example.org", ip = "5.6.7.8" })
    end
  )

  local throttles = 0
  if r1.action == "throttle" then throttles = throttles + 1 end
  if r2.action == "throttle" then throttles = throttles + 1 end

  assert_eq(throttles, 1, "expected exactly one throttled request when one token exists")
end

print("ok: cfm_rules race/compat tests")
