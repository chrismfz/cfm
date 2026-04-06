-- /usr/local/openresty/nginx/lua/cfm_rules.lua
-- Dynamic traffic-rules action executor for cfm.lua.
--
-- Current scope:
--   - apply throttle actions from bridge decision payload
--   - leave allow/challenge/block behavior to existing cfm.lua flow

local _M = {}

local ngx = ngx
local tonumber = tonumber
local tostring = tostring
local math = math
local string = string

local SH = nil
local SH_MISSING_LOGGED = false

local PROFILES = {
  soft_bot = { rate = 2.0, burst = 20 },
  medium_bot = { rate = 1.0, burst = 10 },
  hard_bot = { rate = 0.5, burst = 5 },
}

function _M.init(_cfg)
  SH = ngx.shared.cfm_decisions
  if not SH and not SH_MISSING_LOGGED then
    ngx.log(ngx.ERR, "[cfm_rules] ngx.shared.cfm_decisions is nil; throttling is disabled")
    SH_MISSING_LOGGED = true
  end
end

local function profile_for(name)
  local k = tostring(name or "")
  if k == "" then return PROFILES.soft_bot end
  return PROFILES[k] or PROFILES.soft_bot
end

local function throttle_hit(profileName, host, ip)
  if not SH then
    -- Intentional degraded mode: fail open and allow requests when cfm_decisions SHM is unavailable.
    return false, 0
  end

  local p = profile_for(profileName)
  local key = "tr|" .. tostring(profileName or "soft_bot") .. "|" .. tostring(host or "-") .. "|" .. tostring(ip or "-")
  local lock_key = key .. ":lock"
  local now = ngx.now()

  local locked = false
  for _ = 1, 10 do
    if SH:add(lock_key, true, 0.05) then
      locked = true
      break
    end
    ngx.sleep(0.001)
  end
  if not locked then
    return true, 0.05
  end

  local state = SH:get(key)
  local tokens, last
  if state then
    local t, ts = string.match(tostring(state), "^([^:]+):([^:]+)$")
    tokens = tonumber(t)
    last = tonumber(ts)
  end

  if not tokens then
    -- rollout compatibility with old split keys
    tokens = tonumber(SH:get(key .. ":tok")) or p.burst
    last = tonumber(SH:get(key .. ":ts")) or now
  end

  local elapsed = math.max(0, now - (last or now))
  tokens = math.min(p.burst, tokens + elapsed * p.rate)

  local allow = tokens >= 1
  local retry_after = 0
  if allow then
    tokens = tokens - 1
  else
    local need = 1 - tokens
    retry_after = need > 0 and (need / p.rate) or 1
  end

  local ttl = math.max(2, math.floor((p.burst / p.rate) * 2))
  SH:set(key, tostring(tokens) .. ":" .. tostring(now), ttl)
  SH:delete(lock_key)

  return (not allow), retry_after
end

-- apply executes rule action side effects and returns normalized result:
--   { action = "allow" | "throttle", retry_after = number }
function _M.apply(decision, ctx)
  decision = decision or {}
  ctx = ctx or {}

  local action = tostring(decision.rule_action or "allow")
  if action ~= "throttle" then
    return { action = "allow" }
  end

  local profile = tostring(decision.throttle_profile or ctx.profile or "soft_bot")
  local host = tostring(ctx.host or "-")
  local ip = tostring(ctx.ip or "-")

  local hit, retry_after = throttle_hit(profile, host, ip)
  if hit then
    return { action = "throttle", retry_after = retry_after }
  end
  return { action = "allow" }
end

return _M
