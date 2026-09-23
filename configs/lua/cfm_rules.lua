-- /var/lib/cfm/lua/cfm_rules.lua (CFM-managed canonical location)
-- Dynamic traffic-rules action executor for cfm.lua.
--
-- Current scope:
--   - normalize passthrough rule actions from bridge decision payload
--   - apply throttle side-effects when rule_action == "throttle"

local _M = {}

local shd = require "cfm_shdict" -- counters: never dict:incr(key, n, init) (see cfm_shdict.lua)

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

-- throttle_hit returns (hit, retry_after). hit==true means reject (429).
--
-- Lock-free fixed-window counter (audit F21): ONE atomic SH:incr per request
-- (a window's first hit also an add, via cfm_shdict),
-- keyed on (profile, host, ip, window). The previous implementation took a
-- per-(profile,host,ip) spin-lock (SH:add + up to 10x ngx.sleep(1ms)) around a
-- read-modify-write token bucket, and on lock-acquisition TIMEOUT returned a 429
-- regardless of token availability. Under carrier-grade NAT / a shared proxy,
-- many legit users behind one IP contend on that single lock, so lock losers
-- were 429'd with bucket capacity to spare — over-throttling legit bursts. A
-- lock-free counter has no contention to mis-handle: every request is counted
-- atomically, so the cap is exactly LIMIT/window with no false throttles (and no
-- spin-lock churn on the shared cfm_decisions dict).
--
-- LIMIT requests per WINDOW seconds preserves each profile's rate/burst intent:
-- WINDOW = burst/rate, LIMIT = burst (soft_bot 20/10s = 2/s burst 20; medium
-- 10/10s; hard 5/10s). A fixed window can admit up to ~2x LIMIT across a window
-- boundary — acceptable for a coarse bot throttle. (Deliberately NOT changed:
-- keying purely on IP still shares one budget across a NAT/proxy's users; that
-- is a deeper design question the finding raises separately.)
local function throttle_hit(profileName, host, ip)
  if not SH then
    -- Intentional degraded mode: fail open and allow requests when cfm_decisions SHM is unavailable.
    return false, 0
  end

  local p = profile_for(profileName)
  -- WINDOW = burst/rate reproduces the profile's long-run rate ONLY while burst is
  -- an integer multiple of rate and rate <= burst (true for all 3 shipped
  -- profiles → 10s). A future profile with rate > burst would collapse to
  -- window=1 and enforce burst/s; compute WINDOW to preserve the rate if that
  -- ever changes.
  local window = math.max(1, math.floor(p.burst / p.rate))
  local limit  = p.burst
  local now = ngx.now()
  local win = math.floor(now / window)
  -- IP is the LAST field on purpose: cfm_purge.purge_ip finds throttle keys by
  -- matching the trailing IP on a force-unblock, so the window index goes BEFORE
  -- it. (Format: tr|<profile>|<host>|<window>|<ip>.)
  local key = "tr|" .. tostring(profileName or "soft_bot") .. "|" ..
              tostring(host or "-") .. "|" .. win .. "|" .. tostring(ip or "-")

  -- A fresh window key starts at 1; its TTL (2x the window) is applied on
  -- CREATE only, so the key ages out on its own after the window.
  local count, err = shd.incr(SH, key, 1, window * 2)
  if not count then
    -- incr failed (shdict full and forcible eviction failed). Fail OPEN — a
    -- saturated dict must not black out legitimate traffic (matches the SH-missing
    -- policy above) — and rate-limit the log so it can't become a logging outage.
    if SH:add("tr|_incr_fail_logged", true, 60) then
      ngx.log(ngx.ERR, "[cfm_rules] shdict :incr failed (rate-limited 60s) key=", key,
        " err=", tostring(err), " — throttle may be ineffective")
    end
    return false, 0
  end

  if count > limit then
    -- Over budget for this window. retry_after = whole seconds until it rolls
    -- (>=1 so the integer Retry-After header the caller emits stays meaningful).
    local retry = window - (now - win * window)
    if retry < 1 then retry = 1 end
    return true, math.ceil(retry)
  end
  return false, 0
end

-- apply executes rule action side effects and returns normalized result:
--   { action = "allow" | "challenge" | "block" | "throttle", retry_after = number }
function _M.apply(decision, ctx)
  decision = decision or {}
  ctx = ctx or {}

  local action = tostring(decision.rule_action or "allow")
  if action == "allow" or action == "challenge" or action == "block" then
    return { action = action }
  end
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
