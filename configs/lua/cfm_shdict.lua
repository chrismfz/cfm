-- cfm_shdict.lua — shared-dict counter helper for every edge counter.
--
-- incr(dict, key, n, ttl) counts n (default 1) on key and returns the new
-- value, or nil and the error, like dict:incr. A key it creates gets `ttl`
-- seconds (nil or 0 = no expiry); a later incr leaves the TTL as it is, so a
-- window counter still resets `ttl` after its first hit.
--
-- It replaces dict:incr(key, n, init[, init_ttl]). With init, lua-nginx-module
-- 0.10.26 (verified on nginx 1.24, lua-resty-core 0.1.28) loses counters when
-- a new key's crc32 — the dict's tree hash — equals an existing key's: the
-- other key then reads nil, or both count wrong, for as long as the dict
-- lives. The odds are about K^2/2^33 per node for K live keys, so per-IP rate
-- counters (~100k keys) hit it routinely. incr without init, then add, never
-- takes that path; an add that finds "exists" lost the race to another worker,
-- so incr again.
--
-- Pure: no ngx at load, so any module can require it.

local _M = {}

function _M.incr(dict, key, n, ttl)
  n = n or 1
  local v, err = dict:incr(key, n)
  if v ~= nil or err ~= "not found" then return v, err end
  local ok, aerr = dict:add(key, n, ttl or 0)
  if ok then return n end
  if aerr == "exists" then return dict:incr(key, n) end
  return nil, aerr
end

return _M
