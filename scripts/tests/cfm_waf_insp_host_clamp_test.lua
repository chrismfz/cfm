-- Tests for the waf_insp bucket-key host clamp (audit F49 follow-up).
--
-- The /nginx/waf/stats flush emits one row per (hour, host) shdict bucket, and
-- the Go bridge caps that POST body at 2MB (F49). The row `host` comes from
-- ngx.var.host UNTRUNCATED, so on a catch-all/default vhost a client can send
-- multi-KB Host headers; unclamped, a few hundred distinct oversized hosts
-- inflate the flush batch past 2MB and MaxBytesReader rejects the WHOLE batch,
-- collaterally dropping the legit rows in that same flush. waf_insp_incr now
-- clamps the host used as the bucket key to the DNS maximum (253 octets), which
-- bounds both the shdict key and the flush row. No real FQDN exceeds 253, so
-- this is a no-op for legitimate traffic.
--
-- cfm.lua is an access_by_lua_file, so we extract the real waf_insp_incr() from
-- source and load() it, providing its free names as globals — exercising the
-- PRODUCTION function.

local path = "configs/lua/cfm.lua"
local f = assert(io.open(path, "r"), "cannot open " .. path)
local src = f:read("*a"); f:close()

-- Extract waf_insp_incr() and load it.
local start = src:find("local function waf_insp_incr%(")
assert(start, "waf_insp_incr() not found (renamed/moved?)")
local body = src:sub(start)
local stop = body:find("\nend\n")
assert(stop, "could not delimit waf_insp_incr() body")
local fnsrc = body:sub(1, stop + 4)

-- ── Harness: capture the shdict keys waf_insp_incr writes ─────────────────────
local keys
local function reset() keys = {} end
reset()

_G.ngx = { time = function() return 3600 end } -- hr bucket = floor(3600/3600)*3600 = 3600
_G.SH = {
  incr = function(_, key, _v, _init, _ttl) keys[#keys + 1] = key end,
}
_G.CFG = { waf_stats_enable = true }

local waf_insp_incr = assert(load(fnsrc .. "\nreturn waf_insp_incr"))()
assert(type(waf_insp_incr) == "function", "extracted waf_insp_incr is not a function")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end
-- host part of the per-host bucket key (keys[1] is always the per-host incr).
local function host_of(key) return (key:match("^waf_insp:hr=%d+|host=(.*)$")) end

-- ── Legit host: passes through unchanged (clamp is a no-op) ───────────────────
do
  reset()
  waf_insp_incr("example.com")
  check(#keys == 2, "a non-empty host increments both the per-host and global buckets (got " .. #keys .. ")")
  check(host_of(keys[1]) == "example.com", "legit host is stored verbatim (got '" .. tostring(host_of(keys[1])) .. "')")
  check(host_of(keys[2]) == "", "the second incr is the global total (empty host)")
end

-- ── Max-length legit host (exactly 253): unchanged ───────────────────────────
do
  reset()
  local h253 = string.rep("a", 253)
  waf_insp_incr(h253)
  check(#host_of(keys[1]) == 253, "a 253-octet host is kept in full (got " .. #host_of(keys[1]) .. ")")
  check(host_of(keys[1]) == h253, "the 253-octet host is byte-for-byte preserved")
end

-- ── Oversized host: clamped to 253 in the bucket key ─────────────────────────
do
  reset()
  local huge = string.rep("b", 4096) -- a ~4KB Host header to a catch-all vhost
  waf_insp_incr(huge)
  check(#host_of(keys[1]) == 253,
    "F49: an oversized host is clamped to 253 octets in the bucket key (got " .. #host_of(keys[1]) .. ")")
  check(host_of(keys[1]) == string.rep("b", 253), "the clamped host is the 253-octet prefix")
  -- The whole key stays small, so the flush row it produces can't blow the 2MB cap.
  check(#keys[1] < 300, "the bucket key itself is bounded (~<300 bytes), not multi-KB (got " .. #keys[1] .. ")")
end

-- ── Empty host: only the global bucket, no clamp needed ───────────────────────
do
  reset()
  waf_insp_incr("")
  check(#keys == 1, "an empty host increments only the global bucket (got " .. #keys .. ")")
  check(host_of(keys[1]) == "", "empty host stays empty")
end

-- ── nil host: coalesces to "" without crashing ───────────────────────────────
do
  reset()
  local ok = pcall(waf_insp_incr, nil)
  check(ok, "nil host does not crash")
  check(#keys == 1 and host_of(keys[1]) == "", "nil host behaves as empty (global bucket only)")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_waf_insp_host_clamp_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: waf_insp bucket-key host clamped to DNS max (F49)\n")
