-- Tests for the dashboard stats scan cache (audit F20).
--
-- decisions_stats/sslcache_stats enumerated their dict with get_keys(N), which
-- LOCKS the whole dict for the scan — run on every /cfm-admin/lua-stats poll it
-- stalls request/handshake processing. The scan-derived counts are now cached
-- per worker for SCAN_TTL; the cheap capacity/meta fields stay fresh each call.
--
-- cfm_stats.lua's stats helpers are locals; extract the cache block through
-- decisions_stats and load() it, driving decisions_stats against a mock dict that
-- counts get_keys calls and a controllable clock.

package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local fails = 0
local function check(cond, msg)
  if not cond then fails = fails + 1; io.stderr:write("FAIL: " .. tostring(msg) .. "\n") end
end

local f = assert(io.open("configs/lua/cfm_stats.lua", "r"))
local src = f:read("*a"); f:close()

local SCAN_TTL = tonumber(src:match("SCAN_TTL%s*=%s*(%d+)"))
assert(SCAN_TTL and SCAN_TTL > 0, "could not read SCAN_TTL from cfm_stats.lua")

local a = src:find("local SCAN_TTL", 1, true)
local b = src:find("\nlocal function waf_config", a, true)
assert(a and b, "could not delimit the scan-cache..decisions_stats block")
local block = src:sub(a, b)

-- Mock state ------------------------------------------------------------------
local _now = 1000
local getkeys_calls = 0
local keys = {
  "snap_ips", "snap_vhosts", "pr|1", "pr|2", "ok_touch|x",
  "wafpush|reason|1.2.3.4", "d|1.2.3.4|h|GET|https|/", "rand1", "rand2",
}
local free_val = 1000
local CAP = 64 * 1024 * 1024
local dict = {
  capacity   = function() return CAP end,
  free_space = function() return free_val end,
  get_keys   = function(_, _) getkeys_calls = getkeys_calls + 1; return keys end,
  get        = function(_, k)
    if k == "snap_ts" then return "0" end
    if k == "snap_waf_excludes" then return "[]" end
    return nil
  end,
}
_G.ngx = { now = function() return _now end, time = function() return _now end }
_G.cjson = { decode = function(_) return {} end }
_G.age_s = function() return nil end   -- sslcache_stats calls age_s() on meta timestamps
package.loaded["sslcollector"] = { cert_counts = function() return 3, 2 end }

local decisions_stats, sslcache_stats = assert(load(block .. "\nreturn decisions_stats, sslcache_stats"))()
assert(type(decisions_stats) == "function" and type(sslcache_stats) == "function",
  "extracted decisions_stats/sslcache_stats are not functions")

-- ── first call scans once; counts + capacity are correct ─────────────────────
do
  getkeys_calls = 0; _now = 1000; free_val = 1000
  local r = decisions_stats(dict)
  check(getkeys_calls == 1, "first call performs exactly one get_keys scan")
  check(r.total_keys == #keys, "total_keys = " .. #keys .. ", got " .. tostring(r.total_keys))
  check(r.key_breakdown.snapshot_ips == 1, "snap_ips counted (1)")
  check(r.key_breakdown.snapshot_vhosts == 1, "snap_vhosts counted (1)")
  check(r.key_breakdown.post_resume_entries == 2, "pr| counted (2), got " .. tostring(r.key_breakdown.post_resume_entries))
  check(r.key_breakdown.solved_ip_touch_entries == 1, "ok_touch| counted (1)")
  check(r.key_breakdown.waf_push_cooldowns == 1, "wafpush| counted (1)")
  check(r.key_breakdown.other == 3, "other counted (d|.., rand1, rand2 = 3), got " .. tostring(r.key_breakdown.other))
  check(r.capacity_bytes == CAP and r.free_bytes == 1000, "capacity/free reported")
end

-- ── second call within TTL: scan NOT repeated, but capacity is FRESH ─────────
do
  free_val = 2000   -- capacity changed since the first call
  local r = decisions_stats(dict)
  check(getkeys_calls == 1, "F20: within SCAN_TTL the get_keys scan is NOT repeated")
  check(r.key_breakdown.snapshot_ips == 1, "breakdown served from cache")
  check(r.total_keys == #keys, "total_keys served from cache")
  check(r.free_bytes == 2000, "F20: capacity/free are recomputed FRESH each call (not cached), got " .. tostring(r.free_bytes))
end

-- ── past TTL: the scan runs again and reflects the new key set ───────────────
do
  _now = 1000 + SCAN_TTL + 1
  keys = { "snap_ips" }   -- key set shrank
  local r = decisions_stats(dict)
  check(getkeys_calls == 2, "F20: past SCAN_TTL the scan runs again")
  check(r.total_keys == 1, "refreshed scan reflects the new key set (1)")
  check(r.key_breakdown.other == 0, "refreshed breakdown reflects the new key set")
end

-- ── sslcache: scan cached, meta_count correct, but ingest_lock read FRESH ────
do
  local sk_calls = 0
  local ssl_keys = { "meta:ready", "meta:version", "certhost|a.com", "certhost|b.com" }
  local lock_present = false
  local ssldict = {
    capacity   = function() return 256 * 1024 * 1024 end,
    free_space = function() return 1000 end,
    get_keys   = function(_, _) sk_calls = sk_calls + 1; return ssl_keys end,
    get        = function(_, k) if k == "lock:dumpall" then return lock_present or nil end return nil end,
  }

  _now = 5000
  local r1 = sslcache_stats(ssldict)
  check(sk_calls == 1, "sslcache: first call scans once")
  check(r1.total_keys == #ssl_keys, "sslcache total_keys correct")
  check(r1.meta_count == 2, "sslcache meta_count = 2 (meta:ready, meta:version), got " .. tostring(r1.meta_count))
  check(r1.exact_hosts == 3 and r1.wild_hosts == 2, "cert counts come from the module (fresh)")
  check(r1.ingest_lock == false, "no lock:dumpall → ingest_lock false")

  -- within TTL: scan is cached, but flip lock:dumpall — ingest_lock must update
  lock_present = true
  local r2 = sslcache_stats(ssldict)
  check(sk_calls == 1, "F20: sslcache scan is NOT repeated within the TTL")
  check(r2.meta_count == 2, "sslcache meta_count served from cache")
  check(r2.ingest_lock == true, "F20: ingest_lock is read FRESH each call (not part of the cached scan)")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_stats_scan_cache_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: dashboard stats scan cached per worker for " .. SCAN_TTL .. "s; capacity stays fresh (F20)\n")
