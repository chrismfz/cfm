-- Behaviour test for the /__ssl_debug loopback gate (audit F56).
--
-- The four /__ssl_debug blocks (openresty.conf + angie.conf, ×2 server blocks
-- each) gained a Lua loopback gate that mirrors /cfm-admin/purge-ip: it calls
-- cfm_purge.check_loopback() on the un-forgeable $realip_remote_addr and 403s a
-- request whose real peer is not loopback (closing the CF-Connecting-IP forge of
-- the coarse `allow 127.0.0.1`). Two properties matter and are locked here:
--   1. security   — a real_ip-spoofed "loopback" request is rejected (403).
--   2. DNAT-safety — the endpoint is the canonical edge health probe
--      (internal/dnat/state.go GETs it and treats non-200 as "edge down"), so a
--      genuine loopback probe must still get 200, AND a broken/absent cfm_purge
--      must FAIL OPEN (still 200) rather than turn the probe into a false down.
--
-- `gate()` below is a faithful copy of the content_by_lua_block in the config;
-- keep it in sync with configs/{openresty,angie}.conf `location = /__ssl_debug`.
-- The real matcher (check_loopback semantics) is separately locked by
-- cfm_purge_test.lua — here we mock cfm_purge to drive the gate's control flow.

local out = {}
_G.ngx = {
  status = 200,
  say = function(...)
    local parts = {}
    for _, v in ipairs({ ... }) do parts[#parts + 1] = tostring(v) end
    out[#out + 1] = table.concat(parts)
  end,
  shared = {
    sslcache = {
      get = function(_, k)
        if k == "meta:ready"   then return "1" end
        if k == "meta:version" then return "42" end
        return nil
      end,
    },
  },
}

-- Faithful copy of the config's content_by_lua_block. Returns nothing; effects
-- are observed via ngx.status / out.
local function gate()
  local ok, purge = pcall(require, "cfm_purge")
  if ok and type(purge) == "table"
     and type(purge.check_loopback) == "function" then
    -- pcall the check itself so even a check_loopback that raises fails OPEN.
    local okc, lb = pcall(purge.check_loopback)
    if okc and lb == false then
      ngx.status = 403
      ngx.say("forbidden")
      return
    end
  end
  local d = ngx.shared.sslcache
  ngx.say("ready=",   d:get("meta:ready")   or "0")
  ngx.say("version=", d:get("meta:version") or "-")
end

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- Helper: install a cfm_purge stub whose check_loopback returns `verdict`.
local function set_purge(verdict)
  package.loaded["cfm_purge"] = { check_loopback = function() return verdict end }
end
local function run()
  out = {}; ngx.status = 200
  gate()
end

-- ── 1. Genuine loopback → served 200 with the debug body ─────────────────────
set_purge(true)
run()
check(ngx.status == 200, "loopback: status stays 200 (got " .. tostring(ngx.status) .. ")")
check(out[1] == "ready=1" and out[2] == "version=42",
      "loopback: debug body served")

-- ── 2. Spoofed (real peer non-loopback) → 403, no debug body ─────────────────
set_purge(false)
run()
check(ngx.status == 403, "F56: spoofed loopback rejected with 403 (got " .. tostring(ngx.status) .. ")")
check(out[1] == "forbidden" and out[2] == nil,
      "F56: spoofed request gets 'forbidden', not the ready/version body")

-- ── 3. cfm_purge require FAILS → fail OPEN (200), health probe unbroken ───────
package.loaded["cfm_purge"] = nil
package.preload["cfm_purge"] = function() error("simulated broken cfm_purge") end
run()
package.preload["cfm_purge"] = nil
check(ngx.status == 200,
      "F56/DNAT: require failure fails OPEN — health probe still 200 (got " .. tostring(ngx.status) .. ")")
check(out[1] == "ready=1" and out[2] == "version=42",
      "F56/DNAT: fail-open still serves the debug body")

-- ── 4. cfm_purge loaded but check_loopback missing (partial module) → 200 ────
package.loaded["cfm_purge"] = { some_other_fn = true }
run()
check(ngx.status == 200,
      "F56/DNAT: partial module (no check_loopback) fails OPEN — still 200")
check(out[1] == "ready=1",
      "F56/DNAT: partial module still serves the debug body")

-- ── 5. check_loopback RAISES → fail OPEN (200), not 500 (N1 bulletproofing) ───
package.loaded["cfm_purge"] = {
  check_loopback = function() error("simulated check_loopback runtime error") end,
}
run()
check(ngx.status == 200,
      "F56/DNAT: a raising check_loopback fails OPEN — still 200 (not 500)")
check(out[1] == "ready=1" and out[2] == "version=42",
      "F56/DNAT: raising check_loopback still serves the debug body")

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in cfm_ssl_debug_gate_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: /__ssl_debug loopback gate — spoof 403, loopback+fail-open 200 (F56)\n")
