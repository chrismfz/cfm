-- scripts/tests/cfm_purge_test.lua
--
-- Unit tests for configs/lua/cfm_purge.lua (force-unblock shared-dict purge).
-- Run via `make test-lua` (luajit scripts/tests/cfm_purge_test.lua).
--
-- Locks in the behaviour found during independent review:
--   * per-IP keys for every namespace are purged (incl. panel_* and the
--     wafpush|<reason>|<ip> layout where the IP is the LAST field),
--   * field-positional matching never collateral-purges another IP's keys
--     (e.g. victim IP appearing in a host/URI field),
--   * check_loopback() trusts the real peer ($realip_remote_addr), not the
--     real_ip-rewritten $remote_addr that a CF-fronted request can forge.

local failures = 0
local function check(cond, msg)
  if not cond then
    failures = failures + 1
    io.stderr:write("FAIL: " .. tostring(msg) .. "\n")
  end
end

-- Minimal ngx stub.
local store, hdrs
local ngx_var = {}
_G.ngx = {
  shared = {
    cfm_decisions = {
      get_keys = function(_, _)
        local t = {}
        for k in pairs(store) do t[#t + 1] = k end
        return t
      end,
      delete = function(_, k) store[k] = nil end,
    },
  },
  req = { get_headers = function() return hdrs end },
  var = ngx_var,
}

local purge = dofile("configs/lua/cfm_purge.lua")

-- ── purge_ip: clears every per-IP namespace, leaves others intact ────────────
local function fresh_store()
  return {
    ["tr|soft_bot|example.com|1.2.3.4"]          = "x",
    ["tr|soft_bot|example.com|1.2.3.4:lock"]     = "x",
    ["tr|soft_bot|example.com|1.2.3.4:tok"]      = "x",
    ["tr|soft_bot|example.com|1.2.3.4:ts"]       = "x",
    ["d|1.2.3.4|example.com|GET|https|/"]        = "x",
    ["ds|1.2.3.4|example.com|web"]               = "x",
    ["geo|1.2.3.4"]                              = "x",
    ["ok_touch|1.2.3.4|example.com|web"]         = "x",
    ["wafpush|WAF_RCE:REVERSE_SHELL|1.2.3.4"]    = "x", -- IP is LAST field
    ["panel_cooldown|1.2.3.4|panel.example.com"] = "x",
    ["panel_ok|1.2.3.4|panel.example.com"]       = "x",
    ["panel_loop|1.2.3.4|panel.example.com"]     = "x",
    -- Must SURVIVE (different IP, or victim IP only in a non-IP field):
    ["tr|soft_bot|example.com|9.9.9.9"]          = "x",
    ["wafpush|403waf_flood|9.9.9.9"]             = "x",
    ["panel_cooldown|9.9.9.9|panel.example.com"] = "x",
    ["d|9.9.9.9|1.2.3.4|GET|https|/"]            = "x", -- victim IP as Host field
  }
end

store = fresh_store()
local r = purge.purge_ip("1.2.3.4")
check(r.deleted.throttle == 4,       "throttle should be 4, got " .. tostring(r.deleted.throttle))
check(r.deleted.decision_cache == 2, "decision_cache should be 2, got " .. tostring(r.deleted.decision_cache))
check(r.deleted.geo == 1,            "geo should be 1")
check(r.deleted.ok_touch == 1,       "ok_touch should be 1")
check(r.deleted.wafpush == 1,        "wafpush should be 1 (IP is last field), got " .. tostring(r.deleted.wafpush))
check(r.deleted.panel == 3,          "panel should be 3, got " .. tostring(r.deleted.panel))

check(store["tr|soft_bot|example.com|9.9.9.9"] ~= nil,          "other-IP throttle must survive")
check(store["wafpush|403waf_flood|9.9.9.9"] ~= nil,             "other-IP wafpush must survive")
check(store["panel_cooldown|9.9.9.9|panel.example.com"] ~= nil, "other-IP panel must survive")
check(store["d|9.9.9.9|1.2.3.4|GET|https|/"] ~= nil,            "victim IP in Host field must NOT be purged")

-- ── IPv6: throttle :lock suffix stripping + geo ──────────────────────────────
store = {
  ["geo|2a02:587:dc1f::1"]              = "x",
  ["tr|soft_bot|h|2a02:587:dc1f::1"]    = "x",
  ["tr|soft_bot|h|2a02:587:dc1f::1:lock"] = "x",
}
local r6 = purge.purge_ip("2a02:587:dc1f::1")
check(r6.deleted.geo == 1,      "v6 geo should be 1")
check(r6.deleted.throttle == 2, "v6 throttle should be 2 (incl :lock), got " .. tostring(r6.deleted.throttle))

-- ── bad input / missing dict ─────────────────────────────────────────────────
store = {}
check(purge.purge_ip("").error == "bad ip", "empty ip should error")

-- ── check_loopback: trust real peer, not spoofable rewritten remote_addr ─────
ngx_var.realip_remote_addr = "127.0.0.1"; ngx_var.remote_addr = "127.0.0.1"
check(purge.check_loopback() == true, "real loopback peer should pass")
ngx_var.realip_remote_addr = "::1"; ngx_var.remote_addr = "::1"
check(purge.check_loopback() == true, "::1 peer should pass")
-- CF-fronted spoof: header rewrote remote_addr to 127.0.0.1, real peer is CF edge.
ngx_var.realip_remote_addr = "203.0.113.7"; ngx_var.remote_addr = "127.0.0.1"
check(purge.check_loopback() == false, "CF-spoofed loopback must be rejected (real peer is non-loopback)")
-- realip module absent ($realip_remote_addr nil/empty): fall back to $remote_addr.
ngx_var.realip_remote_addr = nil; ngx_var.remote_addr = "127.0.0.1"
check(purge.check_loopback() == true, "nil realip falls back to remote_addr (loopback → pass)")
ngx_var.realip_remote_addr = ""; ngx_var.remote_addr = "203.0.113.7"
check(purge.check_loopback() == false, "empty realip falls back to remote_addr (non-loopback → reject)")

-- ── check_token ──────────────────────────────────────────────────────────────
-- cfm_purge reads the token through the cfm_bridge_cfg accessor; control it
-- with a fake in package.loaded so these tests exercise cfm_purge's actual
-- comparison + refresh-on-mismatch logic (not an incidental require failure).

-- (a) Accessor present but token unavailable (daemon not started) → fail closed.
package.loaded["cfm_bridge_cfg"] = {
  token = function() return nil, "missing or unreadable" end,
  refresh_token = function() return nil, "missing or unreadable" end,
}
hdrs = { ["X-CFM-Token"] = "whatever" }
check(purge.check_token() == false, "check_token must fail closed when the token is unavailable")

-- (b) Matching token → pass; wrong/missing header → fail.
package.loaded["cfm_bridge_cfg"] = {
  token = function() return "tok-current" end,
  refresh_token = function() return "tok-current" end,
}
hdrs = { ["X-CFM-Token"] = "tok-current" }
check(purge.check_token() == true, "matching token must pass")
hdrs = { ["X-CFM-Token"] = "tok-wrong" }
check(purge.check_token() == false, "wrong token must fail")
hdrs = {}
check(purge.check_token() == false, "missing token header must fail")

-- (c) Rotation race: cache still serves the OLD token, the daemon presents
-- the NEW one — check_token must force one fresh read and accept it, so a
-- force-unblock issued right after a startup token rotation never 403s.
local refreshed = 0
package.loaded["cfm_bridge_cfg"] = {
  token = function() return "tok-old" end,
  refresh_token = function() refreshed = refreshed + 1; return "tok-new" end,
}
hdrs = { ["X-CFM-Token"] = "tok-new" }
check(purge.check_token() == true, "just-rotated token must pass via refresh-on-mismatch")
check(refreshed == 1, "mismatch triggers exactly one forced fresh read")

-- (d) Old accessor module without refresh_token (upgrade lag) → fail closed
-- on mismatch instead of erroring.
package.loaded["cfm_bridge_cfg"] = { token = function() return "tok-old" end }
hdrs = { ["X-CFM-Token"] = "tok-new" }
check(purge.check_token() == false, "mismatch without refresh_token fails closed")
package.loaded["cfm_bridge_cfg"] = nil

if failures > 0 then
  error(failures .. " cfm_purge test assertion(s) failed")
end
print("OK: cfm_purge tests passed")
