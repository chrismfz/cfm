-- Tests for sslcollector.lua's ssl_certificate_by_lua hot path (audit F19 + F43).
--
-- sslcollector.lua is OpenResty-runtime code (requires ngx.ssl / resty.http /
-- ngx.shared), so there is no full harness. We mock just enough to load the
-- module and drive M.set_cert(), and reach the module-local `_store` via a
-- debug upvalue to inject a pre-parsed entry.
--
-- F19: set_cert must NOT parse PEM on the handshake path — it reuses the DER
--      cdata that store_pair parsed once at ingest.
-- F43: the "cache miss" WARN is rate-limited (at most one per MISS_LOG_INTERVAL
--      seconds, carrying a suppressed count), and the attacker-supplied SNI is
--      sanitized on the logged line.

-- ── Mocks (installed before the module is required) ──────────────────────────
local parse_cert_calls, parse_key_calls = 0, 0
local set_cert_arg, set_key_arg
local sslmock -- forward-declare so the closures below capture the local, not a nil global
sslmock = {
  _sni = "",
  server_name = function() return sslmock._sni end,
  parse_pem_cert = function(_) parse_cert_calls = parse_cert_calls + 1; return {} end,
  parse_pem_priv_key = function(_) parse_key_calls = parse_key_calls + 1; return {} end,
  clear_certs = function() return true end,
  set_cert = function(d) set_cert_arg = d; return true end,
  set_priv_key = function(d) set_key_arg = d; return true end,
}
package.loaded["ngx.ssl"] = sslmock
package.loaded["resty.http"] = { new = function() return {} end }
package.loaded["cjson.safe"] = { encode = function() return "{}" end, decode = function() return nil end }

local warn_lines = {}
local _now = 1000
_G.ngx = {
  shared = { sslcache = setmetatable({}, { __index = function() return function() end end }) },
  log = function(level, ...)
    if level == 1 then -- WARN
      local parts = { ... }
      warn_lines[#warn_lines + 1] = table.concat(parts, "")
    end
  end,
  now = function() return _now end,
  WARN = 1, ERR = 2, INFO = 3, DEBUG = 4,
  timer = { at = function() return true end, every = function() return true end },
  worker = { id = function() return 0 end, pid = function() return 1 end, exiting = function() return false end },
  config = { subsystem = "http" },
  re = { match = function() return nil end },
}

-- Intercept the module's load-time token read (const path) without touching the
-- filesystem, so the test never depends on (or writes) a live /var/lib/cfm file.
local _real_loadfile = loadfile
_G.loadfile = function(path)
  if path == "/var/lib/cfm/lua/cfm_token.lua" then
    return function() return string.rep("a", 48) end
  end
  return _real_loadfile(path)
end

package.path = "configs/lua/?.lua;" .. package.path
local M = require("sslcollector")
_G.loadfile = _real_loadfile

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

-- Reach the module-local `_store` upvalue of M.set_cert (white-box injection).
local function store_ref()
  local i = 1
  while true do
    local name, val = debug.getupvalue(M.set_cert, i)
    if not name then break end
    if name == "_store" then return val end
    i = i + 1
  end
  return nil
end

-- ── F19: set_cert reuses the cached DER, never re-parses on the hot path ──────
do
  local store = store_ref()
  check(store ~= nil, "F19: found module-local _store upvalue")
  if store then
    local CD, KD = { "cert_der_cdata" }, { "key_der_cdata" }
    store["e:host.example.com"] = { cert_der = CD, key_der = KD }

    sslmock._sni = "host.example.com"
    parse_cert_calls, parse_key_calls = 0, 0
    set_cert_arg, set_key_arg = nil, nil
    M.set_cert()

    check(parse_cert_calls == 0, "F19: set_cert must NOT call parse_pem_cert (got " .. parse_cert_calls .. ")")
    check(parse_key_calls == 0, "F19: set_cert must NOT call parse_pem_priv_key (got " .. parse_key_calls .. ")")
    check(set_cert_arg == CD, "F19: ssl.set_cert got the cached cert_der cdata")
    check(set_key_arg == KD, "F19: ssl.set_priv_key got the cached key_der cdata")
  end
end

-- ── F43: cache-miss WARN is throttled + SNI-sanitized ────────────────────────
do
  sslmock._sni = "nope.example.com"
  _now = 2000

  -- Warm-up: the first miss logs immediately (so operators see misses promptly),
  -- then the throttle window opens. Confirm it logged, then clear.
  warn_lines = {}
  M.set_cert()
  check(#warn_lines == 1, "F43: the first miss logs immediately (got " .. #warn_lines .. ")")
  warn_lines = {}

  -- 49 more misses within the SAME interval → all suppressed, zero new lines.
  for _ = 1, 49 do M.set_cert() end
  check(#warn_lines == 0, "F43: misses within the interval are suppressed (got " .. #warn_lines .. ")")

  -- Advancing past MISS_LOG_INTERVAL logs once, reporting the accumulated count
  -- (49 suppressed + this one = 50).
  _now = 2000 + 11
  M.set_cert()
  check(#warn_lines == 1, "F43: a miss after the interval logs exactly one WARN (got " .. #warn_lines .. ")")
  check(warn_lines[1]:find("50 miss", 1, true) ~= nil,
        "F43: the WARN reports the coalesced suppressed count (got: " .. tostring(warn_lines[1]) .. ")")

  -- Attacker-controlled SNI with a newline/space is neutralized on the log line.
  sslmock._sni = "evil\n injected=1 .example.com"
  warn_lines = {}
  _now = 5000
  M.set_cert()
  check(#warn_lines == 1, "F43: sanitized-SNI miss logs one WARN")
  check(warn_lines[1]:find("\n injected", 1, true) == nil,
        "F43: raw newline/space from the SNI must NOT appear verbatim in the log (got: " .. tostring(warn_lines[1]) .. ")")
end

if fails > 0 then
  io.stderr:write("\n" .. fails .. " test(s) failed in sslcollector_hotpath_test.lua\n")
  os.exit(1)
end
io.stdout:write("ok: sslcollector hot-path tests (F19 cached-DER + F43 miss-log throttle)\n")
