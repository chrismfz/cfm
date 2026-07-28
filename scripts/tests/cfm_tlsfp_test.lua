-- Standalone test for cfm_tlsfp (the edge half of the TLS fingerprint
-- signal). Run with:
--   luajit scripts/tests/cfm_tlsfp_test.lua
--
-- The two properties that matter here are safety properties, not feature ones:
--
--  1. the value can never carry CR/LF or a stray "|" into the daemon's parser
--     (it ends up in a log line, so header splitting is the risk), and
--  2. a client-supplied X-CFM-TLS is always cleared, even when there is no
--     handshake to describe — otherwise a client picks its own fingerprint.
--
-- It also pins graceful degradation on an older edge: $ssl_curves needs
-- OpenSSL 1.0.2+ and $ssl_alpn_protocol needs nginx 1.21.4+, and reading a
-- variable the edge does not define must produce an empty field rather than
-- raise on the verify path.

package.path = package.path .. ";configs/lua/?.lua;./?.lua"

local vars = {}
local headers = {}
local raise_on = {}

_G.ngx = {
  req = {
    clear_header = function(name) headers[name] = nil end,
    set_header = function(name, value) headers[name] = value end,
  },
}
-- ngx.var behaves like OpenResty's: a table lookup, which may raise for names
-- the edge does not know about.
setmetatable(ngx, { __index = function(_, k) return nil end })
ngx.var = setmetatable({}, {
  __index = function(_, name)
    if raise_on[name] then error("unknown variable \"" .. name .. "\"") end
    return vars[name]
  end,
})

local fp = require "cfm_tlsfp"

local failures = 0
local function check(cond, msg)
  if cond then
    print("ok   - " .. msg)
  else
    failures = failures + 1
    print("FAIL - " .. msg)
  end
end

local function reset()
  vars = {}
  headers = {}
  raise_on = {}
end

-- 1. the happy path: a Chrome-shaped handshake
reset()
vars.ssl_protocol = "TLSv1.3"
vars.ssl_ciphers = "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256"
vars.ssl_curves = "X25519:prime256v1"
vars.ssl_alpn_protocol = "h2"
vars.server_protocol = "HTTP/2.0"
vars.ssl_session_reused = "."
fp.stamp()
-- "." is nginx's not-reused marker for $ssl_session_reused ("r" means reused);
-- it is kept verbatim so the field always says which of the two it saw.
check(headers["X-CFM-TLS"] ==
  "1|TLSv1.3|TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256|X25519:prime256v1|h2|HTTP/2.0|.",
  "stamps the versioned tuple in field order")

-- 2. a resumed session is marked, because a resumed handshake can carry thinner
--    cipher/curve lists and a reader must be able to tell that apart from a
--    strange client
reset()
vars.ssl_protocol = "TLSv1.3"
vars.ssl_session_reused = "r"
fp.stamp()
check(headers["X-CFM-TLS"] == "1|TLSv1.3|||||r", "carries the resumption flag")

-- 3. plain HTTP: nothing to describe, and no stale header left behind
reset()
headers["X-CFM-TLS"] = "1|attacker|chosen|value|h2|HTTP/2.0|"
fp.stamp()
check(headers["X-CFM-TLS"] == nil,
  "clears a client-supplied header even when there is no handshake to stamp")

-- 4. a client-supplied header is replaced, never appended to
reset()
headers["X-CFM-TLS"] = "1|attacker|chosen|value|h2|HTTP/2.0|"
vars.ssl_protocol = "TLSv1.2"
fp.stamp()
check(headers["X-CFM-TLS"] == "1|TLSv1.2||||" .. "|",
  "replaces a client-supplied header with the edge value")

-- 5. header splitting and separator smuggling. nginx will not produce these,
--    but the value reaches a log line, so the sanitiser is the guarantee.
reset()
vars.ssl_protocol = "TLSv1.3"
vars.ssl_ciphers = "AES\r\nX-Injected: 1"
vars.ssl_curves = "X25519|1|spoofed"
vars.ssl_alpn_protocol = "h2\n"
fp.stamp()
local v = headers["X-CFM-TLS"]
check(v ~= nil and not v:find("[\r\n]"), "strips CR/LF from every field")
check(v == "1|TLSv1.3|AESX-Injected:1|X255191spoofed|h2||",
  "strips the field separator out of field contents")

-- 6. graceful degradation: reading a variable the edge does not define must not
--    raise, and must not lose the fields that DO exist
reset()
vars.ssl_protocol = "TLSv1.2"
vars.ssl_ciphers = "ECDHE-RSA-AES128-GCM-SHA256"
raise_on.ssl_curves = true
raise_on.ssl_alpn_protocol = true
local ok = pcall(fp.stamp)
check(ok, "does not raise when an nginx variable is undefined")
check(headers["X-CFM-TLS"] == "1|TLSv1.2|ECDHE-RSA-AES128-GCM-SHA256|||HTTP/1.1|" or
  headers["X-CFM-TLS"] == "1|TLSv1.2|ECDHE-RSA-AES128-GCM-SHA256||||",
  "keeps the fields the edge does provide")

-- 7. bounds: one weird client must not write an unbounded log line
reset()
vars.ssl_protocol = "TLSv1.3"
vars.ssl_ciphers = string.rep("A", 5000)
vars.ssl_curves = string.rep("B", 5000)
fp.stamp()
check(#headers["X-CFM-TLS"] <= 1024, "bounds the total value")

-- 8. "-" is nginx's empty marker, not a value
reset()
vars.ssl_protocol = "TLSv1.3"
vars.ssl_alpn_protocol = "-"
fp.stamp()
check(headers["X-CFM-TLS"] == "1|TLSv1.3||||" .. "|" or
  headers["X-CFM-TLS"]:find("|%-|") == nil, "treats \"-\" as an empty field")

if failures > 0 then
  print(failures .. " check(s) failed")
  os.exit(1)
end
print("all cfm_tlsfp checks passed")
