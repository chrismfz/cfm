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
check(#headers["X-CFM-TLS"] <= 2048, "bounds the total value")

-- 7b. truncation must land on a ":" boundary and say so.
--
-- Production found this: on 2026-07-28 Meta's crawler offered a cipher list
-- longer than the old 512-byte bound and the value was cut mid-name, ending
-- "...:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-S". A partial cipher name is
-- worse than a dropped one — it reads as a cipher, and it fabricates a token
-- that exists in no ClientHello.
reset()
vars.ssl_protocol = "TLSv1.3"
local suites = {}
for i = 1, 80 do suites[i] = "ECDHE-ECDSA-AES256-GCM-SHA384" end
vars.ssl_ciphers = table.concat(suites, ":")
fp.stamp()
local cut = headers["X-CFM-TLS"]:match("^1|TLSv1%.3|([^|]*)|")
check(cut ~= nil and #cut <= 1024, "bounds a single field")
check(cut:sub(-6) == ":TRUNC", "marks a truncated field with a TRUNC token")
for tok in cut:gmatch("[^:]+") do
  check(tok == "ECDHE-ECDSA-AES256-GCM-SHA384" or tok == "TRUNC",
    "every token survives whole: got " .. tok)
end

-- 7d. the tuple must never lose a FIELD, however long the lists are.
--
-- MAX_FIELD bounds each list but not their sum, and the client picks both: it
-- may offer as many unknown suites and groups as it likes and nginx renders
-- every unknown one as hex. Cutting the joined tuple instead of the fields was
-- measured to produce a 2048-byte value with three separators instead of six —
-- ALPN, the HTTP version and the resumption flag gone, so the value read as
-- "a client that offered no ALPN" (the shape the roadmap treats as suspicious),
-- with the TRUNC marker itself cut to "TR" so nothing said it was incomplete.
-- A client could manufacture that on purpose. Every field must survive.
reset()
local many_c, many_g = {}, {}
for i = 1, 200 do many_c[i] = string.format("0x%04x", 0x1300 + i) end
for i = 1, 200 do many_g[i] = string.format("0x%04x", 0x2300 + i) end
vars.ssl_protocol = "TLSv1.3"
vars.ssl_ciphers = table.concat(many_c, ":")
vars.ssl_curves = table.concat(many_g, ":")
vars.ssl_alpn_protocol = "h2"
vars.server_protocol = "HTTP/2.0"
vars.ssl_session_reused = "r"
fp.stamp()
local big = headers["X-CFM-TLS"]
check(big ~= nil, "an oversized ClientHello still yields a value")
local seps = select(2, big:gsub("|", ""))
check(seps == 6, "keeps all seven fields, got " .. seps .. " separators")
check(#big <= 2048, "still within the total bound: " .. #big)
local bf = {}
for field in (big .. "|"):gmatch("([^|]*)|") do bf[#bf + 1] = field end
check(bf[5] == "h2", "ALPN survives an oversized cipher/curve pair, got " .. tostring(bf[5]))
check(bf[6] == "HTTP/2.0", "HTTP version survives, got " .. tostring(bf[6]))
check(bf[7] == "r", "resumption flag survives, got " .. tostring(bf[7]))
-- The marker must be whole. A cut "TR" is worse than no marker: the daemon
-- reads TRUNC as a token, so a mangled one silently reports trunc=false.
check(big:find(":TRUNC|") ~= nil, "the TRUNC marker itself is not cut")
check(big:find(":TR|") == nil, "no half-written marker")

-- 7c. a field that fits is untouched — no TRUNC on a normal browser.
reset()
vars.ssl_protocol = "TLSv1.3"
vars.ssl_ciphers = "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256"
fp.stamp()
check(headers["X-CFM-TLS"]:find("TRUNC") == nil, "does not mark a field that fits")

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
