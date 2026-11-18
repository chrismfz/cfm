-- Rule 601 (rule_ctrl_chars) on Engine.IO v4 HTTP long-polling.
--
-- Engine.IO v4 (the transport under Socket.IO 3+) joins the packets of one
-- polling POST with 0x1E, the record separator. On 2026-11-18 a batched
-- `POST /socket.io/?EIO=4&transport=polling` from a browser on
-- crm-staging.creatures.gr (speedhost) was challenged by 601, and a challenge
-- breaks the XHR. On that request only, 0x1E is framing and is left out of
-- the scan; every other control byte, and the query, still count.

_G.ngx = {
  now           = function() return 1000 end,
  decode_base64 = function(_) return nil end,
  log           = function(_, _) end,
  ERR           = 0, WARN = 1, INFO = 2,
}
package.path = "configs/lua/?.lua;" .. package.path
local det = require("cfm_waf_detectors")
local waf = require("cfm_waf")

local fails = 0
local function check(cond, msg)
  if cond then return end
  fails = fails + 1
  io.stderr:write("FAIL: " .. msg .. "\n")
end

local H = { ["content-type"] = "text/plain;charset=UTF-8" }
-- Two packets in one polling POST: a message and a ping, 0x1E between them.
local BATCH = '42["chat","hello"]\x1e3'
local ARGS = "EIO=4&transport=polling&t=ehgkjs8o&sid=hEzwv1QJ39MhkRLFAAAA"

local function fires(args, body, uri, msg)
  check(det.detect_ctrl_chars(args, body, H, uri) == true, msg .. " (must fire)")
end
local function clean(args, body, uri, msg)
  check(det.detect_ctrl_chars(args, body, H, uri) ~= true, msg .. " (must not fire)")
end

-- ── The production request ─────────────────────────────────────────────────
clean(ARGS, BATCH, "/socket.io/", "batched EIO=4 polling POST")
clean(ARGS, BATCH, "/socket.io", "no trailing slash")
clean(ARGS, BATCH, "/app/socket.io/", "Socket.IO mounted under a prefix (`path` option)")
clean("transport=polling&EIO=4", BATCH, "/socket.io/", "parameters in the other order")
clean("t=1&EIO=4&transport=polling", BATCH, "/socket.io/", "EIO not first")
clean("eio=4&TRANSPORT=POLLING", BATCH, "/socket.io/", "case of the query")

-- ── Only 0x1E is framing ───────────────────────────────────────────────────
fires(ARGS, '42["x","\x01"]\x1e3', "/socket.io/", "another control byte in the batch")
fires(ARGS, '42["x","\x1f"]', "/socket.io/", "0x1F (unit separator) is not the framing byte")
fires("EIO=4&transport=polling&x=%01\1", BATCH, "/socket.io/", "a control byte in the query still counts")

-- ── Only Engine.IO v4 polling on a socket.io path ──────────────────────────
fires(ARGS, BATCH, "/api/socket", "not a socket.io path")
fires(ARGS, BATCH, "/socket.io/x.php", "socket.io is not the last path segment")
fires(ARGS, BATCH, "/notsocket.io/x/", "socket.io elsewhere in the path")
fires("EIO=3&transport=polling", BATCH, "/socket.io/", "EIO=3 frames by length, not 0x1E")
fires("EIO=40&transport=polling", BATCH, "/socket.io/", "EIO=40 is not 4")
fires("EIO=4&transport=websocket", BATCH, "/socket.io/", "websocket transport has no polling batch")
fires("EIO=4&transport=pollingx", BATCH, "/socket.io/", "transport=pollingx")
fires("xEIO=4&transport=polling", BATCH, "/socket.io/", "xEIO is not EIO")
fires("transport=polling", BATCH, "/socket.io/", "no EIO")
fires("EIO=4", BATCH, "/socket.io/", "no transport")

-- ── End to end under the shipped modes ─────────────────────────────────────
local function check_req(args, body, uri)
  return waf.check({
    uri = uri, args = args, method = "POST", raw_uri = uri .. "?" .. args,
    host = "crm.example", ip = "203.0.113.5", peer = "203.0.113.5",
    cookie = "", headers = {
      ["content-type"] = H["content-type"],
      ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
      ["accept"] = "*/*", ["accept-language"] = "el-GR,el;q=0.9",
      ["content-length"] = tostring(#body),
    },
    body = body,
  })
end
local hit, reason = check_req(ARGS, BATCH, "/socket.io/")
check(not (hit and tostring(reason):find("WAF_CTRL_CHARS", 1, true)), "shipped WAF: no 601 on the polling batch (got " .. tostring(reason) .. ")")
local hit2, reason2 = check_req("EIO=4&transport=websocket", BATCH, "/socket.io/")
check(hit2 and tostring(reason2):find("WAF_CTRL_CHARS", 1, true) ~= nil, "shipped WAF: 601 still on a non-polling request (got " .. tostring(reason2) .. ")")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("ok: rule 601 leaves Engine.IO v4 polling framing (0x1E) alone")
