-- Rule 601 (rule_ctrl_chars) does not flag 0x1E, the record separator, in a
-- body (the query keeps the full control-byte set).
--
-- 0x1E is framing in several protocols a browser speaks to the origin:
-- Engine.IO v4 long-polling joins the packets of one POST with it (Socket.IO,
-- under any mount path), ASP.NET SignalR's JSON protocol ends every message
-- with it (the handshake included, POSTed over long-polling / SSE), and
-- RFC 7464 json-seq starts each record with it. On 2026-11-18 601 challenged
-- a batched `POST /socket.io/?EIO=4&transport=polling` on speedhost, and a
-- challenge breaks the XHR (docs/waf.md FP case 13). None of these protocols
-- puts 0x1E in the query, so only the body scan leaves it out; every other
-- control byte counts.

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

local TEXT = { ["content-type"] = "text/plain;charset=UTF-8" }
local JSON = { ["content-type"] = "application/json" }
local function fires(args, body, h, uri, msg)
  check(det.detect_ctrl_chars(args, body, h, uri) == true, msg .. " (must fire)")
end
local function clean(args, body, h, uri, msg)
  check(det.detect_ctrl_chars(args, body, h, uri) ~= true, msg .. " (must not fire)")
end

-- ── 0x1E in a body is framing: never a hit, whatever the path ──────────────
local EIO = "EIO=4&transport=polling&t=ehgkjs8o&sid=hEzwv1QJ39MhkRLFAAAA"
local BATCH = '42["chat","hello"]\x1e3'
clean(EIO, BATCH, TEXT, "/socket.io/", "Engine.IO v4 polling batch (the speedhost request)")
clean(EIO, BATCH, TEXT, "/realtime/", "Socket.IO under a custom `path`")
clean("id=Yd4Q2xg", '{"protocol":"json","version":1}\x1e', TEXT, "/chathub",
      "SignalR handshake over long-polling")
clean("id=Yd4Q2xg", '{"type":1,"target":"Send","arguments":["hi"]}\x1e{"type":6}\x1e', TEXT, "/chathub",
      "SignalR messages")
clean("", '\x1e{"a":1}\n\x1e{"a":2}\n', { ["content-type"] = "application/json-seq" }, "/api/feed",
      "RFC 7464 json-seq")
clean("", '{"a":1}\x1e', JSON, "/wp-json/x/v1/y", "0x1E in a JSON body")

-- ── Every other control byte still counts ──────────────────────────────────
fires(EIO, '42["x","\x01"]\x1e3', TEXT, "/socket.io/", "0x01 beside the framing")
fires("", '{"a":"\x1f"}', JSON, "/api/x", "0x1F (unit separator)")
fires("", '{"a":"\x1d"}', JSON, "/api/x", "0x1D (group separator)")
fires("", '{"a":"\x0e"}', JSON, "/api/x", "0x0E")
fires("", '{"a":"\x08"}', JSON, "/api/x", "0x08")
fires("", '{"a":"\x0b"}', JSON, "/api/x", "0x0B (vertical tab)")
clean("", '{"a":"x\ty\r\nz"}', JSON, "/api/x", "TAB / CR / LF are text")

-- The query keeps the full set, 0x1E included (it is searched as it arrives;
-- whether %01 is decoded is not this test's subject).
fires("q=a\x01b", "", TEXT, "/x", "a raw control byte in the query")
fires("q=a\x1eb", "", TEXT, "/x", "a raw 0x1E in the query")

-- ── End to end under the shipped modes: 601 among the hits or not ──────────
local function has601(args, body, uri)
  local _, _, _, _, hits = waf.check({
    uri = uri, args = args, method = "POST", raw_uri = uri .. "?" .. args,
    host = "crm.example", ip = "203.0.113.5", peer = "203.0.113.5",
    cookie = "", headers = {
      ["content-type"] = TEXT["content-type"],
      ["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
      ["accept"] = "*/*", ["accept-language"] = "el-GR,el;q=0.9",
      ["content-length"] = tostring(#body),
    },
    body = body,
  })
  for _, h in ipairs(hits or {}) do
    if tonumber(h.waf_rule_id) == 601 then return true end
  end
  return false
end
check(not has601(EIO, BATCH, "/socket.io/"), "shipped WAF: no 601 on the polling batch")
check(has601(EIO, '42["x","\x01"]', "/socket.io/"), "shipped WAF: 601 on another control byte")

if fails > 0 then
  io.stderr:write(fails .. " failure(s)\n")
  os.exit(1)
end
print("ok: rule 601 leaves 0x1E (record separator) in a body alone, every other control byte counts")
